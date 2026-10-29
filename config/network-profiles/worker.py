"""Public bounded HTTP fixture, not an engine, owner or general HTTP server."""

import hashlib
import http.client
import json
import sys
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import urlsplit

CHUNK = 65_536
COUNT = 4
DATA = {}
MAX_OBSERVED = 0


def resources():
    if sys.platform == "linux":
        import resource

        result = {
            "process_peak_rss_bytes": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * 1024
        }
    else:
        raise ValueError("LINUX_RESOURCE_OBSERVATION_REQUIRED")
    for name, file in (
        ("container_current_bytes", "memory.current"),
        ("container_lifetime_peak_bytes", "memory.peak"),
    ):
        try:
            value = int(Path("/sys/fs/cgroup", file).read_text())
            result[name] = {"value": value, "reason": None}
        except OSError, ValueError:
            result[name] = {"value": None, "reason": "CGROUP_V2_METRIC_UNAVAILABLE"}
    return result


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, format: str, *args):
        pass

    def respond(self, code, body):
        self.send_response(code)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/ping":
            self.respond(200, b"ok")
        elif self.path == "/metrics":
            self.respond(
                200,
                json.dumps(
                    {
                        **resources(),
                        "stored_bytes": sum(map(len, DATA.values())),
                        "max_inflight_payload_bytes": MAX_OBSERVED,
                    }
                ).encode(),
            )
        elif self.path in DATA:
            self.respond(200, DATA[self.path])
        else:
            self.respond(404, b"")

    def do_PUT(self):
        global MAX_OBSERVED
        size = int(self.headers.get("Content-Length", "-1"))
        if self.path not in {f"/chunk/{n}" for n in range(COUNT)} or not 0 <= size <= CHUNK:
            self.close_connection = True
            self.respond(413, b"")
            return
        self.connection.settimeout(3)
        body = self.rfile.read(size)
        if len(body) != size:
            self.respond(400, b"")
            return
        MAX_OBSERVED = max(MAX_OBSERVED, size)
        DATA[self.path] = body
        self.respond(200, hashlib.sha256(body).hexdigest().encode())


def request(endpoint, method, path, body=None, oversized=False):
    target = urlsplit(endpoint)
    connection = http.client.HTTPConnection(target.hostname, target.port, timeout=5)
    try:
        if oversized:
            connection.putrequest("PUT", path)
            connection.putheader("Content-Length", str(CHUNK + 1))
            connection.endheaders()
        else:
            connection.request(method, path, body=body)
        response = connection.getresponse()
        length = int(response.getheader("Content-Length", "-1"))
        if not 0 <= length <= CHUNK:
            raise ValueError("RESPONSE_LIMIT")
        return response.status, response.read(length)
    finally:
        connection.close()


def batch(endpoint, count):
    admitted = time.monotonic_ns()
    rows = []
    for index in range(count):
        body = bytes([index]) * CHUNK
        started = time.monotonic_ns()
        row = {
            "index": index,
            "queue_ns": started - admitted,
            "outcome": "IO_FAILURE",
            "upload_ns": None,
            "download_ns": None,
            "uploaded_bytes": None,
            "downloaded_bytes": None,
            "max_inflight_payload_bytes": CHUNK,
            "payload_sha256": hashlib.sha256(body).hexdigest(),
        }
        try:
            upload = time.monotonic_ns()
            status, digest = request(endpoint, "PUT", f"/chunk/{index}", body)
            row["upload_ns"] = time.monotonic_ns() - upload
            if status != 200 or digest.decode() != hashlib.sha256(body).hexdigest():
                raise ValueError("UPLOAD_INTEGRITY")
            row["uploaded_bytes"] = CHUNK
            download = time.monotonic_ns()
            status, actual = request(endpoint, "GET", f"/chunk/{index}")
            row["download_ns"] = time.monotonic_ns() - download
            if status != 200 or actual != body:
                raise ValueError("DOWNLOAD_INTEGRITY")
            row.update(outcome="SUCCEEDED", downloaded_bytes=len(actual))
        except TimeoutError, OSError, http.client.HTTPException:
            pass  # Failure bytes remain unknown, never manufactured as zero.
        row["finish_ns"] = time.monotonic_ns() - admitted
        rows.append(row)
    return {"rows": rows, "elapsed_ns": time.monotonic_ns() - admitted, "resources": resources()}


def main():
    action = sys.argv[1]
    if action == "server":
        HTTPServer(("0.0.0.0", 8088), Handler).serve_forever()
    elif action == "control":
        raw = sys.stdin.buffer.read(8193)
        if len(raw) > 8192 or not sys.argv[2].startswith("/proxies"):
            raise ValueError("CONTROL_LIMIT")
        query = urllib.request.Request(
            "http://toxiproxy:8474" + sys.argv[2],
            data=raw or None,
            method=sys.argv[3],
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(query, timeout=5) as reply:
            print(reply.read(8192).decode())
    elif action == "batch":
        count = int(sys.argv[3])
        if not 1 <= count <= COUNT:
            raise ValueError("COUNT_LIMIT")
        print(json.dumps(batch(sys.argv[2], count)))
    elif action == "ping":
        start = time.monotonic_ns()
        status, data = request(sys.argv[2], "GET", "/ping")
        if status != 200 or data != b"ok":
            raise ValueError("PING")
        print(json.dumps({"elapsed_ns": time.monotonic_ns() - start}))
    elif action == "bounds":
        status, _ = request("http://transfer:8088", "PUT", "/chunk/0", oversized=True)
        if status != 413:
            raise ValueError("OVERSIZED_REQUEST_ACCEPTED")
        status, data = request("http://transfer:8088", "GET", "/metrics")
        if status != 200:
            raise ValueError("METRICS")
        print(data.decode())


if __name__ == "__main__":
    main()
