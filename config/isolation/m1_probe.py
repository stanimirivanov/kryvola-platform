"""Instrumented worker: emit bounded structural evidence, never credentials or data."""

import base64
import ctypes
import hashlib
import http.client
import importlib.util
import json
import os
import socket
import ssl
import subprocess
import sys
import tempfile
from pathlib import Path


def fetch():
    raw = subprocess.check_output(
        [
            "/opt/m1/spire-agent",
            "api",
            "fetch",
            "x509",
            "-socketPath",
            "/run/workload/agent.sock",
            "-output",
            "json",
        ],
        stderr=subprocess.PIPE,
        timeout=10,
    )
    return json.loads(raw)["svids"]


def tls(role):
    identity = "spiffe://m1.test/" + role
    svid = next(s for s in fetch() if s["spiffe_id"] == identity)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    with tempfile.TemporaryDirectory(prefix="isolation-svid-") as tmp:
        root = Path(tmp)
        for field, name, label in (
            ("x509_svid", "cert", "CERTIFICATE"),
            ("x509_svid_key", "key", "PRIVATE KEY"),
            ("bundle", "ca", "CERTIFICATE"),
        ):
            path = root / name
            path.write_text(
                ssl.DER_cert_to_PEM_cert(base64.b64decode(svid[field])).replace(
                    "CERTIFICATE", label
                )
            )
            path.chmod(0o600)
        context.load_verify_locations(root / "ca")
        context.load_cert_chain(root / "cert", root / "key")
    return context


def http_request(value):
    conn = http.client.HTTPSConnection(value["host"], 8443, context=tls(value["role"]), timeout=8)
    try:
        conn.connect()
        cert = conn.sock.getpeercert() if conn.sock else None
        if not cert or [x for x in cert.get("subjectAltName", ()) if x[0] == "URI"] != [
            ("URI", "spiffe://m1.test/runtime")
        ]:
            raise ValueError("ISOLATION_RUNTIME_IDENTITY")
        body = value.get("body")
        if "data" in value:
            body = base64.b64decode(value["data"], validate=True)
            content = "application/octet-stream"
        else:
            body = None if body is None else json.dumps(body).encode()
            content = "application/json"
        conn.request(
            value["method"],
            value["path"],
            body,
            {
                "Authorization": "Bearer " + value["token"],
                "Content-Type": content,
                "X-Tenant-Scope": "forged-tenant",
            },
        )
        response = conn.getresponse()
        raw = response.read(131073)
        if len(raw) > 131072:
            raise ValueError("ISOLATION_RESPONSE_LIMIT")
        binary = response.getheader("Content-Type") == "application/octet-stream"
        result = {"status": response.status}
        if binary:
            if response.getheader("Cache-Control") != "no-store":
                raise ValueError("ISOLATION_ARTIFACT_CACHE")
            result["digest"] = hashlib.sha256(raw).hexdigest()
        else:
            result["body"] = json.loads(raw) if raw else None
        return result
    finally:
        conn.close()


def inventory():
    forbidden = (
        "/owner",
        "/run/m1-secrets/database",
        "/run/m1-secrets/database-release",
        "/run/m1-secrets/pg-admin",
        "/run/m1-secrets/admin.key",
        "/run/m1-secrets/release.json",
        "/var/run/docker.sock",
        "/var/run/secrets/kubernetes.io/serviceaccount/token",
    )
    for path in forbidden:
        if Path(path).exists():
            raise ValueError("ISOLATION_CREDENTIAL_VISIBLE")
    status = dict(
        line.split(":", 1)
        for line in Path("/proc/self/status").read_text().splitlines()
        if ":" in line
    )
    if status["NoNewPrivs"].strip() != "1" or int(status["CapBnd"].strip(), 16) != 0:
        raise ValueError("ISOLATION_PRIVILEGE_BOUNDING")
    caps = next(
        x.split()[1]
        for x in Path("/proc/self/status").read_text().splitlines()
        if x.startswith("CapEff:")
    )
    if os.geteuid() != 65532 or int(caps, 16) != 0:
        raise ValueError("ISOLATION_PRIVILEGE")
    try:
        os.setuid(0)
    except PermissionError:
        pass
    else:
        raise ValueError("ISOLATION_ROOT_MUTATION_SUCCEEDED")
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.mount(b"none", b"/tmp", b"tmpfs", 0, None) != -1 or ctypes.get_errno() != 1:
        raise ValueError("ISOLATION_MOUNT_MUTATION_SUCCEEDED")
    return {
        "uid": os.geteuid(),
        "effective_capabilities": int(caps, 16),
        "owner_library": importlib.util.find_spec("kryvola_owner") is not None,
        "forbidden_files_absent": True,
    }


def network(value):
    try:
        with socket.create_connection((value["host"], value["port"]), timeout=2):
            return {"connected": True}
    except (TimeoutError, ConnectionRefusedError, PermissionError):
        return {"connected": False}
    except OSError as error:
        if error.errno not in {101, 113}:
            raise
        return {"connected": False}


if __name__ == "__main__":
    try:
        raw = sys.stdin.buffer.read(131073)
        if len(raw) > 131072:
            raise ValueError("ISOLATION_INPUT_LIMIT")
        value = json.loads(raw)
        mode = value.pop("mode")
        result = {
            "http": http_request,
            "network": network,
            "inventory": lambda _: inventory(),
            "identity": lambda _: {"identities": sorted(s["spiffe_id"] for s in fetch())},
        }[mode](value)
        print(json.dumps(result, separators=(",", ":")))
    except Exception:
        raise SystemExit("M1_WORKER_PROBE_FAILED") from None
