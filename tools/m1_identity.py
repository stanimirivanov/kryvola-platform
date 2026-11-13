"""Ephemeral local SPIRE UID attestation; not a preproduction identity deployment."""

import hashlib
import io
import json
import os
import socket
import subprocess
import tarfile
import time
import urllib.request
from contextlib import contextmanager
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
URL = (
    "https://github.com/spiffe/spire/releases/download/v1.16.0/spire-1.16.0-linux-amd64-musl.tar.gz"
)
DIGEST = "7bcf5e167151a1fc58293768462b44e155ba8784214582aefa6adf18c633d1d5"
TOOLS = ROOT / "build/m1-tools"


def install():
    TOOLS.mkdir(parents=True, exist_ok=True)
    archive = TOOLS / "spire.tar.gz"
    if not archive.exists():
        with urllib.request.urlopen(URL, timeout=60) as response:
            data = response.read((128 << 20) + 1)
        if hashlib.sha256(data).hexdigest() != DIGEST:
            raise ValueError("M1_SPIRE_PIN")
        archive.write_bytes(data)
    if hashlib.sha256(archive.read_bytes()).hexdigest() != DIGEST:
        raise ValueError("M1_SPIRE_PIN")
    with tarfile.open(fileobj=io.BytesIO(archive.read_bytes())) as stream:
        for name in ("spire-server", "spire-agent"):
            entry = stream.getmember("spire-1.16.0/bin/" + name)
            if not entry.isfile() or entry.size > 256 << 20:
                raise ValueError("M1_SPIRE_PIN")
            raw = stream.extractfile(entry)
            if raw is None:
                raise ValueError("M1_SPIRE_PIN")
            data = raw.read()
            target = TOOLS / name
            if target.is_symlink():
                raise ValueError("M1_SPIRE_PIN")
            if not target.exists() or target.read_bytes() != data:
                target.write_bytes(data)
            target.chmod(0o755)


@contextmanager
def identity(folder, socket_folder):
    # Based on SPIRE's join-token bootstrap and unix WorkloadAttestor pattern.
    # The host agent can inspect container peer PIDs without privileged workloads.
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    server_socket = folder / "server.sock"
    agent_socket = socket_folder / "agent.sock"
    (folder / "server.conf").write_text(f'''
server {{ bind_address = "127.0.0.1" bind_port = {port} trust_domain = "m1.test"
 data_dir = "{folder}/server" socket_path = "{server_socket}" log_level = "ERROR" }}
plugins {{
 DataStore "sql" {{ plugin_data {{ database_type = "sqlite3" connection_string = "{folder}/db" }} }}
 KeyManager "disk" {{ plugin_data {{ keys_path = "{folder}/keys.json" }} }}
 NodeAttestor "join_token" {{ plugin_data {{}} }} }}
''')
    (folder / "agent.conf").write_text(f'''
agent {{ data_dir = "{folder}/agent" log_level = "ERROR" trust_domain = "m1.test"
 server_address = "127.0.0.1" server_port = {port} socket_path = "{agent_socket}"
 insecure_bootstrap = true }}
plugins {{ KeyManager "memory" {{ plugin_data {{}} }}
 NodeAttestor "join_token" {{ plugin_data {{}} }}
 WorkloadAttestor "unix" {{ plugin_data {{}} }} }}
''')
    processes, logs = [], []

    def command(binary, *args):
        return subprocess.check_output(
            [str(TOOLS / binary), *map(str, args)], stderr=subprocess.PIPE, timeout=15
        )

    def start(binary, config, *args):
        log = (folder / (binary + ".log")).open("wb")
        logs.append(log)
        process = subprocess.Popen(
            [str(TOOLS / binary), "run", "-config", str(config), *args], stdout=log, stderr=log
        )
        processes.append(process)
        return process

    def ready(path, process):
        deadline = time.monotonic() + 30
        while not path.exists():
            if process.poll() is not None or time.monotonic() > deadline:
                raise ValueError("M1_IDENTITY_STARTUP")
            time.sleep(0.1)

    try:
        server = start("spire-server", folder / "server.conf")
        ready(server_socket, server)
        parent = "spiffe://m1.test/agent"
        token = json.loads(
            command(
                "spire-server",
                "token",
                "generate",
                "-socketPath",
                server_socket,
                "-spiffeID",
                parent,
                "-output",
                "json",
            )
        )["value"]
        for role, uid in (
            ("runtime", 2001),
            ("workflow", 2002),
            ("owner", 3001),
            ("worker", 65532),
            ("probe", os.getuid()),
        ):
            command(
                "spire-server",
                "entry",
                "create",
                "-socketPath",
                server_socket,
                "-parentID",
                parent,
                "-spiffeID",
                "spiffe://m1.test/" + role,
                "-selector",
                f"unix:uid:{uid}",
                "-x509SVIDTTL",
                "45",
            )
        agent = start("spire-agent", folder / "agent.conf", "-joinToken", token)
        ready(agent_socket, agent)
        agent_socket.chmod(0o777)  # Identity comes from peer UID, not socket possession.
        deadline = time.monotonic() + 30
        while True:
            try:
                result = json.loads(
                    command(
                        "spire-agent",
                        "api",
                        "fetch",
                        "x509",
                        "-socketPath",
                        agent_socket,
                        "-output",
                        "json",
                    )
                )
                if any(s["spiffe_id"] == "spiffe://m1.test/probe" for s in result["svids"]):
                    break
            except subprocess.CalledProcessError:
                pass
            if time.monotonic() > deadline:
                raise ValueError("M1_IDENTITY_NOT_ATTESTING")
            time.sleep(0.2)
        yield agent_socket
    finally:
        for process in reversed(processes):
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
        for log in logs:
            log.close()
