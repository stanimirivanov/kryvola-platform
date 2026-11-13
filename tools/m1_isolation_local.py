"""Real M1 local worker probes; host/namespace helpers are explicitly trusted fixtures."""

import hashlib
import json
import secrets
import subprocess
from pathlib import Path
from urllib.parse import urlsplit

if __package__:
    from . import m1, m1_assets, m1_isolation, m1_isolation_case
else:
    import m1
    import m1_assets
    import m1_isolation
    import m1_isolation_case

ROOT = Path(__file__).resolve().parents[1]
PROBE = ROOT / "config/isolation/m1_probe.py"
LISTENERS = ROOT / "config/isolation/m1_listeners.py"


class Local:
    runtime_host = "runtime"

    def __init__(self, stack):
        self.stack = stack
        self.extra = []
        self.owner_canary = b"PUBLIC_ISOLATION_CANARY_NOT_A_KEY_" + secrets.token_hex(24).encode()
        self.sensitive = [self.owner_canary]
        folder = stack.folder / "secrets"
        for name in ("pg-admin", "database", "database-release", "database-events"):
            raw = (folder / name).read_bytes()
            self.sensitive.append(raw)
            if name.startswith("database"):
                self.sensitive.append(urlsplit(raw.decode()).password.encode())

        def collect(value):
            if isinstance(value, dict):
                for key, child in value.items():
                    if key in {"secretKey", "secret_access_key"}:
                        self.sensitive.append(child.encode())
                    else:
                        collect(child)
            elif isinstance(value, list):
                for child in value:
                    collect(child)

        for name in ("s3.json", "s3-server.json"):
            collect(json.loads((folder / name).read_bytes()))
        self.actor = {}
        self.addresses = {}
        for role in (
            "runtime",
            "engine",
            "ray",
            "workflow",
            "owner",
            "broker",
            "s3-client",
            "postgres",
        ):
            identifier = stack.compose("ps", "-q", role).decode().strip()
            info = json.loads(subprocess.check_output(["docker", "inspect", identifier]))[0]
            self.actor[role] = identifier
            self.addresses[role] = info["NetworkSettings"]["Networks"]
        self.image = json.loads(
            subprocess.check_output(["docker", "inspect", self.actor["workflow"]])
        )[0]["Config"]["Image"]
        self.socket = stack.env["M1_SOCKET"]

    def run(self, args, *, payload=None, check=True):
        return subprocess.run(
            ["docker", *args], input=payload, capture_output=True, check=check, timeout=30
        )

    def helper(self, role, argv, payload=None, *, daemon=False, mounts=()):
        name = self.stack.project + "-probe-" + secrets.token_hex(4)
        self.extra.append(name)
        args = [
            "run",
            "--name",
            name,
            "--label",
            "com.docker.compose.project=" + self.stack.project,
            "--label",
            "io.kryvola.m1.invocation=" + self.stack.token,
            "--label",
            "com.docker.compose.service=isolation-probe",
            "--network",
            "container:" + self.actor[role],
            "--user",
            "2002:2002" if role == "workflow" else "65532:65532",
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges:true",
            "--memory",
            "256m",
            "--pids-limit",
            "64",
            "--tmpfs",
            "/tmp:rw,noexec,nosuid,nodev,size=64m",
        ]
        for source, target in mounts:
            args += ["--mount", "type=bind,src=" + str(source) + ",dst=" + target + ",readonly"]
        args += ["-d"] if daemon else ["--rm", "-i"]
        args += ["--entrypoint", "python", self.image, *argv]
        return self.run(args, payload=payload).stdout

    def probe(self, role, value):
        actor = {"worker": "engine", "workflow": "workflow", "ray": "ray"}[role]
        raw = self.helper(
            actor,
            ["/probe.py"],
            json.dumps(value).encode(),
            mounts=[
                (PROBE, "/probe.py"),
                (self.socket, "/run/workload"),
            ],
        )
        if len(raw) > 262144:
            raise ValueError("M1_PROBE_OUTPUT_LIMIT")
        m1_isolation.scan(raw, [*self.sensitive, *getattr(self, "tokens", [])])
        return json.loads(raw)

    def boot(self):
        return json.loads((self.stack.folder / "runtime-state/boot.json").read_bytes())["boot_id"]

    def publish(self, value):
        path = self.stack.folder / "secrets/policy.json"
        path.chmod(0o600)
        path.write_text(json.dumps(value))
        path.chmod(0o444)

    def canonical(self, value):
        code = (
            "import json,sys,base64;"
            "from kryvola_ml.sdk.client import canonical;"
            "from kryvola_ml.sdk.submission import commitment;"
            "r=canonical(json.load(sys.stdin));"
            "print(json.dumps({'raw':base64.b64encode(r).decode(),'digest':commitment('manifest',2,r)}))"
        )
        return json.loads(
            self.stack.execute("owner", "python", "-c", code, payload=json.dumps(value).encode())
        )

    def sql(self, query):
        return self.stack.sql(query).strip()

    def ip(self, role, network):
        return self.addresses[role][self.stack.project + "_" + network]["IPAddress"]

    def listeners(self):
        self.helper(
            "s3-client",
            ["/listeners.py", "metadata"],
            daemon=True,
            mounts=[(LISTENERS, "/listeners.py")],
        )
        self.helper(
            "broker",
            ["/listeners.py", "relay", self.ip("broker", "data")],
            daemon=True,
            mounts=[(LISTENERS, "/listeners.py")],
        )

    def targets_healthy(self):
        code = (
            "import http.client,json,sys;"
            "x=json.load(sys.stdin);"
            "c=http.client.HTTPConnection(x['host'],x['port'],timeout=3);"
            "c.request('GET',x['path']);"
            "r=c.getresponse();"
            "assert r.status==200;"
            "r.read(65536);"
            "print('HEALTHY')"
        )
        for host, port, path in (
            (self.ip("s3-client", "data"), 18080, "/metadata"),
            (self.ip("broker", "data"), 9644, "/v1/status/ready"),
        ):
            raw = self.helper(
                "s3-client",
                ["-c", code],
                json.dumps({"host": host, "port": port, "path": path}).encode(),
            )
            if raw.strip() != b"HEALTHY":
                raise ValueError("M1_TARGET_UNHEALTHY")

    def owner_positive(self):
        code = (
            "from pathlib import Path;"
            "import sys,hashlib;"
            "p=Path('/owner/isolation-canary');"
            "p.write_bytes(sys.stdin.buffer.read());"
            "p.chmod(0o600);"
            "print(hashlib.sha256(p.read_bytes()).hexdigest())"
        )
        raw = self.stack.execute("owner", "python", "-c", code, payload=self.owner_canary)
        if raw.strip().decode() != hashlib.sha256(self.owner_canary).hexdigest():
            raise ValueError("M1_OWNER_POSITIVE")

    def inventory(self):
        values = [
            json.loads(
                self.stack.execute(
                    role, "python3", "-c", PROBE.read_text(), payload=b'{"mode":"inventory"}'
                )
            )
            for role in ("engine", "ray")
        ]
        if values[0] != values[1]:
            raise ValueError("M1_WORKER_INVENTORY")
        return values[0]

    def database_denial(self):
        name = self.stack.project + "-pg-denial"
        self.extra.append(name)
        try:
            args = [
                "run",
                "--rm",
                "--name",
                name,
                "--label",
                "com.docker.compose.project=" + self.stack.project,
                "--label",
                "io.kryvola.m1.invocation=" + self.stack.token,
                "--label",
                "com.docker.compose.service=isolation-probe",
                "--network",
                "container:" + self.actor["engine"],
                "--user",
                "65532:65532",
                "--read-only",
                "--cap-drop",
                "ALL",
                "--security-opt",
                "no-new-privileges:true",
                "--memory",
                "128m",
                "--entrypoint",
                "psql",
                m1_assets.load()["services"]["postgres"],
                "-h",
                "postgres",
                "-U",
                "fabric_runtime",
                "-d",
                "fabric",
                "-w",
                "-c",
                "DELETE FROM fabric_operations WHERE operation_id='m1-isolation-own'",
            ]
            result = self.run(args, check=False)
            if result.returncode == 0 or b"no password supplied" not in result.stderr:
                raise ValueError("M1_DATABASE_NEGATIVE")
        finally:
            self.remove(name)

    def remove(self, name):
        result = self.run(["inspect", name], check=False)
        if result.returncode:
            if b"No such object" in result.stderr or b"No such container" in result.stderr:
                return
            raise ValueError("M1_HELPER_CLEANUP")
        labels = json.loads(result.stdout)[0]["Config"].get("Labels") or {}
        if labels.get("io.kryvola.m1.invocation") != self.stack.token:
            raise ValueError("M1_HELPER_OWNERSHIP")
        self.run(["rm", "-f", name])

    def close(self):
        for name in self.extra:
            self.remove(name)


def qualify():
    stack = m1.Stack("kryvola-m1-" + secrets.token_hex(6))
    adapter = None
    try:
        stack.start()
        stack.verify()
        adapter = Local(stack)
        adapter.owner_positive()
        adapter.listeners()
        stack.wait(adapter.targets_healthy, seconds=20)
        inventory = adapter.inventory()
        campaign = m1_isolation_case.Campaign(adapter)
        denied = campaign.run()
        adapter.database_denial()
        for key, role, port in (("metadata", "s3-client", 18080), ("broker_admin", "broker", 9644)):
            result = adapter.probe(
                "worker", {"mode": "network", "host": adapter.ip(role, "data"), "port": port}
            )
            if result != {"connected": False}:
                raise ValueError("M1_NETWORK_ISOLATION")
            denied[key] = "NETWORK_DENIED_HEALTHY_TARGET"
        for role, port, network in (
            ("s3-client", 18080, "data"),
            ("broker", 9644, "data"),
            ("postgres", 5432, "control"),
        ):
            host = adapter.ip(role, network)
            if adapter.probe("ray", {"mode": "network", "host": host, "port": port}) != {
                "connected": False
            }:
                raise ValueError("M1_RAY_NETWORK_ISOLATION")
        adapter.targets_healthy()
        denied.update(owner_files="NOT_MOUNTED", database="CREDENTIAL_REQUIRED")
        report = {
            "positive": dict.fromkeys(m1_isolation.POSITIVES, True),
            "denied": denied,
            "inventory": inventory,
        }
        logs = stack.compose("logs", "--no-color", "--tail", "100")
        m1_isolation.scan(logs, [*adapter.sensitive, *campaign.tokens])
        if logs.count(b"runtime_auth_denied") < 4:
            raise ValueError("M1_DENIAL_AUDIT_MISSING")
        m1_isolation.validate(report)
        if adapter.probe("worker", {"mode": "identity"}) != {
            "identities": ["spiffe://m1.test/worker"]
        }:
            raise ValueError("M1_LOCAL_IDENTITY_ESCALATION")
        m1_isolation.record(
            "local",
            report,
            [*adapter.sensitive, *campaign.tokens],
            identity="host-unix-uid",
            instrumenter="same-worker-uid-and-network-namespace",
            metadata_target="synthetic-data-network",
            node_hardening_qualified=False,
            inventoried_workers=["engine", "ray"],
        )
        print("M1_LOCAL_AUTHENTICATED_WORKER_ISOLATION_PASSED")
    finally:
        try:
            if adapter:
                adapter.close()
        finally:
            stack.close()


if __name__ == "__main__":
    qualify()
