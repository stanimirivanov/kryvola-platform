"""Owned local Compose fixtures. Configuration checks never start services."""

import argparse
import importlib.util
import json
import os
import re
import secrets
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ACTIVE = ROOT / "build/integration/active.json"
NETWORKS = {
    "postgres": "control",
    "schema": "control",
    "temporal": "control",
    "temporal-cli": "control",
    "ray": "compute",
    "seaweed": "data",
    "s3-client": "data",
    "redpanda": "data",
    "toxiproxy": "data",
}
MOUNTS = {
    "postgres": ["postgres:/var/lib/postgresql/data"],
    "schema": ["./config/local-services/schema.sh:/fixture/schema.sh:ro"],
    "temporal": ["./config/local-services/dynamicconfig.yaml:/etc/temporal/fixture.yaml:ro"],
    "redpanda": ["redpanda:/var/lib/redpanda/data"],
    "seaweed": [
        "seaweed:/data",
        {
            "type": "bind",
            "source": "${FIXTURE_ROOT:?fixture runner required}/s3.json",
            "target": "/fixture/s3.json",
            "read_only": True,
        },
    ],
    "s3-client": [
        {
            "type": "bind",
            "source": "${FIXTURE_ROOT:?fixture runner required}/data",
            "target": "/data",
        }
    ],
}


def configuration(value=None):
    value = value if value is not None else json.loads((ROOT / "compose.yaml").read_text())
    if set(value) != {"services", "networks", "volumes"} or set(value["services"]) != set(NETWORKS):
        raise ValueError("UNEXPECTED_COMPOSE_COMPONENT")
    if value["networks"] != {name: {"internal": True} for name in {"control", "compute", "data"}}:
        raise ValueError("EXTERNAL_OR_BRIDGED_NETWORK")
    for name, service in value["services"].items():
        if (
            not re.fullmatch(r"[^\s@]+@sha256:[a-f0-9]{64}", service["image"])
            or service.get("platform") != "linux/amd64"
            or service["networks"] != [NETWORKS[name]]
            or service.get("volumes", []) != MOUNTS.get(name, [])
            or {
                "ports",
                "build",
                "privileged",
                "devices",
                "network_mode",
                "env_file",
                "secrets",
                "cap_add",
            }.intersection(service)
        ):
            raise ValueError("UNSAFE_SERVICE_BOUNDARY")
    if set(value["services"]["ray"]["environment"]) != {"RAY_USAGE_STATS_ENABLED"}:
        raise ValueError("COMPUTE_CREDENTIAL_INJECTION")
    return value


def run(args, *, env=None, timeout=30, payload=None):
    # CLI output is spooled, not retained in memory; only bounded diagnostic
    # bytes are accepted. These are trusted fixture commands, not an OS sandbox.
    with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
        child = subprocess.Popen(
            list(map(str, args)),
            env=env,
            stdin=subprocess.PIPE,
            stdout=out,
            stderr=err,
            start_new_session=True,
        )
        try:
            child.communicate(payload, timeout=timeout)
        finally:
            if sys.platform == "linux":
                try:
                    os.killpg(child.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            elif child.poll() is None:
                child.kill()
            child.wait()
        out.seek(0)
        err.seek(0)
        stdout, stderr = out.read(65_537), err.read(65_537)
        if len(stdout) > 65_536 or len(stderr) > 65_536:
            raise ValueError("CLI_OUTPUT_LIMIT")
        return subprocess.CompletedProcess(args, child.returncode, stdout, stderr)


class Stack:
    def __init__(self, project):
        if re.fullmatch(r"kryvola-m0-[a-f0-9]{12}", project) is None:
            raise ValueError("UNOWNED_PROJECT")
        self.project = project
        self.folder = ROOT / "build/integration" / project
        self.redactions = []
        self.created = self.claimed = False
        self.env = {
            k: v
            for k, v in os.environ.items()
            if k not in {"PG_PASSWORD", "S3_ACCESS", "S3_SECRET", "FIXTURE_ROOT"}
        }

    def compose(self, *args, timeout=30, payload=None, check=True):
        result = run(
            [
                "docker",
                "compose",
                "--project-name",
                self.project,
                "--file",
                ROOT / "compose.yaml",
                "--env-file",
                self.folder / "fixture.env",
                *args,
            ],
            env=self.env,
            timeout=timeout,
            payload=payload,
        )
        if check and result.returncode:
            diagnostic = result.stderr.decode("utf-8", errors="replace")
            for token in self.redactions:
                diagnostic = diagnostic.replace(token, "[REDACTED]")
            print("FIXTURE_COMMAND_ERROR=" + args[0] + ": " + diagnostic[:4096], file=sys.stderr)
            raise ValueError("COMPOSE_" + args[0].upper() + "_FAILED")
        return result

    def execute(self, service, *args, **kwargs):
        return self.compose("exec", "-T", service, *args, **kwargs)

    def ready(self, service, *args):
        deadline = time.monotonic() + 180
        while time.monotonic() < deadline:
            result = self.execute(service, *args, check=False, timeout=20)
            if result.returncode == 0:
                return result
            time.sleep(2)
        raise ValueError("READINESS_" + service.upper().replace("-", "_"))

    def prepare(self):
        configuration()
        if ACTIVE.exists():
            raise ValueError("EXISTING_FIXTURE_REQUIRES_DOWN")
        endpoint = os.environ.get("DOCKER_HOST")
        if not endpoint:
            result = run(["docker", "context", "inspect"])
            result.check_returncode()
            endpoint = json.loads(result.stdout)[0]["Endpoints"]["docker"]["Host"]
        if not endpoint.startswith(("unix://", "npipe://")):
            raise ValueError("REMOTE_DOCKER_FORBIDDEN")
        result = run(["docker", "info", "--format", "{{.OSType}}"])
        if result.returncode or result.stdout.strip() != b"linux":
            raise ValueError("LINUX_DOCKER_REQUIRED")
        self.folder.mkdir(parents=True, exist_ok=False)
        self.created = True
        (self.folder / "data").mkdir()
        access, secret = secrets.token_hex(12), secrets.token_hex(24)
        (self.folder / "s3.json").write_text(
            json.dumps(
                {
                    "identities": [
                        {
                            "name": "fixture-client",
                            "credentials": [{"accessKey": access, "secretKey": secret}],
                            "actions": ["Admin", "Read", "Write", "List", "Tagging"],
                        }
                    ]
                }
            )
        )
        settings = {
            "PG_PASSWORD": secrets.token_hex(24),
            "S3_ACCESS": access,
            "S3_SECRET": secret,
            "FIXTURE_ROOT": self.folder.as_posix(),
        }
        self.redactions = [settings[k] for k in ("PG_PASSWORD", "S3_ACCESS", "S3_SECRET")]
        (self.folder / "fixture.env").write_text(
            "".join(f"{k}={json.dumps(v)}\n" for k, v in settings.items())
        )
        for name in ("s3.json", "fixture.env"):
            (self.folder / name).chmod(0o600)
        with ACTIVE.open("x", encoding="utf-8") as stream:
            self.claimed = True
            json.dump({"project": self.project}, stream)
        ACTIVE.chmod(0o600)

    def boundary(self):
        ids = self.compose("ps", "--all", "--quiet").stdout.decode().split()
        for identifier in ids:
            result = run(["docker", "inspect", identifier])
            result.check_returncode()
            item = json.loads(result.stdout)[0]
            service = item["Config"]["Labels"]["com.docker.compose.service"]
            if set(item["NetworkSettings"]["Networks"]) != {self.project + "_" + NETWORKS[service]}:
                raise ValueError("RUNTIME_NETWORK_CROSSOVER")
            if item["HostConfig"]["PortBindings"] or (service == "ray" and item["Mounts"]):
                raise ValueError("EXPOSED_RUNTIME_BOUNDARY")
        networks = run(
            [
                "docker",
                "network",
                "ls",
                "--filter",
                "label=com.docker.compose.project=" + self.project,
                "--quiet",
            ]
        )
        networks.check_returncode()
        details = run(["docker", "network", "inspect", *networks.stdout.decode().split()])
        details.check_returncode()
        if len(json.loads(details.stdout)) != 3 or not all(
            n["Internal"] for n in json.loads(details.stdout)
        ):
            raise ValueError("NONINTERNAL_RUNTIME_NETWORK")

    def up(self):
        try:
            self.prepare()
            self.compose("pull", "--quiet", timeout=900)
            self.compose("up", "--detach", "--wait", "--wait-timeout", "240", timeout=300)
            self.boundary()
            # Tests import the same lifecycle, not a second provisioning path.
            spec = importlib.util.spec_from_file_location(
                "fixture_checks", ROOT / "tests/integration/test_services.py"
            )
            if spec is None or spec.loader is None:
                raise ValueError("MISSING_INTEGRATION_CHECKS")
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            module.qualify(self)
            print("LOCAL_FIXTURES_QUALIFIED; no production profile enabled")
        except BaseException:
            if self.claimed:
                self.down()
            elif self.created:
                for name in ("fixture.env", "s3.json"):
                    (self.folder / name).unlink(missing_ok=True)
            raise

    def down(self):
        self.compose("down", "--volumes", "--remove-orphans", timeout=120)
        for kind in ("container", "network", "volume"):
            args = [
                "docker",
                kind,
                "ls",
                "--filter",
                "label=com.docker.compose.project=" + self.project,
                "--quiet",
            ]
            if kind == "container":
                args.append("--all")
            result = run(args)
            if result.returncode or result.stdout.strip():
                raise ValueError("INCOMPLETE_CLEANUP_" + kind.upper())
        ACTIVE.unlink()
        # Remove only generated credential files; retain public observations.
        for name in ("fixture.env", "s3.json"):
            (self.folder / name).unlink()
        print("LOCAL_FIXTURES_REMOVED")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["check", "up", "down"])
    args = parser.parse_args()
    if args.command == "check":
        configuration()
        print("Fixture configuration valid; no services started")
    elif args.command == "up":
        Stack("kryvola-m0-" + secrets.token_hex(6)).up()
    else:
        Stack(json.loads(ACTIVE.read_text())["project"]).down()


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        code = str(error)
        if re.fullmatch(r"[A-Z][A-Z0-9_]{0,80}", code) is None:
            code = type(error).__name__
        print("integration: REJECTED " + code, file=sys.stderr)
        sys.exit(1)
