"""P-M1: verified published local services; no successful inference qualification."""

import argparse
import json
import os
import re
import secrets
import shutil
import subprocess
import tempfile
import time
from contextlib import ExitStack
from pathlib import Path

if __package__:
    from . import m1_assets as assets
    from . import m1_credentials, m1_identity, m1_images
else:
    import m1_assets as assets
    import m1_credentials
    import m1_identity
    import m1_images

ROOT = Path(__file__).resolve().parents[1]
COMPOSE = ROOT / "compose.m1.yaml"
LABEL = "io.kryvola.m1.invocation"


def check():
    locked = assets.load()
    config = json.loads(COMPOSE.read_bytes())
    expected = {
        "postgres",
        "db-init",
        "schema",
        "temporal",
        "temporal-cli",
        "storage",
        "s3-client",
        "broker",
        "runtime",
        "messaging",
        "workflow",
        "ray",
        "owner-init",
        "owner",
        "engine-init",
        "engine",
    }
    assets.require(set(config["services"]) == expected, "M1_COMPOSITION_REJECTED")
    image_roles = {
        "db-init": "POSTGRES",
        "schema": "TEMPORAL_CLI",
        "storage": "S3",
        "broker": "REDPANDA",
        "messaging": "RUNTIME",
        "workflow": "RUNTIME",
        "owner-init": "OWNER",
        "engine-init": "RUNTIME",
    }
    for name, service in config["services"].items():
        assets.require(
            not (
                {"build", "ports", "network_mode", "privileged", "devices", "env_file"}
                & set(service)
            ),
            "M1_COMPOSITION_REJECTED",
        )
        assets.require(
            service["image"]
            == "${M1_"
            + image_roles.get(name, name.upper().replace("-", "_"))
            + "_IMAGE:?m1 runner required}",
            "M1_COMPOSITION_REJECTED",
        )
        assets.require(
            service["labels"] == {LABEL: "${M1_TOKEN:?m1 runner required}"},
            "M1_COMPOSITION_REJECTED",
        )
        for mount in service.get("volumes", []):
            source = mount["source"] if isinstance(mount, dict) else mount.split(":")[0]
            assets.require(
                source in {"postgres", "storage", "broker", "execution", "owner"}
                or source
                in {
                    "./config/m1/" + f
                    for f in ("service.py", "engine_fixture.py", "schema.sh", "dynamicconfig.yaml")
                }
                or source.startswith(
                    (
                        "${M1_RUN:?m1 runner required}/",
                        "${M1_SOCKET:?m1 runner required}",
                        "${M1_CONTEXT:?m1 runner required}/",
                    )
                ),
                "M1_COMPOSITION_REJECTED",
            )
    for value in config["networks"].values():
        assets.require(value["internal"] is True, "M1_COMPOSITION_REJECTED")
    for name in ("ray", "engine"):
        service = config["services"][name]
        assets.require(service["user"] == "65532:65532", "M1_COMPOSITION_REJECTED")
        serialized = json.dumps(service)
        assets.require(
            not any(
                x in serialized
                for x in (
                    "/owner",
                    "/secrets/",
                    "database",
                    "events.key",
                    "admin.key",
                    "release.json",
                )
            ),
            "M1_COMPOSITION_REJECTED",
        )
    assets.require(
        config["services"]["ray"].get("environment")
        == {"HOME": "/tmp", "USER": "m1-compute", "RAY_USAGE_STATS_ENABLED": "0"}
        and not config["services"]["engine"].get("environment"),
        "M1_COMPOSITION_REJECTED",
    )
    owner = config["services"]["owner"]
    assets.require(
        owner["user"] == "3001:3001" and owner["networks"] == ["owner", "control"],
        "M1_COMPOSITION_REJECTED",
    )
    return locked


class Stack:
    def __init__(self, project, *, root=None):
        if not re.fullmatch(r"kryvola-m1-[a-f0-9]{12}", project):
            raise ValueError("M1_PROJECT_REJECTED")
        self.project, self.token = project, secrets.token_hex(24)
        self.folder = (root or ROOT / "build/m1-runs") / project
        self.owned = False
        self.configured = False
        self.building = False
        self.resources = ExitStack()
        self.env = dict(os.environ)

    def compose(self, *args, payload=None):
        return subprocess.check_output(
            [
                "docker",
                "compose",
                "--env-file",
                str(self.folder / "fixture.env"),
                "-p",
                self.project,
                "-f",
                str(COMPOSE),
                *args,
            ],
            cwd=ROOT,
            env=self.env,
            input=payload,
            stderr=subprocess.PIPE,
            timeout=360,
        )

    def objects(self):
        result = []
        for kind, listing in (("container", "ps"), ("network", "network"), ("volume", "volume")):
            command = ["docker", listing] + (["ls"] if listing != "ps" else ["-a"])
            raw = subprocess.check_output(
                command + ["-q", "--filter", "label=com.docker.compose.project=" + self.project],
                text=True,
            )
            for identity in raw.split():
                result.append((kind, identity))
        return result

    def prepare(self):
        locked = check()
        assets.verify(locked)
        endpoint = os.environ.get("DOCKER_HOST")
        if not endpoint:
            context = json.loads(
                subprocess.check_output(["docker", "context", "inspect"], timeout=15)
            )
            endpoint = context[0]["Endpoints"]["docker"]["Host"]
        if not endpoint.startswith("unix://") or os.getuid() == 0:
            raise ValueError("M1_LOCAL_NONROOT_DOCKER_REQUIRED")
        info = json.loads(
            subprocess.check_output(["docker", "info", "--format", "{{json .}}"], timeout=30)
        )
        if (
            info["OSType"] != "linux"
            or info["Architecture"] not in ("x86_64", "amd64")
            or any("rootless" in x for x in info.get("SecurityOptions", []))
        ):
            raise ValueError("M1_LINUX_AMD64_ROOTFUL_REQUIRED")
        if self.objects():
            raise ValueError("M1_PROJECT_ALREADY_EXISTS")
        self.folder.parent.mkdir(parents=True, exist_ok=True)
        self.folder.mkdir(mode=0o700)
        (self.folder / "ownership.json").write_text(
            json.dumps({"project": self.project, "token": self.token})
        )
        self.owned = True
        self.building = True
        images = self.resources.enter_context(m1_images.prepare(locked))
        identity = self.folder / "identity"
        identity.mkdir(mode=0o700)
        socket_folder = Path(
            self.resources.enter_context(
                tempfile.TemporaryDirectory(prefix="m1-workload-", dir="/tmp")
            )
        )
        socket_folder.chmod(0o755)
        self.resources.enter_context(m1_identity.identity(identity, socket_folder))
        password = m1_credentials.create(self.folder / "secrets")
        for role in ("runtime", "workflow", "owner"):
            state = self.folder / (role + "-state")
            state.mkdir()
            state.chmod(0o777)
        context = self.folder / "context"
        context.mkdir()
        m1_images.fixture(context / "execute-fixture.json")
        values = {
            "M1_PROJECT": self.project,
            "M1_TOKEN": self.token,
            "M1_RUN": str(self.folder),
            "M1_SOCKET": str(socket_folder),
            "M1_CONTEXT": str(context),
            "M1_TEMPORAL_PASSWORD": password,
            "M1_ENGINE_DIGEST": locked["permissions"]["image_sha256"],
        }
        for role, image in (locked["services"] | images).items():
            values["M1_" + role.upper().replace("-", "_") + "_IMAGE"] = image
        # Explicit runner values take precedence over any inherited M1 overrides.
        self.env = {k: v for k, v in os.environ.items() if not k.startswith("M1_")} | values
        path = self.folder / "fixture.env"
        path.write_text("\n".join(k + "=" + v for k, v in values.items()) + "\n")
        path.chmod(0o600)
        self.configured = True

    def execute(self, service, *args, payload=None):
        return self.compose("exec", "-T", service, *args, payload=payload)

    def wait(self, function, *, seconds=120):
        deadline = time.monotonic() + seconds
        while True:
            try:
                return function()
            except subprocess.SubprocessError, OSError, ValueError:
                if time.monotonic() >= deadline:
                    raise ValueError("M1_SERVICE_NOT_READY") from None
                time.sleep(2)

    def rpk(self, *args):
        return self.execute(
            "broker",
            "rpk",
            *args,
            "-X",
            "brokers=broker:9092",
            "-X",
            "tls.enabled=true",
            "-X",
            "tls.ca=/run/m1-secrets/ca.crt",
            "-X",
            "tls.cert=/run/m1-secrets/admin.crt",
            "-X",
            "tls.key=/run/m1-secrets/admin.key",
        )

    def aws(self, *args):
        return self.execute("s3-client", "aws", "--endpoint-url", "http://storage:8333", *args)

    def sql(self, command):
        return self.execute(
            "postgres",
            "psql",
            "-U",
            "m1_admin",
            "-d",
            "fabric",
            "-v",
            "ON_ERROR_STOP=1",
            "-Atc",
            command,
        )

    def start(self):
        try:
            self.prepare()
            self.compose(
                "up",
                "-d",
                "postgres",
                "db-init",
                "schema",
                "temporal",
                "temporal-cli",
                "storage",
                "s3-client",
                "broker",
                "ray",
                "owner",
            )
            self.wait(
                lambda: self.execute(
                    "temporal-cli",
                    "temporal",
                    "operator",
                    "namespace",
                    "create",
                    "--address",
                    "temporal:7233",
                    "--namespace",
                    "default",
                )
            )
            self.wait(lambda: self.aws("s3api", "create-bucket", "--bucket", "m1-artifacts"))
            self.wait(lambda: self.rpk("cluster", "info"))
            self.rpk("topic", "create", "m1-events", "m1-dead-letter", "-p", "1", "-r", "1")
            self.compose("up", "-d", "--no-deps", "runtime")
            self.wait(
                lambda: self.execute("runtime", "python", "/opt/m1/service.py", "probe", "runtime")
            )
            boot = json.loads((self.folder / "runtime-state/boot.json").read_bytes())
            policy = self.folder / "secrets/policy.json"
            policy.chmod(0o644)
            policy.write_text(json.dumps(boot | {"grants": []}))
            policy.chmod(0o444)
            self.sql(
                "GRANT CONNECT ON DATABASE fabric TO fabric_events, fabric_release; "
                "GRANT USAGE ON SCHEMA public TO fabric_events, fabric_release; "
                "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public "
                "TO fabric_events, fabric_release;"
            )
            self.compose("up", "-d", "--no-deps", "engine-init")
            self.wait(lambda: self.compose("wait", "engine-init"))
            self.compose("up", "-d", "--no-deps", "messaging", "workflow", "engine")
        except BaseException:
            self.close()
            raise

    def verify(self):
        for role in ("owner", "workflow"):
            self.wait(
                lambda role=role: self.execute(
                    role,
                    "python",
                    "-c",
                    "import json;assert json.load(open('/run/m1-state/ready.json'))['ready']",
                )
            )
        self.wait(lambda: self.execute("ray", "python", "/opt/m1/engine_fixture.py", "probe"))
        self.wait(
            lambda: self.execute(
                "ray",
                "python",
                "-c",
                "import urllib.request,json;assert json.load(urllib.request.urlopen('http://127.0.0.1:8265/api/version',timeout=5))['ray_version']=='2.59.0'",
            )
        )
        count = int(self.sql("SELECT count(*) FROM _sqlx_migrations WHERE success;").strip())
        assets.require(count == 14, "M1_MIGRATION_REJECTED")
        # A real object round trip; the probe is public and contains no inference payload.
        self.execute("s3-client", "sh", "-c", "printf M1-public-startup-probe >/tmp/probe")
        self.aws(
            "s3api",
            "put-object",
            "--bucket",
            "m1-artifacts",
            "--key",
            "startup-probe",
            "--body",
            "/tmp/probe",
        )
        self.aws(
            "s3api",
            "get-object",
            "--bucket",
            "m1-artifacts",
            "--key",
            "startup-probe",
            "/tmp/readback",
        )
        assets.require(
            self.execute("s3-client", "cat", "/tmp/readback") == b"M1-public-startup-probe",
            "M1_STORAGE_REJECTED",
        )
        self.rpk("topic", "list")
        for role in ("messaging", "runtime", "engine", "ray", "owner", "workflow"):
            container = self.compose("ps", "-q", role).decode().strip()
            state = json.loads(subprocess.check_output(["docker", "inspect", container]))[0]
            assets.require(state["State"]["Running"], "M1_PROCESS_EXITED")
        return {
            "schema_version": "platform-m1-startup-v1",
            "migrations": count,
            "runtime_mtls": True,
            "engine_status": "CREATED",
            "inference_executed": False,
            "release_manifests": {
                r: i["assets"]["manifest.json"]["sha256"]
                for r, i in assets.load()["components"].items()
            },
        }

    def close(self):
        if not self.owned:
            return
        marker = self.folder / "ownership.json"
        if (
            not marker.is_file()
            or marker.is_symlink()
            or json.loads(marker.read_bytes()) != {"project": self.project, "token": self.token}
        ):
            raise ValueError("M1_OWNERSHIP_REJECTED")
        if self.configured:
            for kind, identity in self.objects():
                raw = json.loads(subprocess.check_output(["docker", kind, "inspect", identity]))[0]
                labels = (
                    raw.get("Labels", {})
                    if kind != "container"
                    else raw["Config"].get("Labels", {})
                )
                if labels.get(LABEL) != self.token:
                    raise ValueError("M1_OWNERSHIP_REJECTED")
        try:
            if self.configured or not self.building:
                self.compose("down", "--volumes", "--remove-orphans")
            if self.configured and self.objects():
                raise ValueError("M1_CLEANUP_FAILED")
        finally:
            self.resources.close()
        shutil.rmtree(self.folder)
        self.owned = False


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("check", "install", "ci", "up"))
    args = parser.parse_args()
    if args.action == "check":
        check()
        print("M1_LOCK_AND_COMPOSITION_VALID")
        return
    if args.action == "install":
        assets.fetch(check())
        m1_identity.install()
        return
    stack = Stack("kryvola-m1-" + secrets.token_hex(6))
    report = None
    try:
        stack.start()
        report = stack.verify()
        if args.action == "up":
            print("M1_SERVICES_READY; Ctrl-C cleans this invocation", flush=True)
            while True:
                time.sleep(1)
        else:
            # Exercise the same failure-finally path after proving actual readiness.
            raise RuntimeError("M1_CONTROLLED_FAILURE")
    except RuntimeError as error:
        if str(error) != "M1_CONTROLLED_FAILURE":
            raise
    finally:
        stack.close()
    if report:
        report["cleanup_after_failure"] = True
        output = ROOT / "build/m1-report.json"
        output.write_text(json.dumps(report, indent=2) + "\n")
        print("M1_REAL_STARTUP_MIGRATIONS_AND_FAILURE_CLEANUP_VERIFIED")


if __name__ == "__main__":
    main()
