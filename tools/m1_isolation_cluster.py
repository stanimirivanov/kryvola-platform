"""Owned KIND/Cilium/SPIRE probe; synthetic data, actual Fabric authorization."""

import base64
import hashlib
import json
import secrets
import subprocess
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import urlsplit

if __package__:
    from . import (
        m1_assets,
        m1_cluster,
        m1_credentials,
        m1_images,
        m1_isolation,
        m1_isolation_case,
        m1_isolation_profile,
        m1_live_infra,
    )
else:
    import m1_assets
    import m1_cluster
    import m1_credentials
    import m1_images
    import m1_isolation
    import m1_isolation_case
    import m1_isolation_profile
    import m1_live_infra

ROOT = Path(__file__).resolve().parents[1]
PROBE = ROOT / "config/isolation/m1_probe.py"


class Cluster:
    runtime_host = "runtime.m1-control"

    def __init__(self, node, images, folder):
        self.node, self.images, self.folder = node, images, folder
        self.owner_canary = b"PUBLIC_ISOLATION_CANARY_NOT_A_KEY_" + secrets.token_hex(24).encode()
        self.sensitive = [self.owner_canary]
        self.tags = []

    def apply(self, documents):
        m1_cluster.kubectl(
            self.node,
            "apply",
            "--server-side",
            "--field-manager=m1-isolation",
            "-f",
            "-",
            payload=json.dumps(dict(apiVersion="v1", kind="List", items=documents)).encode(),
        )

    def execute(self, domain, pod, container, *args, payload=None):
        return m1_cluster.kubectl(
            self.node,
            "exec",
            "-i",
            "-n",
            "m1-" + domain,
            pod,
            "-c",
            container,
            "--",
            *args,
            payload=payload,
        ).stdout

    def wait(self, function, seconds=120):
        deadline = time.monotonic() + seconds
        while True:
            try:
                return function()
            except subprocess.SubprocessError, ValueError, KeyError:
                if time.monotonic() > deadline:
                    raise ValueError("M1_CLUSTER_PROBE_NOT_READY") from None
                time.sleep(2)

    def probe(self, role, value):
        domain, pod, container = (
            ("compute", "compute", "instrumenter")
            if role == "worker"
            else ("control", "workflow", "workflow")
        )
        raw = self.execute(
            domain,
            pod,
            container,
            "python",
            "/run/isolation/m1_probe.py",
            payload=json.dumps(value).encode(),
        )
        m1_isolation.scan(raw, [*self.sensitive, *getattr(self, "tokens", [])])
        return json.loads(raw)

    def boot(self):
        raw = self.execute("control", "runtime", "runtime", "cat", "/run/m1-state/boot.json")
        return json.loads(raw)["boot_id"]

    def publish(self, value):
        self.execute(
            "control",
            "runtime",
            "runtime",
            "python",
            "-c",
            (
                "from pathlib import Path;import sys;p=Path('/run/m1-state/config/policy.json');"
                "p.write_bytes(sys.stdin.buffer.read());p.chmod(0o600)"
            ),
            payload=json.dumps(value).encode(),
        )

    def canonical(self, value):
        code = (
            "import json,sys,base64;from kryvola_ml.sdk.client import canonical;"
            "from kryvola_ml.sdk.submission import commitment;r=canonical(json.load(sys.stdin));"
            "print(json.dumps({'raw':base64.b64encode(r).decode(),'digest':commitment('manifest',2,r)}))"
        )
        return json.loads(
            self.execute(
                "owner", "owner", "owner", "python", "-c", code, payload=json.dumps(value).encode()
            )
        )

    def sql(self, query):
        return self.execute(
            "control",
            "postgres",
            "postgres",
            "psql",
            "-U",
            "m1_admin",
            "-d",
            "fabric",
            "-v",
            "ON_ERROR_STOP=1",
            "-Atc",
            query,
        ).strip()

    def secret(self, domain, name, values):
        self.apply(
            [
                dict(
                    apiVersion="v1",
                    kind="Secret",
                    metadata=dict(name=name, namespace="m1-" + domain),
                    data={k: base64.b64encode(v).decode() for k, v in values.items()},
                )
            ]
        )

    def prepare(self):
        locked = m1_assets.load()
        for role, domain in (
            ("runtime", "control"),
            ("runtime", "compute"),
            ("owner", "owner"),
        ):
            nodes = json.loads(
                m1_cluster.kubectl(
                    self.node,
                    "get",
                    "nodes",
                    "-l",
                    "kryvola.io.node-restriction.kubernetes.io/domain=" + domain,
                    "-o",
                    "json",
                ).stdout
            )["items"]
            image = self.images[role]
            # Local role images are content-addressed Docker IDs, never published OCI claims.
            if image.startswith("sha256:"):
                tag = "kryvola-isolation-" + role + ":" + self.node.removesuffix("-control-plane")
                if (
                    subprocess.run(
                        ["docker", "image", "inspect", tag], capture_output=True
                    ).returncode
                    == 0
                ):
                    raise ValueError("M1_CLUSTER_IMAGE_EXISTS")
                subprocess.run(["docker", "tag", image, tag], check=True, capture_output=True)
                self.tags.append(tag)
                self.images[role] = tag
            m1_cluster.command(
                "load",
                "docker-image",
                self.images[role],
                "--name",
                self.node.removesuffix("-control-plane"),
                "--nodes",
                nodes[0]["metadata"]["name"],
            )
        # Use the reviewed profile as input; only the explicit synthetic overlay differs.
        placeholder = "fixture@sha256:" + "a" * 64
        docs = m1_isolation_profile.build(dict.fromkeys(("runtime", "owner", "ray"), placeholder))
        for d in docs:
            if d["kind"] == "Pod":
                role = d["metadata"]["name"]
                for c in d["spec"]["containers"]:
                    c["image"] = self.images[
                        "engine"
                        if c["name"] == "engine"
                        else "owner"
                        if role == "owner"
                        else "runtime"
                    ]
        policies = [d for d in docs if d["kind"] in ("NetworkPolicy", "CiliumNetworkPolicy")]
        pods = [d for d in docs if d["kind"] == "Pod"]
        self.apply(
            [d for d in docs if d["kind"] not in ("Pod", "NetworkPolicy", "CiliumNetworkPolicy")]
        )
        scripts = {
            p.name: p.read_text() for p in (PROBE, ROOT / "config/isolation/m1_listeners.py")
        }
        for domain in ("compute", "owner", "control", "data"):
            self.apply(
                [
                    dict(
                        apiVersion="v1",
                        kind="ConfigMap",
                        metadata=dict(name="isolation-probe", namespace="m1-" + domain),
                        data=scripts,
                    )
                ]
            )
        m1_credentials.create(self.folder / "secrets")
        cred = self.folder / "secrets"
        for name in ("database", "s3.json"):
            p = cred / name
            p.chmod(0o600)
            p.write_bytes(
                p.read_bytes()
                .replace(b"@postgres:", b"@postgres.m1-control:")
                .replace(b"http://storage:", b"http://storage.m1-data:")
            )
        self.secret(
            "control",
            "m1-runtime-config",
            {n: (cred / n).read_bytes() for n in ("database", "s3.json", "policy.json")},
        )
        self.secret("control", "database-bootstrap", {"pg-admin": (cred / "pg-admin").read_bytes()})
        self.secret(
            "data",
            "storage-bootstrap",
            {n: (cred / n).read_bytes() for n in ("s3-server.json", "aws")},
        )
        self.sensitive += [
            (cred / "pg-admin").read_bytes(),
            urlsplit((cred / "database").read_text()).password.encode(),
        ]
        self.sensitive += [
            x["credentials"][0]["secretKey"].encode()
            for x in json.loads((cred / "s3-server.json").read_bytes())["identities"]
        ]
        self.apply(backends(locked))
        self.wait(
            lambda: self.execute(
                "control",
                "postgres",
                "postgres",
                "psql",
                "-U",
                "m1_admin",
                "-d",
                "postgres",
                "-Atc",
                "SELECT 1",
            )
        )
        password = urlsplit((cred / "database").read_text()).password
        self.execute(
            "control",
            "postgres",
            "postgres",
            "psql",
            "-U",
            "m1_admin",
            "-d",
            "postgres",
            "-v",
            "ON_ERROR_STOP=1",
            payload=(
                f"CREATE ROLE fabric_runtime LOGIN PASSWORD '{password}';\n"
                "CREATE DATABASE fabric OWNER fabric_runtime;\n"
            ).encode(),
        )
        self.wait(
            lambda: self.execute(
                "data",
                "storage",
                "client",
                "aws",
                "--endpoint-url",
                "http://127.0.0.1:8333",
                "s3api",
                "create-bucket",
                "--bucket",
                "m1-artifacts",
            )
        )
        self.apply(pods)
        self.wait(self.boot)
        self.wait(lambda: self.probe("worker", dict(mode="identity")))
        if self.probe("worker", dict(mode="identity")) != {
            "identities": ["spiffe://m1.test/worker"]
        }:
            raise ValueError("M1_CLUSTER_IDENTITY_ESCALATION")
        return policies


def backend(domain, role, image, command, uid=65532):
    container = dict(
        name=role,
        image=image,
        command=command,
        securityContext=dict(
            allowPrivilegeEscalation=False,
            readOnlyRootFilesystem=True,
            capabilities=dict(drop=["ALL"]),
        ),
        resources=dict(
            requests={"cpu": "100m", "memory": "128Mi", "ephemeral-storage": "32Mi"},
            limits={"cpu": "2", "memory": "1Gi", "ephemeral-storage": "256Mi"},
        ),
        volumeMounts=[dict(name="scratch", mountPath="/tmp"), dict(name="data", mountPath="/data")],
    )
    spec = dict(
        automountServiceAccountToken=False,
        enableServiceLinks=False,
        nodeSelector={"kryvola.io.node-restriction.kubernetes.io/domain": domain},
        securityContext=dict(
            runAsNonRoot=True,
            runAsUser=uid,
            runAsGroup=uid,
            fsGroup=uid,
            seccompProfile=dict(type="RuntimeDefault"),
        ),
        containers=[container],
        volumes=[
            dict(name="scratch", emptyDir={"medium": "Memory", "sizeLimit": "64Mi"}),
            dict(name="data", emptyDir={"sizeLimit": "256Mi"}),
        ],
    )
    return dict(
        apiVersion="v1",
        kind="Pod",
        metadata=dict(name=role, namespace="m1-" + domain, labels={"kryvola.io/role": role}),
        spec=spec,
    )


def backends(locked):
    pg = backend(
        "control",
        "postgres",
        locked["services"]["postgres"],
        ["docker-entrypoint.sh", "postgres"],
        999,
    )
    pg["spec"]["containers"][0]["env"] = [
        dict(name="POSTGRES_USER", value="m1_admin"),
        dict(name="POSTGRES_PASSWORD_FILE", value="/run/bootstrap/pg-admin"),
        dict(name="PGDATA", value="/data/pg"),
    ]
    pg["spec"]["containers"][0]["volumeMounts"].append(
        dict(name="scratch", mountPath="/var/run/postgresql")
    )
    storage = backend(
        "data",
        "storage",
        locked["services"]["s3"],
        [
            "weed",
            "server",
            "-dir=/data",
            "-ip=127.0.0.1",
            "-ip.bind=0.0.0.0",
            "-filer",
            "-s3",
            "-s3.config=/run/bootstrap/s3-server.json",
            "-volume.max=2",
            "-master.volumeSizeLimitMB=32",
        ],
    )
    for pod, secret in ((pg, "database-bootstrap"), (storage, "storage-bootstrap")):
        pod["spec"]["volumes"].append(dict(name="bootstrap", secret=dict(secretName=secret)))
        pod["spec"]["containers"][0]["volumeMounts"].append(
            dict(name="bootstrap", mountPath="/run/bootstrap", readOnly=True)
        )
    client = json.loads(json.dumps(storage["spec"]["containers"][0]))
    client.update(
        name="client",
        image=locked["services"]["s3-client"],
        command=["sleep", "infinity"],
        env=[
            dict(name="AWS_SHARED_CREDENTIALS_FILE", value="/run/bootstrap/aws"),
            dict(name="AWS_DEFAULT_REGION", value="us-east-1"),
            dict(name="AWS_EC2_METADATA_DISABLED", value="true"),
        ],
    )
    storage["spec"]["containers"].append(client)
    broker = backend(
        "data",
        "broker",
        locked["services"]["python"],
        ["python", "-m", "http.server", "9644", "--directory", "/tmp"],
    )
    storage["spec"]["volumes"].append(dict(name="growth", configMap=dict(name="storage-growth")))
    storage["spec"]["containers"][0]["volumeMounts"].append(
        dict(name="growth", mountPath="/etc/seaweedfs", readOnly=True)
    )
    config = dict(
        apiVersion="v1",
        kind="ConfigMap",
        metadata=dict(name="storage-growth", namespace="m1-data"),
        data={"master.toml": (ROOT / "config/isolation/m1_master.toml").read_text()},
    )
    result = [config, pg, storage, broker]
    for domain, role, port in (
        ("control", "postgres", 5432),
        ("data", "storage", 8333),
        ("data", "broker", 9644),
        ("control", "runtime", 8443),
    ):
        result.append(
            dict(
                apiVersion="v1",
                kind="Service",
                metadata=dict(name=role, namespace="m1-" + domain),
                spec=dict(
                    selector={"kryvola.io/role": role}, ports=[dict(port=port, targetPort=port)]
                ),
            )
        )
    return result


@contextmanager
def metadata(adapter):
    nodes = json.loads(
        m1_cluster.kubectl(
            adapter.node,
            "get",
            "nodes",
            "-l",
            "kryvola.io.node-restriction.kubernetes.io/domain=compute",
            "-o",
            "json",
        ).stdout
    )["items"]
    node = nodes[0]["metadata"]["name"]
    name = "m1-metadata-" + secrets.token_hex(12)
    # Only this disposable kind node's network namespace is changed, never the host's.
    subprocess.run(
        ["docker", "exec", node, "ip", "address", "add", "169.254.169.254/32", "dev", "lo"],
        check=True,
        capture_output=True,
    )
    identifier = None
    try:
        created = subprocess.run(
            [
                "docker",
                "create",
                "--name",
                name,
                "--network",
                "container:" + node,
                "--user",
                "65532:65532",
                "--read-only",
                "--cap-drop",
                "ALL",
                "--security-opt",
                "no-new-privileges:true",
                "--pids-limit",
                "32",
                "--memory",
                "128m",
                "--mount",
                "type=bind,src="
                + str(ROOT / "config/isolation/m1_listeners.py")
                + ",dst=/listener.py,readonly",
                "--entrypoint",
                "python",
                adapter.images["runtime"],
                "/listener.py",
                "metadata",
            ],
            check=True,
            capture_output=True,
            timeout=30,
        )
        identifier = created.stdout.decode().strip()
        subprocess.run(["docker", "start", identifier], check=True, capture_output=True, timeout=30)
        yield identifier
    finally:
        try:
            if identifier:
                subprocess.run(
                    ["docker", "rm", "-f", identifier], check=True, capture_output=True, timeout=30
                )
        finally:
            subprocess.run(
                ["docker", "exec", node, "ip", "address", "del", "169.254.169.254/32", "dev", "lo"],
                check=True,
                capture_output=True,
                timeout=30,
            )


def target_health(adapter, metadata_container):
    code = (
        "import urllib.request;assert urllib.request.urlopen("
        "'http://169.254.169.254:18080',timeout=3).read()=="
        "b'SYNTHETIC_METADATA_NOT_A_CREDENTIAL'"
    )
    subprocess.run(
        ["docker", "exec", metadata_container, "python", "-c", code],
        check=True,
        capture_output=True,
        timeout=10,
    )
    adapter.execute(
        "data",
        "broker",
        "broker",
        "python",
        "-c",
        "import urllib.request;assert urllib.request.urlopen('http://127.0.0.1:9644',timeout=3).status==200",
    )
    if adapter.sql("SELECT 1") != b"1":
        raise ValueError("M1_DATABASE_HEALTH")


def campaign_run(adapter, policies):
    addresses = {
        role: json.loads(
            m1_cluster.kubectl(
                adapter.node, "get", "pod", role, "-n", "m1-" + domain, "-o", "json"
            ).stdout
        )["status"]["podIP"]
        for role, domain in (("broker", "data"), ("postgres", "control"))
    }
    canary_code = (
        "from pathlib import Path;import sys,hashlib;"
        "p=Path('/owner/isolation-canary');p.write_bytes(sys.stdin.buffer.read());"
        "p.chmod(0o600);print(hashlib.sha256(p.read_bytes()).hexdigest())"
    )
    raw = adapter.execute(
        "owner", "owner", "owner", "python", "-c", canary_code, payload=adapter.owner_canary
    )
    if raw.strip().decode() != hashlib.sha256(adapter.owner_canary).hexdigest():
        raise ValueError("M1_OWNER_POSITIVE")
    with metadata(adapter) as listener:
        targets = (
            ("metadata", "169.254.169.254", 18080),
            ("broker_admin", addresses["broker"], 9644),
            ("database", addresses["postgres"], 5432),
        )
        for _, host, port in targets:
            adapter.wait(lambda host=host, port=port: healthy_network(adapter, host, port, True))
        adapter.wait(lambda: target_health(adapter, listener))
        # An adversarial ordinary allow policy must not override Cilium's explicit metadata deny.
        allow = dict(
            apiVersion="networking.k8s.io/v1",
            kind="NetworkPolicy",
            metadata=dict(name="adversarial-metadata-allow", namespace="m1-compute"),
            spec=dict(
                podSelector={},
                policyTypes=["Egress"],
                egress=[
                    dict(
                        to=[dict(ipBlock=dict(cidr="169.254.169.254/32"))],
                        ports=[dict(protocol="TCP", port=18080)],
                    )
                ],
            ),
        )
        adapter.apply([*policies, allow])
        for _, host, port in targets:
            adapter.wait(lambda host=host, port=port: healthy_network(adapter, host, port, False))
        campaign = m1_isolation_case.Campaign(adapter)
        adapter.tokens = campaign.tokens
        denied = campaign.run()
        inventory = json.loads(
            adapter.execute(
                "compute",
                "compute",
                "engine",
                "python3",
                "/run/isolation/m1_probe.py",
                payload=b'{"mode":"inventory"}',
            )
        )
        if adapter.probe("worker", dict(mode="identity")) != {
            "identities": ["spiffe://m1.test/worker"]
        }:
            raise ValueError("M1_CLUSTER_IDENTITY_ESCALATION")
        for name, host, port in targets:
            healthy_network(adapter, host, port, False)
            denied[name] = "NETWORK_DENIED_HEALTHY_TARGET"
        target_health(adapter, listener)
        denied["owner_files"] = "NOT_MOUNTED"
        report = dict(
            positive=dict.fromkeys(m1_isolation.POSITIVES, True), denied=denied, inventory=inventory
        )
        m1_isolation.validate(report, database="NETWORK_DENIED_HEALTHY_TARGET")
        logs = m1_cluster.kubectl(
            adapter.node, "logs", "-n", "m1-control", "runtime", "--tail=200"
        ).stdout
        m1_isolation.scan(logs, [*adapter.sensitive, *campaign.tokens])
        if logs.count(b"runtime_auth_denied") < 4:
            raise ValueError("M1_DENIAL_AUDIT_MISSING")
        return m1_isolation.record(
            "cluster",
            report,
            [*adapter.sensitive, *campaign.tokens],
            identity="kubernetes-pod-uid-and-service-account",
            metadata_target="synthetic-link-local",
            worker_launch="instrumented-published-image",
            node_hardening_qualified=False,
        )


def qualify():
    m1_cluster.local_only()
    with (
        tempfile.TemporaryDirectory(prefix="m1-isolation-") as directory,
        m1_images.prepare(m1_assets.load()) as images,
    ):
        adapter = None
        try:
            with m1_live_infra.live_cluster() as node:
                adapter = Cluster(node, images, Path(directory))
                policies = adapter.prepare()
                campaign_run(adapter, policies)
        finally:
            if adapter:
                for tag in adapter.tags:
                    subprocess.run(
                        ["docker", "image", "rm", tag], check=False, capture_output=True, timeout=30
                    )
    print("M1_CLUSTER_WORKER_ISOLATION_PASSED")


def healthy_network(adapter, host, port, wanted):
    if adapter.probe("worker", dict(mode="network", host=host, port=port)) != dict(
        connected=wanted
    ):
        raise ValueError("M1_NETWORK_CONTROL")


if __name__ == "__main__":
    qualify()
