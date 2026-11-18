"""P-M1 real owner-to-owner qualification over admitted published artifacts."""

import base64
import hashlib
import json
import os
import re
import secrets
import select
import subprocess
import sys
import tempfile
import time
from contextlib import ExitStack, contextmanager
from pathlib import Path
from zipfile import ZipFile

if __package__:
    from . import m1, m1_assets, m1_images
else:
    import m1
    import m1_assets
    import m1_images


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def publish_candidate(folder, raw):
    """Readers must observe either no candidate or complete, read-only metadata."""
    folder.mkdir(parents=True, mode=0o755)
    with tempfile.TemporaryDirectory(dir=folder) as directory:
        pending = Path(directory) / "candidate.json"
        pending.write_bytes(raw)
        pending.chmod(0o444)
        pending.replace(folder / "candidate.json")


def require(value, code="M1_INFERENCE_REJECTED"):
    if not value:
        raise ValueError(code)


@contextmanager
def serial_request(stack):
    """Only a successfully completed request permits reuse of mutable fixture authority."""
    require(not (stack.folder / "inference-failed").exists(), "M1_FIXTURE_FAILED")
    active = stack.folder / "inference-active"
    try:
        active.touch(exist_ok=False)
    except FileExistsError:
        raise ValueError("M1_FIXTURE_BUSY") from None
    try:
        yield
    except BaseException:
        (stack.folder / "inference-failed").touch()
        raise
    finally:
        active.unlink()


def scope_sql(operation, alias=""):
    require(not alias or re.fullmatch(r"[a-z_]+", alias))
    prefix = alias + "." if alias else ""
    for key in ("tenant_scope", "operation_id"):
        require(re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", operation[key]))
    return " AND ".join(
        prefix + k + "='" + operation[k] + "'" for k in ("tenant_scope", "operation_id")
    )


def operation_notices(stack, operation):
    """Retain real offsets; preceding operations and duplicate notices are not new work."""
    first = getattr(stack, "_m1_notice_cursor", 0)
    for offset in range(first, first + 64):
        notice, size = broker_record(stack, offset)
        if all(notice[k] == operation[k] for k in ("tenant_scope", "operation_id")):
            yield notice, size, offset


def disclosure_sql(operation):
    return (
        "output_upload_id IN (SELECT output_upload_id FROM fabric_execution_receipts WHERE "
        + scope_sql(operation)
        + ")"
    )


def phase(name):
    print("M1_INFERENCE:" + name, file=sys.stderr, flush=True)


def capture(command, limit, timeout=20):
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    data = bytearray()
    until = time.monotonic() + timeout
    try:
        if process.stdout is None:
            raise ValueError("M1_EVIDENCE_PROCESS")
        while True:
            remaining = until - time.monotonic()
            if remaining <= 0 or not select.select([process.stdout], [], [], remaining)[0]:
                raise ValueError("M1_EVIDENCE_TIMEOUT")
            chunk = os.read(process.stdout.fileno(), min(65536, limit + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
            require(len(data) <= limit, "M1_EVIDENCE_BOUND")
        require(process.wait(timeout=5) == 0, "M1_EVIDENCE_PROCESS")
        return bytes(data)
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()
        if process.stdout is not None:
            process.stdout.close()


def broker_record(stack, offset):
    container = stack.compose("ps", "-q", "broker").decode().strip()
    raw = capture(
        [
            "docker",
            "exec",
            container,
            "rpk",
            "topic",
            "consume",
            "m1-events",
            "--num",
            "1",
            "--offset",
            str(offset),
            "--format",
            "%v",
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
        ],
        32768,
    )
    notice = json.loads(raw)
    require(set(notice) == {"version", "id", "tenant_scope", "operation_id", "kind"})
    require(notice["version"] == 2)
    return notice, len(raw)


def check_logs(raw, markers):
    require(len(raw) <= 1 << 20, "M1_INFERENCE_LOG_BOUND")
    # Public startup documentation can mention bearer authentication or plaintext
    # transport. Reject credential-shaped values and witness fields, plus every
    # exact private canary, rather than treating those words as leaked values.
    if (
        any(marker in raw for marker in markers)
        or any(
            marker in raw.lower()
            for marker in (b"begin private key", b"begin rsa private key", b"client_key")
        )
        or re.search(
            rb"(?i)(?:authorization\s*:\s*bearer\s+\S+|\bbearer\s+[a-z0-9._~+/-]{16,}|plaintext[\"']?\s*[:=])",
            raw,
        )
    ):
        raise ValueError("M1_INFERENCE_LOG_SECRET")


def validate_report(value, locked):
    code = "M1_INFERENCE_REPORT"
    require(
        set(value)
        == {
            "schema_version",
            "assurance",
            "owner_reference_match",
            "logs_clean",
            "bounds_checked",
            "release_manifests",
            "history",
            "broker",
            "images",
            "receipt_assurance",
            "release_assurance",
            "frozen_reference_sha256",
            "invocation",
            "execution",
            "engine_config_sha256",
        },
        code,
    )
    require(value["schema_version"] == "platform-m1-inference-v1", code)
    require(value["engine_config_sha256"] == locked["permissions"]["image_sha256"], code)
    require(re.fullmatch("kryvola-m1-[0-9a-f]{12}", value["invocation"]), code)
    execution = value["execution"]
    require(
        set(execution)
        == {
            "execution_id",
            "workflow_id",
            "disclosure_id",
            "receipt_digest",
            "release_digest",
            "output_manifest_digest",
        },
        code,
    )
    for name, digest in execution.items():
        pattern = r"[0-9a-f]{64}"
        if name in {"execution_id", "workflow_id"}:
            pattern = ("exec-" if name == "execution_id" else "compute-") + pattern
        require(re.fullmatch(pattern, digest), code)
    require(
        all(
            value[field] is True
            for field in ("owner_reference_match", "logs_clean", "bounds_checked")
        ),
        code,
    )
    require(
        all(
            value[field] == "CONFIDENTIALITY_ONLY"
            for field in ("assurance", "receipt_assurance", "release_assurance")
        ),
        code,
    )
    require(
        value["release_manifests"]
        == {
            role: component["assets"]["manifest.json"]["sha256"]
            for role, component in locked["components"].items()
        },
        code,
    )
    for field, bound in (("history", 128), ("broker", 8)):
        observed = value[field]
        require(set(observed) == {"events", "payload_max_bytes"}, code)
        require(type(observed["events"]) is int and 1 <= observed["events"] <= bound, code)
        require(
            type(observed["payload_max_bytes"]) is int
            and 1 <= observed["payload_max_bytes"] <= 32768,
            code,
        )
    require(
        set(value["images"])
        == {
            "runtime",
            "workflow",
            "messaging",
            "ray",
            "engine",
            "owner",
            "postgres",
            "temporal",
            "storage",
            "broker",
        },
        code,
    )
    require(
        all(re.fullmatch(r"sha256:[0-9a-f]{64}", digest) for digest in value["images"].values()),
        code,
    )
    require(
        value["frozen_reference_sha256"]
        == "16268b514e2d8618113d439052975909dd8642bb3c374c1e6bf53a2d477bac21",
        code,
    )
    return value


def secret_file(path, value):
    # These are already-mounted operator files. Preserve their inode and never
    # send a new policy to a caller until the complete write has returned.
    path.chmod(0o600)
    path.write_bytes(value if isinstance(value, bytes) else canonical(value))
    path.chmod(0o444)


def signing_key(signer):
    seed = secrets.token_bytes(32)
    private = bytes.fromhex("302e020100300506032b657004220420") + seed
    public = subprocess.check_output(
        ["openssl", "pkey", "-inform", "DER", "-pubout", "-outform", "DER"],
        input=private,
        stderr=subprocess.DEVNULL,
    )
    return (
        private,
        seed.hex(),
        {
            "signer": signer,
            "key_id": "qualification",
            "key_epoch": "1",
            "public_key_hex": public[-32:].hex(),
        },
    )


class OwnerSession:
    def __init__(self, stack, engine, *, recovery=False, mode=None, request_id=None):
        require(request_id is None or re.fullmatch(r"[0-9a-f]{16}", request_id))
        require(request_id is None or (not recovery and mode is None))
        suffix = "-" + request_id if request_id is not None else ""
        self.log = (stack.folder / ("owner-session" + suffix + ".log")).open("xb")
        os.chmod(self.log.name, 0o600)
        container = stack.compose("ps", "-q", "owner").decode().strip()
        source = (m1.ROOT / "config/m1/owner_inference.py").read_text()
        self.process = subprocess.Popen(
            [
                "docker",
                "exec",
                "-i",
                container,
                "dbus-run-session",
                "--",
                "python",
                "-c",
                source,
                engine,
                *(
                    ["request", request_id]
                    if request_id is not None
                    else [mode]
                    if mode is not None
                    else ["recovery"]
                    if recovery
                    else []
                ),
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=self.log,
        )
        self.noise = bytearray()
        self.buffer = bytearray()
        self.diagnostic_path = (
            m1.ROOT / "build" / (stack.project + "-owner-diagnostic" + suffix + ".log")
        )

    def receive(self, timeout=90):
        stream = self.process.stdout
        if stream is None:
            raise ValueError("M1_OWNER_TIMEOUT")
        until = time.monotonic() + timeout
        while time.monotonic() < until:
            while b"\n" not in self.buffer:
                remaining = until - time.monotonic()
                if remaining <= 0 or not select.select([stream], [], [], remaining)[0]:
                    raise ValueError("M1_OWNER_TIMEOUT")
                chunk = os.read(stream.fileno(), 32781)
                if not chunk:
                    self.log.flush()
                    diagnostic = Path(self.log.name).read_bytes()
                    category = next(
                        (
                            line.decode()
                            for line in diagnostic.splitlines()
                            if line.startswith(b"M1_OWNER_INFERENCE_FAILED:")
                        ),
                        "M1_OWNER_EXIT",
                    )
                    raise ValueError(category)
                self.buffer.extend(chunk)
                require(len(self.buffer) <= 65560, "M1_OWNER_FRAME")
            line, _, rest = self.buffer.partition(b"\n")
            self.buffer = bytearray(rest)
            raw = bytes(line) + b"\n"
            require(len(raw) <= 32780 and raw.endswith(b"\n"), "M1_OWNER_FRAME")
            if raw.startswith(b"M1_CONTROL:"):
                return json.loads(raw.removeprefix(b"M1_CONTROL:"))
            self.noise.extend(raw)
            require(len(self.noise) <= 32768, "M1_OWNER_FRAME")
        raise ValueError("M1_OWNER_TIMEOUT")

    def send(self, value):
        if self.process.stdin is None:
            raise ValueError("M1_OWNER_INPUT")
        raw = canonical(value)
        require(len(raw) <= 32768)
        self.process.stdin.write(raw + b"\n")
        self.process.stdin.flush()

    def close(self):
        if self.process.stdin is not None:
            self.process.stdin.close()
        try:
            self.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait()
        self.log.close()
        diagnostic = Path(self.log.name).read_bytes()
        require(len(diagnostic) <= 32768, "M1_OWNER_DIAGNOSTIC_BOUND")
        self.diagnostic_path.write_bytes(diagnostic)
        self.diagnostic_path.chmod(0o600)
        if self.process.stdout is not None:
            self.process.stdout.close()


class Operator:
    def __init__(self, stack, prepared):
        self.stack, self.prepared = stack, prepared
        self.policy = json.loads((stack.folder / "secrets/policy.json").read_bytes())
        self.tokens = []
        self.coordinator = None

    def save(self):
        secret_file(self.stack.folder / "secrets/policy.json", self.policy)

    def grant(self, lane, fields, peer="owner"):
        token = secrets.token_hex(32)
        self.tokens.append(token)
        grant = {
            "spiffe_id": "spiffe://m1.test/" + peer,
            "token_sha256": hashlib.sha256(token.encode()).hexdigest(),
            "expires_unix_ms": int(time.time() * 1000) + 60000,
            **fields,
        }
        self.policy.setdefault(lane, []).append(grant)
        return token

    def owner_grant(self, request):
        target, action = request["target"], request["action"]
        approval = self.prepared["compute"]["approval"]
        common = {
            name: approval[name]
            for name in ("policy_digest", "policy_epoch", "evidence_policy_digest")
        }
        if action == "CONSUMER_READ":
            require(self.coordinator is not None)
            fields = {
                **target,
                "coordinator": self.coordinator,
                **{k: common[k] for k in ("policy_digest", "policy_epoch")},
            }
            lane = "consumer_grants"
        elif action in {"GET_OPERATION", "CANCEL_OPERATION"}:
            fields = {"scope": target, "actions": [action]}
            lane = "registry_grants"
        else:
            require(
                action
                in {
                    "KEY_CONTEXT_REGISTER",
                    "INPUT_UPLOAD_RESERVE",
                    "INPUT_UPLOAD_PART",
                    "INPUT_UPLOAD_MANIFEST",
                    "INPUT_UPLOAD_FINALIZE",
                    "COMPUTE_APPROVAL_REGISTER",
                    "APPROVED_OPERATION_ADMIT",
                }
            )
            fields = {
                "action": action,
                "target": target,
                "tenant_scope": approval["tenant_scope"],
                "owner_identity": self.prepared["trust"]["signer"],
                "owner": self.prepared["trust"],
                "evidence_policy": "NONE",
                **common,
            }
            lane = "owner_submission_grants"
        if lane != "registry_grants":
            self.policy[lane] = []
        token = self.grant(lane, fields)
        self.save()
        return token


def provision(stack, operator, locked, *, reuse_worker=False):
    prepared = operator.prepared
    operation, plan = prepared["operation"], prepared["plan"]
    identity = {
        name: operation[name] for name in ("tenant_scope", "operation_id", "workflow_epoch")
    }
    actual = json.loads(
        stack.execute(
            "workflow",
            "python",
            "-c",
            r"""
import json, sys
from kryvola_fabric.compute_workflow import workflow_id
from kryvola_fabric.ray_worker import namespace

op = json.load(sys.stdin)
attempt = {"schema_version": "1", **op, "attempt_epoch": "1", "fence": "1"}
execution = "exec-" + workflow_id(op["tenant_scope"], op["operation_id"])[8:]
print(
    json.dumps(
        {"attempt": attempt, "execution_id": execution, "namespace": namespace(attempt, execution)}
    )
)
""",
            payload=canonical(identity),
        )
    )
    attempt, execution, namespace = actual["attempt"], actual["execution_id"], actual["namespace"]
    tokens = {}
    for action, native, scoped in (
        ("GET", "GET_OPERATION", False),
        ("ENSURE", "ENSURE_ATTEMPT", False),
        ("REGISTER", "EXECUTION_REGISTER", True),
        ("SELECT", "RESULT_SELECT", True),
    ):
        scope = {
            **identity,
            "attempt_epoch": "1" if scoped else None,
            "fence": "1" if scoped else None,
        }
        tokens[action] = operator.grant(
            "registry_grants", {"scope": scope, "actions": [native]}, "workflow"
        )
    secret_file(stack.folder / "secrets/tokens.json", tokens)
    worker_private, _, worker = signing_key("m1-worker")
    _, coordinator_seed, coordinator = signing_key("m1-coordinator")
    operator.coordinator = coordinator
    release = prepared["release"]
    approval = release["approval"]

    def encode(value):
        return base64.urlsafe_b64encode(canonical(value)).rstrip(b"=").decode()

    secret_file(
        stack.folder / "secrets/release.json",
        {
            "approval_base64url": encode(approval),
            "signature_base64url": encode(release["envelope"]),
            "owner": prepared["trust"],
            "receipt": worker,
            "coordinator": coordinator,
            "coordinator_seed_hex": coordinator_seed,
            "evidence_policy": "NONE",
            "consent": prepared["consent"],
            **{
                name: approval[name]
                for name in ("policy_digest", "policy_epoch", "evidence_policy_digest")
            },
        },
    )
    if reuse_worker:
        # CoordinatorRelease resolves these private paths once, then reads them
        # per invocation. Only the serialized measurement path reuses this worker.
        stack.execute(
            "workflow",
            "python",
            "-c",
            """
from pathlib import Path
root, = Path('/tmp').glob('m1-release-*')
for name in ('database-release', 'release.json'):
    pending = root / (name + '.pending')
    pending.write_bytes((Path('/run/m1-secrets') / name).read_bytes())
    pending.chmod(0o600)
    pending.replace(root / name)
""",
        )
    else:
        stack.compose("restart", "workflow")
    reads = []
    for reservation, manifest in zip(prepared["reservations"], prepared["manifests"], strict=True):
        scope = {
            "schema_version": "1",
            "attempt": attempt,
            "purpose": "COMPUTE_READ",
            "manifest_digest": reservation["manifest_digest"],
        }
        reads.append(
            [
                operator.grant("grants", {"scope": scope}, "worker")
                for _ in range(1 + len(manifest["ordered_chunk_entries"]))
            ]
        )
    exact = {"attempt": attempt, "execution_id": execution}
    credentials = {
        "reads": reads,
        "output": operator.grant("output_grants", exact, "worker"),
        "receipt": operator.grant("receipt_grants", {**exact, **worker}, "worker"),
    }
    operator.save()
    with ZipFile(next((m1_assets.OUTPUT / "ml").glob("*.whl"))) as wheel:
        request = json.loads(wheel.read("kryvola_ml/_wire/fixtures.json"))["ExecuteRequest"]
    request.update(
        operation=operation,
        engine_digest=locked["permissions"]["image_sha256"],
        program_digest=plan["program_digest"],
        parameter_set_digest=plan["parameters"]["parameter_set_digest"],
        required_operators=plan["operators"],
        output_contract_digest=plan["output_contract_digest"],
        resource_profile_digest=plan["resource_profile_digest"],
    )
    request["execution"].update(
        attempt=attempt,
        execution_id=execution,
        session_epoch="0",
        deadline_unix_ms=operation["deadline_unix_ms"],
    )
    request["input_refs"] = [
        {
            "schema_version": "1",
            "opaque_artifact_id": "input-" + str(i),
            "tenant_scope": operation["tenant_scope"],
            "immutable_version": "1",
            "manifest_digest": reservation["manifest_digest"],
            "byte_length": manifest["serialized_bytes"],
            "media_type": "application/vnd.kryvola.tfhe-ciphertext",
        }
        for i, (reservation, manifest) in enumerate(
            zip(prepared["reservations"], prepared["manifests"], strict=True)
        )
    ]
    raw = stack.execute(
        "workflow",
        "python",
        "-c",
        "import json,sys;from kryvola_fabric.control import encode_control;"
        "sys.stdout.buffer.write(encode_control('ExecuteRequest',json.load(sys.stdin)))",
        payload=canonical(request),
    )
    capabilities = json.loads(
        stack.execute(
            "ray",
            "python",
            "-c",
            r"""
import grpc, json
from kryvola_fabric.control import encode_control, decode_control

with grpc.insecure_channel(
    "unix:/run/execution/engine.sock", options=[("grpc.default_authority", "localhost")]
) as channel:
    reply = channel.unary_unary("/kryvola.spec.v1.EngineService/GetCapabilities")(
        encode_control("GetCapabilitiesRequest", {"schema_version": "1"}), timeout=5
    )
    print(json.dumps(decode_control("GetCapabilitiesResponse", reply)["capabilities"]))
""",
        )
    )
    capability_digest = (
        stack.execute(
            "owner",
            "python",
            "-c",
            "import sys;from kryvola_ml.sdk.submission import commitment;"
            "print(commitment('blob',1,sys.stdin.buffer.read()))",
            payload=canonical(capabilities),
        )
        .decode()
        .strip()
    )
    root = "/run/execution/" + namespace
    assignment = {
        "execute_protobuf_hex": raw.hex(),
        "fabric_address": "",
        "fabric_id": "spiffe://m1.test/runtime",
        "worker_id": "spiffe://m1.test/worker",
        "workload_endpoint": "unix:///run/workload/agent.sock",
        "credentials": credentials,
        "receipt": {
            **{k: worker[k] for k in ("signer", "key_id", "key_epoch")},
            "capability_profile_digest": capability_digest,
            **{
                name: approval[name]
                for name in (
                    "policy_epoch",
                    "consent_digest",
                    "model_digest",
                    "evidence_policy_digest",
                )
            },
            "leakage_profile_digest": plan["leakage_profile_digest"],
        },
        "receipt_key": root + "/receipt.pk8",
        "evaluator": "/opt/kryvola/kryvola-cpu-evaluator",
        "supervisor": "/opt/kryvola/cpu_runner.py",
    }
    stack.execute(
        "engine",
        "python3",
        "-c",
        r"""
import json, os, socket, sys
from pathlib import Path

value = json.load(sys.stdin)
root = Path(value["root"])
root.mkdir(mode=0o700)
assignment = value["assignment"]
assignment["fabric_address"] = socket.gethostbyname("runtime") + ":8443"
for name, data in [
    ("assignment.json", json.dumps(assignment).encode()),
    ("execute.pb", bytes.fromhex(assignment["execute_protobuf_hex"])),
    ("receipt.pk8", bytes.fromhex(value["key"])),
]:
    path = root / name
    path.write_bytes(data)
    path.chmod(0o600)
""",
        payload=canonical({"root": root, "assignment": assignment, "key": worker_private.hex()}),
    )
    stack.compose("exec", "-d", "engine", "/opt/kryvola/kryvola-cpu-engine", root)
    return actual


def run_workflow(stack, actual):
    operation = actual["attempt"]
    notice = next(
        n for n, _, _ in operation_notices(stack, operation) if n["kind"] == "operation_created"
    )
    require(len(canonical(notice)) <= 32768)

    def received():
        require(
            stack.sql(
                "SELECT count(*) FROM fabric_inbox JOIN fabric_outbox ON event_id=id "
                "WHERE kind='operation_created' AND " + scope_sql(operation, "fabric_outbox")
            ).strip()
            == b"1"
        )

    stack.wait(received, seconds=30)
    identifier = (
        stack.execute(
            "workflow",
            "python",
            "-c",
            r"""
import asyncio, json, os, sys
from temporalio.client import Client
from kryvola_fabric.compute_activities import start_from_notification
from kryvola_fabric.compute_workflow import DATA_CONVERTER


async def run():
    client = await Client.connect("temporal:7233", data_converter=DATA_CONVERTER)
    handle = await start_from_notification(
        client, os.environ["M1_TASK_QUEUE"], sys.stdin.buffer.read(), ray=True, release=True
    )
    print(handle.id)


asyncio.run(run())
""",
            payload=canonical(notice),
        )
        .decode()
        .strip()
    )

    def candidate():
        raw = stack.execute(
            "ray",
            "python",
            "-c",
            r"""
import sys
from pathlib import Path
from kryvola_fabric.ray_worker import read_bounded

sys.stdout.buffer.write(
    read_bounded(Path("/run/kryvola/ray") / sys.argv[1] / "candidate.json", 1536)
)
""",
            actual["namespace"],
        )
        value = json.loads(raw)
        require(
            value["attempt"] == actual["attempt"]
            and value["execution_id"] == actual["execution_id"]
        )
        require(
            set(value) == {"schema_version", "attempt", "execution_id", "output_manifest_digest"}
        )
        return raw

    raw = stack.wait(candidate, seconds=40)
    # Export bounded untrusted result metadata across the worker UID boundary.
    # The workflow still validates the exact candidate and commits selection via Fabric.
    folder = stack.folder / "workflow-state/candidates" / actual["namespace"]
    publish_candidate(folder, raw)

    def decision():
        raw = stack.sql(
            "SELECT json_build_object('release',"
            "convert_from(canonical_authorization,'UTF8')::json,'release-signature',"
            "convert_from(canonical_signature,'UTF8')::json,'disclosure_id',disclosure_id) "
            "FROM fabric_disclosure_decisions WHERE " + disclosure_sql(operation)
        )
        require(bool(raw.strip()))
        return json.loads(raw)

    return identifier, stack.wait(decision, seconds=40)


def evidence(stack, owner, operator, identifier, decision, opened, locked):
    where = scope_sql(operator.prepared["operation"])
    require(opened["assurance"] == "CONFIDENTIALITY_ONLY")
    require(operator.prepared["consent"]["allow_unverified_release"] is True)
    require(operator.prepared["consent"]["computation_integrity"] == "UNPROVEN")
    container = stack.compose("ps", "-q", "workflow").decode().strip()
    history = json.loads(
        capture(
            [
                "docker",
                "exec",
                container,
                "python",
                "-c",
                (m1.ROOT / "tools/m1_history.py").read_text(),
                identifier,
            ],
            2 << 20,
            timeout=30,
        )
    )
    require(history["result"]["disclosure_id"] == decision["disclosure_id"])
    receipt = json.loads(
        stack.sql(
            "SELECT convert_from(canonical_receipt,'UTF8') FROM fabric_execution_receipts WHERE "
            + where
        )
    )
    require(receipt["assurance"] == decision["release"]["assurance"] == "CONFIDENTIALITY_ONLY")
    require(receipt["output_manifest_digests"] == [decision["release"]["output_manifest_digest"]])
    require(
        stack.sql("SELECT receipt_digest FROM fabric_execution_receipts WHERE " + where)
        .decode()
        .strip()
        == decision["release"]["receipt_digest"]
    )
    require(
        stack.sql(
            "SELECT "
            + ",".join(
                "(SELECT count(*) FROM "
                + table
                + " WHERE "
                + (
                    disclosure_sql(operator.prepared["operation"])
                    if table == "fabric_disclosure_decisions"
                    else where
                )
                + ")"
                for table in (
                    "fabric_executions",
                    "fabric_execution_receipts",
                    "fabric_selected_results",
                    "fabric_disclosure_decisions",
                )
            )
        ).strip()
        == b"1|1|1|1"
    )
    notices, seen, maximum = [], set(), 0
    for notice, size, offset in operation_notices(stack, operator.prepared["operation"]):
        require(notice["kind"] in {"operation_created", "result_selected"})
        notices.append(canonical(notice))
        seen.add(notice["kind"])
        maximum = max(maximum, size)
        if len(seen) == 2:
            stack._m1_notice_cursor = offset + 1
            break
    require(len(seen) == 2, "M1_BROKER_CONVERGENCE")
    images, logs = {}, []
    roles = {
        "runtime": "RUNTIME",
        "workflow": "RUNTIME",
        "messaging": "RUNTIME",
        "ray": "RAY",
        "engine": "ENGINE",
        "owner": "OWNER",
        "postgres": "POSTGRES",
        "temporal": "TEMPORAL",
        "storage": "S3",
        "broker": "REDPANDA",
    }
    for role, image_role in roles.items():
        container = stack.compose("ps", "-q", role).decode().strip()
        observed = json.loads(capture(["docker", "inspect", container], 128 << 10))[0]
        require(observed["State"]["Running"] is True)
        require(observed["Config"]["Image"] == stack.env["M1_" + image_role + "_IMAGE"])
        images[role] = observed["Image"]
        logs.append(capture(["docker", "logs", container], 1 << 20))
    image = json.loads((m1_assets.OUTPUT / "engines/image-subject.json").read_bytes())
    engine_config = m1_images.image_config(stack.env["M1_ENGINE_IMAGE"])
    require(engine_config == image["config_sha256"])
    logs += [
        bytes(owner.noise),
        Path(owner.log.name).read_bytes(),
        base64.b64decode(history["history_base64"], validate=True),
        *notices,
    ]
    markers = [token.encode() for token in operator.tokens]
    from urllib.parse import urlsplit

    folder = stack.folder / "secrets"
    for name in ("pg-admin", "pg-temporal"):
        markers.append((folder / name).read_bytes().strip())
    for path in folder.glob("database*"):
        password = urlsplit(path.read_text()).password
        if password:
            markers.append(password.encode())
    storage = json.loads((folder / "s3.json").read_bytes())
    markers += [storage[field].encode() for field in ("secret_access_key", "access_key_id")]
    markers.append(
        json.loads((folder / "release.json").read_bytes())["coordinator_seed_hex"].encode()
    )
    for path in folder.glob("*.key"):
        markers += [
            line for line in path.read_bytes().splitlines() if not line.startswith(b"-----")
        ]
    require(sum(map(len, logs)) <= 8 << 20, "M1_INFERENCE_LOG_BOUND")
    for raw in logs:
        check_logs(raw, markers)
        for offset in range(0, len(raw), 12000):
            owner.send({"logs_base64": base64.b64encode(raw[offset : offset + 12000]).decode()})
            require(owner.receive()["stage"] == "LOG_CHUNK_CLEAN")
    owner.send({"scan_done": True})
    audit = owner.receive()
    require(audit == {"stage": "AUDITED", "logs_clean": True, "negative_control": True})
    return validate_report(
        {
            "schema_version": "platform-m1-inference-v1",
            "assurance": opened["assurance"],
            "owner_reference_match": opened["owner_reference_match"],
            "logs_clean": audit["logs_clean"],
            "bounds_checked": True,
            "invocation": stack.project,
            "execution": {
                "execution_id": receipt["execution_id"],
                "workflow_id": identifier,
                "disclosure_id": decision["disclosure_id"],
                "receipt_digest": decision["release"]["receipt_digest"],
                "release_digest": decision["release-signature"]["payload_digest"],
                "output_manifest_digest": decision["release"]["output_manifest_digest"],
            },
            "release_manifests": {
                role: c["assets"]["manifest.json"]["sha256"]
                for role, c in locked["components"].items()
            },
            "history": history["observed"],
            "broker": {"events": len(notices), "payload_max_bytes": maximum},
            "images": images,
            "engine_config_sha256": engine_config,
            "receipt_assurance": receipt["assurance"],
            "release_assurance": decision["release"]["assurance"],
            "frozen_reference_sha256": opened["frozen_reference_sha256"],
        },
        locked,
    )


def qualify(*, stack=None, request_id=None, observer=None):
    """Qualify one request; external fixtures require a fresh identity and serial ownership."""
    owned = stack is None
    require(request_id is None or re.fullmatch(r"[0-9a-f]{16}", request_id))
    if not owned:
        assert request_id is not None
        require(request_id is not None and stack.owned and stack.configured)
        require(
            not (stack.folder / ("owner-session-" + request_id + ".log")).exists(),
            "M1_REQUEST_REPLAYED",
        )
    locked = m1_assets.load()
    if owned:
        stack = m1.Stack("kryvola-m1-" + secrets.token_hex(6))
    resources = ExitStack()
    owner = None
    actual = None
    try:
        if owned:
            stack.start()
            stack.verify()
        resources.enter_context(serial_request(stack))
        boundaries = [time.monotonic_ns()]
        owner = OwnerSession(stack, locked["permissions"]["image_sha256"], request_id=request_id)
        prepared = owner.receive()
        require(prepared["stage"] == "PREPARED")
        require(
            prepared["operation"]["operation_id"]
            == "m1-inference" + ("-" + request_id if request_id else "")
        )
        phase("OWNER_PREPARED")
        boundaries.append(time.monotonic_ns())
        operator = Operator(stack, prepared)
        while True:
            message = owner.receive()
            if message["stage"] == "ADMITTED":
                phase("SDK_ADMITTED")
                boundaries.append(time.monotonic_ns())
                break
            require(message["stage"] == "GRANT")
            owner.send({"token": operator.owner_grant(message)})
        actual = provision(stack, operator, locked, reuse_worker=not owned)
        boundaries.append(time.monotonic_ns())
        phase("EXECUTION_PROVISIONED")
        identifier, decision = run_workflow(stack, actual)
        boundaries.append(time.monotonic_ns())
        phase("RELEASE_COMMITTED")
        release = decision["release"]
        if operator.coordinator is None:
            raise ValueError("M1_COORDINATOR_MISSING")
        scope = {
            "schema_version": "1",
            "disclosure_id": decision["disclosure_id"],
            **{
                key: release[key] for key in ("tenant_scope", "recipient", "output_manifest_digest")
            },
        }
        owner.send(
            {
                "release": release,
                "release-signature": decision["release-signature"],
                "scope": scope,
                "open-policy": {
                    **operator.coordinator,
                    "release_digest": decision["release-signature"]["payload_digest"],
                    "authority": "runtime:8443",
                    "server_spiffe_id": "spiffe://m1.test/runtime",
                },
            }
        )
        while True:
            message = owner.receive()
            if message["stage"] == "OPENED":
                break
            require(message["stage"] == "GRANT")
            owner.send({"token": operator.owner_grant(message)})
        require(message["owner_reference_match"] is True)
        boundaries.append(time.monotonic_ns())
        result = evidence(stack, owner, operator, identifier, decision, message, locked)
        if observer is not None:
            observer(
                {
                    "stages_ns": dict(
                        zip(
                            (
                                "owner_prepare",
                                "admission",
                                "provision",
                                "dispatch_release",
                                "owner_open",
                            ),
                            (b - a for a, b in zip(boundaries[:-1], boundaries[1:], strict=True)),
                            strict=True,
                        )
                    ),
                    "request_ns": boundaries[-1] - boundaries[0],
                    "audit_ns": time.monotonic_ns() - boundaries[-1],
                    "input_bytes": sum(int(m["serialized_bytes"]) for m in prepared["manifests"]),
                    "key_context_digest": prepared["operation"]["key_context_ref"][
                        "key_context_digest"
                    ],
                    "plan_digest": prepared["operation"]["plan_ref"]["plan_digest"],
                    "profile": prepared["plan"]["security_profile"],
                }
            )
        suffix = "-" + request_id if request_id else ""
        path = m1.ROOT / "build" / ("m1-inference-report" + suffix + ".json")
        path.write_bytes(canonical(result) + b"\n")
        return result
    except Exception:
        if actual is not None:
            try:
                observed = stack.execute(
                    "ray",
                    "python",
                    "-c",
                    r"""
import json, sys, grpc
from kryvola_fabric.control import encode_control, decode_control

value = json.load(sys.stdin)
with grpc.insecure_channel(
    "unix:/run/kryvola/ray/" + value["namespace"] + "/engine.sock",
    options=[("grpc.default_authority", "localhost")],
) as channel:
    raw = channel.unary_unary("/kryvola.spec.v1.EngineService/GetExecutionStatus")(
        encode_control(
            "GetExecutionStatusRequest",
            {
                "schema_version": "1",
                "attempt": value["attempt"],
                "execution_id": value["execution_id"],
            },
        ),
        timeout=3,
    )
    reply = decode_control("GetExecutionStatusResponse", raw)
    print(
        json.dumps(
            {
                "physical_state": reply["execution"]["physical_state"],
                "error_code": reply["error_code"],
            }
        )
    )
""",
                    payload=canonical(actual),
                )
                phase("NATIVE_STATUS:" + observed.decode().strip())
                counts = stack.sql(
                    "SELECT (SELECT count(*) FROM fabric_executions),"
                    "(SELECT count(*) FROM fabric_execution_receipts),"
                    "(SELECT count(*) FROM fabric_selected_results)"
                )
                phase("DURABLE_COUNTS:" + counts.decode().strip())
            except OSError, ValueError, subprocess.SubprocessError:
                phase("NATIVE_STATUS_UNAVAILABLE")
        raise
    finally:
        try:
            if owner is not None:
                owner.close()
        finally:
            try:
                resources.__exit__(*sys.exc_info())
            finally:
                if owned:
                    stack.close()


if __name__ == "__main__":
    print(canonical(qualify()).decode())
