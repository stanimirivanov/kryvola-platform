"""Real, bounded execution/transport fault campaign over admitted M1 artifacts."""

# The controller runs outside the component processes it terminates. No fault
# replaces a runtime response or a cryptographic implementation.
import base64
import functools
import hashlib
import inspect
import json
import os
import re
import secrets
import select
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

if __package__:
    from . import m1, m1_assets, m1_images
    from . import m1_inference as live
else:
    import m1
    import m1_assets
    import m1_images
    import m1_inference as live


KINDS = ("duplicate", "lost", "reordered", "bridge", "worker", "completion", "corrupt", "oversized")
CASES = tuple(f"{kind}-{side}" for kind in KINDS for side in ("before", "after"))


def require(value):
    if not value:
        raise ValueError("M1_RECOVERY_EVIDENCE")


def validate_case(value):
    require(value["case"] in CASES and value["boundary_observed"] is True)
    kind, side = value["case"].split("-")
    require(value["logs_clean"] is True and type(value["process_killed"]) is bool)
    require(value["workflow_runs"] == (0 if value["outcome"] == "REJECTED" else 1))
    if kind in {"bridge", "completion"}:
        require(value["retry_attempt_max"] >= 2)
    if kind in {"bridge", "worker", "completion", "lost"}:
        require(value["process_killed"] is True)
    require(len(set(value["execution_ids"])) == value["executions"])
    require(
        all(re.fullmatch(r"exec-[a-f0-9]{64}(?:-duplicate)?", x) for x in value["execution_ids"])
    )
    for field in (
        "executions",
        "receipts",
        "selections",
        "disclosures",
        "current_selections",
        "immutable_objects_checked",
        "pins_checked",
        "history_events",
        "history_payload_max_bytes",
        "output_uploads",
        "distinct_output_uploads",
        "finalized_outputs",
    ):
        require(type(value[field]) is int and value[field] >= 0)
    require(value["selections"] == value["current_selections"] <= 1)
    require(value["disclosures"] <= value["selections"])
    if value["outcome"] == "REJECTED":
        require(value["immutable_objects_checked"] == value["pins_checked"] == 0)
        require(value.get("staging_objects_checked", 0) > 0)
    else:
        require(value["immutable_objects_checked"] > 0 and value["pins_checked"] > 0)
    expected_outputs = (
        1
        if value["case"] == "worker-before"
        else value["executions"]
        if value["outcome"] == "RELEASED"
        else 0
    )
    require(
        value["output_uploads"]
        == value["distinct_output_uploads"]
        == value["finalized_outputs"]
        == expected_outputs
    )
    require(0 <= value["receipts"] <= value["executions"])
    if value["outcome"] == "RELEASED":
        require(value["native_state"] == "SUCCEEDED" and value["native_error"] == "NONE")
        require(value["workflow_status"] == "COMPLETED")
        require(value["selections"] == value["disclosures"] == 1)
        require(value["receipts"] == value["executions"] >= 1)
    elif value["outcome"] == "REJECTED":
        require(kind in {"corrupt", "oversized"} and side == "before")
        require(value["native_state"] is None and value["native_error"] is None)
        require(value["workflow_status"] == "NOT_STARTED" and value["executions"] == 0)
        require(value["selections"] == value["disclosures"] == 0)
    elif value["outcome"] == "FAILED":
        require(kind in {"worker", "corrupt", "oversized"})
        require(value["workflow_status"] == "FAILED")
        if kind == "worker":
            require(value["native_state"] == "RUNNING" and value["native_error"] == "NONE")
        else:
            require(
                value["native_state"] == "FAILED"
                and value["native_error"] in {"UNAVAILABLE", "INVALID_REQUEST"}
            )
        require(value["executions"] == 1 and value["selections"] == value["disclosures"] == 0)
    else:
        require(False)
    if value["workflow_status"] != "NOT_STARTED":
        require(1 <= value["history_events"] <= 128)
        require(1 <= value["history_payload_max_bytes"] <= 32768)
    if kind == "duplicate":
        require(value["executions"] == 2 and value["receipts"] == 2)
    return value


class DatabaseLock:
    """A real PostgreSQL transaction holds a named, empty commit boundary."""

    def __init__(self, stack, table="fabric_inbox"):
        require(table in {"fabric_inbox", "fabric_execution_receipts", "fabric_operation_barriers"})
        self.table = table
        container = stack.compose("ps", "-q", "postgres").decode().strip()
        require(stack.sql("SELECT count(*) FROM " + table).strip() == b"0")
        self.process = subprocess.Popen(
            [
                "docker",
                "exec",
                "-i",
                container,
                "psql",
                "-U",
                "m1_admin",
                "-d",
                "fabric",
                "-Atq",
                "-v",
                "ON_ERROR_STOP=1",
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        if self.process.stdin is None or self.process.stdout is None:
            raise ValueError("M1_RECOVERY_PIPE")
        self.process.stdin.write(
            ("BEGIN; LOCK TABLE " + table + " IN ACCESS EXCLUSIVE MODE;\n\\echo LOCKED\n").encode()
        )
        self.process.stdin.flush()
        require(bool(select.select([self.process.stdout], [], [], 10)[0]))
        require(self.process.stdout.readline().strip() == b"LOCKED")

    def observe(self):
        if self.process.stdin is None or self.process.stdout is None:
            raise ValueError("M1_RECOVERY_PIPE")
        query = (
            "SELECT (SELECT count(*) FROM pg_locks WHERE relation='"
            + self.table
            + "'::regclass AND NOT granted)::text || '|' || "
            "(SELECT count(*) FROM fabric_finalized_artifacts)::text;\n"
        )
        self.process.stdin.write(query.encode())
        self.process.stdin.flush()
        require(bool(select.select([self.process.stdout], [], [], 2)[0]))
        raw = self.process.stdout.readline(128).strip().split(b"|")
        require(len(raw) == 2)
        return int(raw[0]), int(raw[1])

    def close(self):
        if self.process.stdin is None or self.process.stdout is None:
            raise ValueError("M1_RECOVERY_PIPE")
        self.process.stdin.write(b"ROLLBACK;\n\\q\n")
        self.process.stdin.close()
        self.process.wait(timeout=10)
        self.process.stdout.close()


def kill(stack, role):
    container = stack.compose("ps", "-q", role).decode().strip()
    require(bool(container))
    subprocess.run(
        ["docker", "kill", "--signal=KILL", container], capture_output=True, check=True, timeout=20
    )
    state = json.loads(
        live.capture(["docker", "inspect", "--format", "{{json .State}}", container], 8192)
    )
    require(state["ExitCode"] == 137 and not state["Running"] and not state["OOMKilled"])


def start(stack, role):
    # Restart only the killed owned container, without rerunning Compose's
    # one-shot schema/identity initialization dependencies.
    container = stack.compose("ps", "-a", "-q", role).decode().strip()
    require(bool(container))
    subprocess.run(["docker", "start", container], check=True, capture_output=True, timeout=20)


def notices(stack):
    return json.loads(
        stack.sql(
            "SELECT COALESCE(json_agg(json_build_object('version',2,'id',id::text,'tenant"
            "_scope',tenant_scope,'operation_id',operation_id,'kind',kind) ORDER BY id),'"
            "[]') FROM fabric_outbox"
        )
    )


async def deliver_notifications(
    records, queue, *, overlap=False, connect=None, start=None, timeout=8, attempt_timeout=3
):
    """Bound transport setup/retries; ambiguous starts reuse the published workflow ID."""
    import asyncio
    import importlib
    import json
    from datetime import timedelta

    from temporalio.service import RPCError, RPCStatusCode

    if connect is None:
        DATA_CONVERTER = importlib.import_module("kryvola_fabric.compute_workflow").DATA_CONVERTER
        from temporalio.client import Client

        async def connect():
            return await Client.connect(
                "temporal:7233",
                data_converter=DATA_CONVERTER,
                connect_timeout=timedelta(seconds=attempt_timeout),
            )

    if start is None:
        start_from_notification = importlib.import_module(
            "kryvola_fabric.compute_activities"
        ).start_from_notification

        class BoundedClient:
            def __init__(self, client, budget):
                self.client, self.budget = client, budget
                self.data_converter = client.data_converter

            async def start_workflow(self, *args, **kwargs):
                return await self.client.start_workflow(
                    *args, **kwargs, rpc_timeout=timedelta(seconds=self.budget)
                )

            def get_workflow_handle(self, *args, **kwargs):
                return self.client.get_workflow_handle(*args, **kwargs)

        async def start(client, task_queue, raw):
            handle = await start_from_notification(
                BoundedClient(client, attempt_timeout), task_queue, raw, ray=True, release=True
            )
            return None if handle is None else handle.id

    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while loop.time() < deadline:
        phase = "connect"
        try:
            async with asyncio.timeout(min(attempt_timeout, deadline - loop.time())):
                client = await connect()
                phase = "start"

                async def deliver(record, client=client):
                    raw = json.dumps(record, sort_keys=True, separators=(",", ":")).encode()
                    return await start(client, queue, raw)

                if overlap:
                    return await asyncio.gather(*(deliver(record) for record in records))
                return [await deliver(record) for record in records]
        except TimeoutError, OSError:
            pass
        except RPCError as error:
            if error.status not in (RPCStatusCode.UNAVAILABLE, RPCStatusCode.DEADLINE_EXCEEDED):
                raise
        except RuntimeError:
            # The SDK reports an unsuccessful eager transport connection this way.
            if phase != "connect":
                raise
        remaining = deadline - loop.time()
        if remaining > 0:
            await asyncio.sleep(min(0.05, remaining))
    raise ValueError("M1_HANDOFF_UNAVAILABLE")


def deadline_program(body, *, seconds=10):
    require(0 < seconds <= 10)
    # An OS deadline also bounds a native SDK connection that does not finish
    # coroutine cancellation. Only this disposable exec process is terminated.
    return (
        "import signal\n"
        "signal.signal(signal.SIGALRM, signal.SIG_DFL)\n"
        f"signal.setitimer(signal.ITIMER_REAL, {seconds!r})\n" + body
    )


def handoff(stack, records, *, overlap=False):
    """Bound and retry the published idempotent start in the admitted role."""
    program = deadline_program(
        inspect.getsource(deliver_notifications)
        + r"""
import asyncio, json, os, sys
value = json.load(sys.stdin)
try:
    result = asyncio.run(deliver_notifications(
        value["records"], os.environ["M1_TASK_QUEUE"], overlap=value["overlap"]
    ))
except ValueError as error:
    if str(error) != "M1_HANDOFF_UNAVAILABLE":
        raise
    sys.exit(75)
print(json.dumps(result))
"""
    )
    for _ in range(2):
        try:
            return json.loads(
                stack.execute(
                    "workflow",
                    "python",
                    "-c",
                    program,
                    payload=live.canonical({"records": records, "overlap": overlap}),
                )
            )
        except subprocess.CalledProcessError as error:
            if error.returncode not in (75, 128 + 14):
                raise
    # Keep only bounded service-state diagnostics, never container env or logs.
    states = {}
    for role in ("temporal", "workflow", "postgres"):
        container = stack.compose("ps", "-a", "-q", role).decode().strip()
        if container:
            state = json.loads(
                live.capture(
                    ["docker", "inspect", "--format", "{{json .State}}", container], 64 << 10
                )
            )
            states[role] = {k: state[k] for k in ("Running", "ExitCode", "OOMKilled")}
    live.phase("HANDOFF_UNAVAILABLE:" + json.dumps(states, sort_keys=True))
    raise ValueError("M1_HANDOFF_UNAVAILABLE")


def history(stack, identifier):
    return json.loads(
        stack.execute(
            "workflow",
            "python",
            "-c",
            r"""
import asyncio, base64, json, sys
from temporalio.client import Client
from temporalio.api.history.v1 import History
from kryvola_fabric.compute_workflow import DATA_CONVERTER


async def main():
    v = json.load(sys.stdin)
    scope = {"__name__": "qualification_history"}
    exec(v["source"], scope)
    client = await Client.connect("temporal:7233", data_converter=DATA_CONVERTER)
    handle = client.get_workflow_handle(v["id"])
    description = await handle.describe()
    fetched = await handle.fetch_history()
    h = History(events=fetched.events)
    print(
        json.dumps(
            {
                "status": description.status.name,
                "retry_attempt_max": max(
                    (
                        e.activity_task_started_event_attributes.attempt
                        for e in h.events
                        if e.HasField("activity_task_started_event_attributes")
                    ),
                    default=0,
                ),
                "workflow_runs": len(
                    [x async for x in client.list_workflows(query="WorkflowId = '" + v["id"] + "'")]
                ),
                "observed": scope["measure"](h),
                "serialized": base64.b64encode(h.SerializeToString()).decode(),
            }
        )
    )


asyncio.run(main())
""",
            payload=live.canonical(
                {"id": identifier, "source": (m1.ROOT / "tools/m1_history.py").read_text()}
            ),
        )
    )


def tamper(stack, oversized, *, finalized):
    if finalized:
        row = json.loads(
            stack.sql(
                "SELECT json_build_object('id',upload_id,'length',(convert_from(canonical_man"
                "ifest,'UTF8')::json->'ordered_chunk_entries'->0->>'byte_length')::bigint) FR"
                "OM fabric_finalized_artifacts ORDER BY upload_id LIMIT 1"
            )
        )
        key, length = "immutable/" + row["id"] + "/0", row["length"]
    else:
        row = json.loads(
            stack.sql("SELECT json_build_object('id',id) FROM fabric_uploads ORDER BY id LIMIT 1")
        )
        key, length = "staging/" + row["id"] + "/manifest", 32768
    before = json.loads(stack.aws("s3api", "head-object", "--bucket", "m1-artifacts", "--key", key))
    # Public zeros are fault bytes, never a copied key/ciphertext witness.
    length = length + 1 if oversized else before["ContentLength"]
    stack.execute(
        "s3-client",
        "sh",
        "-c",
        'dd if=/dev/zero of=/tmp/m1-fault bs="$1" count=1 2>/dev/null',
        "sh",
        str(length),
    )
    stack.aws(
        "s3api", "put-object", "--bucket", "m1-artifacts", "--key", key, "--body", "/tmp/m1-fault"
    )
    after = json.loads(stack.aws("s3api", "head-object", "--bucket", "m1-artifacts", "--key", key))
    require(after["ContentLength"] == length and after["ETag"] != before["ETag"])


def objects(stack):
    listing = json.loads(
        stack.aws("s3api", "list-objects-v2", "--bucket", "m1-artifacts", "--max-keys", "128")
    )
    require(not listing.get("IsTruncated", False))
    rows = listing.get("Contents", [])
    require(0 < len(rows) <= 128)

    def check(item):
        head = json.loads(
            stack.aws("s3api", "head-object", "--bucket", "m1-artifacts", "--key", item["Key"])
        )
        require(head["ContentLength"] == item["Size"] and head["ETag"] == item["ETag"])

    with ThreadPoolExecutor(max_workers=2) as pool:
        list(pool.map(check, rows, buffersize=2))
    return {
        "immutable": sum(x["Key"].startswith("immutable/") for x in rows),
        "staging": sum(x["Key"].startswith("staging/") for x in rows),
        "sha256": hashlib.sha256(live.canonical(rows)).hexdigest(),
    }


@functools.lru_cache(maxsize=4)
def installed_engine_config(reference, image_id):
    # Both keys are immutable identities observed from the actual container.
    # A changed backend identity causes a new extraction, never a cache hit.
    require(re.fullmatch(r"sha256:[a-f0-9]{64}", image_id))
    return m1_images.image_config(reference)


def audit(stack, owner, operator, workflow_history):
    """Send logs to the still-live owner; private canaries never leave that UID."""
    rows = []
    images = {}
    for role in (
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
    ):
        container = stack.compose("ps", "-a", "-q", role).decode().strip()
        require(bool(container))
        images[role] = (
            live.capture(["docker", "inspect", "--format", "{{.Image}}", container], 1024)
            .decode()
            .strip()
        )
        rows.append(live.capture(["docker", "logs", container], 1 << 20))
    rows += [
        bytes(owner.noise),
        Path(owner.log.name).read_bytes(),
        base64.b64decode(workflow_history.get("serialized", "")),
    ]
    markers = [x.encode() for x in operator.tokens]
    folder = stack.folder / "secrets"
    markers += [path.read_bytes().strip() for path in folder.glob("pg-*")]
    storage = json.loads((folder / "s3.json").read_bytes())
    markers += [storage[k].encode() for k in ("secret_access_key", "access_key_id")]
    from urllib.parse import urlsplit

    for path in folder.glob("database*"):
        password = urlsplit(path.read_text()).password
        if password:
            markers.append(password.encode())
    if operator.coordinator is not None:
        seed = json.loads((folder / "release.json").read_bytes())["coordinator_seed_hex"]
        markers += [seed.encode(), bytes.fromhex(seed)]
        keys = json.loads(
            stack.execute(
                "ray",
                "python",
                "-c",
                r"""
import json
from pathlib import Path

root = Path("/run/kryvola/ray")
paths = list(root.glob("*/receipt.pk8")) + [root / "receipt.pk8"]
assert len(paths) <= 3
out = []
for path in paths:
    assert not path.is_symlink() and path.is_file()
    with path.open("rb") as stream:
        raw = stream.read(65)
    assert len(raw) == 48
    out.append(raw.hex())
print(json.dumps(out))
""",
            )
        )
        for key in keys:
            raw = bytes.fromhex(key)
            markers += [raw, key.encode(), raw[-32:], raw[-32:].hex().encode()]
    for path in folder.glob("*.key"):
        markers += [
            line for line in path.read_bytes().splitlines() if not line.startswith(b"-----")
        ]
    require(sum(map(len, rows)) <= 8 << 20)
    for raw in rows:
        live.check_logs(raw, markers)
        for offset in range(0, len(raw), 12000):
            owner.send({"logs_base64": base64.b64encode(raw[offset : offset + 12000]).decode()})
            require(owner.receive()["stage"] == "LOG_CHUNK_CLEAN")
    owner.send({"scan_done": True})
    require(owner.receive() == {"stage": "AUDITED", "logs_clean": True, "negative_control": True})
    return images


def native_status(stack, actual):
    return json.loads(
        stack.execute(
            "ray",
            "python",
            "-c",
            r"""
import json, sys, grpc
from kryvola_fabric.control import encode_control, decode_control

v = json.load(sys.stdin)
with grpc.insecure_channel(
    "unix:/run/kryvola/ray/" + v["namespace"] + "/engine.sock",
    options=[("grpc.default_authority", "localhost")],
) as channel:
    raw = channel.unary_unary("/kryvola.spec.v1.EngineService/GetExecutionStatus")(
        encode_control(
            "GetExecutionStatusRequest",
            {"schema_version": "1", "attempt": v["attempt"], "execution_id": v["execution_id"]},
        ),
        timeout=3,
    )
    reply = decode_control("GetExecutionStatusResponse", raw)
    assert reply["execution"]["attempt"] == v["attempt"]
    assert reply["execution"]["execution_id"] == v["execution_id"]
    print(
        json.dumps(
            {
                "physical_state": reply["execution"]["physical_state"],
                "error_code": reply["error_code"],
            }
        )
    )
""",
            payload=live.canonical(actual),
        )
    )


def export_candidate(stack, actual):
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
        value["attempt"] == actual["attempt"] and value["execution_id"] == actual["execution_id"]
    )
    require(set(value) == {"schema_version", "attempt", "execution_id", "output_manifest_digest"})
    folder = stack.folder / "workflow-state/candidates" / actual["namespace"]
    folder.mkdir(parents=True, mode=0o755)
    (folder / "candidate.json").write_bytes(raw)
    (folder / "candidate.json").chmod(0o444)


def replay(stack, records):
    broker = stack.compose("ps", "-q", "broker").decode().strip()
    args = [
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
    ]
    for record in records:
        subprocess.run(
            [
                "docker",
                "exec",
                "-i",
                broker,
                "rpk",
                "topic",
                "produce",
                "m1-events",
                "--key",
                f"{len(record['tenant_scope'])}:{record['tenant_scope']}{record['operation_id']}",
                *args,
            ],
            input=live.canonical(record) + b"\n",
            capture_output=True,
            timeout=20,
            check=True,
        )


def refresh_unspent(operator, hashes):
    # Reissue only capabilities not yet presented by the primary execution.
    # Never extend a consumed one-shot capability or an owner submission grant.
    expiry = int(time.time() * 1000) + 45000
    for lane in ("registry_grants", "grants", "output_grants", "receipt_grants"):
        for grant in operator.policy.get(lane, []):
            if grant["token_sha256"] in hashes:
                grant["expires_unix_ms"] = expiry
    operator.save()


def kill_at_barrier(stack, actual, config, stopping, *, worker=False):
    """Observe independently of potentially slow handoff/history RPCs."""
    marker = stack.folder / "workflow-state/barrier-reached"
    state_at_fault = None
    until = time.monotonic() + 75
    while not stopping.is_set() and time.monotonic() < until:
        if marker.exists():
            require(json.loads(marker.read_bytes()) == config)
            if config["action"] == "SELECT" and not worker:
                count = int(stack.sql("SELECT count(*) FROM fabric_selected_results"))
                require(count == (1 if config["edge"] == "after" else 0))
            if config["action"] == "SUBMIT":
                count = json.loads(
                    stack.execute(
                        "workflow",
                        "python",
                        "-c",
                        "import json,sys;"
                        "from kryvola_fabric.ray_dispatch import local_jobs;"
                        "r=local_jobs();print(json.dumps(r('GET','/api/jobs/'+sys.argv[1],None)))",
                        actual["namespace"],
                    )
                )
                require((count is None) == (config["edge"] == "before"))
            if worker:
                require(stack.sql("SELECT count(*) FROM fabric_selected_results").strip() == b"0")
                state_at_fault = native_status(stack, actual)
                require(state_at_fault == {"physical_state": "SUCCEEDED", "error_code": "NONE"})
                kill(stack, "engine")
                (stack.folder / "workflow-state/barrier-release").touch()
            else:
                kill(stack, "workflow")
                start(stack, "workflow")
            return state_at_fault
        stopping.wait(0.02)
    raise ValueError("M1_RECOVERY_MISSING_BOUNDARY")


def kill_at_receipt(stack, actual, lock, stopping):
    # Poll on the already-open SQL session. Docker/Temporal CLI startup must not
    # consume the published Engine's five-second HTTP deadline before SIGKILL.
    until = time.monotonic() + 75
    while not stopping.is_set() and time.monotonic() < until:
        waiting, finalized = lock.observe()
        if waiting:
            require(finalized == 3)
            state = native_status(stack, actual)
            require(state == {"physical_state": "RUNNING", "error_code": "NONE"})
            kill(stack, "engine")
            return state
        stopping.wait(0.025)
    raise ValueError("M1_RECOVERY_MISSING_BOUNDARY")


def finish_worker_kill(pending):
    state = pending.result(timeout=20)
    require(state == {"physical_state": "RUNNING", "error_code": "NONE"})
    return state


def run_case(case):
    require(case in CASES)
    kind, side = case.split("-")
    stack = m1.Stack("kryvola-m1-" + secrets.token_hex(6))
    owner, lock = None, None
    monitor, pending_kill = None, None
    stopping = threading.Event()
    observed = killed = False
    state_at_fault = {"physical_state": None, "error_code": None}
    try:
        stack.start()
        stack.verify()
        if kind == "lost":
            stack.compose("stop", "messaging")
            if side == "before":
                lock = DatabaseLock(stack)
        if kind == "worker" and side == "before":
            lock = DatabaseLock(stack, "fabric_execution_receipts")
        if kind in {"bridge", "completion"} or (kind == "worker" and side == "after"):
            config = {
                "action": "SUBMIT" if kind == "bridge" else "SELECT",
                "edge": "before" if kind == "worker" else side,
            }
            (stack.folder / "workflow-state/recovery.json").write_bytes(live.canonical(config))
        owner = live.OwnerSession(
            stack, m1_assets.load()["permissions"]["image_sha256"], recovery=True
        )
        live.phase("RECOVERY_OWNER_PREPARE")
        prepared = owner.receive()
        require(prepared["stage"] == "PREPARED")
        operator = live.Operator(stack, prepared)
        rejected = False
        while True:
            message = owner.receive()
            if message["stage"] in {"ADMITTED", "REJECTED"}:
                rejected = message["stage"] == "REJECTED"
                break
            require(message["stage"] == "GRANT")
            if (
                kind in {"corrupt", "oversized"}
                and side == "before"
                and message["action"] == "INPUT_UPLOAD_FINALIZE"
                and not observed
            ):
                require(
                    stack.sql("SELECT count(*) FROM fabric_finalized_artifacts").strip() == b"0"
                )
                tamper(stack, kind == "oversized", finalized=False)
                observed = True
            owner.send({"token": operator.owner_grant(message)})
        require(rejected == (kind in {"corrupt", "oversized"} and side == "before"))
        workflow_history: dict = {
            "status": "NOT_STARTED",
            "observed": {"events": 0, "payload_max_bytes": 0},
            "retry_attempt_max": 0,
            "workflow_runs": 0,
        }
        if not rejected:
            live.phase("RECOVERY_ADMITTED")
            actual = live.provision(stack, operator, m1_assets.load())
            pending_hashes = {
                grant["token_sha256"]
                for lane in ("registry_grants", "grants", "output_grants", "receipt_grants")
                for grant in operator.policy.get(lane, [])
            }
            stack.wait(
                lambda: live.require(
                    native_status(stack, actual)
                    == {"physical_state": "CREATED", "error_code": "NONE"}
                ),
                seconds=15,
            )
            if kind in {"corrupt", "oversized"}:
                tamper(stack, kind == "oversized", finalized=True)
                observed = True
            if kind == "lost":
                start(stack, "messaging")
                stack.wait(lambda: live.broker_record(stack, 0), seconds=25)
                if side == "after":
                    stack.wait(
                        lambda: live.require(
                            stack.sql("SELECT count(*) FROM fabric_inbox WHERE handled").strip()
                            == b"1"
                        ),
                        seconds=25,
                    )
                if lock:
                    stack.wait(
                        lambda: live.require(
                            int(
                                stack.sql(
                                    "SELECT count(*) FROM pg_locks "
                                    "WHERE relation='fabric_inbox'::regclass "
                                    "AND NOT granted"
                                )
                            )
                            > 0
                        ),
                        seconds=10,
                    )
                kill(stack, "messaging")
                killed = True
                trim(stack)
                if lock:
                    lock.close()
                    lock = None
                start(stack, "messaging")
                stack.wait(
                    lambda: live.require(
                        stack.sql("SELECT count(*) FROM fabric_inbox WHERE handled").strip() == b"1"
                    ),
                    seconds=25,
                )
                observed = True
            live.phase("RECOVERY_PROVISIONED")
            first = notices(stack)[0]
            records = [first]
            if kind == "duplicate" and side == "before":
                replay(stack, [first])
                first_wire, _ = live.broker_record(stack, 0)
                second_wire, _ = live.broker_record(stack, 1)
                require(first_wire == second_wire == first)
                records = [first_wire, second_wire]
            if kind == "duplicate":
                refresh_unspent(operator, pending_hashes)
                duplicate_execution(stack, operator, actual)
            refresh_unspent(operator, pending_hashes)
            if kind == "worker" and side == "before":
                if lock is None:
                    raise ValueError("M1_RECOVERY_BARRIER")
                monitor = ThreadPoolExecutor(max_workers=1)
                pending_kill = monitor.submit(kill_at_receipt, stack, actual, lock, stopping)
            barrier_fault = kind in {"bridge", "completion"} or (
                kind == "worker" and side == "after"
            )
            if barrier_fault:
                monitor = ThreadPoolExecutor(max_workers=1)
                pending_kill = monitor.submit(
                    kill_at_barrier, stack, actual, config, stopping, worker=kind == "worker"
                )
            try:
                starts = handoff(stack, records, overlap=kind == "duplicate" and side == "before")
            except subprocess.CalledProcessError as error:
                # Killing workflow also terminates a still-running exec client.
                # Retry only after this case's monitor verifies the intended kill
                # and restarts the role; all other handoff failures propagate.
                if not barrier_fault or error.returncode != 137 or pending_kill is None:
                    raise
                pending_kill.result(timeout=20)
                starts = handoff(stack, records)

            live.phase("RECOVERY_STARTED")
            identifier = starts[0]
            require(identifier == "compute-" + actual["execution_id"][5:])
            if kind == "duplicate":
                observed = starts == [identifier, identifier] if side == "before" else True
            released = False
            exported = False
            until = time.monotonic() + 75
            while time.monotonic() < until:
                if pending_kill is not None and pending_kill.done() and not killed:
                    if barrier_fault:
                        state = pending_kill.result()
                        if state is not None:
                            state_at_fault = state
                        live.phase("RECOVERY_KILLED")
                    else:
                        state_at_fault = finish_worker_kill(pending_kill)
                        if lock is None:
                            raise ValueError("M1_RECOVERY_BARRIER")
                        lock.close()
                        lock = None
                        live.phase("RECOVERY_KILLED_RUNNING_WORKER")
                    killed = observed = True
                if not exported:
                    try:
                        export_candidate(stack, actual)
                        exported = True
                    except subprocess.SubprocessError:
                        pass
                if barrier_fault and not killed:
                    # History executes in the role being killed. Wait for the
                    # verified restart before reading it; export can continue.
                    stopping.wait(0.02)
                    continue
                workflow_history = history(stack, identifier)
                if workflow_history["status"] in {"COMPLETED", "FAILED"}:
                    if pending_kill is not None and not killed:
                        # SIGKILL can make Ray/Temporal terminal before Docker's
                        # exit-state inspection has completed in the monitor.
                        state_at_fault = finish_worker_kill(pending_kill)
                        killed = observed = True
                        if lock is None:
                            raise ValueError("M1_RECOVERY_BARRIER")
                        lock.close()
                        lock = None
                        live.phase("RECOVERY_KILLED_RUNNING_WORKER")
                    released = workflow_history["status"] == "COMPLETED"
                    break
                time.sleep(0.2)
            require(workflow_history["status"] in {"COMPLETED", "FAILED"})
            if kind in {"duplicate", "reordered"} and (kind == "reordered" or side == "after"):
                records = notices(stack)
                require(len(records) == 2)
                ordered = list(reversed(records)) if kind == "reordered" else [records[0]]
                live.broker_record(stack, 1)  # Wait for both original records before replay.
                replay(stack, ordered)
                received = [live.broker_record(stack, 2 + n)[0] for n in range(len(ordered))]
                require(received == ordered)
                require(
                    handoff(stack, received, overlap=side == "before")
                    == ([None, identifier] if kind == "reordered" else [identifier])
                )
                observed = True
            if released:
                # PR33 independently opens real results in the canonical full gate.
                require(
                    stack.sql("SELECT count(*) FROM fabric_disclosure_decisions").strip() == b"1"
                )
            owner.send({"audit_only": True})
            if kind != "worker":
                state_at_fault = native_status(stack, actual)
        outcome = (
            "REJECTED"
            if rejected
            else "RELEASED"
            if workflow_history["status"] == "COMPLETED"
            else "FAILED"
        )
        require(observed)
        live.phase("RECOVERY_TERMINAL:" + workflow_history["status"])
        snapshot = objects(stack)
        rows = json.loads(
            stack.sql("""
            SELECT json_build_object(
              'executions',(SELECT count(*) FROM fabric_executions),
              'receipts',(SELECT count(*) FROM fabric_execution_receipts),
              'selections',(SELECT count(*) FROM fabric_selected_results),
              'disclosures',(SELECT count(*) FROM fabric_disclosure_decisions),
              'current_selections',(SELECT count(*) FROM fabric_selected_results s
                JOIN fabric_executions e USING(tenant_scope,operation_id,execution_id)
                JOIN fabric_attempts a USING(tenant_scope,operation_id,attempt_epoch)
                WHERE NOT a.retired),
              'execution_ids',(SELECT COALESCE(json_agg(execution_id ORDER BY execution_id),'[]')
                FROM fabric_executions),
              'output_uploads',(SELECT count(*) FROM fabric_execution_output_uploads),
              'distinct_output_uploads',(SELECT count(DISTINCT upload_id)
                FROM fabric_execution_output_uploads),
              'finalized_outputs',(SELECT count(*) FROM fabric_execution_output_uploads
                JOIN fabric_finalized_artifacts USING(upload_id)),
              'pins_checked',(SELECT count(*) FROM fabric_artifact_pins
                WHERE expires_unix_ms > extract(epoch FROM clock_timestamp())*1000))
        """)
        )
        live.phase("RECOVERY_OBJECTS_CHECKED")
        images = audit(stack, owner, operator, workflow_history)
        engine_config = installed_engine_config(stack.env["M1_ENGINE_IMAGE"], images["engine"])
        require(engine_config == m1_assets.load()["permissions"]["image_sha256"])
        value = {
            "engine_config_sha256": engine_config,
            "case": case,
            "native_state": state_at_fault["physical_state"],
            "native_error": state_at_fault["error_code"],
            "boundary_observed": observed,
            "process_killed": killed,
            "outcome": outcome,
            "workflow_status": workflow_history["status"],
            **rows,
            "immutable_objects_checked": snapshot["immutable"],
            "staging_objects_checked": snapshot["staging"],
            "object_inventory_sha256": snapshot["sha256"],
            "retry_attempt_max": workflow_history["retry_attempt_max"],
            "workflow_runs": workflow_history["workflow_runs"],
            "history_events": workflow_history["observed"]["events"],
            "history_payload_max_bytes": workflow_history["observed"]["payload_max_bytes"],
            "logs_clean": True,
            "images": images,
        }
        return validate_case(value)
    finally:
        stopping.set()
        if monitor is not None:
            monitor.shutdown(wait=True, cancel_futures=True)
        if lock:
            lock.close()
        try:
            if owner:
                owner.close()
        finally:
            stack.close()


def campaign(cases=CASES):
    require(len(set(cases)) == len(cases) and set(cases) <= set(CASES))
    locked = m1_assets.load()
    m1_assets.verify(locked)
    report: dict = {
        "schema_version": "platform-m1-recovery-v1",
        "assurance": "CONFIDENTIALITY_ONLY",
        "release_manifests": {
            role: value["assets"]["manifest.json"]["sha256"]
            for role, value in locked["components"].items()
        },
        "qualified": False,
        "platform_source": subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=m1.ROOT, text=True
        ).strip(),
        "harness_sha256": harness_digest(),
        "lock_sha256": hashlib.sha256((m1.ROOT / "config/m1.lock.json").read_bytes()).hexdigest(),
        "requested_cases": list(cases),
        "cases": [],
    }
    (m1.ROOT / "build/m1-recovery-report.json").write_bytes(live.canonical(report) + b"\n")
    workers = int(os.environ.get("KRYVOLA_M1_RECOVERY_WORKERS", "1"))
    require(workers in (1, 2))
    if workers == 2:
        info = json.loads(live.capture(["docker", "info", "--format", "{{json .}}"], 128 << 10))
        require(info["MemTotal"] >= 16 << 30 and info["NCPU"] >= 4)

    def execute(case):
        print("M1_RECOVERY:START:" + case, flush=True)
        value = run_case(case)
        print("M1_RECOVERY:COMPLETE:" + case + ":" + value["outcome"], flush=True)
        return value

    def append(value):
        report["cases"].append(value)
        (m1.ROOT / "build/m1-recovery-report.json").write_bytes(live.canonical(report) + b"\n")

    append(execute(cases[0]))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        for value in pool.map(execute, cases[1:], buffersize=workers):
            append(value)
    report["qualified"] = set(cases) == set(CASES)
    validate_report(report, cases)
    (m1.ROOT / "build/m1-recovery-report.json").write_bytes(live.canonical(report) + b"\n")
    return report


def trim(stack):
    """Remove the real notification from Kafka, not just from a test variable."""
    container = stack.compose("ps", "-q", "broker").decode().strip()
    args = [
        "docker",
        "exec",
        container,
        "rpk",
        "topic",
        "trim-prefix",
        "m1-events",
        "--offset",
        "1",
        "--no-confirm",
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
    ]
    subprocess.run(args, capture_output=True, check=True, timeout=20)


def duplicate_execution(stack, operator, actual):
    """Actually evaluate a separately registered physical execution before selection."""
    extra = actual["execution_id"] + "-duplicate"
    operation = operator.prepared["operation"]
    namespace = (
        stack.execute(
            "workflow",
            "python",
            "-c",
            (
                "import json,sys;from kryvola_fabric.ray_worker import namespace;v=json.load("
                "sys.stdin);print(namespace(v['attempt'],v['execution_id']))"
            ),
            payload=live.canonical({"attempt": actual["attempt"], "execution_id": extra}),
        )
        .decode()
        .strip()
    )
    original = json.loads(
        stack.execute(
            "engine",
            "python3",
            "-c",
            (
                "import sys;from pathlib import Path;sys.stdout.buffer.write((Path('/run/exec"
                "ution')/sys.argv[1]/'assignment.json').read_bytes())"
            ),
            actual["namespace"],
        )
    )
    raw = stack.execute(
        "workflow",
        "python",
        "-c",
        (
            "import json,sys;from kryvola_fabric.control import decode_control,encode_con"
            "trol;v=json.load(sys.stdin);r=decode_control('ExecuteRequest',bytes.fromhex("
            "v['raw']));r['execution']['execution_id']=v['id'];sys.stdout.buffer.write(en"
            "code_control('ExecuteRequest',r))"
        ),
        payload=live.canonical({"raw": original["execute_protobuf_hex"], "id": extra}),
    )
    exact = {"attempt": actual["attempt"], "execution_id": extra}
    reads = []
    for reservation, manifest in zip(
        operator.prepared["reservations"], operator.prepared["manifests"], strict=True
    ):
        scope = {
            "schema_version": "1",
            "attempt": actual["attempt"],
            "purpose": "COMPUTE_READ",
            "manifest_digest": reservation["manifest_digest"],
        }
        reads.append(
            [
                operator.grant("grants", {"scope": scope}, "worker")
                for _ in range(1 + len(manifest["ordered_chunk_entries"]))
            ]
        )
    receipt = json.loads((stack.folder / "secrets/release.json").read_bytes())["receipt"]
    original["credentials"] = {
        "reads": reads,
        "output": operator.grant("output_grants", exact, "worker"),
        "receipt": operator.grant("receipt_grants", {**exact, **receipt}, "worker"),
    }
    original["execute_protobuf_hex"] = raw.hex()
    original["receipt_key"] = "/run/execution/" + namespace + "/receipt.pk8"
    operator.save()
    stack.execute(
        "engine",
        "python3",
        "-c",
        r"""
import json, sys
from pathlib import Path

v = json.load(sys.stdin)
root = Path("/run/execution") / v["namespace"]
root.mkdir(mode=0o700)
for name, data in [
    ("assignment.json", json.dumps(v["assignment"]).encode()),
    ("execute.pb", bytes.fromhex(v["assignment"]["execute_protobuf_hex"])),
    ("receipt.pk8", (Path("/run/execution") / v["original"] / "receipt.pk8").read_bytes()),
]:
    p = root / name
    p.write_bytes(data)
    p.chmod(0o600)
""",
        payload=live.canonical(
            {"namespace": namespace, "original": actual["namespace"], "assignment": original}
        ),
    )
    stack.compose(
        "exec", "-d", "engine", "/opt/kryvola/kryvola-cpu-engine", "/run/execution/" + namespace
    )
    stack.execute(
        "workflow",
        "python",
        "-c",
        r"""
import asyncio, importlib.util, json, sys
from pathlib import Path
from kryvola_fabric.compute_activities import Registry, ComputeActivities

v = json.load(sys.stdin)
spec = importlib.util.spec_from_file_location("fixture", "/opt/m1/service.py")
s = importlib.util.module_from_spec(spec)
spec.loader.exec_module(s)


def token(action, scope):
    return json.loads(Path("/run/m1-secrets/tokens.json").read_bytes())[action]


r = Registry("runtime", 8443, s.tls("workflow"), "spiffe://m1.test/runtime", token)
identity = {k: v["attempt"][k] for k in ("tenant_scope", "operation_id")}
p = asyncio.run(ComputeActivities(r, None).prepare({**identity, "attempt_epoch": "1"}))
assert p["state"] == "READY" and p["attempt"] == v["attempt"]
r.call(
    "REGISTER",
    "POST",
    "/v1/executions/register",
    v["attempt"],
    {
        "schema_version": "1",
        "attempt": v["attempt"],
        "execution_id": v["id"],
        "plan_digest": v["operation"]["plan_ref"]["plan_digest"],
        "policy_digest": v["operation"]["policy_digest"],
    },
)
""",
        payload=live.canonical({"attempt": actual["attempt"], "id": extra, "operation": operation}),
    )
    stack.execute(
        "workflow",
        "python",
        "-c",
        r"""
import json, sys
from kryvola_fabric.ray_dispatch import execution_envelope, local_jobs, ENTRYPOINT
from kryvola_fabric.ray_worker import canonical

v = json.load(sys.stdin)
e = execution_envelope(v["operation"], v["attempt"], v["id"])
body = {
    "submission_id": e["namespace"],
    "entrypoint": ENTRYPOINT,
    "runtime_env": {"env_vars": {"KRYVOLA_EXECUTION": canonical(e)}},
}
reply = local_jobs()("POST", "/api/jobs/", body)
assert reply["submission_id"] == e["namespace"]
""",
        payload=live.canonical({"operation": operation, "attempt": actual["attempt"], "id": extra}),
    )

    def completed():
        job = json.loads(
            stack.execute(
                "workflow",
                "python",
                "-c",
                (
                    "import json,sys;from kryvola_fabric.ray_dispatch import local_jobs;print(jso"
                    "n.dumps(local_jobs()('GET','/api/jobs/'+sys.argv[1],None)))"
                ),
                namespace,
            )
        )
        require(job["status"] == "SUCCEEDED")
        # Read the actual atomically published Ray candidate, not a fabricated ref.
        value = json.loads(
            stack.execute(
                "ray",
                "python",
                "-c",
                (
                    "import sys;from pathlib import Path;from kryvola_fabric.ray_worker import re"
                    "ad_bounded;sys.stdout.buffer.write(read_bounded(Path('/run/kryvola/ray')/sys"
                    ".argv[1]/'candidate.json',1536))"
                ),
                namespace,
            )
        )
        require(value["execution_id"] == extra and value["attempt"] == actual["attempt"])

    stack.wait(completed, seconds=25)


GROUPS = {
    "notifications": ("duplicate", "lost"),
    "dispatch": ("bridge", "worker"),
    "durability": ("completion", "reordered"),
    "artifacts": ("corrupt", "oversized"),
}


def harness_digest():
    paths = (
        "tools/m1_recovery.py",
        "tools/m1_inference.py",
        "tools/m1_history.py",
        "config/m1/service.py",
        "config/m1/owner_inference.py",
        "compose.m1.yaml",
    )
    return hashlib.sha256(
        live.canonical({p: hashlib.sha256((m1.ROOT / p).read_bytes()).hexdigest() for p in paths})
    ).hexdigest()


def validate_report(report, expected=CASES):
    try:
        require(
            set(report)
            == {
                "schema_version",
                "assurance",
                "qualified",
                "platform_source",
                "harness_sha256",
                "lock_sha256",
                "release_manifests",
                "requested_cases",
                "cases",
            }
        )
        require(report["schema_version"] == "platform-m1-recovery-v1")
        require(report["assurance"] == "CONFIDENTIALITY_ONLY")
        require(bool(expected) and set(expected) <= set(CASES))
        require(report["requested_cases"] == list(expected))
        require(report["qualified"] is (set(expected) == set(CASES)))
        require(
            report["platform_source"]
            == subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=m1.ROOT, text=True).strip()
        )
        require(report["harness_sha256"] == harness_digest())
        require(
            report["lock_sha256"]
            == hashlib.sha256((m1.ROOT / "config/m1.lock.json").read_bytes()).hexdigest()
        )
        locked = m1_assets.load()
        require(
            report["release_manifests"]
            == {
                role: v["assets"]["manifest.json"]["sha256"]
                for role, v in locked["components"].items()
            }
        )
        require([v["case"] for v in report["cases"]] == list(expected))
        roles = {
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
        }
        fields = {
            "case",
            "boundary_observed",
            "process_killed",
            "outcome",
            "workflow_status",
            "executions",
            "receipts",
            "selections",
            "disclosures",
            "current_selections",
            "execution_ids",
            "pins_checked",
            "immutable_objects_checked",
            "staging_objects_checked",
            "object_inventory_sha256",
            "history_events",
            "history_payload_max_bytes",
            "retry_attempt_max",
            "workflow_runs",
            "logs_clean",
            "images",
            "engine_config_sha256",
            "native_state",
            "native_error",
            "output_uploads",
            "distinct_output_uploads",
            "finalized_outputs",
        }
        for case in report["cases"]:
            require(set(case) == fields)
            validate_case(case)
            require(case["engine_config_sha256"] == locked["permissions"]["image_sha256"])
            require(re.fullmatch(r"[a-f0-9]{64}", case["object_inventory_sha256"]))
            require(set(case["images"]) == roles)
            require(
                all(
                    re.fullmatch(r"sha256:[a-f0-9]{64}", digest)
                    for digest in case["images"].values()
                )
            )
        require(len(live.canonical(report)) <= 1 << 20)
        return report
    except KeyError, TypeError, ValueError:
        raise ValueError("M1_RECOVERY_REPORT") from None


def verify_segments(folder):
    combined = None
    gathered = {}
    for group, kinds in GROUPS.items():
        path = folder / ("m1-recovery-" + group) / "m1-recovery-report.json"
        require(path.is_file() and not path.is_symlink() and path.stat().st_size <= 1 << 20)
        report = validate_report(
            json.loads(path.read_bytes()), tuple(c for c in CASES if c.split("-")[0] in kinds)
        )
        if combined is None:
            combined = dict(report)
        for case in report["cases"]:
            require(case["case"] not in gathered)
            gathered[case["case"]] = case
    require(set(gathered) == set(CASES) and combined is not None)
    if combined is None:
        raise ValueError("M1_RECOVERY_REPORT")
    combined.update(qualified=True, requested_cases=list(CASES), cases=[gathered[c] for c in CASES])
    return validate_report(combined)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verify-segments", type=Path)
    args = parser.parse_args()
    result = verify_segments(args.verify_segments) if args.verify_segments else campaign()
    print(live.canonical(result).decode())
