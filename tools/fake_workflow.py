"""Public fake conformance driver. No inference, registry or disclosure authority."""

import asyncio
import base64
import hashlib
import importlib.metadata
import importlib.util
import json
import re
import time
from datetime import timedelta
from importlib.resources import files

if __package__:
    from . import integration, workflow_assets
else:
    import integration
    import workflow_assets

MAX_EVENT = 8192
KIND = "PUBLIC_FAKE_ENGINE_SELFTEST"


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError("DUPLICATE_FAKE_FIELD")
        result[key] = value
    return result


def encode(value):
    raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    if len(raw) > MAX_EVENT:
        raise ValueError("FAKE_EVENT_LIMIT")
    return raw


def event(raw):
    if type(raw) is not bytes or len(raw) > MAX_EVENT:
        raise ValueError("FAKE_EVENT_LIMIT")
    value = json.loads(raw, object_pairs_hook=pairs)
    if (
        not isinstance(value, dict)
        or set(value) != {"kind", "production_ready", "request_hex", "artifact"}
        or value["kind"] != KIND
        or value["production_ready"] is not False
        or not isinstance(value["request_hex"], str)
        or re.fullmatch(r"(?:[0-9a-f]{2}){1,2048}", value["request_hex"]) is None
        or not isinstance(value["artifact"], dict)
        or set(value["artifact"]) != {"key", "version", "sha256", "byte_length"}
    ):
        raise ValueError("FAKE_EVENT_FIELDS")
    ref = value["artifact"]
    if (
        not all(
            isinstance(ref[k], str) and 1 <= len(ref[k]) <= 128
            for k in ("key", "version", "sha256")
        )
        or re.fullmatch("[0-9a-f]{64}", ref["sha256"]) is None
        or type(ref["byte_length"]) is not int
        or not 1 <= ref["byte_length"] <= 4096
    ):
        raise ValueError("FAKE_REFERENCE_FIELDS")
    return value


def bound_request(raw):
    from kryvola_fabric.control import decode_control

    value = event(raw)
    wire = bytes.fromhex(value["request_hex"])
    request = decode_control("ExecuteRequest", wire, temporal=True)
    baseline = decode_control(
        "ExecuteRequest",
        files("kryvola_fabric.conformance").joinpath("public-request.bin").read_bytes(),
        temporal=True,
    )
    # The public artifact triggers the self-test; it is not mislabelled as a ciphertext.
    if (
        request["operation"]["idempotency_key"] != sha(encode(value["artifact"]))
        or request["input_refs"] != baseline["input_refs"]
    ):
        raise ValueError("FAKE_REFERENCE_BINDING")
    return value, wire, request


def artifact(stack, key, raw):
    path = stack.folder / "data/workflow.bin"
    path.write_bytes(raw)
    result = stack.execute(
        "s3-client",
        "aws",
        "--endpoint-url",
        "http://seaweed:8333",
        "s3api",
        "put-object",
        "--bucket",
        "fixture",
        "--key",
        key,
        "--if-none-match",
        "*",
        "--body",
        "/data/workflow.bin",
    )
    version = json.loads(result.stdout)["VersionId"]
    if not isinstance(version, str) or version in {"", "null"}:
        raise ValueError("FAKE_OBJECT_VERSION")
    ref = {"key": key, "version": version, "sha256": sha(raw), "byte_length": len(raw)}
    fetch(stack, ref)
    return ref


def fetch(stack, ref):
    stack.execute(
        "s3-client",
        "aws",
        "--endpoint-url",
        "http://seaweed:8333",
        "s3api",
        "get-object",
        "--bucket",
        "fixture",
        "--key",
        ref["key"],
        "--version-id",
        ref["version"],
        "/data/workflow-read.bin",
    )
    raw = (stack.folder / "data/workflow-read.bin").read_bytes()
    if len(raw) != ref["byte_length"] or sha(raw) != ref["sha256"]:
        raise ValueError("FAKE_OBJECT_HASH")
    return raw


def request_for(ref, engine_digest):
    # Consume the pinned wheel's generated descriptor, not a handwritten wire schema.
    from google.protobuf import descriptor_pb2, descriptor_pool, message_factory

    pool = descriptor_pool.DescriptorPool()
    for file in descriptor_pb2.FileDescriptorSet.FromString(
        files("kryvola_fabric").joinpath("_spec/descriptor.bin").read_bytes()
    ).file:
        pool.Add(file)
    message = message_factory.GetMessageClass(
        pool.FindMessageTypeByName("kryvola.spec.v1.ExecuteRequest")
    )()
    message.ParseFromString(
        files("kryvola_fabric.conformance").joinpath("public-request.bin").read_bytes()
    )
    message.engine_digest = engine_digest  # ty: ignore[unresolved-attribute] - generated dynamic message
    message.operation.idempotency_key = sha(encode(ref))  # ty: ignore[unresolved-attribute] - generated dynamic message
    return message.SerializeToString()


async def traverse(stack, wire, engine_digest, trace):
    from kryvola_fabric.conformance.workflow import FixtureWorkflow
    from temporalio import activity
    from temporalio.client import Client, WorkflowExecutionStatus
    from temporalio.exceptions import ApplicationError
    from temporalio.worker import Replayer, Worker

    identifier = stack.compose("ps", "--quiet", "temporal").stdout.strip().decode()
    endpoint = integration.run(
        [
            "docker",
            "inspect",
            "--format",
            "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
            identifier,
        ]
    )
    endpoint.check_returncode()
    client = await Client.connect(endpoint.stdout.decode().strip() + ":7233", namespace="fixture")

    @activity.defn(name="fixture_execute")
    async def dispatch(payload: bytes) -> str:
        failed, receipt = False, None
        try:
            if payload != wire:
                raise ValueError("FAKE_INTENT_CHANGED")
            task = encode({"intent_digest": sha(payload), "engine_sha256": engine_digest})
            result = await asyncio.to_thread(
                stack.execute,
                "ray",
                "python",
                "/tmp/kryvola-fake/ray_worker.py",
                payload=task,
                timeout=45,
            )
            receipt = json.loads(result.stdout)
            if receipt != {
                "intent_digest": sha(wire),
                "engine_sha256": engine_digest,
                "kind": KIND,
                "production_ready": False,
                "conformance_stdout_sha256": sha(
                    b"FAKE ENGINE loopback conformance passed; "
                    b"no inference or production capability\n"
                ),
            }:
                raise ValueError("FAKE_RECEIPT_MISMATCH")
        except Exception:
            failed = True
        if failed:
            raise ApplicationError("FAKE_DISPATCH_FAILED", non_retryable=True)
        trace.append({"stage": "RAY_TO_PUBLISHED_FAKE_ENGINE", "receipt": receipt})
        return sha(payload)

    queue = stack.project + "-fake"
    async with Worker(client, task_queue=queue, workflows=[FixtureWorkflow], activities=[dispatch]):
        handle = await client.start_workflow(
            FixtureWorkflow.run,
            wire,
            id=queue,
            task_queue=queue,
            execution_timeout=timedelta(seconds=90),
        )
        async with asyncio.timeout(70):
            while not await handle.query(FixtureWorkflow.state):
                if (await handle.describe()).status != WorkflowExecutionStatus.RUNNING:
                    await handle.result()
                await asyncio.sleep(0.1)
        await handle.signal(FixtureWorkflow.observe, sha(wire))
        await handle.signal(FixtureWorkflow.finish)
        result = await handle.result()
        if result != {"intent_digest": sha(wire), "duplicates": 1, "ignored": 0}:
            raise ValueError("FAKE_WORKFLOW_RESULT")
        history = await handle.fetch_history()
    await Replayer(workflows=[FixtureWorkflow]).replay_workflow(history)
    trace.append(
        {
            "stage": "TEMPORAL_TERMINAL_AND_REPLAY",
            "workflow_id": queue,
            "run_id": handle.result_run_id,
            "result": result,
        }
    )


def smoke(stack):
    locked = workflow_assets.verify()
    expected_version = "0.1.0.dev0+g" + locked["fabric"]["source"]
    if importlib.metadata.version("kryvola-fabric") != expected_version:
        raise ValueError("INSTALLED_FABRIC_VERSION")
    engine = workflow_assets.engine()
    engine_digest = workflow_assets.digest(engine)
    ray_id = stack.compose("ps", "--quiet", "ray").stdout.decode().strip()
    stack.execute("ray", "mkdir", "-p", "/tmp/kryvola-fake")
    for source in (engine, integration.ROOT / "config/fake-workflow/ray_worker.py"):
        copied = integration.run(
            ["docker", "cp", source, ray_id + ":/tmp/kryvola-fake/"], timeout=30
        )
        copied.check_returncode()
    role = stack.execute("ray", "/tmp/kryvola-fake/engine", "--artifact-role").stdout.strip()
    if role != b"fake-evaluator":
        raise ValueError("PUBLISHED_FAKE_ROLE")
    began = time.monotonic_ns()
    ref = artifact(stack, "fake-input", encode({"kind": KIND, "case": "loopback-conformance"}))
    wire = request_for(ref, engine_digest)
    raw = encode(
        {"kind": KIND, "production_ready": False, "artifact": ref, "request_hex": wire.hex()}
    )
    bound_request(raw)
    topic = stack.project + "-fake"
    stack.execute("redpanda", "rpk", "topic", "create", topic, "-p", "1", "-r", "1")
    stack.execute("redpanda", "rpk", "topic", "produce", topic, payload=raw + b"\n")
    consumed = stack.execute(
        "redpanda", "rpk", "topic", "consume", topic, "-n", "1", "-o", "start", "-f", "%v"
    ).stdout
    if consumed.strip() != raw:
        raise ValueError("FAKE_BROKER_BYTES_CHANGED")
    value, consumed_wire, _ = bound_request(consumed.strip())
    fetch(stack, value["artifact"])
    trace = [
        {
            "stage": "REDPANDA_TO_TEMPORAL",
            "topic": topic,
            "event_sha256": sha(raw),
            "event_bytes": len(raw),
            "intent_digest": sha(wire),
        }
    ]
    asyncio.run(traverse(stack, consumed_wire, engine_digest, trace))
    output = artifact(stack, "fake-output", encode(trace[1]["receipt"]))
    trace.append({"stage": "IMMUTABLE_FAKE_OUTPUT", "artifact": output})
    report = {
        "kind": KIND,
        "production_ready": False,
        "profile_enabled": False,
        "artifact_scope": "PUBLIC_TRIGGER_AND_SELFTEST_RECEIPT_ONLY",
        "driver_commit": integration.run(["git", "-C", integration.ROOT, "rev-parse", "HEAD"])
        .stdout.decode()
        .strip(),
        "elapsed_ns": time.monotonic_ns() - began,
        "releases": locked,
        "input": ref,
        "output": output,
        "trace": trace,
    }
    evidence = base64.b64encode(encode(report)).decode()
    sql = (
        "CREATE TABLE m0_fake_runs (run_id text PRIMARY KEY, evidence jsonb NOT NULL); "
        f"INSERT INTO m0_fake_runs VALUES ('{stack.project}', "
        f"convert_from(decode('{evidence}','base64'),'UTF8')::jsonb); "
    )
    stack.execute(
        "postgres",
        "psql",
        "-v",
        "ON_ERROR_STOP=1",
        "-U",
        "temporal_fixture",
        "-d",
        "postgres",
        "-c",
        sql,
    )
    stored = stack.execute(
        "postgres",
        "psql",
        "-U",
        "temporal_fixture",
        "-d",
        "postgres",
        "-Atc",
        f"SELECT evidence::text FROM m0_fake_runs WHERE run_id='{stack.project}'",
    )
    if json.loads(stored.stdout) != report:
        raise ValueError("FAKE_SQL_EVIDENCE")
    path = stack.folder / "fake-workflow-report.json"
    with path.open("x", encoding="utf-8") as stream:
        json.dump(report, stream, sort_keys=True)
    spec = importlib.util.spec_from_file_location(
        "fake_checks", integration.ROOT / "tests/integration/test_fake_workflow.py"
    )
    if spec is None or spec.loader is None:
        raise ValueError("MISSING_FAKE_CHECKS")
    checks = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(checks)
    checks.qualify(report, raw, wire)
    stack.boundary()
    print("PUBLISHED_FAKE_WORKFLOW_TRACE_REPLAY_ARTIFACTS_SQL_PASSED")
    return report
