"""Private local experiment journal; deliberately not a qualified MeasurementReport."""

from __future__ import annotations

import hashlib
import json
import math
import os
import selectors
import signal
import subprocess
import sys
import tempfile
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from importlib.resources import files
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

SPEC = files("kryvola_platform").joinpath("_spec")
REPORT = json.loads(SPEC.joinpath("profiles/MeasurementReport.schema.json").read_bytes())
STAGES = set(REPORT["properties"]["latency_ns"]["anyOf"][0]["properties"])
LIMIT = 131_072


def _unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON field")
        result[key] = value
    return result


def decode(raw: bytes) -> Any:
    if len(raw) > LIMIT:
        raise ValueError("JSON exceeds harness limit")
    return json.loads(raw.decode("utf-8"), object_pairs_hook=_unique)


def read(path: Path) -> bytes:
    with path.open("rb") as stream:
        raw = stream.read(LIMIT + 1)
    if len(raw) > LIMIT:
        raise ValueError("input exceeds harness limit")
    return raw


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def validate(context: dict[str, Any], model: bytes, payload: bytes) -> None:
    required = {
        "hardware",
        "software",
        "cache_state",
        "input_sha256",
        "stages",
        "samples",
        "warmups",
        "concurrency",
        "timeout_seconds",
        "budget_seconds",
    }
    if set(context) != required:
        raise ValueError("missing or unknown benchmark configuration field")
    schema = json.loads(SPEC.joinpath("profiles/ModelDescriptor.schema.json").read_bytes())
    Draft202012Validator(schema).validate(decode(model))
    for field in ("hardware", "software", "cache_state"):
        Draft202012Validator(REPORT["properties"][field]).validate(context[field])
    names = [pin["name"] for pin in context["software"]]
    if len(set(names)) != len(names) or not {"benchmark-harness", "workload"} <= set(names):
        raise ValueError("unique benchmark-harness and workload software pins required")
    if len(payload) > LIMIT or context["input_sha256"] != sha(payload):
        raise ValueError("input digest mismatch or oversized input")
    stages = context["stages"]
    if (
        not isinstance(stages, list)
        or not stages
        or any(not isinstance(stage, str) or stage not in STAGES for stage in stages)
        or len(set(stages)) != len(stages)
    ):
        raise ValueError("distinct generated stage names required")
    for name, low, high in (
        ("samples", 1, 1000),
        ("warmups", 0, 100),
        ("concurrency", 1, 8),
        ("timeout_seconds", 1, 300),
        ("budget_seconds", 1, 600),
    ):
        if type(context[name]) is not int or not low <= context[name] <= high:
            raise ValueError(f"invalid bounded setting: {name}")


def quantiles(values: list[int]) -> dict[str, Any]:
    ordered = sorted(values)
    return {
        "samples": len(ordered),
        "method": "nearest-rank",
        "values_ns": {
            f"p{p}": ordered[math.ceil(p * len(ordered) / 100) - 1] if ordered else None
            for p in (50, 95, 99)
        },
        "descriptive_sample_sufficiency": {
            f"p{p}": len(ordered) >= n for p, n in ((50, 2), (95, 20), (99, 100))
        },
    }


def summarize(rows: list[dict[str, Any]], elapsed_ns: int, stages: list[str]) -> dict[str, Any]:
    if elapsed_ns <= 0 or not rows:
        raise ValueError("positive measured window and observations required")
    counts = Counter(row["outcome"] for row in rows)
    successes = counts["SUCCEEDED"]
    return {
        "requested": len(rows),
        "successful": successes,
        "failed": len(rows) - successes,
        "outcomes": dict(sorted(counts.items())),
        "measured_window_ns": elapsed_ns,
        "throughput_microrequests_per_second": successes * 10**15 // elapsed_ns,
        "local_submit_to_finish": quantiles([r["local_elapsed_ns"] for r in rows]),
        "local_queue": quantiles([r["queue_ns"] for r in rows]),
        "process_elapsed": quantiles(
            [r["process_ns"] for r in rows if r["process_ns"] is not None]
        ),
        "successful_worker_stages": {
            s: quantiles([r["stages_ns"][s] for r in rows if r["outcome"] == "SUCCEEDED"])
            for s in stages
        },
    }


def _kill(child: subprocess.Popen[bytes]) -> None:
    if sys.platform == "linux":
        try:
            os.killpg(child.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    child.wait()


def _execute(command: list[str], payload: bytes, deadline: int) -> tuple[str, bytes, int | None]:
    """Linux pipes: bounded output, no shell, and cleanup of the owned process group."""
    output = bytearray()
    with tempfile.TemporaryFile() as source, tempfile.TemporaryDirectory() as directory:
        source.write(payload)
        source.seek(0)
        child = subprocess.Popen(
            command,
            stdin=source,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            cwd=directory,
            start_new_session=True,
            env={"PATH": os.defpath, "HOME": directory, "TMPDIR": directory},
        )
        try:
            assert child.stdout is not None
            os.set_blocking(child.stdout.fileno(), False)
            with selectors.DefaultSelector() as selector:
                selector.register(child.stdout, selectors.EVENT_READ)
                eof, exited = False, False
                while True:
                    if time.monotonic_ns() >= deadline:
                        return "TIMEOUT", b"", None
                    for _key, _event in selector.select(0.01):
                        chunk = os.read(child.stdout.fileno(), 4096)
                        output.extend(chunk)
                        if len(output) > 65_536:
                            return "OUTPUT_LIMIT", b"", None
                        if not chunk:
                            selector.unregister(child.stdout)
                            eof = True
                    code = child.poll()
                    if code is not None and not exited:
                        # Descendants must not keep the inherited pipe open indefinitely.
                        _kill(child)
                        exited = True
                    if code is not None and eof:
                        return "EXIT_FAILED" if code else "SUCCEEDED", bytes(output), code
        finally:
            _kill(child)
            if child.stdout is not None:
                child.stdout.close()


def _attempt(
    command: list[str],
    payload: bytes,
    config: dict[str, Any],
    index: int,
    submitted: int,
    deadline: int,
) -> dict[str, Any]:
    start = time.monotonic_ns()
    outcome, telemetry, code, duration, stages = "NOT_STARTED_BUDGET", b"", None, None, None
    if start < deadline:
        try:
            outcome, telemetry, code = _execute(
                command, payload, min(deadline, start + config["timeout_seconds"] * 10**9)
            )
        except OSError:
            outcome = "LAUNCH_FAILED"
        duration = time.monotonic_ns() - start
        if outcome in {"SUCCEEDED", "EXIT_FAILED"}:
            try:
                record = decode(telemetry)
                if not isinstance(record, dict) or set(record) != {"stages_ns"}:
                    raise ValueError("invalid telemetry")
                stages = record["stages_ns"]
                if (
                    not isinstance(stages, dict)
                    or not set(stages) <= set(config["stages"])
                    or any(type(v) is not int or not 0 <= v <= duration for v in stages.values())
                    or (outcome == "SUCCEEDED" and set(stages) != set(config["stages"]))
                ):
                    raise ValueError("invalid or incomplete stage timings")
            except ValueError, TypeError, RecursionError:
                stages = None
                if outcome == "SUCCEEDED":
                    outcome = "INVALID_TELEMETRY"
    return {
        "index": index,
        "outcome": outcome,
        "exit_code": code,
        "queue_ns": start - submitted,
        "process_ns": duration,
        "local_elapsed_ns": time.monotonic_ns() - submitted,
        "stages_ns": stages,
    }


def run(
    context: dict[str, Any], model: bytes, payload: bytes, command: list[str], destination: Path
) -> dict[str, Any]:
    validate(context, model, payload)
    if sys.platform != "linux":
        raise ValueError("workload execution requires Linux process-group and pipe supervision")
    if (
        not isinstance(command, list)
        or not command
        or len(command) > 64
        or any(not isinstance(arg, str) or len(arg) > 4096 or "\x00" in arg for arg in command)
    ):
        raise ValueError("bounded public argument array required")
    executable = Path(command[0])
    if not executable.is_absolute() or not executable.is_file():
        raise ValueError("absolute executable path required")
    with executable.open("rb") as stream:
        executable_sha = hashlib.file_digest(stream, "sha256").hexdigest()
    destination.mkdir(exist_ok=False)
    provenance = json.loads(SPEC.joinpath("manifest.json").read_bytes())
    archive = {
        "kind": "local-benchmark-journal-v1",
        "context": context,
        "command": command,
        "executable_sha256": executable_sha,
        "model_descriptor_sha256": sha(model),
        "spec_contract_version": provenance["contract_version"],
        "spec_manifest_sha256": sha(SPEC.joinpath("manifest.json").read_bytes()),
    }
    (destination / "context.json").write_text(json.dumps(archive, indent=2) + "\n")
    (destination / "model.json").write_bytes(model)
    deadline = time.monotonic_ns() + context["budget_seconds"] * 10**9
    summaries = {}
    with (destination / "observations.jsonl").open("x", encoding="utf-8") as journal:
        for phase, count in (("warmup", context["warmups"]), ("measured", context["samples"])):
            start = time.monotonic_ns()
            rows = []
            with ThreadPoolExecutor(max_workers=context["concurrency"]) as pool:
                pending = [
                    pool.submit(
                        _attempt, command, payload, context, i, time.monotonic_ns(), deadline
                    )
                    for i in range(count)
                ]
                for future in as_completed(pending):
                    row = future.result()
                    rows.append(row)
                    journal.write(json.dumps({"phase": phase, **row}) + "\n")
                    journal.flush()
            elapsed = time.monotonic_ns() - start
            summaries[phase] = summarize(rows, elapsed, context["stages"]) if rows else None
    (destination / "summary.json").write_text(json.dumps(summaries, indent=2) + "\n")
    return summaries
