"""Measured fresh-service/warm-service pairs; no supported-envelope or SLO verdict.

Run: uv run --locked python -m tools.m1_campaign --pairs 2
Each bounded pair uses fresh keys twice and stays within the existing tenant quota.
Cold means fresh verified service processes, not a flushed OS/image cache. Request
latency excludes setup, audits and telemetry; campaign throughput includes them.
Memory is container-lifetime cgroup v2 peak usage, not a per-request allocation.
"""

import argparse
import hashlib
import os
import platform
import re
import secrets
import subprocess
import time

from kryvola_platform.benchmark import quantiles

from . import m1, m1_assets
from . import m1_inference as inference

STAGES = ("owner_prepare", "admission", "provision", "dispatch_release", "owner_open")
STATES = ("COLD", "WARM_SERVICES")


def validate_sample(row):
    inference.require(row["cache_state"] in STATES and row["outcome"] == "SUCCEEDED")
    inference.require(
        row["key_context_state"] == "FRESH" and row["engine_key_cache"] == "UNOBSERVED"
    )
    metrics = row["measurements"]
    inference.require(
        set(metrics)
        == {
            "stages_ns",
            "request_ns",
            "audit_ns",
            "input_bytes",
            "output_bytes",
            "key_context_digest",
            "plan_digest",
            "profile",
        }
    )
    inference.require(set(metrics["stages_ns"]) == set(STAGES) and metrics["profile"] == "FHE-Q1")
    for digest in (metrics["key_context_digest"], metrics["plan_digest"]):
        inference.require(re.fullmatch("[0-9a-f]{64}", digest))
    for value in list(metrics["stages_ns"].values()) + [
        metrics[k] for k in ("request_ns", "audit_ns", "input_bytes", "output_bytes")
    ]:
        inference.require(type(value) is int and value > 0)
    inference.require(sum(metrics["stages_ns"].values()) == metrics["request_ns"])
    inference.require(set(row["memory_peak_bytes"]) == {"owner", "engine", "ray"})
    inference.require(all(type(n) is int and n > 0 for n in row["memory_peak_bytes"].values()))
    inference.validate_report(row["qualification"], m1_assets.load())


def processes(stack):
    identifiers = stack.compose("ps", "-q").decode().split()
    inference.require(len(identifiers) == 12)
    raw = inference.capture(
        ["docker", "inspect", "--format", "{{.Id}} {{.State.StartedAt}}", *identifiers], 8192
    )
    return sorted(raw.splitlines())


def measure(stack, state):
    observations = []
    report = inference.qualify(
        stack=stack, request_id=secrets.token_hex(8), observer=observations.append
    )
    inference.require(len(observations) == 1)
    digest = report["execution"]["output_manifest_digest"]
    observations[0]["output_bytes"] = int(
        stack.sql(
            "SELECT convert_from(canonical_manifest,'UTF8')::json->>'serialized_bytes' "
            "FROM fabric_finalized_artifacts WHERE manifest_digest='" + digest + "'"
        ).strip()
    )
    row = {
        "cache_state": state,
        "outcome": "SUCCEEDED",
        "measurements": observations[0],
        "qualification": report,
        "key_context_state": "FRESH",
        "engine_key_cache": "UNOBSERVED",
        "memory_peak_bytes": {
            role: int(stack.execute(role, "cat", "/sys/fs/cgroup/memory.peak").strip())
            for role in ("owner", "engine", "ray")
        },
    }
    validate_sample(row)
    return row


def run_pair():
    stack = m1.Stack("kryvola-m1-" + secrets.token_hex(6))
    rows: list[dict] = []
    started = time.monotonic_ns()
    try:
        stack.start()
        stack.verify()
        setup_ns = time.monotonic_ns() - started
        before = processes(stack)
        for state in STATES:
            inference.require(processes(stack) == before)
            row = measure(stack, state)
            inference.require(processes(stack) == before)
            row["fixture_setup_ns"] = setup_ns
            if rows:
                inference.require(
                    row["measurements"]["key_context_digest"]
                    != rows[0]["measurements"]["key_context_digest"]
                )
                inference.require(
                    row["qualification"]["execution"] != rows[0]["qualification"]["execution"]
                )
            rows.append(row)
    except Exception as error:
        rows.append(
            {
                "cache_state": STATES[len(rows)],
                "outcome": "FAILED",
                "error_type": type(error).__name__,
            }
        )
        if len(rows) == 1:
            rows.append({"cache_state": "WARM_SERVICES", "outcome": "NOT_RUN"})
    finally:
        stack.close()
    return rows


def summarize(rows, elapsed_ns):
    inference.require(type(elapsed_ns) is int and elapsed_ns > 0 and rows)
    binding = None
    for row in rows:
        inference.require(
            row["cache_state"] in STATES and row["outcome"] in {"SUCCEEDED", "FAILED", "NOT_RUN"}
        )
        if row["outcome"] != "SUCCEEDED":
            continue
        validate_sample(row)
        report = row["qualification"]
        observed = [
            report[k]
            for k in ("release_manifests", "engine_config_sha256", "frozen_reference_sha256")
        ]
        inference.require(binding is None or observed == binding)
        binding = observed
    result = {}
    for state in STATES:
        selected = [r for r in rows if r["cache_state"] == state]
        good = [r for r in selected if r["outcome"] == "SUCCEEDED"]
        result[state] = {
            "requested": len(selected),
            "successful": len(good),
            "failed": sum(r["outcome"] == "FAILED" for r in selected),
            "not_run": sum(r["outcome"] == "NOT_RUN" for r in selected),
            "request_ns": quantiles([r["measurements"]["request_ns"] for r in good]),
            "stages_ns": {
                s: quantiles([r["measurements"]["stages_ns"][s] for r in good]) for s in STAGES
            },
            "serial_campaign_throughput_microrequests_s": len(good) * 10**15 // elapsed_ns,
        }
    return result


def source_identity():
    return {
        "source": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=m1.ROOT)
        .decode()
        .strip(),
        "source_tree_clean": not subprocess.check_output(
            ["git", "status", "--porcelain"], cwd=m1.ROOT
        ),
        "harness_sha256": {
            p: hashlib.sha256((m1.ROOT / p).read_bytes()).hexdigest()
            for p in (
                "tools/m1_campaign.py",
                "tools/m1_inference.py",
                "config/m1/owner_inference.py",
                "config/m1.lock.json",
                "config/m1/service.py",
                "compose.m1.yaml",
            )
        },
    }


def campaign(pairs):
    inference.require(type(pairs) is int and 1 <= pairs <= 20)
    identity = source_identity()
    inference.require(identity["source_tree_clean"], "M1_CAMPAIGN_DIRTY_SOURCE")
    started = time.monotonic_ns()
    rows = [row for _ in range(pairs) for row in run_pair()]
    elapsed = time.monotonic_ns() - started
    inference.require(source_identity() == identity, "M1_CAMPAIGN_SOURCE_CHANGED")
    return {
        "schema_version": "platform-m1-campaign-v1",
        "assurance": "CONFIDENTIALITY_ONLY",
        **identity,
        "host": {
            "machine": platform.machine(),
            "kernel": platform.release(),
            "logical_cpus": os.cpu_count(),
            "python": platform.python_version(),
        },
        "memory_scope": "container_lifetime_cgroup_v2_peak_bytes",
        "timing_scope": "monotonic_request_excludes_setup_audit_telemetry;throughput_includes_all",
        "os_image_cache": "UNCONTROLLED",
        "pairs": pairs,
        "campaign_wall_ns": elapsed,
        "observations": rows,
        "summary": summarize(rows, elapsed),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pairs", type=int, choices=range(1, 21), default=2)
    args = parser.parse_args()
    report = campaign(args.pairs)
    path = m1.ROOT / "build" / ("m1-campaign-" + secrets.token_hex(6) + ".json")
    path.write_bytes(inference.canonical(report) + b"\n")
    print(path)
    if any(r["outcome"] != "SUCCEEDED" for r in report["observations"]):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
