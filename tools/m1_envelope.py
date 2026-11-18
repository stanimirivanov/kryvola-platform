"""Publish/check a narrow local envelope; report validity is not an SLO pass."""

import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path

from kryvola_platform.benchmark import _unique

from . import m1_campaign as c
from .m1_inference import canonical, require

OBJECTIVES = {"COLD": 15_000_000_000, "WARM_SERVICES": 5_000_000_000}


def source(raw):
    require(raw["source_tree_clean"] is True and re.fullmatch("[0-9a-f]{40}", raw["source"]))
    require(raw["source"] != "0" * 40)
    require(raw["harness_sha256"] == c.source_identity()["harness_sha256"])
    try:
        for path, digest in raw["harness_sha256"].items():
            data = subprocess.check_output(
                ["git", "show", "HEAD:" + path], cwd=c.m1.ROOT, stderr=subprocess.PIPE
            )
            require(hashlib.sha256(data).hexdigest() == digest)
    except subprocess.CalledProcessError:
        raise ValueError("M1_ENVELOPE_SOURCE") from None


def validate(raw):
    require(
        set(raw)
        == set(
            (
                "schema_version assurance source source_tree_clean harness_sha256 host "
                "memory_scope timing_scope os_image_cache pairs campaign_wall_ns "
                "observations summary"
            ).split()
        )
    )
    require(
        raw["schema_version"] == "platform-m1-campaign-v1"
        and raw["assurance"] == "CONFIDENTIALITY_ONLY"
    )
    source(raw)
    require(raw["memory_scope"] == "container_lifetime_cgroup_v2_peak_bytes")
    require(
        raw["timing_scope"]
        == "monotonic_request_excludes_setup_audit_telemetry;throughput_includes_all"
    )
    require(raw["os_image_cache"] == "UNCONTROLLED")
    host = raw["host"]
    require(set(host) == {"machine", "kernel", "logical_cpus", "python"})
    require(type(host["logical_cpus"]) is int and 0 < host["logical_cpus"] <= 65536)
    require(
        all(
            isinstance(host[k], str) and re.fullmatch(r"[A-Za-z0-9_.+ -]{1,128}", host[k])
            for k in ("machine", "kernel", "python")
        )
    )
    require(type(raw["pairs"]) is int and 1 <= raw["pairs"] <= 20)
    rows = raw["observations"]
    require(len(rows) == 2 * raw["pairs"])
    seen, invocations, known_ns = set(), set(), 0
    limits = json.loads(c.m1.COMPOSE.read_bytes())["services"]
    for offset in range(0, len(rows), 2):
        pair, byte_count, prior = rows[offset : offset + 2], 0, None
        require(pair[0]["outcome"] != "FAILED" or pair[1]["outcome"] == "NOT_RUN")
        for state, row in zip(c.STATES, pair, strict=True):
            require(row["cache_state"] == state)
            if row["outcome"] != "SUCCEEDED":
                require(
                    set(row)
                    == (
                        {"cache_state", "outcome", "error_type"}
                        if row["outcome"] == "FAILED"
                        else {"cache_state", "outcome"}
                    )
                )
                require(row["outcome"] in {"FAILED", "NOT_RUN"})
                require(
                    row["outcome"] != "NOT_RUN"
                    or (state == "WARM_SERVICES" and pair[0]["outcome"] == "FAILED")
                )
                if row["outcome"] == "FAILED":
                    require(re.fullmatch("[A-Za-z][A-Za-z0-9_]{0,63}", row["error_type"]))
                continue
            require(pair[0]["outcome"] == "SUCCEEDED")
            require(
                set(row)
                == set(
                    (
                        "cache_state outcome measurements qualification key_context_state "
                        "engine_key_cache memory_peak_bytes fixture_setup_ns"
                    ).split()
                )
            )
            c.validate_sample(row)
            metrics, q = row["measurements"], row["qualification"]
            require(type(row["fixture_setup_ns"]) is int and row["fixture_setup_ns"] > 0)
            for key, value in {
                "key_context_digest": metrics["key_context_digest"],
                "plan_digest": metrics["plan_digest"],
                **q["execution"],
            }.items():
                require((key, value) not in seen)
                seen.add((key, value))
            if prior is None:
                require(q["invocation"] not in invocations)
                invocations.add(q["invocation"])
                known_ns += row["fixture_setup_ns"]
            else:
                require(
                    q["invocation"] == prior["qualification"]["invocation"]
                    and q["images"] == prior["qualification"]["images"]
                )
                require(row["fixture_setup_ns"] == prior["fixture_setup_ns"])
            prior = row
            known_ns += metrics["request_ns"] + metrics["audit_ns"]
            byte_count += metrics["input_bytes"] + metrics["output_bytes"]
            for role, peak in row["memory_peak_bytes"].items():
                limit = limits[role]["mem_limit"]
                require(peak <= int(limit[:-1]) * {"m": 1 << 20, "g": 1 << 30}[limit[-1]])
        require(byte_count <= 128 << 20)
    require(type(raw["campaign_wall_ns"]) is int and raw["campaign_wall_ns"] >= known_ns)
    require(canonical(raw["summary"]) == canonical(c.summarize(rows, raw["campaign_wall_ns"])))


def build(raw):
    try:
        validate(raw)
        latency, gaps = (
            {},
            ["engine_key_cache", "OS_image_cache", "native_CPU_stage_isolation", "wire_bytes"],
        )
        for state, objective in OBJECTIVES.items():
            summary = raw["summary"][state]
            q = summary["request_ns"]
            sufficient = q["descriptive_sample_sufficiency"]["p95"]
            status = (
                "INCONCLUSIVE"
                if not sufficient
                else "OBJECTIVE_MET"
                if q["values_ns"]["p95"] <= objective
                else "OBJECTIVE_MISSED"
            )
            latency[state] = {
                "objective_p95_ns": objective,
                "status": status,
                "observed_exceedances": sum(
                    r["measurements"]["request_ns"] > objective
                    for r in raw["observations"]
                    if r["cache_state"] == state and r["outcome"] == "SUCCEEDED"
                ),
            }
            if not sufficient:
                gaps.append(state + "_p95")
        return {
            "schema_version": "platform-m1-supported-envelope-v1",
            "campaign_sha256": hashlib.sha256(canonical(raw)).hexdigest(),
            "policy_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            "campaign": raw,
            "decision": "ASYNCHRONOUS_ONLY"
            if all(r["outcome"] == "SUCCEEDED" for r in raw["observations"])
            else "INCONCLUSIVE",
            "production_ready": False,
            "assurance": "CONFIDENTIALITY_ONLY",
            "computation_integrity": "UNPROVEN",
            "scope": {
                "profile": "FHE-Q1",
                "workload": "frozen_uint8_pair_circuit",
                "concurrency": 1,
                "owner_keys": "FRESH",
                "deployment": "locked_local_compose",
                "distribution": "owner_approved_development_only",
            },
            "measured": {
                "summary": raw["summary"],
                "memory_scope": raw["memory_scope"],
                "byte_scope": "serialized_artifacts",
                "stage_scope": "request_boundary_intervals",
            },
            "latency": latency,
            "inconclusive": gaps,
            "unsupported": [
                "synchronous_latency_guarantee",
                "general_ML_models",
                "cryptographic_computation_integrity",
                "remote_capacity",
            ],
            "externally_unapproved": ["production_activation"],
        }
    except KeyError, TypeError, IndexError, AttributeError:
        raise ValueError("M1_ENVELOPE_INCOMPLETE") from None


def check(report):
    require(canonical(report) == canonical(build(report["campaign"])), "M1_ENVELOPE_TAMPERED")
    require(report["decision"] == "ASYNCHRONOUS_ONLY", "M1_ENVELOPE_INCONCLUSIVE")


def read(path):
    with path.open("rb") as stream:
        raw = stream.read((1 << 20) + 1)
    require(len(raw) <= 1 << 20)
    return json.loads(raw, object_pairs_hook=_unique)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("measure", "check"))
    parser.add_argument("path", type=Path)
    parser.add_argument("--pairs", type=int, choices=range(1, 21), default=2)
    args = parser.parse_args()
    if args.mode == "measure":
        report = build(c.campaign(args.pairs))
        args.path.parent.mkdir(parents=True, exist_ok=True)
        args.path.write_bytes(canonical(report) + b"\n")
    else:
        report = read(args.path)
    check(report)
    print("M1_ENVELOPE_ASYNCHRONOUS_ONLY " + str(args.path))


if __name__ == "__main__":
    main()
