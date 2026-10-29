"""Source-bound numeric research campaign import; never runs/distributes crypto here."""

import base64
import json
import re
import subprocess
import tempfile
from fractions import Fraction
from pathlib import Path
from uuid import uuid4

from kryvola_platform.benchmark import decode, quantiles, sha

ROOT = Path(__file__).resolve().parents[1]
EXPERIMENTS = {"tfhe-eval", "tfhe-compact", "proof-modes"}
EVAL_STAGES = {
    "dispatch",
    "encrypt_encode",
    "key_expand",
    "keygen",
    "native_decode",
    "native_encode",
    "owner_decode_decrypt",
    "owner_total",
}
COMPACT_STAGES = {
    "setup",
    "crs",
    "native_encrypt_encode",
    "compact_encrypt",
    "prove",
    "verify",
    "unproven_expand",
    "verified_expand",
    "key_expand",
    "owner_decrypt",
    "owner_total",
}


def read(path, maximum=131072):
    if path.is_symlink() or not path.is_file() or path.stat().st_size > maximum:
        raise ValueError("CAMPAIGN_FILE_LIMIT")
    return path.read_bytes()


def profile(path):
    value = decode(read(path))
    if (
        set(value)
        != {
            "schema_version",
            "kind",
            "repository",
            "source",
            "run_id",
            "attempts",
            "source_files",
            "fixture_source",
            "fixture_manifest_sha256",
            "observations",
            "required_unmeasured_stages",
            "production_qualified",
        }
        or type(value["schema_version"]) is not int
        or value["schema_version"] != 1
        or value["kind"] != "FHE_Q1_RESEARCH_CAMPAIGNS"
        or value["repository"] != "stanimirivanov/kryvola-engines"
        or not re.fullmatch("[a-f0-9]{40}", value["source"])
        or type(value["run_id"]) is not int
        or value["run_id"] <= 0
        or len(value["attempts"]) != 2
        or len(set(value["attempts"])) != 2
        or any(type(a) is not int or a < 1 for a in value["attempts"])
        or value["production_qualified"] is not False
    ):
        raise ValueError("CAMPAIGN_PROFILE")
    if (
        not re.fullmatch("[a-f0-9]{40}", value["fixture_source"])
        or not re.fullmatch("[a-f0-9]{64}", value["fixture_manifest_sha256"])
        or value["required_unmeasured_stages"]
        != [
            "key_upload",
            "authorized_key_cache_miss",
            "actual_network_transfer",
            "owner_to_owner_end_to_end",
        ]
    ):
        raise ValueError("CAMPAIGN_REQUIRED_GAPS")
    if set(value["source_files"]) != {
        "experiments/tfhe/Cargo.lock",
        "experiments/sp1/Cargo.lock",
        "config/dependency-policy.json",
        "experiments/tfhe/fixture.lock.json",
        "experiments/sp1/profiles/modes.json",
        "rust-toolchain.toml",
    } or any(not re.fullmatch("[a-f0-9]{64}", s) for s in value["source_files"].values()):
        raise ValueError("CAMPAIGN_SOURCE_PINS")
    folder = (path.resolve().parent / value["observations"]).resolve()
    if not folder.is_relative_to(ROOT / "evidence/feasibility"):
        raise ValueError("CAMPAIGN_CORPUS_BOUNDARY")
    return value, folder


def api(endpoint, maximum=2 << 20):
    # Inert files: build-log ANSI escapes are never emitted to a terminal or retained in the corpus.
    with tempfile.TemporaryFile() as output:
        subprocess.run(
            ["gh", "api", "--allow-escape-sequences", endpoint],
            stdout=output,
            stderr=subprocess.DEVNULL,
            check=True,
            timeout=60,
        )
        output.seek(0)
        raw = output.read(maximum + 1)
    if len(raw) > maximum:
        raise ValueError("CAMPAIGN_UPSTREAM_LIMIT")
    return raw


def extract(raw):
    reports = []
    for line in raw.decode("utf-8-sig").splitlines():
        line = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", line)
        start = line.find('{"')
        if start < 0:
            continue
        try:
            value = decode(line[start:].encode())
        except ValueError:
            continue
        if isinstance(value, dict) and value.get("experiment") in EXPERIMENTS:
            if "native_executed" in value:  # Configuration-only output is never a measurement.
                if value != {
                    "experiment": value["experiment"],
                    "native_executed": False,
                    "status": "configuration_only",
                }:
                    raise ValueError("CAMPAIGN_FAKE_EXECUTION_FLAG")
                continue
            if any(v["experiment"] == value["experiment"] for v in reports):
                raise ValueError("CAMPAIGN_DUPLICATE_REPORT")
            reports.append(value)
    return reports


def capture(path, attempt):
    config, folder = profile(path)
    if attempt not in config["attempts"]:
        raise ValueError("CAMPAIGN_ATTEMPT")
    base = f"repos/{config['repository']}/actions/runs/{config['run_id']}/attempts/{attempt}"
    run = json.loads(api(base))
    jobs = json.loads(api(base + "/jobs?per_page=100"))
    if (
        run["head_sha"] != config["source"]
        or run["run_attempt"] != attempt
        or run["status"] != "completed"
        or run["event"] != "push"
        or run["repository"]["full_name"] != config["repository"]
        or run["path"] != ".github/workflows/ci.yml"
        or jobs["total_count"] != 3
        or {j["name"] for j in jobs["jobs"]} != {"native", "sp1", "verify"}
    ):
        raise ValueError("CAMPAIGN_UPSTREAM_INCOMPLETE_OR_CHANGED")
    for name, expected in config["source_files"].items():
        content = json.loads(
            api(f"repos/{config['repository']}/contents/{name}?ref={config['source']}")
        )
        if sha(base64.b64decode(content["content"])) != expected:
            raise ValueError("CAMPAIGN_SOURCE_CHANGED")
    reports, metadata = [], []
    for job in sorted(jobs["jobs"], key=lambda j: j["name"]):
        if (
            job["head_sha"] != config["source"]
            or job["run_attempt"] != attempt
            or job["status"] != "completed"
        ):
            raise ValueError("CAMPAIGN_JOB_CHANGED")
        item = {
            k: job[k]
            for k in (
                "id",
                "name",
                "conclusion",
                "runner_id",
                "runner_name",
                "started_at",
                "completed_at",
            )
        }
        if job["name"] != "verify" and job["conclusion"] != "skipped" and job["runner_id"]:
            logs = api(f"repos/{config['repository']}/actions/jobs/{job['id']}/logs")
            item["logs_sha256"] = sha(logs)
            reports.extend(extract(logs))
        metadata.append(item)
    # Validate the public numeric shape before writing any report out of the importer.
    for report in reports:
        validate_report(report, config)
    target = folder / f"attempt-{attempt}"
    target.mkdir(parents=True, exist_ok=False)
    meta = {
        "source": config["source"],
        "run_id": config["run_id"],
        "attempt": attempt,
        "conclusion": run["conclusion"],
        "jobs": metadata,
        "source_files": config["source_files"],
    }
    files = {
        "metadata.json": json.dumps(meta, sort_keys=True).encode(),
        "observations.jsonl": b"".join(
            json.dumps(r, sort_keys=True).encode() + b"\n" for r in reports
        ),
    }
    for name, raw in files.items():
        (target / name).write_bytes(raw)
    (target / "manifest.json").write_text(
        json.dumps(
            {"profile_sha256": sha(read(path)), "files": {n: sha(raw) for n, raw in files.items()}},
            sort_keys=True,
        )
        + "\n"
    )


def number(value, maximum=1800 * 10**9):
    if type(value) is not int or not 0 <= value <= maximum:
        raise ValueError("CAMPAIGN_NUMERIC_VALUE")


def shape(value, fields):
    if not isinstance(value, dict) or set(value) != set(fields.split()):
        raise ValueError("CAMPAIGN_REPORT_FIELDS")


def hashes(value, names):
    for name in names.split():
        if not isinstance(value[name], str) or re.fullmatch("[a-f0-9]{64}", value[name]) is None:
            raise ValueError("CAMPAIGN_HASH_BINDING")


def validate_report(value, config):
    def integers_only(node):
        if isinstance(node, float):
            raise ValueError("CAMPAIGN_NONINTEGER_OR_NONFINITE")
        if isinstance(node, dict):
            for child in node.values():
                integers_only(child)
        elif isinstance(node, list):
            for child in node:
                integers_only(child)

    integers_only(value)
    experiment = value["experiment"]
    common = "experiment production_qualified rust_toolchain native_binary_sha256 host "
    if experiment == "tfhe-eval":
        shape(
            value,
            common
            + (
                "address_space_limit_per_process_bytes cache_state fixture_manifest_s"
                "ha256 fixture_source gpu native pbs rayon_threads reservation_is_est"
                "imate tfhe_version workload_binding_rejection_verified"
            ),
        )
        shape(
            value["native"],
            (
                "experiment cases integer_mismatches negative_cases stages_ns observa"
                "tions binding_blake3 parameter_blake3 key_context_blake3 program_bla"
                "ke3 fixture_blake3 input_blake3 serialized_key_bytes serialized_inpu"
                "t_bytes serialized_output_bytes owner_peak_rss_bytes evaluator_peak_"
                "rss_bytes reservation_bytes"
            ),
        )
        hashes(
            value["native"],
            (
                "binding_blake3 parameter_blake3 key_context_blake3 program_blake3 fi"
                "xture_blake3 input_blake3"
            ),
        )
        if value["pbs"] != {
            "count": None,
            "elapsed_ns": None,
            "estimate": None,
            "reason": "PBS_STATS_FEATURE_DISABLED",
        }:
            raise ValueError("CAMPAIGN_UNINSTRUMENTED_PBS")
        shape(
            value["gpu"],
            (
                "benchmark_executed device_detected reason speedup status upstream_re"
                "vision upstream_target"
            ),
        )
        if value["gpu"]["benchmark_executed"] is not False or value["gpu"]["speedup"] is not None:
            raise ValueError("CAMPAIGN_UNAPPROVED_GPU")
        if (
            type(value["gpu"]["device_detected"]) is not bool
            or value["gpu"]["status"] != "UNAVAILABLE"
            or value["gpu"]["reason"] not in {"GPU_FEATURE_NOT_APPROVED", "NO_USABLE_NVIDIA_DEVICE"}
            or value["gpu"]["upstream_target"] != "bench_integer_gpu"
            or value["gpu"]["upstream_revision"] != "187fc0b95ab35352422deec6c027d0bd8743b6db"
        ):
            raise ValueError("CAMPAIGN_GPU_SCOPE")
    elif experiment == "tfhe-compact":
        shape(
            value,
            common
            + (
                "address_space_limit_per_process_bytes crs_setup expansion_reservatio"
                "n_bytes native proof_load rayon_threads relation reservation_is_esti"
                "mate tfhe_version"
            ),
        )
        shape(
            value["native"],
            (
                "experiment values negative_cases integer_mismatches serialized_bytes"
                " stages_ns context_blake3 crs_blake3 public_key_blake3"
            ),
        )
        hashes(value["native"], "context_blake3 crs_blake3 public_key_blake3")
        shape(
            value["native"]["serialized_bytes"],
            (
                "native compact proven_list expanded_compact expanded_proven crs publ"
                "ic_key evaluation_key"
            ),
        )
        for size in value["native"]["serialized_bytes"].values():
            number(size, 64 << 20)
            if size == 0:
                raise ValueError("CAMPAIGN_MISSING_RESOURCE")
        number(value["expansion_reservation_bytes"], 4 << 30)
        if value["proof_load"] != "Verify" or value["crs_setup"] != "LOCAL_RESEARCH_UNQUALIFIED":
            raise ValueError("CAMPAIGN_UNQUALIFIED_SETUP")
    elif experiment == "proof-modes":
        shape(
            value,
            common
            + (
                "batch_elapsed_ns cache_state profile_sha256 profiles queue_policy sa"
                "mples sdk_version"
            ),
        )
    if value["production_qualified"] is not False or value["rust_toolchain"] != "1.98.1":
        raise ValueError("CAMPAIGN_QUALIFICATION_OR_TOOLCHAIN")
    if re.fullmatch("[a-f0-9]{64}", value["native_binary_sha256"]) is None:
        raise ValueError("CAMPAIGN_BINARY_BINDING")
    if experiment in {"tfhe-eval", "tfhe-compact"}:
        if (
            value["tfhe_version"] != "1.8.1"
            or value["rayon_threads"] != 2
            or not isinstance(value["host"], str)
            or not 1 <= len(value["host"]) <= 256
            or value["address_space_limit_per_process_bytes"] != 4 << 30
            or value["reservation_is_estimate"] is not True
        ):
            raise ValueError("CAMPAIGN_TFHE_PROFILE")
        native = value["native"]
        if (
            native["experiment"] != experiment
            or type(native["integer_mismatches"]) is not int
            or native["integer_mismatches"] != 0
        ):
            raise ValueError("CAMPAIGN_REFERENCE_FAILURE")
        stages = native["stages_ns"]
        if set(stages) != (EVAL_STAGES if experiment == "tfhe-eval" else COMPACT_STAGES):
            raise ValueError("CAMPAIGN_STAGE_SET")
        for ns in stages.values():
            number(ns, 600 * 10**9)
        if experiment == "tfhe-eval" and stages["owner_total"] < sum(
            stages[k] for k in ("keygen", "encrypt_encode", "dispatch", "owner_decode_decrypt")
        ):
            raise ValueError("CAMPAIGN_OWNER_ACCOUNTING")
        if experiment == "tfhe-compact" and stages["owner_total"] < sum(
            ns for key, ns in stages.items() if key != "owner_total"
        ):
            raise ValueError("CAMPAIGN_COMPACT_ACCOUNTING")
        if experiment == "tfhe-eval":
            if (
                value["fixture_source"] != config["fixture_source"]
                or value["fixture_manifest_sha256"] != config["fixture_manifest_sha256"]
                or value["cache_state"] != "FRESH_PROCESS_SINGLE_EXPANSION_REUSED_FOR_100_CASES"
                or type(native["cases"]) is not int
                or native["cases"] != 100
                or type(native["negative_cases"]) is not int
                or native["negative_cases"] != 1
                or value["workload_binding_rejection_verified"] is not True
                or len(native["observations"]) != 100
            ):
                raise ValueError("CAMPAIGN_FROZEN_WORKLOAD")
            for index, row in enumerate(native["observations"]):
                if len(row) != 2 or type(row[0]) is not int or row[0] != index:
                    raise ValueError("CAMPAIGN_CASE_OBSERVATION")
                number(row[1], 480 * 10**9)
            for key in (
                "serialized_key_bytes",
                "serialized_input_bytes",
                "serialized_output_bytes",
                "owner_peak_rss_bytes",
                "evaluator_peak_rss_bytes",
                "reservation_bytes",
            ):
                number(native[key], 4 << 30)
                if native[key] == 0:
                    raise ValueError("CAMPAIGN_MISSING_RESOURCE")
            if stages["dispatch"] < sum(r[1] for r in native["observations"]) + sum(
                stages[k] for k in ("native_decode", "key_expand", "native_encode")
            ):
                raise ValueError("CAMPAIGN_TIME_ACCOUNTING")
        elif (
            native["values"] != 2
            or native["negative_cases"] != 6
            or value["relation"] != "COMPACT_PKE_INPUT_VALIDITY_ONLY"
        ):
            raise ValueError("CAMPAIGN_COMPACT_RELATION")
    elif experiment == "proof-modes":
        shape(value["host"], "system machine cpu")
        number(value["batch_elapsed_ns"])
        if any(not isinstance(s, str) or not 1 <= len(s) <= 256 for s in value["host"].values()):
            raise ValueError("CAMPAIGN_PROOF_HOST")
        if (
            value["sdk_version"] != "6.9.0"
            or len(value["samples"]) != 2
            or value["profile_sha256"]
            != config["source_files"]["experiments/sp1/profiles/modes.json"]
            or value["profiles"]["CORE_CPU"]["verifier_privacy"] != "NOT_ZERO_KNOWLEDGE"
        ):
            raise ValueError("CAMPAIGN_PROOF_PROFILE")
        if (
            value["cache_state"] != "FRESH_PROCESS_OS_CACHE_UNCONTROLLED"
            or value["queue_policy"] != "LOCAL_FIFO_TWO_ADMITTED_ONE_ACTIVE"
            or set(value["profiles"]) != {"CORE_CPU", "COMPRESSED", "GROTH16", "PLONK"}
        ):
            raise ValueError("CAMPAIGN_PROOF_SCOPE")
        for mode, fields in value["profiles"].items():
            shape(fields, "input_domain reason setup status verifier_privacy witness_access")
            if fields["status"] != ("RESEARCH_ONLY" if mode == "CORE_CPU" else "DISABLED"):
                raise ValueError("CAMPAIGN_UNAPPROVED_PROOF_MODE")
        previous = 0
        for index, row in enumerate(value["samples"]):
            shape(row, "index queue_ns process_ns end_to_end_ns native")
            proof = row["native"]
            shape(
                proof,
                (
                    "cycle_limit elf_blake3 experiment journal_blake3 journal_bytes mode "
                    "negative_cases outcome proof_bytes prove_ns total_ns verify_ns vk_di"
                    "gest"
                ),
            )
            hashes(proof, "elf_blake3 journal_blake3 vk_digest")
            if (
                row["index"] != index
                or proof["experiment"] != "sp1-relation"
                or proof["mode"] != "CORE_CPU"
                or proof["outcome"] != 0
                or proof["negative_cases"] != 7
            ):
                raise ValueError("CAMPAIGN_PROOF_FAILURE")
            for key in ("index", "queue_ns", "process_ns", "end_to_end_ns"):
                number(row[key])
            if (
                row["queue_ns"] < previous
                or row["end_to_end_ns"] != row["queue_ns"] + row["process_ns"]
                or row["process_ns"] < proof["total_ns"]
                or row["end_to_end_ns"] > value["batch_elapsed_ns"]
            ):
                raise ValueError("CAMPAIGN_FIFO_ACCOUNTING")
            previous = row["end_to_end_ns"]
            for key in ("prove_ns", "verify_ns", "total_ns", "proof_bytes", "journal_bytes"):
                number(proof[key])
            number(proof["outcome"])
            number(proof["cycle_limit"])
            if proof["proof_bytes"] == 0 or proof["journal_bytes"] == 0:
                raise ValueError("CAMPAIGN_MISSING_PROOF_BYTES")
            if proof["total_ns"] < proof["prove_ns"] + proof["verify_ns"]:
                raise ValueError("CAMPAIGN_PROOF_ACCOUNTING")
    else:
        raise ValueError("CAMPAIGN_UNKNOWN_EXPERIMENT")


def variance(values):
    if len(values) != 2:
        return {"value": None, "reason": "TWO_SUCCESSFUL_CAMPAIGNS_REQUIRED"}
    result = Fraction((values[0] - values[1]) ** 2, 2)
    return {
        "numerator": result.numerator,
        "denominator": result.denominator,
        "estimator": "sample_variance_ddof_1",
        "samples": 2,
    }


def load_campaign(config, path, folder, attempt):
    target = folder / f"attempt-{attempt}"
    if not target.resolve().is_relative_to(folder.resolve()):
        raise ValueError("CAMPAIGN_CAPTURE_BOUNDARY")
    if not (target / "manifest.json").exists():
        return {
            "attempt": attempt,
            "outcome": "INCOMPLETE_OR_FAILED",
            "metadata": {"jobs": [], "reason": "MISSING_OR_INCOMPLETE_CAPTURE"},
            "reports": {},
        }
    manifest = decode(read(target / "manifest.json"))
    if manifest["profile_sha256"] != sha(read(path)) or set(manifest["files"]) != {
        "metadata.json",
        "observations.jsonl",
    }:
        raise ValueError("CAMPAIGN_MANIFEST")
    for name, digest in manifest["files"].items():
        if sha(read(target / name)) != digest:
            raise ValueError("CAMPAIGN_CORPUS_CHANGED")
    meta = decode(read(target / "metadata.json"))
    if (
        meta["source"] != config["source"]
        or meta["run_id"] != config["run_id"]
        or meta["attempt"] != attempt
        or meta["source_files"] != config["source_files"]
        or {j["name"] for j in meta["jobs"]} != {"native", "sp1", "verify"}
        or len(meta["jobs"]) != 3
    ):
        raise ValueError("CAMPAIGN_METADATA_BINDING")
    for job in meta["jobs"]:
        runner = job["runner_id"]
        unassigned_failure = job["conclusion"] != "success" and (
            runner is None or (type(runner) is int and runner == 0)
        )
        if (
            type(job["id"]) is not int
            or job["id"] <= 0
            or (not unassigned_failure and (type(runner) is not int or runner <= 0))
        ):
            raise ValueError("CAMPAIGN_JOB_IDENTITY")
    reports = [decode(line) for line in read(target / "observations.jsonl").splitlines()]
    if len({r["experiment"] for r in reports}) != len(reports):
        raise ValueError("CAMPAIGN_DUPLICATE_REPORT")
    for report in reports:
        validate_report(report, config)
    complete = (
        meta["conclusion"] == "success"
        and all(j["conclusion"] == "success" for j in meta["jobs"])
        and {r["experiment"] for r in reports} == EXPERIMENTS
    )
    return {
        "attempt": attempt,
        "outcome": "SUCCEEDED" if complete else "INCOMPLETE_OR_FAILED",
        "metadata": meta,
        "reports": {r["experiment"]: r for r in reports},
    }


def summarize(campaigns, config):
    successful = [c for c in campaigns if c["outcome"] == "SUCCEEDED"]
    reasons = ["UNMEASURED_" + s.upper() for s in config["required_unmeasured_stages"]]
    reasons += [
        "INSUFFICIENT_OWNER_AND_PROOF_SAMPLES_FOR_TAIL_QUALIFICATION",
        "HARDWARE_AND_OS_CACHE_UNCONTROLLED",
    ]
    if len(successful) != 2:
        reasons.append("FAILED_OR_INCOMPLETE_CAMPAIGN")
    variants = {
        experiment: [
            {"attempt": c["attempt"], "sha256": c["reports"][experiment]["native_binary_sha256"]}
            for c in successful
        ]
        for experiment in sorted(EXPERIMENTS)
    }
    for experiment, builds in variants.items():
        if len({b["sha256"] for b in builds}) > 1:
            reasons.append("BINARY_VARIANT_" + experiment.upper().replace("-", "_"))
    metrics, within, costs = {}, [], {}
    for c in successful:
        evaluation = c["reports"]["tfhe-eval"]["native"]
        within.append(
            {
                "attempt": c["attempt"],
                "case_evaluation": quantiles([r[1] for r in evaluation["observations"]]),
                "case_scope": "100_CORRELATED_PUBLIC_CASES_ONE_FRESH_KEY_CONTEXT",
            }
        )
        costs[str(c["attempt"])] = {
            "serialized_bytes": {
                k: evaluation[k]
                for k in (
                    "serialized_key_bytes",
                    "serialized_input_bytes",
                    "serialized_output_bytes",
                )
            },
            "input_expansion_ratio": {
                "numerator": evaluation["serialized_input_bytes"],
                "denominator": 200,
            },
            "output_expansion_ratio": {
                "numerator": evaluation["serialized_output_bytes"],
                "denominator": 200,
            },
            "expansion_scope": "100_PUBLIC_TWO_UINT8_INPUT_OUTPUT_CASES_INCLUDES_NATIVE_ENVELOPES",
            "owner_peak_rss_bytes": evaluation["owner_peak_rss_bytes"],
            "evaluator_peak_rss_bytes": evaluation["evaluator_peak_rss_bytes"],
            "reservation_bytes_estimate": evaluation["reservation_bytes"],
            "compact_serialized_bytes": c["reports"]["tfhe-compact"]["native"]["serialized_bytes"],
        }
    for stage in sorted(EVAL_STAGES):
        samples = [c["reports"]["tfhe-eval"]["native"]["stages_ns"][stage] for c in successful]
        metrics[stage] = {
            "unit": "ns",
            "campaign_values": samples,
            "variance_ns_squared": variance(samples),
        }
    evaluation_totals = [
        sum(row[1] for row in c["reports"]["tfhe-eval"]["native"]["observations"])
        for c in successful
    ]
    metrics["case_evaluation_total"] = {
        "unit": "ns",
        "campaign_values": evaluation_totals,
        "variance_ns_squared": variance(evaluation_totals),
        "scope": "SUM_OF_100_CASE_TIMINGS_ALREADY_INCLUDED_IN_DISPATCH",
    }
    compact = {
        stage: {"unit": "ns", "campaign_values": values, "variance_ns_squared": variance(values)}
        for stage in sorted(COMPACT_STAGES)
        for values in [
            [c["reports"]["tfhe-compact"]["native"]["stages_ns"][stage] for c in successful]
        ]
    }
    proof = {}
    for stage in ("prove_ns", "verify_ns", "total_ns", "proof_bytes"):
        values = [
            [r["native"][stage] for r in c["reports"]["proof-modes"]["samples"]] for c in successful
        ]
        means = [Fraction(sum(v), len(v)) for v in values]
        proof[stage] = {
            "unit": "bytes" if stage == "proof_bytes" else "ns",
            "campaign_sample_values": values,
            "between_campaign_mean_variance": variance(means),
        }
    return {
        "kind": "REAL_CRYPTO_RESEARCH_OBSERVATIONS",
        "qualification": "INCONCLUSIVE" if reasons else "RESEARCH_ONLY",
        "production_qualified": False,
        "profile_enabled": False,
        "reasons": reasons,
        "requested_campaigns": len(campaigns),
        "successful_campaigns": len(successful),
        "failed_or_incomplete_campaigns": len(campaigns) - len(successful),
        "owner_and_native_stages": metrics,
        "successful_attempt_order": [c["attempt"] for c in successful],
        "measured_binary_variants": variants,
        "within_campaign_descriptive": within,
        "compact_input_validity_stages": compact,
        "separate_sp1_metadata_proof": proof,
        "expansion_and_memory": costs,
        "missing_stages": {
            s: {"value": None, "reason": "NOT_MEASURED_BY_NATIVE_RESEARCH_ADAPTER"}
            for s in config["required_unmeasured_stages"]
        },
        "monetary_cost": {"value": None, "reason": "NO_CRYPTO_WORKER_BILLING_OR_RATE_CARD"},
        "proof_peak_rss_bytes": {"value": None, "reason": "NOT_INSTRUMENTED_BY_PROOF_ADAPTER"},
        "campaigns": campaigns,
        "proof_scope": (
            "COMPACT_INPUT_VALIDITY_AND_SEPARATE_SP1_PUBLIC_METADATA_NOT_FHE_EVALUATION_PROOF"
        ),
        "fake_orchestration_timings_included": False,
    }


def build_report(path):
    config, folder = profile(path)
    campaigns = [load_campaign(config, path, folder, a) for a in config["attempts"]]
    ids = [j["id"] for c in campaigns for j in c["metadata"]["jobs"]]
    if len(ids) != len(set(ids)):
        raise ValueError("CAMPAIGN_INITIALIZATIONS_NOT_DISTINCT")
    good = [c for c in campaigns if c["outcome"] == "SUCCEEDED"]
    if len(good) == 2:
        keys = [c["reports"]["tfhe-eval"]["native"]["key_context_blake3"] for c in good]
        if keys[0] == keys[1]:
            raise ValueError("CAMPAIGN_KEY_CONTEXT_REUSED")
        bindings = [
            (
                c["reports"]["tfhe-eval"]["native"]["parameter_blake3"],
                c["reports"]["tfhe-eval"]["native"]["program_blake3"],
                c["reports"]["tfhe-eval"]["native"]["fixture_blake3"],
            )
            for c in good
        ]
        if bindings[0] != bindings[1]:
            raise ValueError("CAMPAIGN_WORKLOAD_BINDING_CHANGED")
        proofs = {
            tuple(r["native"][k] for k in ("elf_blake3", "vk_digest", "journal_blake3"))
            for c in good
            for r in c["reports"]["proof-modes"]["samples"]
        }
        if len(proofs) != 1:
            raise ValueError("CAMPAIGN_PROOF_STATEMENT_CHANGED")
    report = summarize(campaigns, config)
    report["profile_sha256"] = sha(read(path))
    return report


def run_profile(path, output=None):
    report = build_report(path)
    output = output or ROOT / "build/campaigns" / uuid4().hex
    output.mkdir(parents=True, exist_ok=False)
    (output / "summary.json").write_text(json.dumps(report, indent=2) + "\n")
    print("CRYPTO_CAMPAIGN_" + report["qualification"] + " report=" + str(output / "summary.json"))
    return report
