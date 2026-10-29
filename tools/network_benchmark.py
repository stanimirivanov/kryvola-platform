"""Private shaped-transfer journal; no crypto, SLO or billing qualification."""

import hashlib
import json
import re
import secrets
import time
from decimal import Decimal
from typing import Any

if __package__:
    from . import integration
else:
    import integration

ROOT = integration.ROOT
PROFILE = ROOT / "config/network-profiles/profiles.json"
PROFILE_SHA = "6546ef7263e0ffa031ff757c2f9d2197ccc73d3428b27f5c360b02306651255c"
SCRIPT = "/fixture/worker.py"
ENDPOINT = "http://toxiproxy:8667"


def source_commit():
    result = integration.run(["git", "-C", ROOT, "rev-parse", "HEAD"])
    result.check_returncode()
    value = result.stdout.decode().strip()
    if re.fullmatch("[0-9a-f]{40}", value) is None:
        raise ValueError("MISSING_SOURCE_BINDING")
    return value


def profiles():
    raw = PROFILE.read_bytes()
    if hashlib.sha256(raw).hexdigest() != PROFILE_SHA:
        raise ValueError("UNREVIEWED_NETWORK_PROFILE")
    return json.loads(raw)


def integer(value, minimum=0):
    if type(value) is not int or not minimum <= value <= 600 * 10**9:
        raise ValueError("INVALID_OBSERVATION_INTEGER")


def cost(window_ns, rows):
    integer(window_ns, 1)
    rates = profiles()["rate_card"]
    known = sum(r["downloaded_bytes"] for r in rows if r["downloaded_bytes"] is not None)
    incomplete = any(r["downloaded_bytes"] is None or r["uploaded_bytes"] is None for r in rows)
    compute = (
        window_ns * rates["container_nano_usd_per_second"] * len(rates["charged_containers"])
        + 10**9
        - 1
    ) // 10**9
    transfer = (known * rates["download_payload_nano_usd_per_gib"] + (1 << 30) - 1) // (1 << 30)
    return {
        "compute_window_nano_usd": compute,
        "known_download_payload_nano_usd": transfer,
        "total_nano_usd": None if incomplete else compute + transfer,
        "reason": "FAILED_ATTEMPT_BYTES_UNOBSERVED" if incomplete else None,
    }


def validate_batch(value, expected_count, expected_outcome):
    if set(value) != {"rows", "elapsed_ns", "resources"} or len(value["rows"]) != expected_count:
        raise ValueError("INVALID_TRANSFER_BATCH")
    integer(value["elapsed_ns"], 1)
    previous = 0
    for index, row in enumerate(value["rows"]):
        if set(row) != {
            "index",
            "queue_ns",
            "outcome",
            "upload_ns",
            "download_ns",
            "uploaded_bytes",
            "downloaded_bytes",
            "max_inflight_payload_bytes",
            "finish_ns",
            "payload_sha256",
        }:
            raise ValueError("INVALID_TRANSFER_ROW")
        integer(row["index"])
        if (
            not isinstance(row["payload_sha256"], str)
            or re.fullmatch("[0-9a-f]{64}", row["payload_sha256"]) is None
        ):
            raise ValueError("MISSING_PAYLOAD_BINDING")
        if row["index"] != index or row["outcome"] != expected_outcome:
            raise ValueError("UNEXPECTED_TRANSFER_OUTCOME")
        for key in ("queue_ns", "finish_ns", "max_inflight_payload_bytes"):
            integer(row[key])
        if (
            not previous <= row["queue_ns"] <= row["finish_ns"] <= value["elapsed_ns"]
            or row["max_inflight_payload_bytes"] > 65_536
        ):
            raise ValueError("INFLIGHT_OR_QUEUE_BOUND")
        previous = row["finish_ns"]
        for key in ("upload_ns", "download_ns", "uploaded_bytes", "downloaded_bytes"):
            if row[key] is not None:
                integer(row[key])
            elif expected_outcome == "SUCCEEDED":
                raise ValueError("MISSING_SUCCESS_METRIC")
        if expected_outcome == "SUCCEEDED" and (
            row["uploaded_bytes"] != 65_536
            or row["downloaded_bytes"] != 65_536
            or row["max_inflight_payload_bytes"] != 65_536
            or row["upload_ns"] + row["download_ns"] > row["finish_ns"] - row["queue_ns"]
        ):
            raise ValueError("TRANSFER_ACCOUNTING")
        if expected_outcome == "IO_FAILURE" and row["downloaded_bytes"] is not None:
            raise ValueError("FAILURE_BYTES_MUST_REMAIN_UNKNOWN")
    resource = value["resources"]
    integer(resource["process_peak_rss_bytes"], 1)
    for key in ("container_current_bytes", "container_lifetime_peak_bytes"):
        metric = resource[key]
        if set(metric) != {"value", "reason"}:
            raise ValueError("MISSING_RESOURCE_CLASSIFICATION")
        if metric["value"] is None:
            if metric["reason"] != "CGROUP_V2_METRIC_UNAVAILABLE":
                raise ValueError("MISSING_RESOURCE_REASON")
        else:
            integer(metric["value"], 1)
            if metric["reason"] is not None:
                raise ValueError("INCONSISTENT_RESOURCE")


def worker(stack, action, *args, payload=None):
    raw = stack.execute("transfer", "python", SCRIPT, action, *args, payload=payload).stdout.strip()
    return json.loads(raw) if raw else None


def memory_snapshot(value):
    match = re.fullmatch(r"([0-9]+(?:\.[0-9]+)?)(B|kB|MB|GB|KiB|MiB|GiB) / .+", value)
    if match is None:
        raise ValueError("UNKNOWN_DOCKER_MEMORY_UNIT")
    factors = {
        "B": 1,
        "kB": 1000,
        "MB": 10**6,
        "GB": 10**9,
        "KiB": 1024,
        "MiB": 1 << 20,
        "GiB": 1 << 30,
    }
    observed = int(Decimal(match[1]) * factors[match[2]])
    integer(observed, 1)
    return observed


def control(stack, path, method="POST", value=None):
    return worker(
        stack,
        "control",
        path,
        method,
        payload=json.dumps(value).encode() if value is not None else None,
    )


def shaped(stack, name):
    expected = profiles()[name]
    for stream in ("upstream", "downstream"):
        for kind, attribute, setting in (
            ("latency", "latency", expected["latency_ms_each_direction"]),
            ("bandwidth", "rate", expected["bandwidth_decimal_kB_s_each_direction"]),
        ):
            if setting:
                control(
                    stack,
                    "/proxies/bench/toxics",
                    value={
                        "name": kind + "_" + stream,
                        "type": kind,
                        "stream": stream,
                        "toxicity": 1.0,
                        "attributes": {attribute: setting},
                    },
                )
    actual = control(stack, "/proxies/bench", "GET")
    for kind, attribute, setting in (
        ("latency", "latency", expected["latency_ms_each_direction"]),
        ("bandwidth", "rate", expected["bandwidth_decimal_kB_s_each_direction"]),
    ):
        if (
            setting
            and sum(
                t["type"] == kind and t["attributes"][attribute] == setting
                for t in actual["toxics"]
            )
            != 2
        ):
            raise ValueError("TOXIC_CONFIGURATION_MISMATCH")
    return actual


def observe(stack):
    configuration = profiles()
    journal = stack.folder / "network-observations.jsonl"
    with journal.open("x", encoding="utf-8") as stream:
        stream.write(
            json.dumps(
                {
                    "kind": "context",
                    "profile_sha256": PROFILE_SHA,
                    "profiles": configuration,
                    "images": {
                        k: v["image"] for k, v in integration.configuration()["services"].items()
                    },
                    "source_commit": source_commit(),
                }
            )
            + "\n"
        )

    def retain(kind, value):
        with journal.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps({"kind": kind, "value": value}) + "\n")

    stack.ready("transfer", "python", SCRIPT, "ping", "http://transfer:8088")
    control(
        stack,
        "/proxies",
        value={
            "name": "bench",
            "listen": "0.0.0.0:8667",
            "upstream": "transfer:8088",
            "enabled": True,
        },
    )
    results: dict[str, Any] = {}
    try:
        for name in ("lan", "wan"):
            actual = shaped(stack, name)
            start = time.monotonic_ns()
            pings = [worker(stack, "ping", ENDPOINT)["elapsed_ns"] for _ in range(3)]
            launched = time.monotonic_ns()
            batch = worker(stack, "batch", ENDPOINT, "4")
            process_ns = time.monotonic_ns() - launched
            retain(
                name + "_raw_batch",
                {"batch": batch, "pings_ns": pings, "process_elapsed_ns": process_ns},
            )
            validate_batch(batch, 4, "SUCCEEDED")
            bounds = worker(stack, "bounds")
            if (
                bounds["stored_bytes"] != 4 * 65_536
                or bounds["max_inflight_payload_bytes"] != 65_536
            ):
                raise ValueError("SERVER_MEMORY_BOUND")
            ids = stack.compose("ps", "--quiet", "transfer", "toxiproxy").stdout.decode().split()
            snapshot = integration.run(
                ["docker", "stats", "--no-stream", "--format", "{{json .}}", *ids], timeout=15
            )
            snapshot.check_returncode()
            stats = [json.loads(line) for line in snapshot.stdout.splitlines()]
            if len(stats) != 2 or any(not s.get("MemUsage") for s in stats):
                raise ValueError("MISSING_CONTAINER_STATS")
            for snapshot in stats:
                snapshot["approx_cache_adjusted_usage_bytes"] = memory_snapshot(
                    snapshot["MemUsage"]
                )
            window = time.monotonic_ns() - start
            results[name] = {
                "pings_ns": pings,
                "batch": batch,
                "process_elapsed_ns": process_ns,
                "window_ns": window,
                "applied_proxy": actual,
                "server": bounds,
                "serialized_bulk_payload_bytes": sum(
                    r["uploaded_bytes"] + r["downloaded_bytes"] for r in batch["rows"]
                ),
                "docker_stats_cache_adjusted_snapshots": stats,
                "cost": cost(window, batch["rows"]),
            }
            retain(name + "_complete_observation", results[name])
        wan = configuration["wan"]
        if min(results["wan"]["pings_ns"]) < 2 * wan["latency_ms_each_direction"] * 10**6 * 7 // 10:
            raise ValueError("LATENCY_NOT_OBSERVED")
        minimum = 2 * 4 * 65_536 * 10**9 // (wan["bandwidth_decimal_kB_s_each_direction"] * 1000)
        if results["wan"]["batch"]["elapsed_ns"] < minimum * 7 // 10:
            raise ValueError("BANDWIDTH_NOT_OBSERVED")
        for toxic in results["wan"]["applied_proxy"]["toxics"]:
            control(stack, "/proxies/bench/toxics/" + toxic["name"], "DELETE")
        began = time.monotonic_ns()
        control(stack, "/proxies/bench", value={"enabled": False})
        failed = worker(stack, "batch", ENDPOINT, "1")
        retain("disconnect_attempt", failed)
        validate_batch(failed, 1, "IO_FAILURE")
        ended_failure = time.monotonic_ns()
        control(stack, "/proxies/bench", value={"enabled": True})
        retry_started = time.monotonic_ns()
        recovered = worker(stack, "batch", ENDPOINT, "1")
        retain("recovery_attempt", recovered)
        validate_batch(recovered, 1, "SUCCEEDED")
        elapsed = time.monotonic_ns() - began
        results["disconnect_retry"] = {
            "attempts": [failed, recovered],
            "retry_delay_ns": retry_started - ended_failure,
            "elapsed_ns": elapsed,
            "cost": cost(elapsed, failed["rows"] + recovered["rows"]),
        }
    finally:
        control(stack, "/proxies/bench", "DELETE")
    report = {
        "kind": "PUBLIC_HTTP_FIXTURE_ONLY",
        "profile_sha256": PROFILE_SHA,
        "profiles": configuration,
        "source_commit": source_commit(),
        "byte_scope": "BULK_CHUNK_BODIES_ONLY_EXCLUDES_RECEIPTS_HEADERS_PINGS_AND_CONTROL",
        "harness_sha256": hashlib.sha256(
            (ROOT / "tools/network_benchmark.py").read_bytes()
        ).hexdigest(),
        "worker_sha256": hashlib.sha256(
            (ROOT / "config/network-profiles/worker.py").read_bytes()
        ).hexdigest(),
        "images": {k: v["image"] for k, v in integration.configuration()["services"].items()},
        "cache_state": "FRESH_CONNECTIONS_OS_CACHES_UNCONTROLLED",
        "key_cache": "NOT_APPLICABLE_NO_CRYPTO",
        "expanded_bytes": {"value": None, "reason": "NO_CRYPTO_EXPANSION"},
        "owner_work_ns": {"value": None, "reason": "PUBLIC_TRANSFER_FIXTURE_NO_OWNER"},
        "observations": results,
        "production_qualified": False,
    }
    info = integration.run(
        [
            "docker",
            "info",
            "--format",
            '{"os":{{json .OSType}},"architecture":{{json .Architecture}},'
            '"cpus":{{.NCPU}},"memory_bytes":{{.MemTotal}},'
            '"server_version":{{json .ServerVersion}}}',
        ]
    )
    info.check_returncode()
    report["observed_docker_host"] = json.loads(info.stdout)
    output = stack.folder / "network-report.json"
    with output.open("x", encoding="utf-8") as stream:
        json.dump(report, stream, sort_keys=True)
    print("NETWORK_CHECK_PASSED report=" + str(output))
    return report


def execute():
    profiles()  # Reject changed configuration before provisioning anything.
    if __package__:
        from . import release_conformance
    else:
        import release_conformance
    admission = release_conformance.controls()
    stack = integration.Stack("kryvola-m0-" + secrets.token_hex(6))
    try:
        stack.up()
        if __package__:
            from .fake_workflow import smoke
        else:
            from fake_workflow import smoke
        fake = smoke(stack)
        report = observe(stack)
        release_conformance.finish(stack, fake, admission)
        return report
    finally:
        if stack.claimed and integration.ACTIVE.exists():
            stack.down()
