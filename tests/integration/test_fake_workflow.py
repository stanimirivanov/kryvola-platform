"""Assertions over the actual published-package traversal; no synthetic pass fallback."""

import hashlib


def qualify(report, event, wire):
    assert report["kind"] == "PUBLIC_FAKE_ENGINE_SELFTEST"
    assert report["production_ready"] is False and report["profile_enabled"] is False
    assert [item["stage"] for item in report["trace"]] == [
        "REDPANDA_TO_TEMPORAL",
        "RAY_TO_PUBLISHED_FAKE_ENGINE",
        "TEMPORAL_TERMINAL_AND_REPLAY",
        "IMMUTABLE_FAKE_OUTPUT",
    ]
    digest = hashlib.sha256(wire).hexdigest()
    assert report["trace"][0]["intent_digest"] == digest
    assert report["trace"][1]["receipt"]["intent_digest"] == digest
    assert report["trace"][2]["result"]["intent_digest"] == digest
    assert report["trace"][0]["event_bytes"] == len(event) <= 8192
    for ref in (report["input"], report["output"]):
        assert ref["version"] not in {"", "null"}
        assert len(ref["sha256"]) == 64 and 0 < ref["byte_length"] <= 4096
    assert set(report["releases"]) == {"fabric", "engines"}
