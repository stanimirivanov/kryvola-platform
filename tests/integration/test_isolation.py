"""Evaluate only evidence from successful live probes and positive controls."""


def qualify(report):
    assert report["kind"] == "LOCAL_SYNTHETIC_ISOLATION_ONLY"
    assert report["production_qualified"] is False
    assert report["owner_positive_control"] is True
    assert set(report["probes"]) == {"ray", "redpanda", "temporal"}
    for role, probe in report["probes"].items():
        assert probe["positive_control"] is True and probe["uid"] > 0
        assert len(probe["denials"]) == (5 if role == "ray" else 3)
        assert all(row["denied"] is True for row in probe["denials"])
    assert len(report["scanned"]) == 6
