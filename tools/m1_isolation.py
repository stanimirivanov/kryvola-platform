"""M1 compromised-worker evidence: precise denials, live positives, no secret output."""

import hashlib
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

if __package__:
    from . import isolation
else:
    import isolation

POSITIVES = {
    "coordinator_before",
    "coordinator_after",
    "artifact_before",
    "artifact_after",
    "owner_canary",
    "denied_targets_before",
    "denied_targets_after",
    "privileged_route",
}
EXPECTED = {
    "foreign_tenant": "FORBIDDEN",
    "stolen_coordinator": "FORBIDDEN",
    "privileged_mutation": "FORBIDDEN",
    "release_grant": "FORBIDDEN",
    "metadata": "NETWORK_DENIED_HEALTHY_TARGET",
    "broker_admin": "NETWORK_DENIED_HEALTHY_TARGET",
    "database": "CREDENTIAL_REQUIRED",
    "owner_files": "NOT_MOUNTED",
}


def validate(value, *, database="CREDENTIAL_REQUIRED"):
    expected = EXPECTED | {"database": database}
    if (
        set(value) != {"positive", "denied", "inventory"}
        or value["positive"] != dict.fromkeys(POSITIVES, True)
        or any(v is not True for v in value["positive"].values())
        or value["denied"] != expected
        or type(value["inventory"].get("effective_capabilities")) is not int
        or value["inventory"].get("owner_library") is not False
        or value["inventory"].get("forbidden_files_absent") is not True
        or value["inventory"]
        != {
            "uid": 65532,
            "effective_capabilities": 0,
            "owner_library": False,
            "forbidden_files_absent": True,
        }
    ):
        raise ValueError("M1_ISOLATION_EVIDENCE")
    return value


def scan(raw, secrets):
    for secret in [b"-----BEGIN PRIVATE KEY-----", b"-----BEGIN RSA PRIVATE KEY-----", *secrets]:
        isolation.scan(raw, secret)


def record(fixture, evidence, secrets, *, destination=None, **boundaries):
    if fixture not in {"local", "cluster"}:
        raise ValueError("M1_ISOLATION_FIXTURE")
    validate(
        evidence,
        database="CREDENTIAL_REQUIRED" if fixture == "local" else "NETWORK_DENIED_HEALTHY_TARGET",
    )
    paths = [
        ROOT / "config/m1.lock.json",
        ROOT / "compose.m1.yaml",
        ROOT / "deploy/m1/boundaries.json",
        ROOT / "tools/m1_cluster.py",
        *[
            ROOT / "tools" / name
            for name in (
                "m1.py",
                "m1_assets.py",
                "m1_images.py",
                "m1_identity.py",
                "m1_credentials.py",
            )
        ],
        *sorted((ROOT / "config/m1").glob("*.py")),
        ROOT / "tools/m1_live_infra.py",
        *sorted((ROOT / "tools").glob("m1_isolation*.py")),
        *sorted((ROOT / "config/isolation").glob("m1_*.py")),
        *sorted((ROOT / "config/isolation").glob("*.json")),
        ROOT / "config/isolation/m1_master.toml",
    ]
    report = dict(
        schema_version=1,
        fixture=fixture,
        evidence=evidence,
        boundaries=boundaries,
        production_threat_model_qualified=False,
        working_tree_clean=not bool(
            subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT)
        ),
        source=subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
        inputs={
            str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in paths
        },
    )
    raw = (json.dumps(report, sort_keys=True, indent=2) + "\n").encode()
    scan(raw, secrets)
    output = destination or ROOT / ("build/m1-" + fixture + "-isolation.json")
    output.write_bytes(raw)
    return report
