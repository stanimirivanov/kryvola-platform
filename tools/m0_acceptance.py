"""Detached M0 evidence audit. Current pending inputs cannot authorize acceptance."""

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path
from uuid import uuid4

if __package__:
    from . import architecture, campaign, integration, release_conformance
else:
    import architecture
    import campaign
    import integration
    import release_conformance

ROOT = Path(__file__).resolve().parents[1]
POLICY = "config/m0-acceptance.json"
POLICY_SHA = "490765adf4977d6d77347c7cb7937906d8443220a2ecb89f01cb1a58377dada0"
LIVE = {
    "release-conformance-report.json",
    "isolation-report.json",
    "fake-workflow-report.json",
    "network-report.json",
}
BLOCKERS = [
    "RATIFICATION_PENDING",
    "NAMED_OWNER_SECURITY_SIGNOFFS_MISSING",
    "SCOPED_LEGAL_PARAMETER_APPROVAL_MISSING",
    "SIGNED_FIVE_COMPONENT_CANDIDATE_NOT_SUBMITTED",
    "ML_RELEASE_ARTIFACT_NOT_SUBMITTED",
    "PLATFORM_SIGNED_RELEASE_ARTIFACT_NOT_SUBMITTED",
]


def require(condition, code):
    if not condition:
        raise ValueError(code)


def read(path):
    return campaign.read(path)


def inputs():
    policy = read(ROOT / POLICY)
    require(campaign.sha(policy) == POLICY_SHA, "M0_POLICY_CHANGED")
    pins = campaign.decode(policy)
    require(set(pins) == {"ratification", "crypto", "ml"}, "M0_MISSING_INPUT")
    for pin in pins.values():
        path = ROOT / pin["file"]
        require(
            path.resolve().is_relative_to((ROOT / "evidence/m0").resolve()), "M0_INPUT_BOUNDARY"
        )
        require(campaign.sha(read(path)) == pin["sha256"], "M0_INPUT_CHANGED")
    ratification = read(ROOT / pins["ratification"]["file"]).decode("utf-8")
    require(
        "M0 decision: **BLOCKED_PENDING_SIGNOFFS**." in ratification, "M0_UNREVIEWED_RATIFICATION"
    )
    architecture.verify_contracts(ROOT)
    summary = campaign.build_report(ROOT / "config/benchmarks/fhe-q1.json")
    require(
        summary == campaign.decode(read(ROOT / "evidence/feasibility/fhe-q1/summary.json")),
        "M0_CAMPAIGN_DRIFT",
    )
    require(
        summary["successful_campaigns"] == 2 and summary["qualification"] == "INCONCLUSIVE",
        "M0_CAMPAIGN_MISSING",
    )
    return (
        pins,
        campaign.decode(read(ROOT / "spec.lock.json")),
        campaign.decode(read(ROOT / "config/fake-workflow/releases.json")),
        summary,
    )


def source_commit():
    require(
        not subprocess.run(
            ["git", "status", "--porcelain", "--untracked-files=normal"],
            cwd=ROOT,
            capture_output=True,
            check=True,
            timeout=30,
        ).stdout,
        "M0_DIRTY_SOURCE",
    )
    source = (
        subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, check=True, timeout=30
        )
        .stdout.decode()
        .strip()
    )
    require(re.fullmatch("[a-f0-9]{40}", source) is not None, "M0_SOURCE_IDENTITY")
    return source


def validate_live(reports, source, releases):
    require(set(reports) == LIVE, "M0_LIVE_REPORTS_MISSING")
    conformance, fake = (
        reports["release-conformance-report.json"],
        reports["fake-workflow-report.json"],
    )
    isolation, network = reports["isolation-report.json"], reports["network-report.json"]
    require(
        conformance["kind"] == "EXPERIMENTAL_FIXTURE_SET_CONFORMANT"
        and conformance["platform_commit"]
        == fake["driver_commit"]
        == network["source_commit"]
        == source,
        "M0_STALE_LIVE_SOURCE",
    )
    require(
        conformance["production_ready"] is False
        and fake["production_ready"] is False
        and fake["profile_enabled"] is False
        and isolation["production_qualified"] is False
        and network["production_qualified"] is False,
        "M0_PRODUCTION_CLAIM",
    )
    require(
        conformance["full_five_component_candidate"] == "NOT_SUBMITTED"
        and conformance["packages"] == fake["releases"] == releases
        and conformance["live_checks"] == "PUBLISHED_NATIVE_FAKE_AND_TEMPORAL_REPLAY_PASSED",
        "M0_FALSE_COMPOSITION",
    )
    require(
        {v["case"]: v["exit_code"] for v in conformance["negative_controls"]}
        == dict.fromkeys(release_conformance.CASES, 1)
        and len(conformance["negative_controls"]) == len(release_conformance.CASES),
        "M0_NEGATIVE_CONTROLS",
    )
    expected = {name: v["image"] for name, v in integration.configuration()["services"].items()}
    require(
        set(conformance["images"]) == set(expected) and network["images"] == expected,
        "M0_RUNTIME_IMAGES",
    )
    for name, image in conformance["images"].items():
        require(
            image["service"] == name
            and image["reference"] == expected[name]
            and re.fullmatch("sha256:[a-f0-9]{64}", image["id"]) is not None,
            "M0_RUNTIME_IMAGE",
        )
    require(
        fake["kind"] == "PUBLIC_FAKE_ENGINE_SELFTEST"
        and network["kind"] == "PUBLIC_HTTP_FIXTURE_ONLY"
        and isolation["kind"] == "LOCAL_SYNTHETIC_ISOLATION_ONLY"
        and isolation["canary_type"] == "SYNTHETIC_NON_KEY"
        and isolation["owner_positive_control"] is True,
        "M0_WRONG_EVIDENCE_CLASS",
    )
    require(set(isolation["probes"]) == {"ray", "redpanda", "temporal"}, "M0_ISOLATION_PROBES")
    for name, count in (("ray", 5), ("redpanda", 3), ("temporal", 3)):
        probe = isolation["probes"][name]
        require(
            probe["positive_control"] is True
            and len(probe["denials"]) == count
            and all(row["denied"] is True for row in probe["denials"]),
            "M0_ISOLATION_FAILURE",
        )
    require(
        set(isolation["scanned"])
        == {
            "broker-record",
            "temporal-history",
            "owner-logs",
            "ray-logs",
            "broker-logs",
            "workflow-logs",
        },
        "M0_SCAN_COVERAGE",
    )


def assess(source, live=None):
    pins, spec, releases, summary = inputs()
    blockers, evidence = list(BLOCKERS), {}
    if live is None:
        blockers.append("CURRENT_RUN_LIVE_EVIDENCE_MISSING")
    else:
        require(
            live.resolve().is_relative_to((ROOT / "build/integration").resolve()),
            "M0_LIVE_BOUNDARY",
        )
        reports = {}
        for name in sorted(LIVE):
            raw = read(live / name)
            reports[name] = campaign.decode(raw)
            evidence[name] = {
                "path": (live / name).relative_to(ROOT / "build").as_posix(),
                "sha256": campaign.sha(raw),
            }
        validate_live(reports, source, releases)
    components = {
        "spec": {
            "source": spec["revision"],
            "artifact_kind": "GENERATED_BUNDLE_MANIFEST",
            "manifest_sha256": spec["manifest_sha256"],
        },
        **{
            name: {
                "source": pin["source"],
                "artifact_kind": "PUBLISHED_EXPERIMENTAL_FIXTURE",
                "subjects": pin["assets"],
                "signature_evidence": "LIVE_FIXTURE_GATE" if live else "NOT_CHECKED_IN_THIS_AUDIT",
            }
            for name, pin in releases.items()
        },
        "ml": {
            "source": pins["ml"]["revision"],
            "artifact_kind": "PUBLIC_FIXTURE_MANIFEST_ONLY",
            "fixture_sha256": pins["ml"]["sha256"],
            "release_artifact": None,
        },
        "platform": {
            "source": source,
            "artifact_kind": "TESTED_DRIVER_SOURCE_ONLY",
            "release_artifact": None,
        },
    }
    require(set(components) == {"spec", "fabric", "engines", "ml", "platform"}, "M0_COMPONENTS")
    lock = {
        "kind": "M0_EVIDENCE_INVENTORY_NOT_ACCEPTED_RELEASE_SET",
        "platform_commit": source,
        "components": components,
        "reviews": pins,
        "contract": spec,
        "live_evidence": evidence,
        "campaign_sha256": campaign.sha(read(ROOT / "evidence/feasibility/fhe-q1/summary.json")),
        "input_hashes": {
            p: campaign.sha(read(ROOT / p))
            for p in (
                POLICY,
                "spec.lock.json",
                "compose.yaml",
                "config/fake-workflow/releases.json",
                "tools/m0_acceptance.py",
            )
        },
    }
    report = {
        "kind": "M0_ACCEPTANCE_AUDIT",
        "status": "BLOCKED",
        "accepted": False,
        "production_ready": False,
        "profile_enabled": False,
        "m1_admitted": False,
        "accepted_release_set": None,
        "mandatory_blockers": sorted(blockers),
        "live_fixture_scope": "PASSED_IN_PROCESS_CHECKS" if live else "MISSING",
        "optional_exclusions": {
            "gpu": "UNAVAILABLE",
            "other_proof_modes": "UNMEASURED_DISABLED",
            "risc_zero": "DEFERRED",
        },
        "crypto_qualification": summary["qualification"],
        "ratification": "BLOCKED_PENDING_SIGNOFFS",
    }
    return lock, report


def verify_bundle(folder):
    manifest = campaign.decode(read(folder / "manifest.json"))
    require(set(manifest) == {"lock.json", "report.json"}, "M0_BUNDLE_FILES")
    for name, digest in manifest.items():
        require(campaign.sha(read(folder / name)) == digest, "M0_BUNDLE_CHANGED")
    lock, report = (campaign.decode(read(folder / name)) for name in ("lock.json", "report.json"))
    require(
        report["status"] == "BLOCKED"
        and report["accepted"] is False
        and report["production_ready"] is False
        and report["profile_enabled"] is False
        and report["m1_admitted"] is False
        and report["accepted_release_set"] is None
        and set(BLOCKERS) <= set(report["mandatory_blockers"]),
        "M0_FALSE_ACCEPTANCE",
    )
    require(lock["kind"] == "M0_EVIDENCE_INVENTORY_NOT_ACCEPTED_RELEASE_SET", "M0_FALSE_LOCK")
    require(
        set(lock["components"]) == {"spec", "fabric", "engines", "ml", "platform"}
        and lock["components"]["platform"]["source"] == lock["platform_commit"],
        "M0_COMPONENTS",
    )
    require(
        all(re.fullmatch("[a-f0-9]{40}", item["source"]) for item in lock["components"].values()),
        "M0_SOURCE_IDENTITY",
    )
    return report


def publish(live=None, output=None):
    lock, report = assess(source_commit(), live)
    output = output or ROOT / "build/m0" / uuid4().hex
    output.mkdir(parents=True, exist_ok=False)
    manifest = {}
    for name, value in (("lock.json", lock), ("report.json", report)):
        raw = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()
        (output / name).write_bytes(raw)
        manifest[name] = campaign.sha(raw)
    (output / "manifest.json").write_bytes((json.dumps(manifest, sort_keys=True) + "\n").encode())
    verify_bundle(output)
    print("M0_ACCEPTANCE_BLOCKED report=" + str(output / "report.json"))
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--audit-only", action="store_true")
    parser.add_argument("--live", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--verify", type=Path)
    args = parser.parse_args()
    if args.check and (args.audit_only or args.live or args.output or args.verify):
        parser.error("--check only validates pinned inputs")
    if args.verify and (args.live or args.output):
        parser.error("--verify does not generate artifacts")
    if args.check:
        inputs()
        print("M0 input pins valid; no acceptance, services or publication")
        return 0
    report = verify_bundle(args.verify) if args.verify else publish(args.live, args.output)
    if args.verify:
        print("M0_ACCEPTANCE_BLOCKED; bundle integrity is not approval")
    return 0 if args.audit_only and report["status"] == "BLOCKED" else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ValueError, KeyError, TypeError, OSError, subprocess.SubprocessError:
        print("M0_ACCEPTANCE_ERROR", file=sys.stderr)
        raise SystemExit(2) from None
