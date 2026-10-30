"""Pending human/release inputs never become an accepted M0 or production release."""

import copy
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from tools import m0_acceptance as gate

SOURCE = "a" * 40


class AcceptanceTests(unittest.TestCase):
    def test_live_evidence_rejects_stale_false_composition_and_failed_controls(self):
        releases = {"fixture": "unit-test-only"}
        images = {k: v["image"] for k, v in gate.integration.configuration()["services"].items()}
        records = {
            "release-conformance-report.json": {
                "kind": "EXPERIMENTAL_FIXTURE_SET_CONFORMANT",
                "platform_commit": SOURCE,
                "production_ready": False,
                "full_five_component_candidate": "NOT_SUBMITTED",
                "packages": releases,
                "live_checks": "PUBLISHED_NATIVE_FAKE_AND_TEMPORAL_REPLAY_PASSED",
                "negative_controls": [
                    {"case": c, "exit_code": 1} for c in gate.release_conformance.CASES
                ],
                "images": {
                    k: {"service": k, "reference": v, "id": "sha256:" + "b" * 64}
                    for k, v in images.items()
                },
            },
            "fake-workflow-report.json": {
                "kind": "PUBLIC_FAKE_ENGINE_SELFTEST",
                "driver_commit": SOURCE,
                "production_ready": False,
                "profile_enabled": False,
                "releases": releases,
            },
            "network-report.json": {
                "kind": "PUBLIC_HTTP_FIXTURE_ONLY",
                "source_commit": SOURCE,
                "production_qualified": False,
                "images": images,
            },
            "isolation-report.json": {
                "kind": "LOCAL_SYNTHETIC_ISOLATION_ONLY",
                "production_qualified": False,
                "canary_type": "SYNTHETIC_NON_KEY",
                "owner_positive_control": True,
                "probes": {
                    k: {"positive_control": True, "denials": [{"denied": True}] * n}
                    for k, n in (("ray", 5), ("redpanda", 3), ("temporal", 3))
                },
                "scanned": [
                    "broker-record",
                    "temporal-history",
                    "owner-logs",
                    "ray-logs",
                    "broker-logs",
                    "workflow-logs",
                ],
            },
        }
        gate.validate_live(records, SOURCE, releases)
        for mutate in (
            lambda r: r["network-report.json"].update(source_commit="c" * 40),
            lambda r: r["fake-workflow-report.json"].update(production_ready=True),
            lambda r: r["release-conformance-report.json"].update(
                full_five_component_candidate="ACCEPTED"
            ),
            lambda r: r["release-conformance-report.json"]["negative_controls"].pop(),
            lambda r: r["isolation-report.json"]["probes"]["ray"]["denials"][0].update(
                denied=False
            ),
        ):
            changed = copy.deepcopy(records)
            mutate(changed)
            with self.assertRaises(ValueError):
                gate.validate_live(changed, SOURCE, releases)

    def test_full_audit_is_emitted_after_cleanup_and_not_after_live_failure(self):
        from tools import fake_workflow, isolation, network_benchmark

        for fails in (False, True):
            events = []
            stack = SimpleNamespace(
                claimed=True,
                folder=Path("unused"),
                up=lambda: None,
                down=lambda events=events: events.append("cleanup"),
            )
            with (
                patch.object(network_benchmark, "profiles"),
                patch.object(gate.release_conformance, "controls", return_value={}),
                patch.object(gate.release_conformance, "finish"),
                patch.object(gate.integration, "Stack", return_value=stack),
                patch.object(gate.integration, "ACTIVE", SimpleNamespace(exists=lambda: True)),
                patch.object(fake_workflow, "smoke", return_value={}),
                patch.object(network_benchmark, "observe", return_value={}),
                patch.object(
                    isolation,
                    "qualify",
                    side_effect=ValueError("fixture failure") if fails else None,
                ),
                patch.object(
                    gate,
                    "publish",
                    side_effect=lambda events=events, **kwargs: events.append("audit"),
                ),
            ):
                if fails:
                    with self.assertRaises(ValueError):
                        network_benchmark.execute(acceptance_audit=True)
                else:
                    network_benchmark.execute(acceptance_audit=True)
            self.assertEqual(events, ["cleanup"] if fails else ["cleanup", "audit"])

    def test_five_sources_missing_artifacts_and_optional_exclusions_remain_distinct(self):
        lock, report = gate.assess(SOURCE)
        self.assertEqual(set(lock["components"]), {"spec", "fabric", "engines", "ml", "platform"})
        self.assertIsNone(lock["components"]["ml"]["release_artifact"])
        self.assertIsNone(lock["components"]["platform"]["release_artifact"])
        self.assertIn("CURRENT_RUN_LIVE_EVIDENCE_MISSING", report["mandatory_blockers"])
        self.assertFalse(report["accepted"])
        self.assertFalse(report["m1_admitted"])
        self.assertIsNone(report["accepted_release_set"])
        self.assertEqual(report["optional_exclusions"]["gpu"], "UNAVAILABLE")
        self.assertTrue(set(gate.BLOCKERS) <= set(report["mandatory_blockers"]))

    def test_bad_pins_and_missing_live_reports_fail_instead_of_synthetic_success(self):
        with (
            patch.object(gate, "POLICY_SHA", "0" * 64),
            self.assertRaisesRegex(ValueError, "M0_POLICY_CHANGED"),
        ):
            gate.inputs()
        with self.assertRaisesRegex(ValueError, "M0_LIVE_REPORTS_MISSING"):
            gate.validate_live({}, SOURCE, {})
        with patch.object(gate.subprocess, "run") as run:
            run.return_value.stdout = b" M changed-file"
            with self.assertRaisesRegex(ValueError, "M0_DIRTY_SOURCE"):
                gate.source_commit()

    def test_detached_hashes_no_overwrite_and_false_acceptance_reject(self):
        with (
            tempfile.TemporaryDirectory() as temporary,
            patch.object(gate, "source_commit", return_value=SOURCE),
        ):
            folder = Path(temporary) / "bundle"
            gate.publish(output=folder)
            self.assertEqual(gate.verify_bundle(folder)["status"], "BLOCKED")
            with self.assertRaises(FileExistsError):
                gate.publish(output=folder)
            original = (folder / "report.json").read_bytes()
            (folder / "report.json").write_bytes(original + b" ")
            with self.assertRaisesRegex(ValueError, "M0_BUNDLE_CHANGED"):
                gate.verify_bundle(folder)
            forged = json.loads(original)
            forged.update(accepted=True, status="ACCEPTED")
            raw = json.dumps(forged).encode()
            (folder / "report.json").write_bytes(raw)
            manifest = json.loads((folder / "manifest.json").read_bytes())
            manifest["report.json"] = gate.campaign.sha(raw)
            (folder / "manifest.json").write_text(json.dumps(manifest))
            with self.assertRaisesRegex(ValueError, "M0_FALSE_ACCEPTANCE"):
                gate.verify_bundle(folder)

    def test_acceptance_cli_rejects_blocked_bundle_but_audit_and_check_are_explicit(self):
        command = [sys.executable, "tools/m0_acceptance.py"]
        with (
            tempfile.TemporaryDirectory() as temporary,
            patch.object(gate, "source_commit", return_value=SOURCE),
        ):
            folder = Path(temporary) / "bundle"
            gate.publish(output=folder)
            for flags, expected in (
                (["--check"], 0),
                (["--verify", str(folder)], 1),
                (["--verify", str(folder), "--audit-only"], 0),
            ):
                result = subprocess.run(
                    command + flags, cwd=gate.ROOT, capture_output=True, timeout=30
                )
                self.assertEqual(result.returncode, expected)


if __name__ == "__main__":
    unittest.main()
