"""A process error alone must never turn a recovery campaign green."""

import copy
import unittest


class RecoveryEvidenceTests(unittest.TestCase):
    def test_campaign_covers_both_sides_of_every_named_fault(self):
        from tools.m1_recovery import CASES

        self.assertEqual(
            set(CASES),
            {
                f"{kind}-{side}"
                for kind in (
                    "duplicate",
                    "lost",
                    "reordered",
                    "bridge",
                    "worker",
                    "completion",
                    "corrupt",
                    "oversized",
                )
                for side in ("before", "after")
            },
        )

    def test_missing_or_contradictory_evidence_is_rejected(self):
        from tools.m1_recovery import validate_case

        value = {
            "case": "completion-after",
            "retry_attempt_max": 2,
            "workflow_runs": 1,
            "native_state": "SUCCEEDED",
            "native_error": "NONE",
            "output_uploads": 1,
            "distinct_output_uploads": 1,
            "finalized_outputs": 1,
            "boundary_observed": True,
            "process_killed": True,
            "outcome": "RELEASED",
            "workflow_status": "COMPLETED",
            "executions": 1,
            "receipts": 1,
            "selections": 1,
            "disclosures": 1,
            "current_selections": 1,
            "immutable_objects_checked": 3,
            "pins_checked": 1,
            "history_events": 40,
            "history_payload_max_bytes": 2048,
            "execution_ids": ["exec-" + "a" * 64],
            "logs_clean": True,
        }
        validate_case(value)
        for key, bad in (
            ("boundary_observed", False),
            ("retry_attempt_max", 1),
            ("workflow_runs", 2),
            ("native_state", "CREATED"),
            ("distinct_output_uploads", 0),
            ("process_killed", False),
            ("selections", 2),
            ("current_selections", 0),
            ("immutable_objects_checked", 0),
            ("pins_checked", 0),
            ("history_events", 0),
            ("logs_clean", False),
            ("workflow_status", "RUNNING"),
        ):
            changed = copy.deepcopy(value)
            changed[key] = bad
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, "M1_RECOVERY_EVIDENCE"):
                validate_case(changed)

    def test_partial_or_stale_reports_cannot_qualify_the_whole_campaign(self):
        from tools.m1_recovery import validate_report

        for report in (
            {},
            {"schema_version": "platform-m1-recovery-v1", "cases": []},
            {"schema_version": "platform-m1-recovery-v1", "qualified": True, "cases": []},
        ):
            with self.assertRaisesRegex(ValueError, "M1_RECOVERY_REPORT"):
                validate_report(report)

    def test_complete_source_bound_report_and_all_segments_are_required(self):
        import hashlib
        import json
        import subprocess
        import tempfile
        from pathlib import Path

        from tools import m1, m1_assets
        from tools.m1_recovery import (
            CASES,
            GROUPS,
            harness_digest,
            validate_report,
            verify_segments,
        )

        locked = m1_assets.load()
        report: dict = {
            "schema_version": "platform-m1-recovery-v1",
            "assurance": "CONFIDENTIALITY_ONLY",
            "qualified": True,
            "platform_source": subprocess.check_output(
                ["git", "rev-parse", "HEAD"], text=True
            ).strip(),
            "harness_sha256": harness_digest(),
            "lock_sha256": hashlib.sha256(
                (m1.ROOT / "config/m1.lock.json").read_bytes()
            ).hexdigest(),
            "release_manifests": {
                k: v["assets"]["manifest.json"]["sha256"] for k, v in locked["components"].items()
            },
            "requested_cases": list(CASES),
            "cases": [],
        }
        for name in CASES:
            rejected = name in {"corrupt-before", "oversized-before"}
            failed = name in {"worker-before", "corrupt-after", "oversized-after"}
            count = 0 if rejected else 2 if name.startswith("duplicate-") else 1
            value = {
                "case": name,
                "native_state": None
                if rejected
                else "RUNNING"
                if name == "worker-before"
                else "FAILED"
                if failed
                else "SUCCEEDED",
                "native_error": None
                if rejected
                else "UNAVAILABLE"
                if failed and name != "worker-before"
                else "NONE",
                "output_uploads": 1
                if name == "worker-before"
                else 0
                if rejected or failed
                else count,
                "distinct_output_uploads": 1
                if name == "worker-before"
                else 0
                if rejected or failed
                else count,
                "finalized_outputs": 1
                if name == "worker-before"
                else 0
                if rejected or failed
                else count,
                "boundary_observed": True,
                "process_killed": True,
                "outcome": "REJECTED" if rejected else "FAILED" if failed else "RELEASED",
                "workflow_status": "NOT_STARTED"
                if rejected
                else "FAILED"
                if failed
                else "COMPLETED",
                "executions": count,
                "receipts": 0 if failed else count,
                "selections": int(not (rejected or failed)),
                "disclosures": int(not (rejected or failed)),
                "current_selections": int(not (rejected or failed)),
                "immutable_objects_checked": 0 if rejected else 2,
                "staging_objects_checked": 2,
                "pins_checked": 0 if rejected else 2,
                "history_events": 0 if rejected else 40,
                "history_payload_max_bytes": 0 if rejected else 2048,
                "retry_attempt_max": 0 if rejected else 2,
                "workflow_runs": 0 if rejected else 1,
                "execution_ids": ["exec-" + str(n) * 64 for n in range(1, count + 1)],
                "logs_clean": True,
                "object_inventory_sha256": "b" * 64,
                "engine_config_sha256": locked["permissions"]["image_sha256"],
                "images": {
                    r: "sha256:" + "c" * 64
                    for r in (
                        "runtime",
                        "workflow",
                        "messaging",
                        "ray",
                        "engine",
                        "owner",
                        "postgres",
                        "temporal",
                        "storage",
                        "broker",
                    )
                },
            }
            report["cases"].append(value)
        validate_report(report)
        for field in ("platform_source", "harness_sha256", "lock_sha256"):
            changed = copy.deepcopy(report)
            changed[field] = "0" * 64
            with (
                self.subTest(field=field),
                self.assertRaisesRegex(ValueError, "M1_RECOVERY_REPORT"),
            ):
                validate_report(changed)
        changed = copy.deepcopy(report)
        changed["cases"][0]["plaintext"] = [7, 15]
        with self.assertRaisesRegex(ValueError, "M1_RECOVERY_REPORT"):
            validate_report(changed)
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            for group, kinds in GROUPS.items():
                part = copy.deepcopy(report)
                part["qualified"] = False
                part["cases"] = [v for v in part["cases"] if v["case"].split("-")[0] in kinds]
                part["requested_cases"] = [v["case"] for v in part["cases"]]
                path = root / ("m1-recovery-" + group)
                path.mkdir()
                (path / "m1-recovery-report.json").write_text(json.dumps(part))
            self.assertTrue(verify_segments(root)["qualified"])
            (path / "m1-recovery-report.json").unlink()
            with self.assertRaises(ValueError):
                verify_segments(root)

    def test_refresh_only_changes_the_expiry_of_unspent_capabilities(self):
        import tempfile
        import time
        from pathlib import Path
        from types import SimpleNamespace

        from tools.m1_recovery import refresh_unspent

        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "secrets").mkdir()
            (root / "secrets/policy.json").write_text("{}")
            pending = {"token_sha256": "a" * 64, "expires_unix_ms": 0, "scope": {"fence": "1"}}
            used = {"token_sha256": "b" * 64, "expires_unix_ms": 0, "scope": {"fence": "1"}}
            owner = {"token_sha256": "c" * 64, "expires_unix_ms": 0}
            from tools.m1_inference import Operator

            operator = Operator(SimpleNamespace(folder=root), {})
            operator.policy = {"grants": [pending, used], "owner_submission_grants": [owner]}
            before = int(time.time() * 1000)
            refresh_unspent(operator, {"a" * 64})
            self.assertGreater(pending["expires_unix_ms"], before)
            self.assertLessEqual(pending["expires_unix_ms"], int(time.time() * 1000) + 45000)
            self.assertEqual(used["expires_unix_ms"], 0)
            self.assertEqual(owner["expires_unix_ms"], 0)
            self.assertEqual(pending["scope"], {"fence": "1"})
