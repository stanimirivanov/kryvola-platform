"""Disclosure qualification requires corroborated effects, never error-only success."""

import copy
import unittest


class DisclosureEvidenceTests(unittest.TestCase):
    def test_owner_probes_require_real_fetch_rejection_and_successful_reconnect(self):
        from tools.m1_disclosure import validate_case

        ledger = [["a" * 64, "b" * 64]]
        value: dict = {
            "case": "owner-reconnect",
            "executions": 1,
            "receipts": 1,
            "fence": 0,
            "retired": 0,
            "selections": 1,
            "disclosures": 1,
            "acknowledged": False,
            "stale_status": None,
            "history_events": 30,
            "workflow_status": "COMPLETED",
            "objects": 4,
            "pins": 1,
            "logs_clean": True,
            "boundary_observed": True,
            "before": {"ledger": ledger},
            "checks": {
                "opened": True,
                "keyring_stopped": True,
                **{
                    fault: {"rejected": True, "fetched": True}
                    for fault in ("malformed", "substituted", "unavailable")
                },
            },
            "ledger": ledger,
            "workflow_runs": 1,
        }
        validate_case(value)
        for fault in ("malformed", "substituted", "unavailable"):
            changed = copy.deepcopy(value)
            changed["checks"][fault]["fetched"] = False
            with self.subTest(fault=fault), self.assertRaises(ValueError):
                validate_case(changed)
        for key in ("opened", "keyring_stopped"):
            changed = copy.deepcopy(value)
            changed["checks"][key] = False
            with self.subTest(key=key), self.assertRaises(ValueError):
                validate_case(changed)

    def test_recovery_requires_one_unchanged_disclosure_after_two_real_runs(self):
        from tools.m1_disclosure import validate_case

        ledger = [["a" * 64, "b" * 64]]
        value: dict = {
            "case": "rollover-recovery",
            "executions": 1,
            "receipts": 1,
            "fence": 2,
            "retired": 1,
            "selections": 1,
            "disclosures": 1,
            "acknowledged": False,
            "stale_status": 409,
            "history_events": 30,
            "workflow_status": "COMPLETED",
            "objects": 4,
            "pins": 1,
            "logs_clean": True,
            "boundary_observed": True,
            "before": {"ledger": ledger},
            "checks": {"opened": True, "successor_epoch": "2", "replacement_status": 409},
            "ledger": ledger,
            "workflow_runs": 2,
        }
        validate_case(value)
        for key, bad in (
            ("workflow_runs", 1),
            ("ledger", [["c" * 64, "b" * 64]]),
            ("ledger", [["a" * 64, "c" * 64]]),
            ("disclosures", 2),
        ):
            changed = copy.deepcopy(value)
            changed[key] = bad
            with self.subTest(key=key), self.assertRaises(ValueError):
                validate_case(changed)

        changed = copy.deepcopy(value)
        changed["checks"]["replacement_status"] = 200
        with self.assertRaises(ValueError):
            validate_case(changed)

    def test_cancel_ack_requires_committed_fencing_and_no_new_release(self):
        from tools.m1_disclosure import validate_case

        value: dict = {
            "case": "cancel-before",
            "executions": 1,
            "receipts": 1,
            "fence": 2,
            "retired": 1,
            "selections": 0,
            "disclosures": 0,
            "acknowledged": True,
            "stale_status": 409,
            "history_events": 12,
            "workflow_status": "CANCELED",
            "objects": 3,
            "pins": 1,
            "logs_clean": True,
            "boundary_observed": True,
            "before": {"selections": 0, "disclosures": 0},
            "checks": {"admission_svid_age_ms": 50000},
            "ledger": [],
            "workflow_runs": 1,
        }
        validate_case(value)
        for key, bad in (
            ("fence", 1),
            ("retired", 0),
            ("disclosures", 1),
            ("acknowledged", False),
            ("stale_status", 200),
            ("logs_clean", False),
            ("boundary_observed", False),
        ):
            changed = copy.deepcopy(value)
            changed[key] = bad
            with self.subTest(key=key), self.assertRaises(ValueError):
                validate_case(changed)

        changed = copy.deepcopy(value)
        changed["checks"]["admission_svid_age_ms"] = 0
        with self.assertRaises(ValueError):
            validate_case(changed)

    def test_impossible_oracle_transition_is_rejected(self):
        from tools.m1_disclosure import check_trace

        oracle = {
            "initial": 0,
            "actions": ["cancel-commit", "cancel-ack"],
            "outcomes": ["COMMITTED", "ACKNOWLEDGED"],
            "nodes": [{"edges": [[0, 0, 1]]}, {"edges": [[1, 1, 1]]}],
        }
        check_trace(oracle, [("cancel-commit", "COMMITTED"), ("cancel-ack", "ACKNOWLEDGED")])
        with self.assertRaises(ValueError):
            check_trace(oracle, [("cancel-ack", "ACKNOWLEDGED")])

    def test_partial_or_stale_campaign_cannot_qualify(self):
        from tools.m1_disclosure import validate_report

        for value in (
            {},
            {"qualified": True, "cases": []},
            {"schema_version": "platform-m1-disclosure-v1", "cases": []},
        ):
            with self.assertRaises(ValueError):
                validate_report(value)

    def test_no_missing_or_invalid_segment_can_qualify(self):
        import json
        import tempfile
        from pathlib import Path

        from tools.m1_disclosure import verify_segments

        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ValueError):
                verify_segments(directory)
            for name in ("one", "two", "three"):
                path = Path(directory) / name
                path.mkdir()
                (path / "m1-disclosure-report.json").write_text(json.dumps({"qualified": True}))
            with self.assertRaises(ValueError):
                verify_segments(directory)
