"""Numeric/provenance negative controls; no crypto is executed by these tests."""

import copy
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from fractions import Fraction
from pathlib import Path
from unittest.mock import patch

from tools import campaign

PROFILE = campaign.ROOT / "config/benchmarks/fhe-q1.json"


class CampaignTests(unittest.TestCase):
    def setUp(self):
        self.config, self.folder = campaign.profile(PROFILE)
        self.first = campaign.load_campaign(self.config, PROFILE, self.folder, 1)

    def test_exact_variance_and_inconclusive_failure_denominator(self):
        self.assertEqual(campaign.variance([10, 14])["numerator"], 8)
        self.assertEqual(campaign.variance([5, 5])["numerator"], 0)
        value = campaign.variance([Fraction(1, 2), Fraction(3, 2)])
        self.assertEqual((value["numerator"], value["denominator"]), (1, 2))
        failed = {"attempt": 2, "outcome": "INCOMPLETE_OR_FAILED", "reports": {}, "metadata": {}}
        report = campaign.summarize([self.first, failed], self.config)
        self.assertEqual(
            (
                report["requested_campaigns"],
                report["successful_campaigns"],
                report["failed_or_incomplete_campaigns"],
            ),
            (2, 1, 1),
        )
        self.assertEqual(report["qualification"], "INCONCLUSIVE")
        self.assertFalse(report["production_qualified"])
        self.assertTrue(all(v["value"] is None for v in report["missing_stages"].values()))
        self.assertIsNone(
            report["owner_and_native_stages"]["keygen"]["variance_ns_squared"]["value"]
        )

    def test_real_numeric_shapes_reject_extra_material_nonintegers_and_false_context(self):
        native = self.first["reports"]["tfhe-eval"]
        mutations = []
        for key, value in (
            ("private_key", "not-a-key"),
            ("production_qualified", True),
            ("cache_state", "WARM_REUSED_KEY"),
        ):
            bad = copy.deepcopy(native)
            bad[key] = value
            mutations.append(bad)
        for value in (-1, True, 1.5, float("nan")):
            bad = copy.deepcopy(native)
            bad["native"]["stages_ns"]["keygen"] = value
            mutations.append(bad)
        bad = copy.deepcopy(native)
        bad["native"]["observations"].pop()
        mutations.append(bad)
        for bad in mutations:
            with self.assertRaises(ValueError):
                campaign.validate_report(bad, self.config)

    def test_proof_mode_and_queue_corruption_reject(self):
        original = self.first["reports"]["proof-modes"]
        for change in ("mode", "queue"):
            bad = copy.deepcopy(original)
            if change == "mode":
                bad["samples"][0]["native"]["mode"] = "GROTH16"
            else:
                bad["samples"][1]["queue_ns"] = 0
            with self.assertRaises(ValueError):
                campaign.validate_report(bad, self.config)

    def test_config_only_and_duplicate_stdout_are_not_measurements(self):
        config = json.dumps(
            {"experiment": "tfhe-eval", "native_executed": False, "status": "configuration_only"}
        ).encode()
        row = json.dumps(self.first["reports"]["tfhe-eval"]).encode()
        self.assertEqual(campaign.extract(config), [])
        self.assertEqual(len(campaign.extract(config + b"\n\x1b[32m" + row + b"\x1b[0m")), 1)
        with self.assertRaisesRegex(ValueError, "CAMPAIGN_DUPLICATE_REPORT"):
            campaign.extract(row + b"\n" + row)

    def test_capture_tamper_and_interruption_are_distinct(self):
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            target = folder / "attempt-1"
            shutil.copytree(self.folder / "attempt-1", target)
            (target / "observations.jsonl").write_bytes(b"tampered")
            with self.assertRaisesRegex(ValueError, "CAMPAIGN_CORPUS_CHANGED"):
                campaign.load_campaign(self.config, PROFILE, folder, 1)
            (target / "manifest.json").unlink()
            missing = campaign.load_campaign(self.config, PROFILE, folder, 1)
            self.assertEqual(missing["outcome"], "INCOMPLETE_OR_FAILED")

    def test_skipped_job_remains_a_failure_instead_of_a_successful_sample(self):
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            target = folder / "attempt-1"
            shutil.copytree(self.folder / "attempt-1", target)
            meta = copy.deepcopy(self.first["metadata"])
            meta["conclusion"] = "failure"
            job = next(j for j in meta["jobs"] if j["name"] == "verify")
            job.update(conclusion="skipped", runner_id=None, runner_name="")
            raw = json.dumps(meta).encode()
            (target / "metadata.json").write_bytes(raw)
            manifest = json.loads((target / "manifest.json").read_bytes())
            manifest["files"]["metadata.json"] = campaign.sha(raw)
            (target / "manifest.json").write_text(json.dumps(manifest))
            result = campaign.load_campaign(self.config, PROFILE, folder, 1)
            self.assertEqual(result["outcome"], "INCOMPLETE_OR_FAILED")
            report = campaign.summarize([self.first, result], self.config)
            self.assertEqual(report["failed_or_incomplete_campaigns"], 1)
            self.assertEqual(report["successful_campaigns"], 1)

    def test_profile_cli_is_offline_and_capture_flags_cannot_be_ignored(self):
        command = [sys.executable, "tools/benchmark.py", "run", "--profile", str(PROFILE)]
        result = subprocess.run(
            command + ["--check-only"],
            cwd=campaign.ROOT,
            capture_output=True,
            check=True,
            timeout=20,
        )
        self.assertIn(b"no network, crypto or services", result.stdout)
        for flags in (
            ["--check-only", "--capture-attempt", "1"],
            ["--check-only", "--output", "unused"],
        ):
            result = subprocess.run(
                command + flags,
                cwd=campaign.ROOT,
                capture_output=True,
                timeout=20,
            )
            self.assertEqual(result.returncode, 2)

    def test_initialization_and_statement_bindings_are_enforced(self):
        second = copy.deepcopy(self.first)
        second["attempt"] = 2
        for job in second["metadata"]["jobs"]:
            job["id"] += 1000000
        for mutation, expected in (
            ("key", "CAMPAIGN_KEY_CONTEXT_REUSED"),
            ("fixture", "CAMPAIGN_WORKLOAD_BINDING_CHANGED"),
            ("proof", "CAMPAIGN_PROOF_STATEMENT_CHANGED"),
        ):
            changed = copy.deepcopy(second)
            if mutation != "key":
                changed["reports"]["tfhe-eval"]["native"]["key_context_blake3"] = "a" * 64
            if mutation == "fixture":
                changed["reports"]["tfhe-eval"]["native"]["fixture_blake3"] = "b" * 64
            if mutation == "proof":
                changed["reports"]["proof-modes"]["samples"][0]["native"]["journal_blake3"] = (
                    "c" * 64
                )
            with (
                patch.object(campaign, "load_campaign", side_effect=[self.first, changed]),
                self.assertRaisesRegex(ValueError, expected),
            ):
                campaign.build_report(PROFILE)

    def test_checked_in_campaigns_and_summary_replay(self):
        report = campaign.build_report(PROFILE)
        self.assertEqual(report["successful_campaigns"], 2)
        self.assertEqual(report["failed_or_incomplete_campaigns"], 0)
        self.assertEqual(report["qualification"], "INCONCLUSIVE")
        self.assertEqual(
            report,
            json.loads((self.folder / "summary.json").read_bytes()),
        )


if __name__ == "__main__":
    unittest.main()
