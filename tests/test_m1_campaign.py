"""Measured campaigns reject incomplete observations and unsupported cache claims."""

import unittest
from unittest.mock import patch


class CampaignTests(unittest.TestCase):
    def test_campaign_requires_committed_source_before_provisioning(self):
        from tools import m1_campaign as campaign

        with (
            patch.object(campaign, "source_identity", return_value={"source_tree_clean": False}),
            patch.object(campaign, "run_pair") as run,
        ):
            with self.assertRaises(ValueError):
                campaign.campaign(1)
            run.assert_not_called()

    def test_campaign_rejects_source_changes_during_measurement(self):
        from tools import m1_campaign as campaign

        with (
            patch.object(
                campaign,
                "source_identity",
                side_effect=[
                    {"source": "a", "source_tree_clean": True},
                    {"source": "b", "source_tree_clean": True},
                ],
            ),
            patch.object(campaign, "run_pair", return_value=[self.sample()]),
        ):
            with self.assertRaises(ValueError):
                campaign.campaign(1)

    def sample(self, state="COLD"):
        from test_m1_inference import report

        from tools import m1_campaign as campaign

        return {
            "cache_state": state,
            "outcome": "SUCCEEDED",
            "measurements": {
                "stages_ns": dict.fromkeys(campaign.STAGES, 10),
                "request_ns": 50,
                "audit_ns": 20,
                "input_bytes": 60000,
                "output_bytes": 200,
                "key_context_digest": "a" * 64,
                "plan_digest": "b" * 64,
                "profile": "FHE-Q1",
            },
            "memory_peak_bytes": {"owner": 100, "engine": 200, "ray": 300},
            "key_context_state": "FRESH",
            "engine_key_cache": "UNOBSERVED",
            "qualification": report(),
        }

    def test_observations_require_complete_integer_nanoseconds_and_real_bindings(self):
        from tools.m1_campaign import validate_sample

        validate_sample(self.sample())
        for field, value in (
            ("request_ns", 51),
            ("input_bytes", -1),
            ("audit_ns", True),
            ("stages_ns", {"owner_prepare": 10}),
            ("profile", "OTHER"),
        ):
            sample = self.sample()
            sample["measurements"][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                validate_sample(sample)
        sample = self.sample()
        sample["engine_key_cache"] = "HIT"
        with self.assertRaises(ValueError):
            validate_sample(sample)

    def test_summary_counts_failures_and_does_not_infer_p95_from_one_success(self):
        from tools.m1_campaign import summarize

        summary = summarize(
            [self.sample(), {"cache_state": "WARM_SERVICES", "outcome": "FAILED"}], 1000
        )
        self.assertEqual(summary["COLD"]["successful"], 1)
        self.assertEqual(summary["WARM_SERVICES"]["failed"], 1)
        self.assertFalse(summary["COLD"]["request_ns"]["descriptive_sample_sufficiency"]["p95"])
        self.assertIsNone(summary["WARM_SERVICES"]["request_ns"]["values_ns"]["p95"])
        substituted = self.sample("WARM_SERVICES")
        substituted["qualification"]["engine_config_sha256"] = "f" * 64
        with self.assertRaises(ValueError):
            summarize([self.sample(), substituted], 1000)

    def test_failed_cold_request_prevents_warm_reuse_and_always_cleans_up(self):
        from tools import m1_campaign as campaign

        with (
            patch.object(campaign.m1, "Stack") as factory,
            patch.object(campaign, "processes", return_value=["stable"]),
            patch.object(campaign, "measure", side_effect=ValueError("private detail")) as measure,
        ):
            rows = campaign.run_pair()
        self.assertEqual([r["outcome"] for r in rows], ["FAILED", "NOT_RUN"])
        self.assertNotIn("private detail", str(rows))
        factory.return_value.close.assert_called_once()
        measure.assert_called_once()
