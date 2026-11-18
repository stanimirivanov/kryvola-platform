"""Envelope gates must never upgrade incomplete evidence into a latency claim."""

import copy
import tempfile
import unittest
from pathlib import Path


class EnvelopeTests(unittest.TestCase):
    def campaign(self, pairs=1, seconds=1):
        from test_m1_campaign import CampaignTests

        from tools import m1_campaign as c

        rows = []
        for i in range(pairs * 2):
            row = CampaignTests().sample(c.STATES[i % 2])
            row["fixture_setup_ns"] = 10
            row["qualification"]["invocation"] = "kryvola-m1-" + f"{i // 2:012x}"
            for k in row["qualification"]["execution"]:
                old = row["qualification"]["execution"][k]
                row["qualification"]["execution"][k] = old[:-64] + f"{i + 1:064x}"
            row["measurements"].update(
                key_context_digest=f"{i + 1:064x}",
                plan_digest=f"{i + 1:064x}",
                request_ns=seconds * 10**9,
                stages_ns=dict.fromkeys(c.STAGES, seconds * 10**9 // 5),
            )
            rows.append(row)
        return {
            "schema_version": "platform-m1-campaign-v1",
            "assurance": "CONFIDENTIALITY_ONLY",
            **c.source_identity(),
            "source_tree_clean": True,
            "host": {"machine": "x86_64", "kernel": "test", "logical_cpus": 2, "python": "3.14.7"},
            "memory_scope": "container_lifetime_cgroup_v2_peak_bytes",
            "timing_scope": (
                "monotonic_request_excludes_setup_audit_telemetry;throughput_includes_all"
            ),
            "os_image_cache": "UNCONTROLLED",
            "pairs": pairs,
            "campaign_wall_ns": pairs * seconds * 3 * 10**9,
            "observations": rows,
            "summary": c.summarize(rows, pairs * seconds * 3 * 10**9),
        }

    def test_small_samples_only_support_async_local_scope_with_explicit_gaps(self):
        from tools.m1_envelope import build, check

        report = build(self.campaign())
        self.assertEqual(report["decision"], "ASYNCHRONOUS_ONLY")
        self.assertEqual(report["latency"]["COLD"]["status"], "INCONCLUSIVE")
        self.assertFalse(report["production_ready"])
        self.assertIn("production_activation", report["externally_unapproved"])
        self.assertIn("engine_key_cache", report["inconclusive"])
        check(report)
        for field, value in (
            ("decision", "SYNCHRONOUS_SUPPORTED"),
            ("production_ready", True),
            ("production_ready", 0),
            ("policy_sha256", "0" * 64),
        ):
            forged = copy.deepcopy(report)
            forged[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                check(forged)

    def test_twenty_samples_distinguish_met_and_missed_objectives_without_activation(self):
        from tools.m1_envelope import build

        for seconds, expected in ((1, "OBJECTIVE_MET"), (20, "OBJECTIVE_MISSED")):
            report = build(self.campaign(20, seconds))
            self.assertEqual(report["latency"]["WARM_SERVICES"]["status"], expected)
            self.assertEqual(report["decision"], "ASYNCHRONOUS_ONLY")

    def test_missing_stages_wrong_units_stale_bindings_and_duplicate_evidence_fail(self):
        from tools.m1_envelope import build

        mutations = (
            lambda r: r["observations"][0]["measurements"]["stages_ns"].pop("admission"),
            lambda r: r["observations"][0]["measurements"].update(request_ns=True),
            lambda r: r["observations"][0]["measurements"].update(profile="OTHER"),
            lambda r: r["harness_sha256"].update({"compose.m1.yaml": "0" * 64}),
            lambda r: r["summary"]["COLD"].update(successful=99),
            lambda r: r["summary"]["COLD"].update(successful=1.0),
            lambda r: r.update(pairs=2),
            lambda r: r["observations"].reverse(),
            lambda r: r["observations"][1].update(
                measurements=copy.deepcopy(r["observations"][0]["measurements"])
            ),
            lambda r: r["observations"][0]["qualification"]["release_manifests"].update(
                fabric="0" * 64
            ),
            lambda r: r.update(source_tree_clean=False),
            lambda r: r.update(source="0" * 40),
            lambda r: r.update(campaign_wall_ns=1000),
            lambda r: r["observations"][0]["measurements"].pop("input_bytes"),
            lambda r: r["observations"][0]["memory_peak_bytes"].update(owner=2 << 30),
        )
        for mutate in mutations:
            raw = self.campaign()
            mutate(raw)
            with self.subTest(mutation=mutate), self.assertRaises(ValueError):
                build(raw)

    def test_failed_or_unrun_requests_cannot_qualify_an_envelope(self):
        from tools import m1_campaign as c
        from tools.m1_envelope import build, check

        raw = self.campaign()
        raw["observations"] = [
            {"cache_state": "COLD", "outcome": "FAILED", "error_type": "ValueError"},
            {"cache_state": "WARM_SERVICES", "outcome": "NOT_RUN"},
        ]
        raw["summary"] = c.summarize(raw["observations"], raw["campaign_wall_ns"])
        report = build(raw)
        self.assertEqual(report["decision"], "INCONCLUSIVE")
        with self.assertRaises(ValueError):
            check(report)

    def test_reader_rejects_duplicate_fields_and_oversized_artifacts(self):
        from tools.m1_envelope import read

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"
            for raw in (b'{"decision":1,"decision":2}', b" " * ((1 << 20) + 1)):
                path.write_bytes(raw)
                with self.assertRaises(ValueError):
                    read(path)

    def test_workflow_publishes_fresh_report_and_checks_committed_snapshot(self):
        from tools import m1

        text = (m1.ROOT / ".github/workflows/integration.yml").read_text()
        self.assertIn("tools.m1_envelope measure build/m1-supported-envelope.json", text)
        self.assertIn("tools.m1_envelope check evidence/m1-supported-envelope.json", text)
