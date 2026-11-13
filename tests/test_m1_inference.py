"""Qualification cannot turn incomplete, stale or oversized evidence green."""

import copy
import sys
import unittest

from tools import m1_assets


def report():
    locked = m1_assets.load()
    return {
        "schema_version": "platform-m1-inference-v1",
        "assurance": "CONFIDENTIALITY_ONLY",
        "owner_reference_match": True,
        "logs_clean": True,
        "bounds_checked": True,
        "engine_config_sha256": locked["permissions"]["image_sha256"],
        "invocation": "kryvola-m1-0123456789ab",
        "execution": {
            "execution_id": "exec-" + "1" * 64,
            "workflow_id": "compute-" + "2" * 64,
            **{
                key: "3" * 64
                for key in (
                    "disclosure_id",
                    "receipt_digest",
                    "release_digest",
                    "output_manifest_digest",
                )
            },
        },
        "release_manifests": {
            r: c["assets"]["manifest.json"]["sha256"] for r, c in locked["components"].items()
        },
        "history": {"events": 24, "payload_max_bytes": 2048},
        "broker": {"events": 2, "payload_max_bytes": 256},
        "images": {
            role: "sha256:" + "a" * 64
            for role in (
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
        "receipt_assurance": "CONFIDENTIALITY_ONLY",
        "release_assurance": "CONFIDENTIALITY_ONLY",
        "frozen_reference_sha256": (
            "16268b514e2d8618113d439052975909dd8642bb3c374c1e6bf53a2d477bac21"
        ),
    }


class InferenceEvidenceTests(unittest.TestCase):
    def test_capture_rejects_oversized_child_output(self):
        from tools.m1_inference import capture

        with self.assertRaisesRegex(ValueError, "M1_EVIDENCE_BOUND"):
            capture([sys.executable, "-c", "print('x'*1024)"], 128)
        self.assertEqual(capture([sys.executable, "-c", "print('ok')"], 128), b"ok\n")
        with self.assertRaisesRegex(ValueError, "M1_EVIDENCE_TIMEOUT"):
            capture([sys.executable, "-c", "import time; time.sleep(30)"], 128, timeout=0.05)

    def test_incomplete_or_stale_evidence_is_rejected(self):
        from tools.m1_inference import validate_report

        mutations = (
            lambda r: r.update(owner_reference_match=False),
            lambda r: r.update(logs_clean=False),
            lambda r: r.update(engine_config_sha256="0" * 64),
            lambda r: r["release_manifests"].update(fabric="0" * 64),
            lambda r: r["history"].update(payload_max_bytes=32769),
            lambda r: r["images"].pop("engine"),
            lambda r: r.update(plaintext=[1, 2]),
            lambda r: r["execution"].update(receipt_digest="not-a-digest"),
        )
        for mutate in mutations:
            value = copy.deepcopy(report())
            mutate(value)
            with self.assertRaisesRegex(ValueError, "M1_INFERENCE_REPORT"):
                validate_report(value, m1_assets.load())

    def test_complete_bounded_evidence_is_accepted(self):
        from tools.m1_inference import validate_report

        value = report()
        self.assertEqual(validate_report(value, m1_assets.load()), value)

    def test_logs_reject_credentials_and_private_key_material(self):
        from tools.m1_inference import check_logs

        for raw in (b"Bearer " + b"a" * 64, b"-----BEGIN PRIVATE KEY-----", b"log " + b"b" * 48):
            with self.assertRaisesRegex(ValueError, "M1_INFERENCE_LOG_SECRET"):
                check_logs(raw, [b"b" * 48])
        check_logs(b"runtime ready; workflow completed", [b"b" * 48])

    def test_public_security_wording_is_distinct_from_private_values(self):
        from tools.m1_inference import check_logs

        check_logs(b"Bearer authentication supported; plaintext transport configuration", [])
        for raw in (b'"plaintext": [7, 15]', b"Authorization: Bearer " + b"a" * 64):
            with self.assertRaisesRegex(ValueError, "M1_INFERENCE_LOG_SECRET"):
                check_logs(raw, [])
