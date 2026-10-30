"""Synthetic acceptance prerequisites only; no actual project approvals are created."""

import copy
import subprocess
import sys
import unittest
from pathlib import Path
from typing import Any
from unittest.mock import patch

import test_m0_candidate as fixtures
import test_review_evidence as reviews

from kryvola_platform import release_set as rs
from tools import m0_accept as gate


class AcceptTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.CandidateTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        f = self.fixture
        self.root = f.root / "request"
        self.root.mkdir()
        composition = self.root / "composition"
        (composition / "candidate").mkdir(parents=True)
        (composition / "live").mkdir()
        with patch.object(rs.Cosign, "verify_publisher"):
            candidate, lock = f.assemble()
        self.base = rs._json(candidate)
        self.releases = {
            name: {
                "source": f.selection["components"][name]["publisher_source"],
                "assets": {
                    **rs._json((f.root / name / "manifest.json").read_bytes())["subjects"],
                    "manifest.json": f.selection["components"][name]["manifest_sha256"],
                    "manifest.sigstore.json": rs._sha(
                        (f.root / name / "manifest.sigstore.json").read_bytes()
                    ),
                },
            }
            for name in ("fabric", "engines")
        }
        retained = {
            "candidate/candidate.json": candidate,
            "candidate/lock.json": lock,
            "candidate/selection.json": gate.m0_candidate.encode(f.selection),
            "candidate/model.json": f.model_raw,
            "candidate/measurement.json": f.report_raw,
        }
        source = self.base["components"]["platform"]["source_revision"]
        images = {
            n: v["image"]
            for n, v in gate.m0_acceptance.integration.configuration()["services"].items()
        }
        records = {
            "release-conformance-report.json": {
                "kind": "EXPERIMENTAL_FIXTURE_SET_CONFORMANT",
                "platform_commit": source,
                "production_ready": False,
                "full_five_component_candidate": "NOT_SUBMITTED",
                "packages": self.releases,
                "live_checks": "PUBLISHED_NATIVE_FAKE_AND_TEMPORAL_REPLAY_PASSED",
                "negative_controls": [
                    {"case": c, "exit_code": 1}
                    for c in gate.m0_acceptance.release_conformance.CASES
                ],
                "images": {
                    n: {"service": n, "reference": ref, "id": "sha256:" + "a" * 64}
                    for n, ref in images.items()
                },
            },
            "fake-workflow-report.json": {
                "kind": "PUBLIC_FAKE_ENGINE_SELFTEST",
                "driver_commit": source,
                "production_ready": False,
                "profile_enabled": False,
                "releases": self.releases,
            },
            "network-report.json": {
                "kind": "PUBLIC_HTTP_FIXTURE_ONLY",
                "source_commit": source,
                "production_qualified": False,
                "images": images,
            },
            "isolation-report.json": {
                "kind": "LOCAL_SYNTHETIC_ISOLATION_ONLY",
                "production_qualified": False,
                "canary_type": "SYNTHETIC_NON_KEY",
                "owner_positive_control": True,
                "probes": {
                    n: {"positive_control": True, "denials": [{"denied": True}] * count}
                    for n, count in (("ray", 5), ("redpanda", 3), ("temporal", 3))
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
        retained.update({"live/" + n: gate.m0_candidate.encode(v) for n, v in records.items()})
        retained["live/network-observations.jsonl"] = b"{}\n"
        for name, raw in retained.items():
            (composition / name).write_bytes(raw)
        report = {
            "kind": "EXACT_NONPRODUCTION_FIXTURE_COMPOSITION_TESTED",
            "candidate_sha256": rs._sha(candidate),
            "input_lock_sha256": rs._sha(lock),
            "platform_source": source,
            "components": self.base["components"],
            "cleanup_verified": True,
            "production_ready": False,
            "m0_accepted": False,
            "m1_admitted": False,
            "subjects": {n: rs._sha(v) for n, v in retained.items()},
        }
        report_raw = gate.m0_candidate.encode(report)
        (composition / "report.json").write_bytes(report_raw)
        ratification = {
            "version": 1,
            "status": "RATIFIED_FOR_M0_NONPRODUCTION",
            "scope": gate.review_evidence.SCOPE,
            "contract_revision": rs.SPEC_REVISION,
            "candidate_sha256": rs._sha(candidate),
            "composition_sha256": rs._sha(report_raw),
            "exclusions": ["Synthetic fixture-only acceptance"],
            "conditions": [],
        }
        ratification_raw = gate.m0_candidate.encode(ratification)
        legal = {
            "version": 1,
            "disposition": "REVIEWED_ALLOWED_NONPRODUCTION_FAKE_ONLY",
            "intended_use": f.selection["intended_use"],
            "parameter_set_digest": self.base["workload"]["parameter_set_digest"],
            "parameter_security": "APPROVED_RESEARCH_BASELINE_ONLY",
            "crypto_permissions": "DISTRIBUTION_SERVICE_DENIED",
            "conditions": [],
        }
        legal_raw = gate.m0_candidate.encode(legal)
        admitted = copy.deepcopy(self.base)
        admitted.update(
            ratification_revision="c" * 40,
            legal={
                "disposition": "REVIEWED_ALLOWED",
                "intended_use": legal["intended_use"],
                "evidence_sha256": [rs._sha(legal_raw)],
            },
        )
        admitted_raw = gate.m0_candidate.encode(admitted)
        self.raw = {
            "ratification.json": ratification_raw,
            "legal.json": legal_raw,
            "admitted-candidate.json": admitted_raw,
            "admitted-candidate.sigstore.json": b"fixture-signature",
        }
        subjects = {
            "candidate.json": candidate,
            "admitted-candidate.json": admitted_raw,
            "selection.json": retained["candidate/selection.json"],
            "model.json": f.model_raw,
            "measurement.json": f.report_raw,
            "ratification.json": ratification_raw,
            "composition-report.json": report_raw,
            "legal.json": legal_raw,
            "generated/manifest.json": rs._MANIFEST,
        }
        packet = {
            "version": 1,
            "scope": gate.review_evidence.SCOPE,
            "contract_revision": rs.SPEC_REVISION,
            "composition_sha256": rs._sha(report_raw),
            "candidate_digests": {n: rs._sha(v) for n, v in subjects.items()},
            "exclusions": ratification["exclusions"],
        }
        packet_raw = gate.m0_candidate.encode(packet)
        self.raw["review-packet.json"] = packet_raw
        reviewer = reviews.ReviewTests()
        reviewer.setUp()
        trust = reviewer.trust
        trust.update(subject_sha256=rs._sha(packet_raw), intended_use=legal["intended_use"])
        (self.root / "reviews").mkdir()
        for role, (raw, bundle) in reviewer.evidence.items():
            decision = rs._json(raw)
            decision.update(subject_sha256=rs._sha(packet_raw), intended_use=legal["intended_use"])
            data = gate.m0_candidate.encode(decision)
            trust["roles"][role]["evidence_sha256"] = rs._sha(data)
            slug = role.lower().replace(" ", "-")
            self.raw["reviews/" + slug + ".json"] = data
            self.raw["reviews/" + slug + ".sigstore.json"] = bundle
        for name, raw in self.raw.items():
            (self.root / name).write_bytes(raw)
        self.policy: dict[str, Any] = {
            "composition_sha256": rs._sha(report_raw),
            "ratification_sha256": rs._sha(ratification_raw),
            "selection_sha256": rs._sha(retained["candidate/selection.json"]),
            "ratification_revision": "c" * 40,
            "review_trust": trust,
            "release_policy": {
                "candidate_sha256": rs._sha(admitted_raw),
                "intended_use": legal["intended_use"],
                "reviewer_key": "-----BEGIN PUBLIC KEY-----\nfixture",
                "components": {
                    n: {
                        "reference": c["reference"],
                        "builder_id": c["builder_id"],
                        "build_type": c["build_type"],
                        "source": c["publisher_source"],
                        "manifest_sha256": c["manifest_sha256"],
                        "subject": c["subject"],
                    }
                    for n, c in f.selection["components"].items()
                },
            },
        }

    def evaluate(self):
        with (
            patch.object(rs.Cosign, "verify"),
            patch.object(rs.Cosign, "verify_publisher"),
            patch.object(
                gate.m0_acceptance, "inputs", return_value=(None, None, self.releases, None)
            ),
        ):
            return gate.evaluate(
                self.root,
                self.fixture.root,
                self.policy,
                rs.Cosign(Path("fixture")),
                now=reviews.NOW,
            )

    def test_synthetic_complete_evaluation_allows_development_only(self):
        result = self.evaluate()
        self.assertTrue(result["accepted"])
        self.assertFalse(result["production_ready"])
        self.assertFalse(result["profile_enabled"])
        self.assertFalse(result["deployment_authorized"])

    def test_every_approval_and_signed_input_is_required(self):
        for name in self.raw:
            path = self.root / name
            raw = path.read_bytes()
            path.unlink()
            with self.subTest(name=name), self.assertRaises((ValueError, OSError)):
                self.evaluate()
            path.write_bytes(raw)
        for name in ("composition_sha256", "ratification_sha256", "selection_sha256"):
            old = self.policy[name]
            self.policy[name] = "0" * 64
            with self.assertRaises(ValueError):
                self.evaluate()
            self.policy[name] = old

    def test_cleanup_stale_controls_isolation_and_promotion_are_rejected(self):
        report_path = self.root / "composition/report.json"
        report_raw = report_path.read_bytes()
        original_pin = self.policy["composition_sha256"]
        for field, value in (
            ("cleanup_verified", False),
            ("production_ready", True),
            ("m0_accepted", True),
            ("candidate_sha256", "0" * 64),
        ):
            report = rs._json(report_raw)
            report[field] = value
            raw = gate.m0_candidate.encode(report)
            report_path.write_bytes(raw)
            self.policy["composition_sha256"] = rs._sha(raw)
            with self.assertRaises(ValueError):
                self.evaluate()
        report_path.write_bytes(report_raw)
        self.policy["composition_sha256"] = original_pin
        for name, mutate, error in (
            (
                "network-report.json",
                lambda r: r.update(source_commit="0" * 40),
                "M0_STALE_LIVE_SOURCE",
            ),
            (
                "release-conformance-report.json",
                lambda r: r["negative_controls"].pop(),
                "M0_NEGATIVE_CONTROLS",
            ),
            (
                "isolation-report.json",
                lambda r: r["probes"]["ray"]["denials"][0].update(denied=False),
                "M0_ISOLATION_FAILURE",
            ),
        ):
            path = self.root / "composition/live" / name
            original = path.read_bytes()
            value = rs._json(original)
            mutate(value)
            raw = gate.m0_candidate.encode(value)
            path.write_bytes(raw)
            report = rs._json(report_raw)
            report["subjects"]["live/" + name] = rs._sha(raw)
            modified_report = gate.m0_candidate.encode(report)
            report_path.write_bytes(modified_report)
            self.policy["composition_sha256"] = rs._sha(modified_report)
            with self.assertRaisesRegex(ValueError, error):
                self.evaluate()
            path.write_bytes(original)
            report_path.write_bytes(report_raw)
            self.policy["composition_sha256"] = original_pin

    def test_missing_artifact_and_unresolved_conditions_cannot_accept(self):
        for role in gate.m0_candidate.COMPONENTS:
            path = self.fixture.root / role / "manifest.json"
            raw = path.read_bytes()
            path.unlink()
            with self.assertRaises((ValueError, OSError)):
                self.evaluate()
            path.write_bytes(raw)
        role = "Security reviewer"
        path = self.root / "reviews/security-reviewer.json"
        decision = rs._json(path.read_bytes())
        decision.update(decision="CONDITIONAL", conditions=["Unresolved fixture finding"])
        raw = gate.m0_candidate.encode(decision)
        path.write_bytes(raw)
        self.policy["review_trust"]["roles"][role]["evidence_sha256"] = rs._sha(raw)
        with self.assertRaises(ValueError):
            self.evaluate()

    def test_cli_missing_trust_rejects_without_traceback_or_output(self):
        result = subprocess.run(
            [
                sys.executable,
                gate.m0_acceptance.__file__,
                "--evaluate",
                str(self.root),
                "--assets",
                str(self.fixture.root),
                "--policy",
                str(self.root / "missing-policy"),
            ],
            capture_output=True,
        )
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, b"")
        self.assertEqual(result.stderr.strip(), b"M0_ACCEPTANCE_REJECTED")

    def test_bad_signature_or_pending_ratification_never_accepts(self):
        with (
            patch.object(rs.Cosign, "verify", side_effect=rs.ReleaseError("SIGNATURE_REJECTED")),
            patch.object(rs.Cosign, "verify_publisher"),
            patch.object(
                gate.m0_acceptance, "inputs", return_value=(None, None, self.releases, None)
            ),
        ):
            with self.assertRaises(rs.ReleaseError):
                gate.evaluate(
                    self.root,
                    self.fixture.root,
                    self.policy,
                    rs.Cosign(Path("fixture")),
                    now=reviews.NOW,
                )
        path = self.root / "ratification.json"
        value = rs._json(path.read_bytes())
        value["status"] = "PENDING"
        raw = gate.m0_candidate.encode(value)
        path.write_bytes(raw)
        self.policy["ratification_sha256"] = rs._sha(raw)
        with self.assertRaises(ValueError):
            self.evaluate()
