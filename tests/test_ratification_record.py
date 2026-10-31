"""Synthetic successor binding tests; no actual project authority is supplied."""

import copy
import os
import subprocess
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any
from unittest.mock import patch

import test_m0_accept as fixtures
import test_review_evidence as review_fixtures

from kryvola_platform import release_set as rs
from tools import ratification_record as gate


class RecordTests(unittest.TestCase):
    def setUp(self):
        self.f = fixtures.AcceptTests()
        self.f.setUp()
        self.addCleanup(self.f.doCleanups)
        self.root = self.f.root
        report = rs._json((self.root / "composition/report.json").read_bytes())
        archive = b"opaque synthetic retained archive"
        (self.root / "composition/evidence.tar").write_bytes(archive)
        ledger = {
            "version": 1,
            "status": "RECORDED_NONPRODUCTION_QUALIFICATION",
            "components": report["components"],
            "candidate_sha256": report["candidate_sha256"],
            "input_lock_sha256": report["input_lock_sha256"],
            "report_sha256": rs._sha((self.root / "composition/report.json").read_bytes()),
            "evidence": {
                "reference": "https://example.invalid/immutable/archive#sha256=" + rs._sha(archive),
                "archive_sha256": rs._sha(archive),
            },
            "cleanup_verified": True,
            "production_ready": False,
            "m0_accepted": False,
            "m1_admitted": False,
        }
        raw = gate.m0_publication.encode(ledger)
        (self.root / "ledger.json").write_bytes(raw)
        self.git_files = {
            "docs/m0-ratification-proposal.json": (self.root / "ratification.json").read_bytes(),
            "docs/m0-composition-qualification.json": raw,
            "docs/m0-ratification-decision.md": b"synthetic pending history",
        }
        self.record: dict[str, Any] = {
            "version": 1,
            "status": "RECORDED_SUCCESSOR",
            "scope": gate.review_evidence.SCOPE,
            "predecessor_sha256": rs._sha(self.git_files["docs/m0-ratification-decision.md"]),
            "proposal_revision": self.f.policy["ratification_revision"],
            "ledger_sha256": rs._sha(raw),
            "ratification_sha256": self.f.policy["ratification_sha256"],
            "packet_sha256": self.f.policy["review_trust"]["subject_sha256"],
            "reviews": [],
            "production_ready": False,
            "profile_enabled": False,
            "m0_accepted": False,
            "m1_admitted": False,
        }
        for role in gate.review_evidence.ROLES:
            slug = role.lower().replace(" ", "-")
            self.record["reviews"].append(
                {
                    "role": role,
                    "decision_sha256": rs._sha((self.root / f"reviews/{slug}.json").read_bytes()),
                    "bundle_sha256": rs._sha(
                        (self.root / f"reviews/{slug}.sigstore.json").read_bytes()
                    ),
                }
            )
        self.policy = {
            n: self.record[n] for n in ("predecessor_sha256", "proposal_revision", "ledger_sha256")
        }
        self.policy["acceptance_policy"] = self.f.policy

    def verify(self, signature_error=None):
        raw = gate.m0_publication.encode(self.record)
        self.policy["record_sha256"] = rs._sha(raw)
        with (
            patch.object(
                gate, "committed", side_effect=lambda repo, rev, name: self.git_files[name]
            ),
            patch.object(rs.Cosign, "verify", side_effect=signature_error),
            patch.object(rs.Cosign, "verify_publisher"),
            patch.object(
                gate.m0_accept.m0_acceptance, "inputs", return_value=(None, None, self.f.releases)
            ),
        ):
            return gate.verify(
                raw,
                self.root,
                self.f.fixture.root,
                self.policy,
                self.root,
                rs.Cosign(Path("unused")),
                now=review_fixtures.NOW,
            )

    def test_actual_evaluator_delegation_never_returns_admission(self):
        result = self.verify()
        self.assertTrue(result["authenticated"])
        self.assertFalse(result["m0_accepted"])
        self.assertFalse(result["m1_admitted"])
        self.assertFalse(result["deployment_authorized"])

    def test_record_binding_role_and_policy_mismatch_reject(self):
        original = copy.deepcopy(self.record)
        for key, value in (
            ("status", "PROPOSED_SUCCESSOR"),
            ("predecessor_sha256", "0" * 64),
            ("proposal_revision", "b" * 40),
            ("packet_sha256", "0" * 64),
            ("m1_admitted", True),
            ("reviews", []),
        ):
            self.record = {**copy.deepcopy(original), key: value}
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.verify()
        self.record = original
        self.record["reviews"][0]["bundle_sha256"] = "0" * 64
        with self.assertRaises(ValueError):
            self.verify()

    def test_changed_git_subjects_and_request_files_reject(self):
        for name in self.git_files:
            original = self.git_files[name]
            self.git_files[name] = b"changed"
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.verify()
            self.git_files[name] = original
        for name in (
            "ledger.json",
            "composition/evidence.tar",
            "reviews/security-reviewer.json",
            "review-packet.json",
            "composition/live/isolation-report.json",
        ):
            path = self.root / name
            raw = path.read_bytes()
            path.write_bytes(b"changed")
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.verify()
            path.write_bytes(raw)

    def test_freshness_revocation_conditions_and_bad_signatures_propagate(self):
        with self.assertRaises(ValueError):
            self.verify(signature_error=ValueError("bad signature"))
        trust = self.f.policy["review_trust"]
        original = copy.deepcopy(trust)
        for update in (
            {"valid_until": "2000-01-01T00:00:00Z"},
            {"revoked_evidence_sha256": [trust["roles"]["Legal reviewer"]["evidence_sha256"]]},
        ):
            trust.update(update)
            with self.assertRaises(ValueError):
                self.verify()
            trust.clear()
            trust.update(copy.deepcopy(original))
        # Evaluator failures (including real signature/conditional controls tested
        # in existing review tests) must never become authenticated record success.
        with patch.object(gate.m0_accept, "evaluate", side_effect=ValueError("denied")):
            with self.assertRaises(ValueError):
                self.verify()

    def test_independent_record_pin_and_symlink_inputs_fail(self):
        self.policy["record_sha256"] = "0" * 64
        with self.assertRaises(ValueError):
            gate.verify(
                gate.m0_publication.encode(self.record),
                self.root,
                self.root,
                self.policy,
                self.root,
                None,
            )
        path = self.root / "ledger.json"
        raw = path.read_bytes()
        path.unlink()
        target = self.root / "other.json"
        target.write_bytes(raw)
        path.symlink_to(target)
        with self.assertRaises(ValueError):
            self.verify()


class GitTests(unittest.TestCase):
    def test_reads_actual_immutable_commit_and_rejects_symlink_or_noncommit(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)

            def git(*args):
                return subprocess.check_output(
                    ["git", "-C", str(root), *args], stderr=subprocess.DEVNULL
                )

            git("init", "-q")
            (root / "payload").write_bytes(b"committed payload")
            (root / "link").symlink_to("payload")
            git("add", "payload", "link")
            git(
                "-c",
                "user.name=Fixture",
                "-c",
                "user.email=fixture@example.invalid",
                "-c",
                "commit.gpgsign=false",
                "commit",
                "-qm",
                "fixture",
            )
            revision = git("rev-parse", "HEAD").decode().strip()
            (root / "payload").write_bytes(b"dirty bytes ignored")
            with patch.dict(os.environ, {"GIT_DIR": "/not-used"}):
                self.assertEqual(gate.committed(root, revision, "payload"), b"committed payload")
            for name in ("link", "missing"):
                with self.assertRaises(ValueError):
                    gate.committed(root, revision, name)
            with self.assertRaises(ValueError):
                gate.committed(root, "main", "payload")

    def test_cli_rejects_missing_inputs_without_original_diagnostics(self):
        result = subprocess.run(
            [
                sys.executable,
                "tools/ratification_record.py",
                "--record",
                "missing",
                "--request",
                "missing",
                "--assets",
                "missing",
                "--policy",
                "missing",
                "--spec-repository",
                "missing",
            ],
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stderr.strip(), "RATIFICATION_RECORD_REJECTED")
        self.assertEqual(result.stdout, "")
