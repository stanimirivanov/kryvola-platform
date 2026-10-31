"""Synthetic solo policy tests; no owner approval is created or posted."""

import copy
import subprocess
import sys
import unittest
from pathlib import Path
from typing import Any
from unittest.mock import patch

import test_m0_accept as fixtures
import test_review_evidence as reviews

from kryvola_platform import release_set as rs
from tools import solo_m0_review as gate


class SoloTests(unittest.TestCase):
    def setUp(self):
        self.f = fixtures.AcceptTests()
        self.f.setUp()
        self.addCleanup(self.f.doCleanups)
        self.root = self.f.root
        composition = rs._json((self.root / "composition/report.json").read_bytes())
        self.subject = {
            "version": 2,
            "governance": gate.MODE,
            "scope": gate.review_evidence.SCOPE,
            "intended_use": self.f.fixture.selection["intended_use"],
            "candidate_sha256": composition["candidate_sha256"],
            "composition_sha256": self.f.policy["composition_sha256"],
            "selection_sha256": self.f.policy["selection_sha256"],
            "exclusions": ["no production or crypto clearance"],
            "production_ready": False,
            "profile_enabled": False,
        }
        self.report = {
            "version": 1,
            "kind": "AGENTIC_REVIEW",
            "subject_sha256": "",
            "reviewer": "synthetic agent",
            "repositories": list(gate.m0_candidate.COMPONENTS),
            "checks": {
                n: {"status": "PASS", "summary": "synthetic checked evidence"} for n in gate.DOMAINS
            },
            "blockers": [],
            "residual_risks": ["fake only"],
            "limitations": ["not a legal opinion"],
        }
        self.policy = {
            "version": 2,
            "governance": gate.MODE,
            "subject_sha256": "",
            "agentic_review_sha256": "",
            "composition_sha256": self.f.policy["composition_sha256"],
            "selection_sha256": self.f.policy["selection_sha256"],
            "intended_use": self.subject["intended_use"],
            "owner_login": "owner",
            "repository": "stanimirivanov/kryvola-spec",
            "pull_request": 123,
            "approval_comment_id": 456,
            "reviewed_revision": "a" * 40,
            "valid_until": "2030-01-01T00:00:00Z",
            "revoked_comment_ids": [],
        }
        self.refresh()

    def refresh(self):
        raw = gate.m0_candidate.encode(self.subject)
        (self.root / "solo-subject.json").write_bytes(raw)
        self.policy["subject_sha256"] = rs._sha(raw)
        self.report["subject_sha256"] = rs._sha(raw)
        raw = gate.m0_candidate.encode(self.report)
        (self.root / "agentic-review.json").write_bytes(raw)
        self.policy["agentic_review_sha256"] = rs._sha(raw)
        self.pull: dict[str, Any] = {
            "head": {"sha": self.policy["reviewed_revision"]},
            "draft": False,
        }
        self.comment = {
            "id": 456,
            "user": {"login": "owner"},
            "updated_at": "2026-01-01T00:00:00Z",
            "body": gate.approval_body(
                self.policy["subject_sha256"],
                self.policy["agentic_review_sha256"],
                self.policy["intended_use"],
                self.policy["reviewed_revision"],
            ),
        }

    def verify(self, signature_error=None, comments=None):
        with (
            patch.object(rs.Cosign, "verify_publisher", side_effect=signature_error),
            patch.object(
                gate.m0_accept.m0_acceptance, "inputs", return_value=(None, None, self.f.releases)
            ),
        ):
            return gate.verify(
                self.root,
                self.f.fixture.root,
                self.policy,
                rs.Cosign(Path("unused")),
                fetch=lambda _: (self.pull, comments if comments is not None else [self.comment]),
                now=reviews.NOW,
            )

    def test_one_report_and_owner_comment_reuse_real_qualification_checks(self):
        # No eight-role decisions or admitted candidate are consumed by this path.
        for path in (self.root / "reviews").iterdir():
            path.unlink()
        (self.root / "admitted-candidate.json").unlink()
        result = self.verify()
        self.assertTrue(result["owner_approved"])
        self.assertTrue(result["eligible_for_m0_ratification"])
        self.assertFalse(result["m0_accepted"])
        self.assertFalse(result["deployment_authorized"])
        self.assertEqual(self.f.base["legal"]["disposition"], "UNRESOLVED")

    def test_pending_wrong_owner_edit_revocation_and_new_head_reject(self):
        original = copy.deepcopy(self.comment)
        for change in (
            {"body": "PENDING"},
            {"user": {"login": "agent"}},
            {"body": "KRYVOLA_SOLO_OWNER_WITHDRAW"},
            {"updated_at": "2099-01-01T00:00:00Z"},
        ):
            self.comment = {**copy.deepcopy(original), **change}
            with self.assertRaises(ValueError):
                self.verify()
        self.comment = original
        with self.assertRaises(ValueError):
            self.verify(comments=[])
        with self.assertRaises(ValueError):
            self.verify(
                comments=[
                    self.comment,
                    {**self.comment, "id": 457, "body": "KRYVOLA_SOLO_OWNER_WITHDRAW"},
                ]
            )
        self.pull["head"]["sha"] = "b" * 40
        with self.assertRaises(ValueError):
            self.verify()

    def test_incoming_evidence_cannot_select_policy_and_stale_policy_rejects(self):
        for key, value in (
            ("subject_sha256", "0" * 64),
            ("agentic_review_sha256", "0" * 64),
            ("owner_login", "other"),
            ("valid_until", "2000-01-01T00:00:00Z"),
            ("version", 1),
        ):
            original = self.policy[key]
            self.policy[key] = value
            with self.assertRaises(ValueError):
                self.verify()
            self.policy[key] = original

    def test_rehashed_agent_blockers_missing_domains_and_activation_reject(self):
        original = copy.deepcopy(self.report)
        for change in (
            {"blockers": ["unresolved technical defect"]},
            {"checks": {}},
            {"repositories": ["spec"]},
            {"limitations": []},
        ):
            self.report = {**copy.deepcopy(original), **change}
            self.refresh()
            with self.assertRaises(ValueError):
                self.verify()
        self.report = original
        self.subject["production_ready"] = True
        self.refresh()
        with self.assertRaises(ValueError):
            self.verify()

    def test_live_subject_tampering_and_publisher_signature_failure_reject(self):
        with self.assertRaises(ValueError):
            self.verify(signature_error=ValueError("invalid publisher"))
        path = self.root / "composition/live/isolation-report.json"
        path.write_bytes(b"{}")
        with self.assertRaises(ValueError):
            self.verify()

    def test_cli_missing_inputs_cannot_report_approval(self):
        result = subprocess.run(
            [
                sys.executable,
                "tools/solo_m0_review.py",
                "--request",
                "missing",
                "--assets",
                "missing",
                "--policy",
                "missing",
            ],
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stderr.strip(), "SOLO_OWNER_REVIEW_REJECTED")
        self.assertEqual(result.stdout, "")

    def test_owner_comment_revocation_and_authenticated_api_adapter(self):
        self.policy["revoked_comment_ids"] = [456]
        with self.assertRaises(ValueError):
            self.verify()
        self.policy["revoked_comment_ids"] = []
        import json
        from types import SimpleNamespace

        responses = [self.pull, [self.comment]]
        with patch.object(
            gate.subprocess,
            "run",
            side_effect=[SimpleNamespace(stdout=json.dumps(r).encode()) for r in responses],
        ) as run:
            pull, comments = gate.github(self.policy)
        self.assertEqual(run.call_args_list[0].args[0][2:4], ["--hostname", "github.com"])
        self.assertEqual(pull, self.pull)
        self.assertEqual(comments, [self.comment])
        self.assertIn(
            "repos/stanimirivanov/kryvola-spec/issues/123/comments?per_page=100&page=1",
            run.call_args_list[1].args[0],
        )
        self.assertNotIn("--slurp", run.call_args_list[1].args[0])
        with patch.object(
            gate.subprocess, "run", side_effect=subprocess.CalledProcessError(1, "gh")
        ):
            with self.assertRaises(subprocess.CalledProcessError):
                gate.github(self.policy)

    def test_github_crlf_comment_preserves_exact_field_checks(self):
        original = str(self.comment["body"])
        self.comment["body"] = original.replace("\n", "\r\n")
        self.assertTrue(self.verify()["owner_approved"])
        self.comment["body"] = original.replace("\n", "\r")
        with self.assertRaises(ValueError):
            self.verify()
        self.comment["body"] = original.replace("\n", "\r\n").replace(
            str(self.policy["subject_sha256"]), "0" * 64
        )
        with self.assertRaises(ValueError):
            self.verify()

    def test_rest_pagination_does_not_lose_later_owner_comments(self):
        import json
        from types import SimpleNamespace

        responses = [self.pull, [self.comment] * 100, [{**self.comment, "id": 457}]]
        with patch.object(
            gate.subprocess,
            "run",
            side_effect=[SimpleNamespace(stdout=json.dumps(r).encode()) for r in responses],
        ) as run:
            _, comments = gate.github(self.policy)
        self.assertEqual(len(comments), 101)
        self.assertEqual(comments[-1]["id"], 457)
        self.assertTrue(run.call_args_list[-1].args[0][-1].endswith("page=2"))
