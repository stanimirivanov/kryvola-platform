"""Synthetic temporary publication fixtures; no actual acceptance or network publication."""

import io
import tarfile
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import Mock, patch

from tools import m0_publication as publication

SOURCE = "a" * 40
RESULT = {
    "accepted": True,
    "production_ready": False,
    "profile_enabled": False,
    "deployment_authorized": False,
    "kind": "synthetic fixture only",
}


class PublicationTests(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.request = self.root / "request"
        for name in publication.FILES:
            path = self.request / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"{}")
        self.output = self.root / "output"
        self.policy = b'{"fixture_only":true}'
        self.verifier = Mock()

    def prepare(self):
        with patch.object(publication.m0_accept, "evaluate", return_value=RESULT):
            return publication.prepare(
                self.request, self.root, self.policy, SOURCE, self.output, self.verifier
            )

    def test_missing_approvals_or_failed_evaluation_create_no_payload(self):
        with patch.object(publication.m0_accept, "evaluate", side_effect=ValueError("pending")):
            with self.assertRaises(ValueError):
                publication.prepare(
                    self.request, self.root, self.policy, SOURCE, self.output, self.verifier
                )
        self.assertFalse(self.output.exists())
        (self.request / "reviews/legal-reviewer.json").unlink()
        with self.assertRaises(ValueError):
            publication.prepare(
                self.request, self.root, self.policy, SOURCE, self.output, self.verifier
            )
        self.assertFalse(self.output.exists())

    def test_download_verification_re_evaluates_and_refuses_unauthenticated_inputs(self):
        sha = self.prepare()
        (self.output / "acceptance.sigstore.json").write_bytes(b"fixture")
        with patch.object(publication.m0_accept, "evaluate", return_value=RESULT) as evaluate:
            result = publication.verify(
                self.output, self.root, self.policy, SOURCE, sha, self.verifier
            )
            self.assertEqual(result, RESULT)
            evaluate.assert_called_once()
            self.assertEqual(
                self.verifier.verify_publisher.call_args.args[-2:], (publication.IDENTITY, SOURCE)
            )
        with patch.object(publication.m0_accept, "evaluate", side_effect=ValueError("revoked")):
            with self.assertRaises(ValueError):
                publication.verify(self.output, self.root, self.policy, SOURCE, sha, self.verifier)
        for source, digest, policy in (
            ("b" * 40, sha, self.policy),
            (SOURCE, "0" * 64, self.policy),
            (SOURCE, sha, b"{}"),
        ):
            with self.assertRaises(ValueError):
                publication.verify(self.output, self.root, policy, source, digest, self.verifier)
        self.verifier.verify_publisher.side_effect = ValueError("wrong signer")
        with self.assertRaises(ValueError):
            publication.verify(self.output, self.root, self.policy, SOURCE, sha, self.verifier)

    def test_incomplete_download_and_changed_report_archive_reject(self):
        sha = self.prepare()
        with self.assertRaises(ValueError):
            publication.verify(self.output, self.root, self.policy, SOURCE, sha, self.verifier)
        (self.output / "acceptance.sigstore.json").write_bytes(b"fixture")
        (self.output / "evidence.tar").write_bytes(b"changed report archive")
        with self.assertRaises(ValueError):
            publication.verify(self.output, self.root, self.policy, SOURCE, sha, self.verifier)

    def test_even_signed_malformed_archives_cannot_escape_the_evidence_allowlist(self):
        self.prepare()
        (self.output / "acceptance.sigstore.json").write_bytes(b"fixture")
        with tarfile.open(self.output / "evidence.tar", "w") as archive:
            entry = tarfile.TarInfo("../escaped.json")
            entry.size = 2
            archive.addfile(entry, io.BytesIO(b"{}"))
        payload = publication.rs._json((self.output / "acceptance.json").read_bytes())
        payload["evidence_sha256"] = publication.rs._artifact_digest(self.output / "evidence.tar")
        raw = publication.encode(payload)
        (self.output / "acceptance.json").write_bytes(raw)
        with self.assertRaises(ValueError):
            publication.verify(
                self.output, self.root, self.policy, SOURCE, publication.rs._sha(raw), self.verifier
            )
        self.assertFalse((self.root / "escaped.json").exists())

    def test_allowlist_excludes_extra_keys_and_preserves_exact_evidence(self):
        (self.request / "private.key").write_bytes(b"not a real key")
        self.prepare()
        with tarfile.open(self.output / "evidence.tar") as archive:
            self.assertEqual(set(archive.getnames()), publication.FILES)
            self.assertNotIn("private.key", archive.getnames())
        with self.assertRaises(ValueError):
            self.prepare()

    def test_workflow_is_opt_in_main_only_and_write_permissions_are_separate(self):
        workflow = (
            Path(publication.__file__).resolve().parents[1] / ".github/workflows/m0-acceptance.yml"
        ).read_text()
        self.assertEqual(workflow.count("vars.M0_ACCEPTANCE_PUBLICATION_ENABLED == 'true'"), 2)
        self.assertIn("needs: qualify", workflow)
        self.assertIn("environment: m0-acceptance", workflow)
        self.assertIn("M0_ACCEPTANCE_POLICY_JSON", workflow)
        self.assertNotIn("contents: write", workflow.split("  publish:")[0])
        self.assertNotIn("--clobber", workflow)
