"""Synthetic reviewers only; no project authority or approval is supplied by fixtures."""

import copy
import json
import os
import subprocess
import unittest
from datetime import UTC, datetime
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any
from unittest.mock import Mock

from kryvola_platform.release_set import Cosign, ReleaseError
from tools import review_evidence as reviews

NOW = datetime(2026, 10, 30, 12, tzinfo=UTC)
ROOT = Path(__file__).resolve().parents[1]


def encode(value):
    return json.dumps(value, sort_keys=True).encode()


class ReviewTests(unittest.TestCase):
    def setUp(self):
        self.subject = encode(
            {
                "version": 1,
                "scope": reviews.SCOPE,
                "contract_revision": "a" * 40,
                "candidate_digests": {"fixture-only": "b" * 64},
                "composition_sha256": None,
                "exclusions": ["Synthetic test packet"],
            }
        )
        self.trust: dict[str, Any] = {
            "version": 1,
            "subject_sha256": reviews.digest(self.subject),
            "intended_use": "fixture-only",
            "valid_until": "2026-11-02T00:00:00Z",
            "roles": {},
            "revoked_evidence_sha256": [],
            "revoked_key_sha256": [],
        }
        self.evidence = {}
        for role in reviews.ROLES:
            decision = {
                "version": 1,
                "role": role,
                "identity": "fixture-person",
                "authority": "fixture " + role,
                "decision": "APPROVE",
                "review_url": "https://example.invalid/review",
                "subject_sha256": reviews.digest(self.subject),
                "intended_use": "fixture-only",
                "issued_at": "2026-10-29T00:00:00Z",
                "expires_at": "2026-11-01T00:00:00Z",
                "conditions": [],
                "supersedes_sha256": None,
            }
            self.store(role, decision)
            self.trust["roles"][role] = {
                "identity": "fixture-person",
                "authority": "fixture " + role,
                "public_key": "-----BEGIN PUBLIC KEY-----\nfixture-only\n-----END PUBLIC KEY-----",
                "evidence_sha256": reviews.digest(self.evidence[role][0]),
                "predecessor_sha256": None,
            }

    def store(self, role, decision):
        self.evidence[role] = (encode(decision), b"fixture-signature")
        if role in getattr(self, "trust", {}).get("roles", {}):
            self.trust["roles"][role]["evidence_sha256"] = reviews.digest(self.evidence[role][0])

    def verify(self, verifier=None):
        return reviews.verify_reviews(
            self.subject, self.trust, self.evidence, verifier or Mock(), now=NOW
        )

    def test_authentication_never_accepts_m0_and_unresolved_decisions_block(self):
        verifier = Mock()
        result = self.verify(verifier)
        self.assertEqual(verifier.verify.call_count, 8)
        self.assertFalse(result["m0_accepted"])
        self.assertFalse(result["m1_admitted"])
        for kind in ("REJECT", "CONDITIONAL", "WITHDRAW"):
            role = "Security reviewer"
            decision = json.loads(self.evidence[role][0])
            decision.update(decision=kind, conditions=["Unresolved fixture finding"])
            self.store(role, decision)
            self.assertEqual(self.verify()["blocking_roles"], [role])

    def test_wrong_role_identity_subject_use_and_time_are_rejected(self):
        original = copy.deepcopy(self.evidence)
        for field, value in (
            ("role", "Legal reviewer"),
            ("identity", "other"),
            ("authority", "untrusted"),
            ("subject_sha256", "0" * 64),
            ("intended_use", "production"),
            ("issued_at", "2026-10-31T00:00:00Z"),
            ("expires_at", "2026-10-30T12:00:00Z"),
            ("expires_at", "2026-11-03T00:00:00Z"),
            ("decision", "PENDING"),
            ("conditions", ["Hidden approval condition"]),
            ("supersedes_sha256", "0" * 64),
        ):
            self.evidence = copy.deepcopy(original)
            decision = json.loads(self.evidence[reviews.ROLES[0]][0])
            decision[field] = value
            self.store(reviews.ROLES[0], decision)
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                self.verify()

    def test_incomplete_trust_stale_packet_and_revocations_reject(self):
        for mutate in (
            lambda t: t["roles"].pop("Legal reviewer"),
            lambda t: t.update(subject_sha256="0" * 64),
            lambda t: t.update(valid_until="2026-10-30T12:00:00Z"),
            lambda t: t["revoked_evidence_sha256"].append(
                reviews.digest(self.evidence[reviews.ROLES[0]][0])
            ),
            lambda t: t["revoked_key_sha256"].append(
                reviews.digest(t["roles"][reviews.ROLES[0]]["public_key"].encode())
            ),
        ):
            original = copy.deepcopy(self.trust)
            mutate(self.trust)
            with self.assertRaises(ValueError):
                self.verify()
            self.trust = original
        self.evidence.pop("Spec lead")
        with self.assertRaises(ValueError):
            self.verify()

    def test_signature_failure_duplicate_json_and_stale_predecessor_reject(self):
        verifier = Mock()
        verifier.verify.side_effect = ReleaseError("SIGNATURE_REJECTED")
        with self.assertRaises(ReleaseError):
            self.verify(verifier)
        role = reviews.ROLES[0]
        raw, bundle = self.evidence[role]
        duplicate = b'{"version":1,' + raw[1:]
        self.evidence[role] = (duplicate, bundle)
        self.trust["roles"][role]["evidence_sha256"] = reviews.digest(duplicate)
        with self.assertRaises(ValueError):
            self.verify()
        decision = json.loads(raw)
        self.trust["roles"][role]["predecessor_sha256"] = "c" * 64
        self.store(role, decision)
        with self.assertRaises(ValueError):
            self.verify()
        decision["supersedes_sha256"] = "c" * 64
        self.store(role, decision)
        self.assertFalse(self.verify()["m0_accepted"])

    @unittest.skipUnless(
        os.environ.get("KRYVOLA_RELEASE_SIGNATURE_TESTS") == "1", "real signatures run in full CI"
    )
    def test_real_signatures_and_wrong_authority_key(self):
        executable = ROOT / ".tools/cosign"
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            env = {"PATH": os.defpath, "HOME": str(root), "COSIGN_PASSWORD": ""}
            # Verify checksum before invoking the tool for synthetic signing setup.
            import platform

            from kryvola_platform.release_set import COSIGN_DIGESTS

            self.assertEqual(
                reviews.digest(executable.read_bytes()), COSIGN_DIGESTS[platform.system()]
            )

            def command(*args):
                subprocess.run(
                    [str(executable), *map(str, args)],
                    cwd=root,
                    env=env,
                    check=True,
                    capture_output=True,
                    timeout=60,
                )

            for name in ("right", "wrong"):
                command("generate-key-pair", "--output-key-prefix", root / name)
            for role in reviews.ROLES:
                raw = self.evidence[role][0]
                (root / "blob").write_bytes(raw)
                command(
                    "sign-blob",
                    "--yes",
                    "--use-signing-config=false",
                    "--tlog-upload=false",
                    "--key",
                    root / "right.key",
                    "--bundle",
                    root / "bundle",
                    root / "blob",
                )
                self.evidence[role] = (raw, (root / "bundle").read_bytes())
                self.trust["roles"][role]["public_key"] = (root / "right.pub").read_text()
            self.verify(Cosign(executable))
            self.trust["roles"][reviews.ROLES[0]]["public_key"] = (root / "wrong.pub").read_text()
            with self.assertRaises(ReleaseError):
                self.verify(Cosign(executable))
