"""Synthetic input policy tests and opt-in real, offline Cosign signature integration."""

import hashlib
import json
import os
import platform
import subprocess
import unittest
from dataclasses import replace
from importlib.resources import files
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from kryvola_platform.inventory import validate_release_inventory
from kryvola_platform.release_set import (
    SPEC_REVISION,
    ComponentInput,
    ComponentPolicy,
    Cosign,
    ReleaseError,
    ReleasePolicy,
    validate_release_set,
)

ROOT = Path(__file__).resolve().parents[1]


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


class ReleaseTests(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        spec = files("kryvola_platform").joinpath("_spec")
        self.release = json.loads((ROOT / "config/release-candidate.json").read_bytes())
        model = json.loads(spec.joinpath("fixtures/profiles/model.json").read_bytes())
        report = json.loads(spec.joinpath("fixtures/profiles/measurement.json").read_bytes())
        self.inputs, trusted = {}, {}
        manifest_digest = digest(spec.joinpath("manifest.json").read_bytes())
        for name, pin in self.release["components"].items():
            blob = self.root / name
            blob.write_bytes(encode({"fixture": name}))
            pin["artifact_sha256"] = digest(blob.read_bytes())
            reference = (
                f"ghcr.io/kryvola/{name}@sha256:{pin['artifact_sha256']}"
                if name == "engines"
                else f"https://example.invalid/{pin['version']}/{name}#sha256={pin['artifact_sha256']}"
            )
            trust = ComponentPolicy(
                reference,
                "https://example.invalid/builder",
                "https://example.invalid/build/v1",
                b"fixture-public-key",
            )
            repository = "https://github.com/stanimirivanov/" + pin["name"]
            statement = {
                "_type": "https://in-toto.io/Statement/v1",
                "predicateType": "https://slsa.dev/provenance/v1",
                "subject": [{"name": reference, "digest": {"sha256": pin["artifact_sha256"]}}],
                "predicate": {
                    "buildDefinition": {
                        "buildType": trust.build_type,
                        "externalParameters": {
                            "repository": repository,
                            "ref": pin["source_revision"],
                            "version": pin["version"],
                        },
                        "resolvedDependencies": [
                            {
                                "uri": "git+" + repository,
                                "digest": {"gitCommit": pin["source_revision"]},
                            },
                            {
                                "uri": "urn:kryvola:spec-bundle",
                                "digest": {"sha256": manifest_digest},
                            },
                        ],
                    },
                    "runDetails": {"builder": {"id": trust.builder_id}},
                },
            }
            self.inputs[name] = ComponentInput(
                reference, blob, encode(statement), b"fixture-bundle"
            )
            trusted[name] = trust
        for value in (model, report, self.release):
            value["workload"]["engine_digest"] = self.release["components"]["engines"][
                "artifact_sha256"
            ]
        report["schema_source_revision"] = SPEC_REVISION
        report["software"] = [
            dict(
                pin,
                **{
                    k: self.release["components"]["engines"][k]
                    for k in ("version", "source_revision", "artifact_sha256")
                },
            )
            if pin["name"] == "engine-image"
            else pin
            for pin in report["software"]
        ]
        model_raw = encode(model)
        report["model_descriptor_sha256"] = digest(model_raw)
        report_raw = encode(report)
        legal = b"Synthetic integration only; not an actual legal or production approval"
        self.evidence = {digest(raw): raw for raw in (model_raw, report_raw, legal)}
        self.release.update(
            model_descriptor_sha256=digest(model_raw), measurement_report_sha256=digest(report_raw)
        )
        self.release["legal"].update(
            disposition="REVIEWED_ALLOWED", evidence_sha256=[digest(legal)]
        )
        self.policy = ReleasePolicy(
            digest(encode(self.release)),
            self.release["legal"]["intended_use"],
            b"fixture-reviewer-key",
            trusted,
        )
        self.verifier = Cosign(
            ROOT / ".tools" / ("cosign.exe" if platform.system() == "Windows" else "cosign")
        )
        self.bundle = b"fixture-review-bundle"

    def admit(self, raw=None, policy=None):
        validate_release_set(
            raw if raw is not None else encode(self.release),
            self.bundle,
            self.inputs,
            self.evidence,
            policy or self.policy,
            self.verifier,
        )

    def test_policy_fixture_and_separate_inventory_entry_point(self):
        self.assertEqual(
            SPEC_REVISION, json.loads((ROOT / "spec.lock.json").read_bytes())["revision"]
        )
        with patch.object(Cosign, "verify") as verify:
            self.admit()
            self.assertEqual(verify.call_count, 6)
            path = self.root / "candidate.json"
            path.write_bytes(encode(self.release))
            validate_release_inventory(
                path, self.bundle, self.inputs, self.evidence, self.policy, self.verifier
            )
        with self.assertRaises(ReleaseError):
            Cosign(self.root / "missing").verify(b"data", b"bundle", b"key")
        tampered = self.root / "tampered"
        tampered.write_bytes(b"not-the-pinned-binary")
        with patch("subprocess.run") as run, self.assertRaises(ReleaseError):
            Cosign(tampered).verify(b"data", b"bundle", b"key")
        run.assert_not_called()

    def test_admission_snapshots_input_mappings_before_verification(self):
        def mutate(*args):
            self.inputs.clear()
            self.evidence.clear()
            trust = self.policy.components
            assert isinstance(trust, dict)
            trust.clear()

        with patch.object(Cosign, "verify", side_effect=mutate):
            self.admit()

    def test_changed_identity_schema_legal_and_production_claims_fail(self):
        for mutate in (
            lambda r: r.update(production_ready=True),
            lambda r: r.update(profile_enabled=True),
            lambda r: r.update(bundle_manifest_sha256="0" * 64),
            lambda r: r.update(schema_source_revision="b" * 40),
            lambda r: r["legal"].update(disposition="UNRESOLVED"),
            lambda r: r["legal"].update(evidence_sha256=[]),
            lambda r: r["legal"].update(intended_use="foreign"),
            lambda r: r["components"]["fabric"].update(name="kryvola-engines"),
            lambda r: r["components"]["fabric"].update(version="latest"),
            lambda r: r["components"]["fabric"].update(source_revision="b" * 40),
        ):
            candidate = json.loads(encode(self.release))
            mutate(candidate)
            raw = encode(candidate)
            with patch.object(Cosign, "verify"), self.assertRaises(ReleaseError):
                self.admit(raw, replace(self.policy, candidate_sha256=digest(raw)))

    def test_altered_artifact_evidence_reference_and_provenance_fail(self):
        original = self.inputs["fabric"]
        cases = []
        for section, key, value in (
            ("buildDefinition", "buildType", "wrong"),
            ("runDetails", "builder", {"id": "wrong"}),
            ("buildDefinition", "resolvedDependencies", []),
            ("buildDefinition", "externalParameters", {}),
        ):
            statement = json.loads(original.provenance)
            statement["predicate"][section][key] = value
            cases.append(replace(original, provenance=encode(statement)))
        statement = json.loads(original.provenance)
        statement["subject"][0]["digest"]["sha256"] = "0" * 64
        cases.extend(
            [
                replace(original, provenance=encode(statement)),
                replace(original, reference="fabric:latest"),
            ]
        )
        statement = json.loads(original.provenance)
        statement["predicate"]["buildDefinition"]["resolvedDependencies"][1]["digest"]["sha256"] = (
            "0" * 64
        )
        cases.append(replace(original, provenance=encode(statement)))
        for bad in cases:
            self.inputs["fabric"] = bad
            policy = self.policy
            if bad.reference == "fabric:latest":
                policy = replace(
                    policy,
                    components={
                        **policy.components,
                        "fabric": replace(policy.components["fabric"], reference=bad.reference),
                    },
                )
            with patch.object(Cosign, "verify"), self.assertRaises(ReleaseError):
                self.admit(policy=policy)
        self.inputs["fabric"] = original
        original.artifact.write_bytes(b"altered")
        with patch.object(Cosign, "verify"), self.assertRaises(ReleaseError):
            self.admit()

    def test_duplicate_json_digest_selection_and_signature_fail_closed(self):
        for raw in (
            b'{"schema_version":"1","schema_version":"2"}',
            b"{}" * 70000,
            b'{"a":NaN}',
            b'{"a":1e999}',
        ):
            with self.assertRaises(ReleaseError):
                self.admit(raw)
        with patch.object(Cosign, "verify", side_effect=ReleaseError("sensitive-marker")):
            with self.assertRaises(ReleaseError) as caught:
                self.admit()
            self.assertEqual(str(caught.exception), "RELEASE_SET_REJECTED")
            self.assertIsNone(caught.exception.__context__)
        key = next(iter(self.evidence))
        self.evidence[key] += b" "
        with self.assertRaises(ReleaseError):
            self.admit()

    @unittest.skipUnless(
        os.environ.get("KRYVOLA_RELEASE_SIGNATURE_TESTS") == "1",
        "real signatures run in full CI gate",
    )
    def test_real_cosign_acceptance_and_wrong_key_changed_bytes_rejection(self):
        env = {
            "PATH": os.defpath,
            "HOME": str(self.root),
            "USERPROFILE": str(self.root),
            "COSIGN_PASSWORD": "",
        }
        if "SYSTEMROOT" in os.environ:
            env["SYSTEMROOT"] = os.environ["SYSTEMROOT"]

        def command(*args):
            result = subprocess.run(
                [str(self.verifier.executable), *args],
                cwd=self.root,
                env=env,
                capture_output=True,
                timeout=60,
                check=False,
            )
            self.assertEqual(
                result.returncode, 0, "Synthetic Cosign command failed; raw output suppressed"
            )

        # Verify tool integrity before any key generation or signing execution.
        from kryvola_platform.release_set import COSIGN_DIGESTS

        self.assertEqual(
            digest(self.verifier.executable.read_bytes()), COSIGN_DIGESTS[platform.system()]
        )
        for name in ("reviewer", "builder"):
            command("generate-key-pair", "--output-key-prefix", str(self.root / name))

        def sign(raw, name):
            blob, bundle = self.root / "signing-blob", self.root / "signing-bundle"
            blob.write_bytes(raw)
            command(
                "sign-blob",
                "--key",
                str(self.root / (name + ".key")),
                "--bundle",
                str(bundle),
                "--use-signing-config=false",
                "--tlog-upload=false",
                "--yes",
                str(blob),
            )
            return bundle.read_bytes()

        reviewer, builder = [
            (self.root / (name + ".pub")).read_bytes() for name in ("reviewer", "builder")
        ]
        self.policy = replace(
            self.policy,
            reviewer_key=reviewer,
            components={
                name: replace(trust, public_key=builder)
                for name, trust in self.policy.components.items()
            },
        )
        self.inputs = {
            name: replace(item, signature_bundle=sign(item.provenance, "builder"))
            for name, item in self.inputs.items()
        }
        raw = encode(self.release)
        self.bundle = sign(raw, "reviewer")
        self.admit()
        with self.assertRaises(ReleaseError):
            self.verifier.verify(raw, self.bundle, builder)
        with self.assertRaises(ReleaseError):
            self.admit(raw + b" ", replace(self.policy, candidate_sha256=digest(raw + b" ")))
        item = self.inputs["fabric"]
        self.inputs["fabric"] = replace(item, provenance=item.provenance + b" ")
        with self.assertRaises(ReleaseError):
            self.admit()
