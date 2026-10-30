"""Existing publisher shapes are adapted without inferring publisher or reviewer trust."""

import io
import platform
import subprocess
import tarfile
import unittest
from dataclasses import replace
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

import test_release_set as existing
from test_release_set import digest, encode

from kryvola_platform import release_set as rs
from kryvola_platform.publisher import validate_publication


class PublisherTests(unittest.TestCase):
    def fixture(self, root, name):
        source = "a" * 40
        version = "0.1.0.dev0+g" + source
        identity = f"https://github.com/stanimirivanov/kryvola-{name}/.github/workflows/release.yml@refs/heads/main"
        repository = identity.split("/.github")[0]
        subject = f"kryvola_{name}-{version}-py3-none-any.whl"
        if name == "spec":
            subject = "contracts.tar"
        if name == "engines":
            subject = "package.tar"
        blob = root / subject
        blob.write_bytes(b"fixture artifact")
        if name == "spec":
            with tarfile.open(blob, "w") as archive:
                entry = tarfile.TarInfo("generated/manifest.json")
                entry.size = len(rs._MANIFEST)
                archive.addfile(entry, io.BytesIO(rs._MANIFEST))
        pin = {
            "source_revision": rs.SPEC_REVISION if name == "spec" else source,
            "artifact_sha256": rs._artifact_digest(blob),
            "version": "0.1.0-dev0.g" + source,
        }
        definition = {
            "buildType": "fixture-build",
            "externalParameters": {"repository": repository, "ref": source, "version": version},
            "resolvedDependencies": [
                {"uri": "git+" + repository, "digest": {"gitCommit": source}},
                {"uri": "urn:kryvola:spec-bundle", "digest": {"sha256": digest(rs._MANIFEST)}},
            ],
        }
        if name == "spec":
            definition["externalParameters"] = {"source": source}
        if name == "engines":
            definition["externalParameters"] = {"role": "fake-evaluator"}
        statement = {
            "_type": "https://in-toto.io/Statement/v1",
            "predicateType": "https://slsa.dev/provenance/v1",
            "subject": [{"name": subject, "digest": {"sha256": pin["artifact_sha256"]}}],
            "predicate": {
                "buildDefinition": definition,
                "runDetails": {"builder": {"id": identity}},
            },
        }
        assets = {subject: blob}
        if name != "spec":
            for filename in (
                ["sbom.json"] if name == "engines" else ["LICENSE", "uv.lock", "sbom.spdx.json"]
            ):
                assets[filename] = root / filename
                assets[filename].write_bytes(b"fixture")
        if name == "platform":
            assets["driver.tar"] = root / "driver.tar"
            assets["driver.tar"].write_bytes(b"driver")
            statement["subject"].append(
                {
                    "name": "driver.tar",
                    "digest": {"sha256": rs._artifact_digest(assets["driver.tar"])},
                }
            )
        assets["provenance.json"] = root / "provenance.json"
        assets["provenance.json"].write_bytes(encode(statement))
        manifest = {
            "source": source,
            "subjects": {n: rs._artifact_digest(p) for n, p in assets.items()},
        }
        if name == "engines":
            manifest.update(role="fake-evaluator", distribution="FAKE_ONLY_EXPERIMENTAL")
        else:
            from kryvola_platform.publisher import LABELS

            manifest.update(distribution=LABELS[name][1], production_ready=False)
            manifest["format" if name == "spec" else "schema_version"] = LABELS[name][0]
            if name != "spec":
                manifest["version"] = version
        raw = encode(manifest)
        publication = rs.PublicationInput(raw, b"signed-manifest-fixture", assets)
        from urllib.parse import quote

        reference = (
            repository
            + "/releases/download/experimental-"
            + source
            + "/"
            + quote(subject, safe="")
            + "#sha256="
            + pin["artifact_sha256"]
        )
        item = rs.ComponentInput(reference, blob, b"", b"", publication)
        trust = rs.ComponentPolicy(
            "fixture-ref",
            identity,
            "fixture-build",
            b"",
            rs.PublisherPolicy(source, digest(raw), subject),
        )
        return pin, item, trust

    def test_all_five_actual_archive_formats_and_independent_bindings(self):
        for name in ("spec", "fabric", "engines", "ml", "platform"):
            with self.subTest(name=name), TemporaryDirectory() as temporary:
                pin, item, trust = self.fixture(Path(temporary), name)
                with patch.object(rs.Cosign, "verify_publisher") as verify:
                    validate_publication(name, pin, item, trust, rs.Cosign(Path("cosign")))
                    self.assertEqual(verify.call_args.args[-1], trust.publisher.source)
                    for wrong in (
                        replace(trust.publisher, source="b" * 40),
                        replace(trust.publisher, manifest_sha256="0" * 64),
                        replace(trust.publisher, subject="substitute"),
                    ):
                        with self.assertRaises(ValueError):
                            validate_publication(
                                name,
                                pin,
                                item,
                                replace(trust, publisher=wrong),
                                rs.Cosign(Path("cosign")),
                            )
                    changed = dict(item.publication.assets)
                    changed.pop("provenance.json")
                    with self.assertRaises(ValueError):
                        validate_publication(
                            name,
                            pin,
                            replace(item, publication=replace(item.publication, assets=changed)),
                            trust,
                            rs.Cosign(Path("cosign")),
                        )

    def test_release_set_routes_keyless_mode_and_rejects_mode_mixing(self):
        fixture = existing.ReleaseTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        name = "ml"
        root = fixture.root / "publisher"
        root.mkdir()
        pin, item, trust = self.fixture(root, name)
        candidate_pin = fixture.release["components"][name]
        candidate_pin.update(pin)
        reference = item.reference
        fixture.inputs[name] = replace(item, reference=reference)
        components = dict(fixture.policy.components)
        components[name] = replace(trust, reference=reference)
        policy = replace(
            fixture.policy, candidate_sha256=digest(encode(fixture.release)), components=components
        )
        with (
            patch.object(rs.Cosign, "verify"),
            patch.object(rs.Cosign, "verify_publisher") as verify,
        ):
            fixture.admit(policy=policy)
            verify.assert_called_once()
            components[name] = replace(components[name], public_key=b"mixed-key")
            with self.assertRaises(rs.ReleaseError):
                fixture.admit(policy=policy)

    def test_oci_record_binds_raw_registry_manifest_bytes(self):
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = "a" * 40
            blob = root / "registry-manifest.json"
            blob.write_bytes(b"{}")
            sha = rs._artifact_digest(blob)
            image = "ghcr.io/stanimirivanov/kryvola-engines/fake-evaluator@sha256:" + sha
            identity = "https://github.com/stanimirivanov/kryvola-engines/.github/workflows/release.yml@refs/heads/main"
            predicate = {
                "source": source,
                "archive_manifest_sha256": "c" * 64,
                "dockerfile_sha256": "d" * 64,
                "builder": identity,
                "scope": "FAKE_ONLY_EXPERIMENTAL_NOT_SLSA_LEVEL",
            }
            statement = {
                "_type": "https://in-toto.io/Statement/v1",
                "predicateType": "https://slsa.dev/provenance/v1",
                "subject": [{"name": image.split("@")[0], "digest": {"sha256": sha}}],
                "predicate": predicate,
            }
            assets = {n: root / n for n in ("sbom.json", "provenance.json")}
            assets["sbom.json"].write_bytes(b"fixture")
            assets["provenance.json"].write_bytes(encode(statement))
            manifest = {
                "format": "fake-oci-v1",
                "source": source,
                "image": image,
                "production_ready": False,
                "archive_manifest_sha256": "c" * 64,
                "dockerfile_sha256": "d" * 64,
                "subjects": {n: rs._artifact_digest(p) for n, p in assets.items()},
            }
            raw = encode(manifest)
            item = rs.ComponentInput(
                image, blob, b"", b"", rs.PublicationInput(raw, b"fixture", assets)
            )
            trust = rs.ComponentPolicy(
                image,
                identity,
                "fake-oci-v1",
                b"",
                rs.PublisherPolicy(source, digest(raw), "@oci-manifest"),
            )
            pin = {"source_revision": source, "artifact_sha256": sha}
            with patch.object(rs.Cosign, "verify_publisher"):
                validate_publication("engines", pin, item, trust, rs.Cosign(Path("cosign")))
                with self.assertRaises(ValueError):
                    validate_publication(
                        "engines",
                        pin,
                        replace(item, reference=image.replace("fake-evaluator", "owner")),
                        trust,
                        rs.Cosign(Path("cosign")),
                    )
                assets["provenance.json"].write_bytes(b"substitution")
                with self.assertRaises(ValueError):
                    validate_publication("engines", pin, item, trust, rs.Cosign(Path("cosign")))

    def test_keyless_verifier_pins_identity_issuer_source_trigger_and_propagates_failure(self):
        with TemporaryDirectory() as temporary:
            executable = Path(temporary) / "cosign"
            executable.write_bytes(b"fixture-tool")
            identity = "https://github.com/stanimirivanov/kryvola-ml/.github/workflows/release.yml@refs/heads/main"
            with (
                patch.dict(rs.COSIGN_DIGESTS, {platform.system(): digest(b"fixture-tool")}),
                patch.object(
                    rs.subprocess, "run", return_value=subprocess.CompletedProcess([], 0)
                ) as run,
            ):
                verifier = rs.Cosign(executable)
                verifier.verify_publisher(b"manifest", b"bundle", identity, "a" * 40)
                command = run.call_args.args[0]
                self.assertEqual(command[command.index("--certificate-identity") + 1], identity)
                self.assertIn("https://token.actions.githubusercontent.com", command)
                self.assertIn("workflow_dispatch", command)
                self.assertNotIn("--insecure-ignore-tlog", command)
                run.return_value.returncode = 1
                with self.assertRaises(rs.ReleaseError):
                    verifier.verify_publisher(b"manifest", b"bundle", identity, "a" * 40)
                with self.assertRaises(rs.ReleaseError):
                    verifier.verify_publisher(
                        b"manifest", b"bundle", "https://wrong.invalid", "a" * 40
                    )
