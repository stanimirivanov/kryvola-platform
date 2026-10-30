"""Synthetic publisher fixtures exercise assembly without real approvals or releases."""

import copy
import io
import json
import subprocess
import sys
import tarfile
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any
from unittest.mock import patch

import test_publisher as publisher_fixtures

from kryvola_platform import release_set as rs
from tools import m0_candidate as candidate


class CandidateTests(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.selection: dict[str, Any] = {
            "version": 1,
            "intended_use": "Synthetic fake fixture only",
            "model_sha256": "",
            "measurement_sha256": "",
            "components": {},
        }
        fixture = publisher_fixtures.PublisherTests()
        for name in candidate.COMPONENTS:
            folder = self.root / name
            folder.mkdir()
            pin, item, trust = fixture.fixture(folder, name)
            if name == "spec":
                pin["version"] = rs._VERSION
            if name == "engines":
                binary = b"fake binary fixture"
                with tarfile.open(item.artifact, "w") as archive:
                    for filename, raw in (
                        ("engine", binary),
                        ("LICENSE", b"license"),
                        ("Cargo.lock", b'[[package]]\nname="fake-only"\nversion="0.1.0"\n'),
                    ):
                        entry = tarfile.TarInfo(filename)
                        entry.size = len(raw)
                        archive.addfile(entry, io.BytesIO(raw))
                pin["artifact_sha256"] = rs._artifact_digest(item.artifact)
                provenance = rs._json(item.publication.assets["provenance.json"].read_bytes())
                provenance["subject"][0]["digest"]["sha256"] = pin["artifact_sha256"]
                provenance["predicate"]["buildDefinition"]["internalParameters"] = {
                    "first_binary_sha256": rs._sha(binary),
                    "second_binary_sha256": rs._sha(binary),
                }
                item.publication.assets["provenance.json"].write_bytes(candidate.encode(provenance))
            manifest = rs._json(item.publication.manifest)
            manifest["subjects"] = {
                n: rs._artifact_digest(p) for n, p in item.publication.assets.items()
            }
            raw = candidate.encode(manifest)
            (folder / "manifest.json").write_bytes(raw)
            (folder / "manifest.sigstore.json").write_bytes(b"signature fixture")
            reference = item.reference.split("#")[0] + "#sha256=" + pin["artifact_sha256"]
            self.selection["components"][name] = {
                **pin,
                "reference": reference,
                "artifact_filename": item.artifact.name,
                "publisher_source": trust.publisher.source,
                "manifest_sha256": rs._sha(raw),
                "subject": trust.publisher.subject,
                "builder_id": trust.builder_id,
                "build_type": trust.build_type,
            }
        spec = rs._SPEC
        self.model = json.loads(spec.joinpath("fixtures/profiles/model.json").read_bytes())
        self.report = json.loads(spec.joinpath("fixtures/profiles/measurement.json").read_bytes())
        self.report["schema_source_revision"] = rs.SPEC_REVISION
        self.report["features"] = ["fake-engine"]
        engine = self.selection["components"]["engines"]
        for value in (self.model, self.report):
            value["workload"]["engine_digest"] = engine["artifact_sha256"]
        self.report["software"] = [
            {
                "name": "engine-image",
                **{k: engine[k] for k in ("version", "source_revision", "artifact_sha256")},
            }
        ]
        self.refresh()

    def refresh(self):
        self.model_raw = candidate.encode(self.model)
        self.report["model_descriptor_sha256"] = rs._sha(self.model_raw)
        self.report_raw = candidate.encode(self.report)
        self.selection.update(
            model_sha256=rs._sha(self.model_raw), measurement_sha256=rs._sha(self.report_raw)
        )

    def assemble(self):
        return candidate.assemble(
            candidate.encode(self.selection),
            self.model_raw,
            self.report_raw,
            self.root,
            rs.Cosign(Path("fixture-cosign")),
        )

    def test_complete_candidate_is_deterministic_unsigned_and_pending(self):
        with patch.object(rs.Cosign, "verify_publisher") as verify:
            first = self.assemble()
            self.assertEqual(first, self.assemble())
            self.assertEqual(verify.call_count, 10)
        value, lock = map(json.loads, first)
        self.assertIsNone(value["ratification_revision"])
        self.assertEqual(value["legal"]["disposition"], "UNRESOLVED")
        self.assertFalse(value["production_ready"])
        self.assertFalse(value["profile_enabled"])
        self.assertFalse(lock["m0_accepted"])
        self.assertEqual(lock["candidate_sha256"], rs._sha(first[0]))
        self.assertEqual(set(value["components"]), set(candidate.COMPONENTS))

    def test_missing_component_drift_mutable_reference_and_signature_reject(self):
        original = copy.deepcopy(self.selection)
        for mutate in (
            lambda s: s["components"].pop("ml"),
            lambda s: s["components"]["ml"].update(manifest_sha256="0" * 64),
            lambda s: s["components"]["fabric"].update(reference="https://example.invalid/latest"),
            lambda s: s["components"]["spec"].update(source_revision="a" * 40),
            lambda s: s["components"]["platform"].update(artifact_filename="../escape"),
        ):
            self.selection = copy.deepcopy(original)
            mutate(self.selection)
            with patch.object(rs.Cosign, "verify_publisher"), self.assertRaises(ValueError):
                self.assemble()
        self.selection = original
        with (
            patch.object(
                rs.Cosign, "verify_publisher", side_effect=rs.ReleaseError("PUBLISHER_REJECTED")
            ),
            self.assertRaises(rs.ReleaseError),
        ):
            self.assemble()
        artifact = self.root / "ml" / self.selection["components"]["ml"]["artifact_filename"]
        artifact.write_bytes(b"changed")
        with patch.object(rs.Cosign, "verify_publisher"), self.assertRaises(ValueError):
            self.assemble()

    def test_fake_candidate_cannot_import_crypto_or_wrong_contract_measurements(self):
        original = copy.deepcopy(self.report)
        for mutate in (
            lambda r: r.update(origin="MEASURED"),
            lambda r: r.update(schema_source_revision="a" * 40),
            lambda r: r.update(features=["crypto-research"]),
            lambda r: r["software"].append({**r["software"][0], "name": "tfhe-rs"}),
            lambda r: r["workload"].update(engine_digest="0" * 64),
        ):
            self.report = copy.deepcopy(original)
            mutate(self.report)
            self.refresh()
            with patch.object(rs.Cosign, "verify_publisher"), self.assertRaises(ValueError):
                self.assemble()

    def test_cli_missing_inputs_writes_no_candidate(self):
        output = self.root / "new-output"
        result = subprocess.run(
            [
                sys.executable,
                candidate.__file__,
                "--selection",
                str(self.root / "missing"),
                "--model",
                "missing",
                "--measurement",
                "missing",
                "--assets",
                str(self.root),
                "--output",
                str(output),
            ],
            capture_output=True,
        )
        self.assertEqual(result.returncode, 2)
        self.assertFalse(output.exists())
