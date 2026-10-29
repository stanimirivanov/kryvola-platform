"""Offline checks for upstream evidence, installed bytes and runtime-image admission."""

import copy
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch
from zipfile import ZipFile

from tools import architecture
from tools import release_conformance as gate


class ConformanceTests(unittest.TestCase):
    def evidence(self):
        trust = gate.policy()
        run = {
            "id": trust["run_id"],
            "run_attempt": 1,
            "head_sha": trust["source"],
            "conclusion": "success",
            "status": "completed",
            "event": "push",
            "head_branch": "main",
            "repository": {"full_name": trust["repository"]},
            "path": ".github/workflows/ci.yml",
        }
        jobs = [
            {
                "name": name,
                "head_sha": trust["source"],
                "run_attempt": 1,
                "status": "completed",
                "conclusion": "success",
                "steps": [{"name": step, "conclusion": "success"}],
            }
            for name, step in trust["jobs"].items()
        ]
        return trust, {"run": run, "jobs": {"total_count": 3, "jobs": jobs}}

    def test_missing_failed_or_wrong_revision_is_not_evidence(self):
        trust, good = self.evidence()
        self.assertEqual(gate.upstream(good, trust)["source"], trust["source"])
        variants = []
        for field, value in (
            ("head_sha", "b" * 40),
            ("run_attempt", 2),
            ("conclusion", "failure"),
            ("head_branch", "feature/unsafe"),
        ):
            bad = copy.deepcopy(good)
            bad["run"][field] = value
            variants.append(bad)
        bad = copy.deepcopy(good)
        bad["jobs"]["jobs"][1]["steps"][0]["conclusion"] = "skipped"
        variants.append(bad)
        bad = copy.deepcopy(good)
        bad["jobs"]["jobs"].pop()
        variants.append(bad)
        for bad in variants:
            with self.assertRaises(ValueError):
                gate.upstream(bad, trust)

    def test_installed_code_must_equal_the_admitted_wheel(self):
        source = "a" * 40
        version = "0.1.0.dev0+g" + source
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "fabric").mkdir()
            (root / "kryvola_fabric").mkdir()
            (root / "kryvola_fabric/control.py").write_bytes(b"modified")
            with ZipFile(root / "fabric/package.whl", "w") as archive:
                archive.writestr("kryvola_fabric/control.py", b"published")
            dist = SimpleNamespace(version=version, locate_file=lambda name: root / name)
            with patch.object(gate.importlib.metadata, "distribution", return_value=dist):
                with self.assertRaisesRegex(ValueError, "CONFORMANCE_INSTALLED_BYTES"):
                    gate.installed(
                        root,
                        {"fabric": {"source": source, "assets": {"package.whl": "a" * 64}}},
                        root,
                    )

    def test_optional_and_conditional_sibling_sources_reject(self):
        for declaration in (
            '[project.optional-dependencies]\ntest=["helper @ file:../outside"]',
            '[tool.uv.sources]\nhelper=[{path="../outside"}]',
        ):
            with tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                (root / "pyproject.toml").write_text('[project]\nname="fixture"\n' + declaration)
                self.assertTrue(architecture.dependency_errors(root, "kryvola-platform"))

    def test_broken_baseline_never_counts_as_successful_negative_controls(self):
        with (
            patch.object(gate, "admit", side_effect=ValueError("broken baseline")),
            patch.object(gate.importlib.util, "spec_from_file_location") as load,
        ):
            with self.assertRaises(ValueError):
                gate.controls()
            load.assert_not_called()

    def test_runtime_image_content_drift_rejects(self):
        reference = "fixture@sha256:" + "a" * 64
        stack = SimpleNamespace(compose=Mock(return_value=SimpleNamespace(stdout=b"container")))
        actual = {"service": "ray", "reference": reference, "id": "old-image"}
        resolved = {"id": "different-image", "digests": [reference]}
        values = [
            subprocess.CompletedProcess([], 0, json.dumps(v).encode()) for v in (actual, resolved)
        ]
        fake = {
            "kind": "PUBLIC_FAKE_ENGINE_SELFTEST",
            "production_ready": False,
            "profile_enabled": False,
            "releases": {},
        }
        with (
            patch.object(
                gate.integration,
                "configuration",
                return_value={"services": {"ray": {"image": reference}}},
            ),
            patch.object(gate.integration, "run", side_effect=values),
        ):
            with self.assertRaisesRegex(ValueError, "CONFORMANCE_RUNTIME_IMAGE"):
                gate.finish(stack, fake, {"packages": {}})


if __name__ == "__main__":
    unittest.main()
