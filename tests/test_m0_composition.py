"""Exact-composition checks never turn stale reports or cleanup failures into success."""

import json
import subprocess
import tarfile
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import Mock, patch
from zipfile import ZipFile

from tools import m0_composition as gate


class CompositionTests(unittest.TestCase):
    def test_installed_package_bytes_version_and_editable_sources_reject(self):
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            package = root / "kryvola_ml"
            package.mkdir()
            (package / "__init__.py").write_bytes(b"installed")
            wheel = root / "ml.whl"
            with ZipFile(wheel, "w") as archive:
                archive.writestr("kryvola_ml/__init__.py", b"published")
            dist = SimpleNamespace(
                version="0.1.0.dev0+g" + "a" * 40,
                read_text=lambda _: None,
                locate_file=lambda name: root / name,
            )
            with (
                patch.object(gate.importlib.metadata, "distribution", return_value=dist),
                patch.object(
                    gate.importlib.util,
                    "find_spec",
                    return_value=SimpleNamespace(origin=str(package / "__init__.py")),
                ),
            ):
                with self.assertRaises(ValueError):
                    gate.installed("ml", wheel, "a" * 40)
                (package / "__init__.py").write_bytes(b"published")
                gate.installed("ml", wheel, "a" * 40)
                dist.read_text = lambda _: '{"dir_info":{"editable":true}}'
                with self.assertRaises(ValueError):
                    gate.installed("ml", wheel, "a" * 40)

    def test_driver_must_equal_all_selected_source_bytes(self):
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "README.md").write_bytes(b"source")
            archive = root / "driver.tar"
            import io

            with tarfile.open(archive, "w") as tar:
                entry = tarfile.TarInfo("README.md")
                entry.size = 7
                tar.addfile(entry, io.BytesIO(b"changed"))
            with (
                patch.object(gate, "ROOT", root),
                patch.object(gate.publication, "git", return_value="README.md\0"),
            ):
                with self.assertRaises(ValueError):
                    gate.driver(archive)

    def test_tampered_bundle_fails_before_runtime_or_installation(self):
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name in (
                "selection.json",
                "model.json",
                "measurement.json",
                "candidate.json",
                "lock.json",
            ):
                (root / name).write_bytes(b"changed")
            with (
                patch.object(gate.m0_candidate, "assemble", return_value=(b"expected", b"lock")),
                patch.object(gate, "installed") as installed,
            ):
                with self.assertRaises(ValueError):
                    gate.preflight(root, root, Mock())
                installed.assert_not_called()

    def test_completion_callback_is_not_called_after_cleanup_failure(self):
        from tools import fake_workflow, isolation

        stack = SimpleNamespace(
            claimed=True,
            folder=Path("unused"),
            up=Mock(),
            down=Mock(side_effect=ValueError("cleanup failed")),
        )
        completed = Mock()
        with (
            patch.object(gate.network_benchmark, "profiles"),
            patch.object(gate.m0_acceptance.release_conformance, "controls", return_value={}),
            patch.object(gate.network_benchmark.integration, "Stack", return_value=stack),
            patch.object(
                gate.network_benchmark.integration, "ACTIVE", SimpleNamespace(exists=lambda: True)
            ),
            patch.object(fake_workflow, "smoke", return_value={}),
            patch.object(gate.network_benchmark, "observe", return_value={}),
            patch.object(isolation, "qualify"),
            patch.object(gate.m0_acceptance.release_conformance, "finish"),
        ):
            with self.assertRaisesRegex(ValueError, "cleanup failed"):
                gate.network_benchmark.execute(completed=completed)
            completed.assert_not_called()

    def test_oci_qualification_rejects_wrong_runtime_before_container_creation(self):
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "selection.json").write_text(
                json.dumps(
                    {
                        "components": {
                            "engines": {
                                "subject": "@oci-manifest",
                                "reference": "fixture@sha256:" + "a" * 64,
                                "publisher_source": "b" * 40,
                            }
                        }
                    }
                )
            )

            def run(args, **kwargs):
                config = [{"Config": {"User": "root", "Entrypoint": ["/opt/kryvola/engine"]}}]
                return subprocess.CompletedProcess(args, 0, json.dumps(config).encode())

            with patch.object(
                gate.network_benchmark.integration, "run", side_effect=run
            ) as invoked:
                with self.assertRaises(ValueError):
                    gate.engine_oci(root, SimpleNamespace(executable="cosign"))
                self.assertFalse(
                    any(call.args[0][:2] == ["docker", "create"] for call in invoked.call_args_list)
                )

    def test_only_owned_fresh_post_cleanup_reports_are_retained(self):
        for failure in (None, "live", "cleanup", "stale", "isolation", "drift"):
            with self.subTest(failure=failure), TemporaryDirectory() as temporary:
                root = Path(temporary)
                folder = root / "build/integration/fresh"
                bundle = root / "bundle"
                bundle.mkdir()
                for name in (
                    "candidate.json",
                    "lock.json",
                    "selection.json",
                    "model.json",
                    "measurement.json",
                ):
                    (bundle / name).write_bytes(b"{}")
                if failure == "stale":
                    folder.mkdir(parents=True)
                events = []

                def execute(*, completed, events=events, failure=failure, folder=folder):
                    events.append("live")
                    if failure in {"live", "cleanup"}:
                        raise ValueError("failed live gate or cleanup")
                    folder.mkdir(parents=True, exist_ok=True)
                    for name in gate.LIVE:
                        (folder / name).write_bytes(b"{}")
                    events.append("cleanup")
                    completed(folder)

                preflight = ("a" * 40, {}, "b" * 64, "c" * 64, {"components": {}})
                result = SimpleNamespace(exists=lambda: False)
                output = root / "retained"
                with (
                    patch.object(gate, "ROOT", root),
                    patch.object(
                        gate,
                        "preflight",
                        side_effect=[
                            preflight,
                            preflight
                            if failure != "drift"
                            else ("different", {}, "b" * 64, "c" * 64, {}),
                        ],
                    ),
                    patch.object(gate, "engine_oci"),
                    patch.object(gate.network_benchmark, "execute", side_effect=execute),
                    patch.object(gate.network_benchmark.integration, "ACTIVE", result),
                    patch.object(
                        gate.m0_acceptance,
                        "validate_live",
                        side_effect=ValueError("bad isolation") if failure == "isolation" else None,
                    ),
                ):
                    if failure:
                        with self.assertRaises(ValueError):
                            gate.qualify(bundle, root, output, Mock())
                        self.assertFalse(output.exists())
                    else:
                        report = gate.qualify(bundle, root, output, Mock())
                        self.assertEqual(events, ["live", "cleanup"])
                        self.assertTrue(report["cleanup_verified"])
                        self.assertFalse(report["m0_accepted"])
                        self.assertTrue((output / "evidence.tar").is_file())
                        for name, digest in report["subjects"].items():
                            self.assertEqual(gate.rs._sha((output / name).read_bytes()), digest)
