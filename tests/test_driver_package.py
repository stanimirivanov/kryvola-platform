"""Driver packages reject unsafe extraction and missing installed resources."""

import io
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from zipfile import ZipFile

from tools import check_wheel as driver


class DriverTests(unittest.TestCase):
    def test_archive_boundary_and_incomplete_inputs(self):
        for name, kind in (
            ("../escape", tarfile.REGTYPE),
            ("tools/link", tarfile.SYMTYPE),
            ("build/report", tarfile.REGTYPE),
            ("tools/only.py", tarfile.REGTYPE),
        ):
            with tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                archive = root / "test.tar"
                with tarfile.open(archive, "w") as tar:
                    entry = tarfile.TarInfo(name)
                    entry.type = kind
                    tar.addfile(entry, io.BytesIO(b""))
                with self.assertRaises(ValueError):
                    driver.extract_driver(archive, root / "out")

    def test_resource_drift_rejected_before_driver_execution(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            wheel = root / "test.whl"
            with ZipFile(wheel, "w") as archive:
                archive.writestr("kryvola_platform/_spec/manifest.json", b"changed")

            def fixture(_archive, target):
                path = target / "src/kryvola_platform/_spec"
                path.mkdir(parents=True)
                (path / "manifest.json").write_bytes(b"expected")

            with (
                patch.object(driver, "extract_driver", side_effect=fixture),
                patch.object(driver.subprocess, "run") as run,
            ):
                with self.assertRaisesRegex(ValueError, "WHEEL_RESOURCES_CHANGED"):
                    driver.check(wheel, root / "driver.tar")
                run.assert_not_called()

    def test_missing_configuration_propagates_driver_failure(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            wheel = root / "test.whl"
            with ZipFile(wheel, "w") as archive:
                archive.writestr("kryvola_platform/_spec/manifest.json", b"expected")

            def fixture(_archive, target):
                path = target / "src/kryvola_platform/_spec"
                path.mkdir(parents=True)
                (path / "manifest.json").write_bytes(b"expected")

            with (
                patch.object(driver, "extract_driver", side_effect=fixture),
                patch.object(
                    driver.subprocess,
                    "run",
                    side_effect=subprocess.CalledProcessError(1, "missing config"),
                ),
            ):
                with self.assertRaises(subprocess.CalledProcessError):
                    driver.check(wheel, root / "driver.tar")
