"""Owner helper packages are verified before entering an image build context."""

import hashlib
import tempfile
import unittest
from pathlib import Path


class OwnerPackageTests(unittest.TestCase):
    def test_changed_cached_package_cannot_be_staged(self):
        from tools.m1_owner_packages import stage

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cache, destination = root / "cache", root / "context"
            cache.mkdir()
            (cache / "helper.deb").write_bytes(b"changed")
            entry = {
                "name": "helper.deb",
                "url": "https://deb.debian.org/debian/pool/main/h/helper/helper.deb",
                "sha256": hashlib.sha256(b"original").hexdigest(),
                "bytes": 8,
            }
            with self.assertRaisesRegex(ValueError, "M1_OWNER_PACKAGE_CHANGED"):
                stage(destination, entries=[entry], cache=cache)
            self.assertFalse(destination.exists())

    def test_exact_package_is_copied_without_modification(self):
        from tools.m1_owner_packages import stage

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cache, destination = root / "cache", root / "context"
            cache.mkdir()
            data = b"qualified package bytes"
            (cache / "helper.deb").write_bytes(data)
            entry = {
                "name": "helper.deb",
                "url": "https://deb.debian.org/debian/pool/main/h/helper/helper.deb",
                "sha256": hashlib.sha256(data).hexdigest(),
                "bytes": len(data),
            }
            stage(destination, entries=[entry], cache=cache)
            self.assertEqual((destination / "helper.deb").read_bytes(), data)
