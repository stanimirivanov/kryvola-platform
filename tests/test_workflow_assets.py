"""Offline release pin and archive boundaries; actual publishers verify in full CI."""

import copy
import hashlib
import json
import platform
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tools import workflow_assets as assets


class WorkflowAssetTests(unittest.TestCase):
    def test_tag_and_hash_drift_rejected(self):
        original = assets.pins()
        for field, value in (("source", "main"), ("assets", {"untrusted.whl": "a" * 64})):
            changed = copy.deepcopy(original)
            changed["fabric"][field] = value
            with tempfile.TemporaryDirectory() as temporary:
                path = Path(temporary) / "pins.json"
                path.write_text(json.dumps(changed))
                with patch.object(assets, "LOCK", path), self.assertRaises(ValueError):
                    assets.pins()

    def test_tampered_asset_never_reaches_signature_or_execution(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / ".tools").mkdir()
            name = "cosign.exe" if platform.system() == "Windows" else "cosign"
            (root / ".tools" / name).write_bytes(b"verifier-fixture")
            (root / "fabric").mkdir()
            (root / "fabric/manifest.json").write_bytes(b"changed")
            with (
                patch.object(assets, "ROOT", root),
                patch.object(assets, "OUTPUT", root),
                patch.object(
                    assets, "pins", return_value={"fabric": {"assets": {"manifest.json": "a" * 64}}}
                ),
                patch.dict(
                    assets.COSIGN_DIGESTS,
                    {platform.system(): hashlib.sha256(b"verifier-fixture").hexdigest()},
                ),
                patch.object(assets.integration, "run") as run,
            ):
                with self.assertRaisesRegex(ValueError, "WORKFLOW_ASSET_CHANGED"):
                    assets.verify()
                run.assert_not_called()

    def test_archive_paths_cannot_escape(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "engines").mkdir()
            with tarfile.open(root / "engines/package.tar", "w") as archive:
                archive.addfile(tarfile.TarInfo("../engine"))
            with (
                patch.object(assets, "OUTPUT", root),
                self.assertRaisesRegex(ValueError, "FAKE_ARCHIVE_BOUNDARY"),
            ):
                assets.engine()
            self.assertFalse((root / "engine").exists())


if __name__ == "__main__":
    unittest.main()
