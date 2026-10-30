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
            name = "cosign"
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
                patch.object(assets.Cosign, "verify_publisher") as run,
            ):
                with self.assertRaisesRegex(ValueError, "WORKFLOW_ASSET_CHANGED"):
                    assets.verify()
                run.assert_not_called()

    def test_shared_signature_denial_keeps_the_admission_probe_error_code(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / ".tools").mkdir()
            (root / ".tools/cosign").write_bytes(b"verifier-fixture")
            folder = root / "fabric"
            folder.mkdir()
            for name in ("manifest.json", "manifest.sigstore.json"):
                (folder / name).write_bytes(b"fixture")
            locked = {
                "fabric": {
                    "source": "a" * 40,
                    "assets": {
                        name: assets.digest(folder / name)
                        for name in ("manifest.json", "manifest.sigstore.json")
                    },
                }
            }
            with (
                patch.object(assets, "pins", return_value=locked),
                patch.dict(
                    assets.COSIGN_DIGESTS,
                    {platform.system(): hashlib.sha256(b"verifier-fixture").hexdigest()},
                ),
                patch.object(
                    assets.Cosign,
                    "verify_publisher",
                    side_effect=assets.ReleaseError("PUBLISHER_REJECTED"),
                ),
            ):
                with self.assertRaisesRegex(ValueError, "^WORKFLOW_PUBLISHER_REJECTED$"):
                    assets.verify(root, root)
            # Unexpected verifier failures must not masquerade as the intended denial.
            with (
                patch.object(assets, "pins", return_value=locked),
                patch.dict(
                    assets.COSIGN_DIGESTS,
                    {platform.system(): hashlib.sha256(b"verifier-fixture").hexdigest()},
                ),
                patch.object(
                    assets.Cosign, "verify_publisher", side_effect=RuntimeError("setup failure")
                ),
            ):
                with self.assertRaises(RuntimeError):
                    assets.verify(root, root)

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
