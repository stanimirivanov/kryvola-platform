import hashlib
import io
import json
import tarfile
import tempfile
import unittest
from pathlib import Path


def archive(path, changed=False):
    config = json.dumps(
        {
            "architecture": "amd64",
            "os": "linux",
            "config": {},
            "rootfs": {"type": "layers", "diff_ids": []},
        }
    ).encode()
    digest = hashlib.sha256(config).hexdigest()
    name = "blobs/sha256/" + digest
    with tarfile.open(path, "w") as stream:
        for filename, raw in (
            ("manifest.json", json.dumps([{"Config": name}]).encode()),
            (name, config + (b" " if changed else b"")),
        ):
            member = tarfile.TarInfo(filename)
            member.size = len(raw)
            stream.addfile(member, io.BytesIO(raw))
    return digest


class ImageIdentityTests(unittest.TestCase):
    def test_hashes_configuration_bytes_instead_of_manifest_identity(self):
        from tools.m1_images import config_digest

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "image.tar"
            digest = archive(path)
            self.assertEqual(config_digest(path), digest)

    def test_changed_configuration_cannot_match_the_reference(self):
        from tools.m1_images import config_digest

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "image.tar"
            archive(path, changed=True)
            with self.assertRaisesRegex(ValueError, "M1_IMAGE_CONFIG"):
                config_digest(path)
