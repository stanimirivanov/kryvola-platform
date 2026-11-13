"""M1 admission rejects drift before executing a publisher verifier or service."""

import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock


def fixture(root):
    source = "a" * 40
    spec = {
        "repository": "https://github.com/stanimirivanov/kryvola-spec",
        "revision": "b" * 40,
        "contract_version": "0.1.0-preview.10",
        "artifact_root": "contracts/spec",
        "manifest_sha256": "c" * 64,
        "native_artifact_root": "contracts/native",
        "native_manifest_sha256": "2" * 64,
    }
    components: dict = {}
    for role in ("fabric", "engines", "ml"):
        folder = root / role
        folder.mkdir()
        workflow = "m1-release.yml" if role == "engines" else "release.yml"
        release = "experimental" if role == "ml" else "m1"
        assets = {}
        for name, data in {
            "manifest.json": (
                b'{"schema_version":"m0-fixture","distribution":"FAKE_ONLY_EXPERIMENTAL"}'
            ),
            "manifest.sigstore.json": b"public signature fixture",
            "provenance.json": b"{}",
            "spec.lock.json": json.dumps(spec).encode(),
        }.items():
            (folder / name).write_bytes(data)
            assets[name] = {
                "sha256": hashlib.sha256(data).hexdigest(),
                "url": f"https://github.com/stanimirivanov/kryvola-{role}/releases/download/{release}-{source}/{name}",
            }
        components[role] = {
            "source": source,
            "identity": f"https://github.com/stanimirivanov/kryvola-{role}/.github/workflows/{workflow}@refs/heads/main",
            "spec": spec.copy(),
            "assets": assets,
        }
    components["ml"]["spec"].update(
        artifact_root="src/kryvola_ml/_spec", native_artifact_root="src/kryvola_ml/_wire"
    )
    return {
        "schema_version": "platform-m1-lock-v1",
        "components": components,
        "services": {
            name: name + "@sha256:" + "d" * 64
            for name in (
                "postgres",
                "s3",
                "redpanda",
                "temporal",
                "temporal-cli",
                "ray",
                "python",
                "s3-client",
            )
        },
        "permissions": {
            "profile": "OWNER_APPROVED_DEVELOPMENT_ONLY",
            "source": source,
            "cpu_sha256": "e" * 64,
            "image_sha256": "f" * 64,
            "owner_sha256": "1" * 64,
            "owner": "stanimirivanov",
            "run_id": "123",
        },
        "compatibility": {
            "engines_spec": spec.copy(),
            "fabric_ml_spec": spec.copy(),
            "control_assets": {
                name: "3" * 64 for name in ("descriptor.bin", "schemas.json", "limits.json")
            },
        },
    }


class M1AssetTests(unittest.TestCase):
    def test_unlisted_wheel_cannot_reach_signature_or_image_assembly(self):
        from tools import m1_assets

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            locked = fixture(root)
            (root / "ml/unlisted.whl").write_bytes(b"unverified package")
            verifier = Mock()
            with self.assertRaisesRegex(ValueError, "M1_ASSET_CHANGED"):
                m1_assets.verify(locked, root, verifier=verifier)
            verifier.assert_not_called()

    def test_lock_requires_all_m1_components_and_immutable_service_images(self):
        from tools import m1_assets

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            valid = fixture(root)
            path = root / "lock.json"
            path.write_text(json.dumps(valid))
            self.assertEqual(m1_assets.load(path), valid)
            missing = copy.deepcopy(valid)
            del missing["components"]["ml"]
            mutable = copy.deepcopy(valid)
            mutable["services"]["postgres"] = "postgres:latest"
            wrong = copy.deepcopy(valid)
            wrong["components"]["fake"] = wrong["components"].pop("engines")
            for value in (missing, mutable, wrong):
                with self.subTest(value=value):
                    path.write_text(json.dumps(value))
                    with self.assertRaises(ValueError):
                        m1_assets.load(path)

    def test_missing_or_tampered_asset_fails_before_any_signature_verification(self):
        from tools import m1_assets

        for missing in (False, True):
            with self.subTest(missing=missing), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                locked = fixture(root)
                path = root / "ml/manifest.json"
                path.unlink() if missing else path.write_bytes(b"tampered")
                verifier = Mock()
                with self.assertRaisesRegex(ValueError, "M1_ASSET_CHANGED"):
                    m1_assets.verify(locked, root, verifier=verifier)
                verifier.assert_not_called()

    def test_correctly_hashed_m0_fixture_is_not_an_m1_release(self):
        from tools import m1_assets

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            locked = fixture(root)
            verifier = Mock()
            with self.assertRaisesRegex(ValueError, "M1_PROFILE_REJECTED"):
                m1_assets.verify(locked, root, verifier=verifier)
            verifier.assert_not_called()

    def test_asset_names_cannot_escape_the_component_directory(self):
        from tools import m1_assets

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            valid = fixture(root)
            for name in ("../escape", "/absolute", "nested/file", "nested\\file"):
                with self.subTest(name=name):
                    changed = copy.deepcopy(valid)
                    assets = changed["components"]["engines"]["assets"]
                    assets[name] = assets.pop("manifest.json")
                    path = root / "lock.json"
                    path.write_text(json.dumps(changed))
                    with self.assertRaises(ValueError):
                        m1_assets.load(path)
