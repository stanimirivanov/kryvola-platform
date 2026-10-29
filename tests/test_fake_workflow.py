"""Offline public-event boundaries; no services or external artifacts required."""

import copy
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

from tools import fake_workflow as fake


class FakeWorkflowTests(unittest.TestCase):
    def test_published_contract_and_reference_binding(self):
        ref = self.fixture()["artifact"]
        wire = fake.request_for(ref, "b" * 64)
        value = {**self.fixture(), "request_hex": wire.hex()}
        _, decoded, request = fake.bound_request(fake.encode(value))
        self.assertEqual(decoded, wire)
        self.assertEqual(request["engine_digest"], "b" * 64)
        for field, replacement in (
            ("version", "different"),
            ("sha256", "c" * 64),
            ("byte_length", 33),
        ):
            changed = copy.deepcopy(value)
            changed["artifact"][field] = replacement
            with self.assertRaisesRegex(ValueError, "FAKE_REFERENCE_BINDING"):
                fake.bound_request(fake.encode(changed))
        value["request_hex"] += "f81f01"
        with self.assertRaises(ValueError):
            fake.bound_request(fake.encode(value))

    def test_changed_object_hash_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            (folder / "data").mkdir()
            (folder / "data/workflow-read.bin").write_bytes(b"changed")
            stack = SimpleNamespace(folder=folder, execute=Mock())
            with self.assertRaisesRegex(ValueError, "FAKE_OBJECT_HASH"):
                fake.fetch(stack, self.fixture()["artifact"])

    def fixture(self):
        return {
            "kind": fake.KIND,
            "production_ready": False,
            "request_hex": "00",
            "artifact": {
                "key": "public-input",
                "version": "immutable-version",
                "sha256": "a" * 64,
                "byte_length": 32,
            },
        }

    def test_reference_only_event_and_fake_label(self):
        good = self.fixture()
        self.assertEqual(fake.event(fake.encode(good)), good)
        for field, value in (
            ("kind", "INFERENCE"),
            ("production_ready", 0),
            ("request_hex", "ciphertext"),
            ("request_hex", "0" * 4098),
        ):
            bad = copy.deepcopy(good)
            bad[field] = value
            with self.assertRaises(ValueError):
                fake.event(fake.encode(bad))
        for field in ("private_key", "ciphertext", "proof", "credentials"):
            bad = copy.deepcopy(good)
            bad[field] = "not-real-sensitive-data"
            with self.assertRaises(ValueError):
                fake.event(fake.encode(bad))

    def test_limits_duplicates_and_malformed_references(self):
        for raw in (b"x" * 8193, b'{"kind":"a","kind":"b"}', b"[]", b"{}"):
            with self.assertRaises(ValueError):
                fake.event(raw)
        for field, value in (
            ("byte_length", True),
            ("byte_length", 4097),
            ("sha256", "Z" * 64),
            ("version", ""),
            ("key", "x" * 129),
        ):
            bad = self.fixture()
            bad["artifact"][field] = value
            with self.assertRaises(ValueError):
                fake.event(fake.encode(bad))


if __name__ == "__main__":
    unittest.main()
