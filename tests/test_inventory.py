import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from jsonschema import ValidationError

from kryvola_platform.inventory import validate_inventory


class InventoryTests(unittest.TestCase):
    def fixture(self) -> dict[str, object]:
        return {
            "schema_version": "1",
            "stage": "foundation",
            "production_ready": False,
            "profiles": [
                {"profile_id": "FHE-Q1", "enabled": False, "qualification": "unqualified"}
            ],
        }

    def test_valid_disabled_foundation_inventory(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "inventory.json"
            path.write_text(json.dumps(self.fixture()), encoding="utf-8")
            validate_inventory(path)

    def test_enabled_unqualified_or_production_claim_fails(self) -> None:
        for change in [
            {"production_ready": True},
            {
                "profiles": [
                    {"profile_id": "FHE-Q1", "enabled": True, "qualification": "unqualified"}
                ]
            },
        ]:
            with self.subTest(change=change), TemporaryDirectory() as directory:
                path = Path(directory) / "inventory.json"
                path.write_text(json.dumps({**self.fixture(), **change}), encoding="utf-8")
                with self.assertRaises(ValidationError):
                    validate_inventory(path)

    def test_missing_input_fails(self) -> None:
        with TemporaryDirectory() as directory, self.assertRaises(OSError):
            validate_inventory(Path(directory) / "missing.json")
