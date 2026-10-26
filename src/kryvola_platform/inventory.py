"""Validate a foundation inventory, never a production qualification certificate."""

import json
from importlib.resources import files
from pathlib import Path

from jsonschema import Draft202012Validator


def validate_inventory(path: Path) -> None:
    schema = json.loads(
        files("kryvola_platform")
        .joinpath("_spec/foundation-inventory.schema.json")
        .read_text(encoding="utf-8")
    )
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(json.loads(path.read_text(encoding="utf-8")))
