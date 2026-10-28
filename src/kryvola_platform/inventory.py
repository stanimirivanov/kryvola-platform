"""Validate a foundation inventory, never a production qualification certificate."""

import json
from collections.abc import Mapping
from importlib.resources import files
from pathlib import Path
from typing import TYPE_CHECKING

from jsonschema import Draft202012Validator

if TYPE_CHECKING:
    from kryvola_platform.release_set import ComponentInput, Cosign, ReleasePolicy


def validate_inventory(path: Path) -> None:
    schema = json.loads(
        files("kryvola_platform")
        .joinpath("_spec/foundation-inventory.schema.json")
        .read_text(encoding="utf-8")
    )
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(json.loads(path.read_text(encoding="utf-8")))


def validate_release_inventory(
    path: Path,
    signature_bundle: bytes,
    components: Mapping[str, ComponentInput],
    evidence: Mapping[str, bytes],
    policy: ReleasePolicy,
    verifier: Cosign,
) -> None:
    """Separate versioned release admission; the foundation path remains unchanged."""
    from kryvola_platform.release_set import MAX_METADATA, validate_release_set

    with path.open("rb") as stream:
        raw = stream.read(MAX_METADATA + 1)
    validate_release_set(raw, signature_bundle, components, evidence, policy, verifier)
