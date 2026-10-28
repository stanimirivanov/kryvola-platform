"""Offline M0 input admission. This module never deploys or qualifies a release."""

import hashlib
import json
import math
import os
import platform
import re
import subprocess
from collections.abc import Mapping
from dataclasses import dataclass, replace
from importlib.resources import files
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any
from urllib.parse import urlsplit

from jsonschema import Draft202012Validator, ValidationError

SPEC_REVISION = "1a5b57a590487ba116913050af8041f5e5f1fb52"
MAX_METADATA = 131072
COSIGN_VERSION = "v3.1.3"
COSIGN_DIGESTS = {
    "Linux": "4629c757b7618056f8ddd7e2625ae9fdd94c0372a65049520bc7d9df9efc7f71",
    "Windows": "9fe59be0eca1271873ce019061335eb1ac419b7059202e797828467ddabe33be",
}
_SPEC = files("kryvola_platform").joinpath("_spec")
_MANIFEST = _SPEC.joinpath("manifest.json").read_bytes()
_VERSION = json.loads(_MANIFEST)["contract_version"]
_VALIDATORS = {
    name: Draft202012Validator(
        json.loads(_SPEC.joinpath(f"profiles/{name}.schema.json").read_bytes())
    )
    for name in ("ReleaseCandidate", "ModelDescriptor", "MeasurementReport")
}
_COMPONENTS = {"spec", "fabric", "engines", "ml", "platform"}


class ReleaseError(ValueError):
    """A fixed safe error code, without source diagnostics or exception chains."""


def _require(condition: bool) -> None:
    if not condition:
        raise ValueError


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        _require(key not in result)
        result[key] = value
    return result


def _json(raw: bytes) -> dict[str, Any]:
    _require(type(raw) is bytes and len(raw) <= MAX_METADATA)
    value = json.loads(
        raw.decode("utf-8"), object_pairs_hook=_pairs, parse_constant=_constant, parse_float=_float
    )
    _require(isinstance(value, dict))
    return value


def _constant(value: str) -> None:
    raise ValueError


def _float(value: str) -> float:
    result = float(value)
    _require(math.isfinite(result))
    return result


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


@dataclass(frozen=True)
class ComponentPolicy:
    """Trusted exact subject, builder/build-type and public key, supplied independently."""

    reference: str
    builder_id: str
    build_type: str
    public_key: bytes


@dataclass(frozen=True)
class ReleasePolicy:
    """Operator-owned selection and approval key; never construct from candidate data."""

    candidate_sha256: str
    intended_use: str
    reviewer_key: bytes
    components: Mapping[str, ComponentPolicy]


@dataclass(frozen=True)
class ComponentInput:
    """Local artifact bytes plus a signed in-toto/SLSA provenance statement."""

    reference: str
    artifact: Path
    provenance: bytes
    signature_bundle: bytes


@dataclass(frozen=True)
class Cosign:
    executable: Path

    def verify(self, payload: bytes, bundle: bytes, public_key: bytes) -> None:
        """Pinned-key-only mode; no Fulcio identity, log or timestamp claim is made."""
        valid = False
        try:
            _require(platform.machine().lower() in {"amd64", "x86_64"})
            with self.executable.open("rb") as stream:
                _require(
                    hashlib.file_digest(stream, "sha256").hexdigest()
                    == COSIGN_DIGESTS[platform.system()]
                )
            _require(type(public_key) is bytes and len(public_key) <= 8192)
            _require(public_key.startswith(b"-----BEGIN PUBLIC KEY-----"))
            _require(type(bundle) is bytes and 0 < len(bundle) <= MAX_METADATA)
            _require(type(payload) is bytes and len(payload) <= MAX_METADATA)
            with TemporaryDirectory(prefix="kryvola-verify-") as directory:
                root = Path(directory)
                for name, raw in (("blob", payload), ("bundle", bundle), ("key.pub", public_key)):
                    (root / name).write_bytes(raw)
                # No ambient cloud/OIDC credentials, user config or cached trust roots.
                env = {"PATH": os.defpath, "HOME": directory, "USERPROFILE": directory}
                if "SYSTEMROOT" in os.environ:
                    env["SYSTEMROOT"] = os.environ["SYSTEMROOT"]
                result = subprocess.run(
                    [
                        str(self.executable.resolve()),
                        "verify-blob",
                        "--key",
                        str(root / "key.pub"),
                        "--bundle",
                        str(root / "bundle"),
                        "--insecure-ignore-tlog",
                        "--offline",
                        str(root / "blob"),
                    ],
                    cwd=root,
                    env=env,
                    capture_output=True,
                    timeout=30,
                    check=False,
                )
                valid = result.returncode == 0
        except OSError, ValueError, KeyError, subprocess.SubprocessError:
            pass
        if not valid:
            raise ReleaseError("SIGNATURE_REJECTED")


def _artifact_digest(path: Path) -> str:
    _require(path.is_file() and not path.is_symlink())
    digest = hashlib.sha256()
    total = 0
    with path.open("rb") as stream:
        while chunk := stream.read(1048576):
            total += len(chunk)
            _require(total <= 1073741824)
            digest.update(chunk)
    return digest.hexdigest()


def _immutable(reference: str, digest: str, version: str) -> bool:
    if re.fullmatch(r"[a-z0-9][a-z0-9./_-]+@sha256:" + digest, reference):
        return True
    url = urlsplit(reference)
    return (
        url.scheme == "https"
        and bool(url.hostname)
        and url.username is None
        and url.password is None
        and not url.query
        and url.fragment == "sha256=" + digest
        and version in url.path.split("/")
    )


def validate_release_set(
    candidate: bytes,
    signature_bundle: bytes,
    components: Mapping[str, ComponentInput],
    evidence: Mapping[str, bytes],
    policy: ReleasePolicy,
    verifier: Cosign,
) -> None:
    """Admit exact local integration inputs only; success is not an execution permit.

    Evidence contains model, measurement and legal files keyed by exact SHA-256.
    Callers retain digest identities and must reverify bytes at their later use.
    """
    valid = False
    try:
        components, evidence = dict(components), dict(evidence)
        policy = replace(policy, components=dict(policy.components))
        release = _json(candidate)
        _require(_sha(candidate) == policy.candidate_sha256)
        _VALIDATORS["ReleaseCandidate"].validate(release)
        _require(set(components) == set(policy.components) == _COMPONENTS)
        _require(release["schema_source_revision"] == SPEC_REVISION)
        _require(release["ratification_revision"] != SPEC_REVISION)
        _require(release["contract_version"] == _VERSION)
        _require(release["bundle_manifest_sha256"] == _sha(_MANIFEST))
        legal = release["legal"]
        _require(legal["disposition"] == "REVIEWED_ALLOWED" and bool(legal["evidence_sha256"]))
        _require(legal["intended_use"] == policy.intended_use)
        _require(len(set(legal["evidence_sha256"])) == len(legal["evidence_sha256"]))
        hashes = {
            release["model_descriptor_sha256"],
            release["measurement_report_sha256"],
            *legal["evidence_sha256"],
        }
        _require(set(evidence) == hashes)
        for digest, raw in evidence.items():
            _require(type(raw) is bytes and len(raw) <= MAX_METADATA and _sha(raw) == digest)
        model = _json(evidence[release["model_descriptor_sha256"]])
        report = _json(evidence[release["measurement_report_sha256"]])
        _VALIDATORS["ModelDescriptor"].validate(model)
        _VALIDATORS["MeasurementReport"].validate(report)
        _require(model["workload"] == report["workload"] == release["workload"])
        _require(report["evidence"] == release["evidence"])
        _require(report["schema_source_revision"] == SPEC_REVISION)
        _require(report["contract_version"] == _VERSION)
        _require(report["model_descriptor_sha256"] == release["model_descriptor_sha256"])
        _require(
            len(set(release["workload"]["operators"])) == len(release["workload"]["operators"])
        )
        relations = release["evidence"]["relations"]
        _require(len(set(relations)) == len(relations))
        _require((release["evidence"]["policy"] == "NONE") == (not relations))
        pins = release["components"]
        _require(pins["spec"]["source_revision"] == SPEC_REVISION)
        _require(pins["spec"]["version"] == _VERSION)
        _require(pins["engines"]["artifact_sha256"] == release["workload"]["engine_digest"])
        engine = [p for p in report["software"] if p["name"] == "engine-image"]
        _require(
            len(engine) == 1
            and all(
                engine[0][k] == pins["engines"][k]
                for k in ("version", "source_revision", "artifact_sha256")
            )
        )
        verifier.verify(candidate, signature_bundle, policy.reviewer_key)
        for name, pin in pins.items():
            item, trust = components[name], policy.components[name]
            _require(pin["name"] == "kryvola-" + name)
            _require(item.reference == trust.reference)
            _require(_immutable(item.reference, pin["artifact_sha256"], pin["version"]))
            _require(_artifact_digest(item.artifact) == pin["artifact_sha256"])
            statement = _json(item.provenance)
            _require(statement["_type"] == "https://in-toto.io/Statement/v1")
            _require(statement["predicateType"] == "https://slsa.dev/provenance/v1")
            _require(
                statement["subject"]
                == [{"name": item.reference, "digest": {"sha256": pin["artifact_sha256"]}}]
            )
            definition = statement["predicate"]["buildDefinition"]
            repository = "https://github.com/stanimirivanov/" + pin["name"]
            _require(definition["buildType"] == trust.build_type and bool(trust.build_type))
            _require(
                definition["externalParameters"]
                == {
                    "repository": repository,
                    "ref": pin["source_revision"],
                    "version": pin["version"],
                }
            )
            source = {"uri": "git+" + repository, "digest": {"gitCommit": pin["source_revision"]}}
            _require(
                [d for d in definition["resolvedDependencies"] if d.get("uri") == source["uri"]]
                == [source]
            )
            schema = {"uri": "urn:kryvola:spec-bundle", "digest": {"sha256": _sha(_MANIFEST)}}
            _require(
                [d for d in definition["resolvedDependencies"] if d.get("uri") == schema["uri"]]
                == [schema]
            )
            _require(
                statement["predicate"]["runDetails"]["builder"]["id"] == trust.builder_id
                and bool(trust.builder_id)
            )
            verifier.verify(item.provenance, item.signature_bundle, trust.public_key)
        valid = True
    except (
        ValueError,
        KeyError,
        TypeError,
        OSError,
        ValidationError,
        RecursionError,
        AttributeError,
    ):
        pass
    if not valid:
        raise ReleaseError("RELEASE_SET_REJECTED")
