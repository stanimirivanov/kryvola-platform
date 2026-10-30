"""Explicit download/verification of independently pinned public fixture releases."""

import argparse
import hashlib
import json
import platform
import re
import tarfile
import urllib.parse
import urllib.request
from pathlib import Path

from kryvola_platform.release_set import COSIGN_DIGESTS, Cosign

ROOT = Path(__file__).resolve().parents[1]
LOCK = ROOT / "config/fake-workflow/releases.json"
OUTPUT = ROOT / "build/workflow-assets"


def digest(path, maximum=128 << 20):
    if path.is_symlink() or not path.is_file() or path.stat().st_size > maximum:
        raise ValueError("WORKFLOW_ASSET_FILE")
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def pins(lock=None):
    value = json.loads((lock or LOCK).read_bytes())
    if set(value) != {"fabric", "engines"}:
        raise ValueError("WORKFLOW_COMPONENTS")
    for role, component in value.items():
        if (
            set(component) != {"source", "assets"}
            or not re.fullmatch("[a-f0-9]{40}", component["source"])
            or not isinstance(component["assets"], dict)
        ):
            raise ValueError("WORKFLOW_COMPONENT_PIN")
        expected = {"manifest.json", "manifest.sigstore.json", "provenance.json"}
        expected |= (
            {"package.tar", "sbom.json"}
            if role == "engines"
            else {
                "LICENSE",
                "uv.lock",
                "sbom.spdx.json",
                f"kryvola_fabric-0.1.0.dev0+g{component['source']}-py3-none-any.whl",
            }
        )
        if set(component["assets"]) != expected or any(
            not isinstance(v, str) or re.fullmatch("[a-f0-9]{64}", v) is None
            for v in component["assets"].values()
        ):
            raise ValueError("WORKFLOW_ASSET_PIN")
    return value


def verify(root=None, output=None, lock=None):
    root, output = root or ROOT, output or OUTPUT
    locked = pins(lock) if lock is not None else pins()
    executable = root / ".tools" / "cosign"
    if digest(executable, 256 << 20) != COSIGN_DIGESTS[platform.system()]:
        raise ValueError("WORKFLOW_VERIFIER_PIN")
    for role, component in locked.items():
        folder = output / role
        for name, expected in component["assets"].items():
            if digest(folder / name) != expected:
                raise ValueError("WORKFLOW_ASSET_CHANGED")
        Cosign(executable).verify_publisher(
            (folder / "manifest.json").read_bytes(),
            (folder / "manifest.sigstore.json").read_bytes(),
            f"https://github.com/stanimirivanov/kryvola-{role}/.github/workflows/release.yml@refs/heads/main",
            component["source"],
        )
        manifest = json.loads((folder / "manifest.json").read_bytes())
        if (
            manifest["source"] != component["source"]
            or set(manifest["subjects"])
            != set(component["assets"]) - {"manifest.json", "manifest.sigstore.json"}
            or any(
                component["assets"].get(name) != sha for name, sha in manifest["subjects"].items()
            )
        ):
            raise ValueError("WORKFLOW_SUBJECT_BINDING")
        if role == "fabric":
            if (
                manifest["distribution"] != "EXPERIMENTAL_CONFORMANCE_ONLY"
                or manifest["production_ready"] is not False
            ):
                raise ValueError("FABRIC_QUALIFICATION_LABEL")
            deps = json.loads((folder / "provenance.json").read_bytes())["predicate"][
                "buildDefinition"
            ]["resolvedDependencies"]
            expected_spec = json.loads((root / "spec.lock.json").read_bytes())["manifest_sha256"]
            if {"uri": "urn:kryvola:spec-bundle", "digest": {"sha256": expected_spec}} not in deps:
                raise ValueError("WORKFLOW_SPEC_MISMATCH")
        elif (
            manifest["role"] != "fake-evaluator"
            or manifest["distribution"] != "FAKE_ONLY_EXPERIMENTAL"
        ):
            raise ValueError("ENGINE_QUALIFICATION_LABEL")
    return locked


def engine():
    # Call only after verification, then check extracted bytes again at dispatch.
    with tarfile.open(OUTPUT / "engines/package.tar") as archive:
        if sorted(m.name for m in archive.getmembers()) != [
            "Cargo.lock",
            "LICENSE",
            "engine",
        ] or any(not m.isfile() or m.size > 32 << 20 for m in archive.getmembers()):
            raise ValueError("FAKE_ARCHIVE_BOUNDARY")
        stream = archive.extractfile("engine")
        if stream is None:
            raise ValueError("MISSING_FAKE_ENGINE")
        raw = stream.read()
    provenance = json.loads((OUTPUT / "engines/provenance.json").read_bytes())
    builds = provenance["predicate"]["buildDefinition"]["internalParameters"]
    if not (
        hashlib.sha256(raw).hexdigest()
        == builds["first_binary_sha256"]
        == builds["second_binary_sha256"]
    ):
        raise ValueError("FAKE_BINARY_BINDING")
    path = OUTPUT / "engine"
    path.write_bytes(raw)
    path.chmod(0o755)
    return path


def install():
    for role, component in pins().items():
        folder = OUTPUT / role
        folder.mkdir(parents=True, exist_ok=True)
        for name, expected in component["assets"].items():
            path = folder / name
            if not path.exists():
                url = (
                    f"https://github.com/stanimirivanov/kryvola-{role}/releases/download/"
                    f"experimental-{component['source']}/" + urllib.parse.quote(name, safe="")
                )
                with urllib.request.urlopen(url, timeout=60) as response:
                    raw = response.read((128 << 20) + 1)
                if len(raw) > 128 << 20 or hashlib.sha256(raw).hexdigest() != expected:
                    raise ValueError("WORKFLOW_DOWNLOAD_PIN")
                with path.open("xb") as stream:
                    stream.write(raw)
    verify()
    engine()
    print("PUBLISHED_FAKE_ASSETS_VERIFIED")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["install", "check", "verify"])
    args = parser.parse_args()
    if args.command == "install":
        install()
    elif args.command == "verify":
        verify()
    else:
        pins()
        print("Workflow pins valid; no download or services")


if __name__ == "__main__":
    main()
