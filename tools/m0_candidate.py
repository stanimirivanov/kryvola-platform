"""Resolve a disabled unsigned M0 candidate from independently selected publisher inputs."""

import argparse
import json
import re
import sys
import tarfile
import tomllib
from pathlib import Path

from kryvola_platform import release_set as rs
from kryvola_platform.publisher import validate_publication

COMPONENTS = ("spec", "fabric", "engines", "ml", "platform")


def require(condition):
    if not condition:
        raise ValueError("M0_CANDIDATE_REJECTED")


def fields(value, names):
    require(type(value) is dict and set(value) == set(names.split()))


def read(path):
    require(path.is_file() and not path.is_symlink() and path.stat().st_size <= rs.MAX_METADATA)
    return path.read_bytes()


def local(root, name):
    require(
        isinstance(name, str)
        and re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9._+@-]{0,255}", name) is not None
    )
    path = root / name
    require(not root.is_symlink() and root.is_dir() and not path.is_symlink())
    return path


def encode(value):
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n"
    ).encode()


def assemble(selection_raw, model_raw, report_raw, assets_root, verifier):
    selection = rs._json(selection_raw)
    fields(selection, "version intended_use model_sha256 measurement_sha256 components")
    require(type(selection["version"]) is int and selection["version"] == 1)
    require(
        isinstance(selection["intended_use"], str) and 0 < len(selection["intended_use"]) <= 2048
    )
    require(
        rs._sha(model_raw) == selection["model_sha256"]
        and rs._sha(report_raw) == selection["measurement_sha256"]
    )
    fields(selection["components"], " ".join(COMPONENTS))
    require(assets_root.is_dir() and not assets_root.is_symlink())
    model, report = rs._json(model_raw), rs._json(report_raw)
    rs._VALIDATORS["ModelDescriptor"].validate(model)
    rs._VALIDATORS["MeasurementReport"].validate(report)
    require(model["workload"] == report["workload"] and model["model_visibility"] == "PUBLIC")
    require(report["model_descriptor_sha256"] == rs._sha(model_raw))
    require(
        report["schema_source_revision"] == rs.SPEC_REVISION
        and report["contract_version"] == rs._VERSION
    )
    # Only fake engine publishers exist in this closure slice. Never relabel real
    # crypto research or real service measurements as fake composition evidence.
    require(report["origin"] == "SYNTHETIC_FIXTURE" and "fake-engine" in report["features"])
    require({p["name"] for p in report["software"]} <= {"engine-image", "benchmark-harness"})
    require(report["evidence"]["policy"] == "NONE" and report["evidence"]["relations"] == [])
    components, resolved = {}, {}
    for name in COMPONENTS:
        chosen = selection["components"][name]
        fields(
            chosen,
            "source_revision version artifact_sha256 reference artifact_filename "
            "publisher_source manifest_sha256 subject builder_id build_type",
        )
        pin = {
            "name": "kryvola-" + name,
            **{k: chosen[k] for k in ("version", "source_revision", "artifact_sha256")},
        }
        folder = assets_root / name
        require(folder.is_dir() and not folder.is_symlink())
        raw = read(folder / "manifest.json")
        signature = read(folder / "manifest.sigstore.json")
        manifest = rs._json(raw)
        require(type(manifest["subjects"]) is dict)
        paths = {filename: local(folder, filename) for filename in manifest["subjects"]}
        artifact = local(folder, chosen["artifact_filename"])
        require(rs._artifact_digest(artifact) == chosen["artifact_sha256"])
        require(re.fullmatch("[a-f0-9]{40}", chosen["source_revision"]) is not None)
        if name == "spec":
            require(pin["source_revision"] == rs.SPEC_REVISION and pin["version"] == rs._VERSION)
        if chosen["subject"] == "@oci-manifest":
            require(
                name == "engines"
                and chosen["reference"]
                == "ghcr.io/stanimirivanov/kryvola-engines/fake-evaluator@sha256:"
                + chosen["artifact_sha256"]
            )
        else:
            require(chosen["artifact_filename"] == chosen["subject"])
        publication = rs.PublicationInput(raw, signature, paths)
        item = rs.ComponentInput(chosen["reference"], artifact, b"", b"", publication)
        trust = rs.ComponentPolicy(
            chosen["reference"],
            chosen["builder_id"],
            chosen["build_type"],
            b"",
            rs.PublisherPolicy(
                chosen["publisher_source"], chosen["manifest_sha256"], chosen["subject"]
            ),
        )
        validate_publication(name, pin, item, trust, verifier)
        if name == "engines" and chosen["subject"] == "package.tar":
            with tarfile.open(artifact) as archive:
                members = []
                for member in archive:
                    members.append(member)
                    require(len(members) <= 3 and member.isfile() and member.size <= 512 << 20)
                require(sorted(m.name for m in members) == ["Cargo.lock", "LICENSE", "engine"])
                stream = archive.extractfile("engine")
                if stream is None:
                    raise ValueError("MISSING_FAKE_BINARY")
                import hashlib

                binary_digest = hashlib.sha256()
                while chunk := stream.read(262144):
                    binary_digest.update(chunk)
                binary_sha = binary_digest.hexdigest()
                builds = rs._json(read(paths["provenance.json"]))["predicate"]["buildDefinition"][
                    "internalParameters"
                ]
                require(
                    binary_sha == builds["first_binary_sha256"] == builds["second_binary_sha256"]
                )
                require(archive.getmember("Cargo.lock").size <= rs.MAX_METADATA)
                lock_stream = archive.extractfile("Cargo.lock")
                if lock_stream is None:
                    raise ValueError("MISSING_FAKE_LOCK")
                packages = tomllib.loads(lock_stream.read().decode())["package"]
                require(not any(p["name"] in {"tfhe", "sp1-sdk"} for p in packages))
        components[name] = pin
        resolved[name] = {
            "reference": chosen["reference"],
            "publication_source": chosen["publisher_source"],
            "manifest_sha256": rs._sha(raw),
            "signature_sha256": rs._sha(signature),
            "subjects": {filename: rs._artifact_digest(path) for filename, path in paths.items()},
        }
    engines = [p for p in report["software"] if p["name"] == "engine-image"]
    require(engines == [{**components["engines"], "name": "engine-image"}])
    require(model["workload"]["engine_digest"] == components["engines"]["artifact_sha256"])
    candidate = {
        "schema_version": "1",
        "stage": "M0_CONTRACT_CANDIDATE",
        "production_ready": False,
        "profile_enabled": False,
        "qualification": "UNQUALIFIED",
        "schema_source_revision": rs.SPEC_REVISION,
        "ratification_revision": None,
        "contract_version": rs._VERSION,
        "bundle_manifest_sha256": rs._sha(rs._MANIFEST),
        "workload": model["workload"],
        "evidence": report["evidence"],
        "model_descriptor_sha256": rs._sha(model_raw),
        "measurement_report_sha256": rs._sha(report_raw),
        "components": components,
        "legal": {
            "disposition": "UNRESOLVED",
            "intended_use": selection["intended_use"],
            "evidence_sha256": [],
        },
    }
    rs._VALIDATORS["ReleaseCandidate"].validate(candidate)
    candidate_raw = encode(candidate)
    lock = {
        "kind": "VERIFIED_PUBLISHERS_UNSIGNED_UNTESTED_M0_CANDIDATE",
        "candidate_sha256": rs._sha(candidate_raw),
        "selection_sha256": rs._sha(selection_raw),
        "model_sha256": rs._sha(model_raw),
        "measurement_sha256": rs._sha(report_raw),
        "components": resolved,
        "ratification": "PENDING",
        "legal": "PENDING",
        "composition_tests": "NOT_RUN",
        "m0_accepted": False,
        "m1_admitted": False,
    }
    return candidate_raw, encode(lock)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--selection", type=Path, required=True)
    parser.add_argument("--model", type=Path, required=True)
    parser.add_argument("--measurement", type=Path, required=True)
    parser.add_argument("--assets", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--cosign", type=Path, default=Path(__file__).resolve().parents[1] / ".tools/cosign"
    )
    args = parser.parse_args()
    try:
        require(not args.output.exists())
        model, measurement = read(args.model), read(args.measurement)
        selection = read(args.selection)
        candidate, lock = assemble(
            selection, model, measurement, args.assets, rs.Cosign(args.cosign)
        )
        # No artifacts are emitted until every publisher and binding passes.
        args.output.mkdir(parents=False, exist_ok=False)
        for name, raw in (
            ("selection.json", selection),
            ("candidate.json", candidate),
            ("lock.json", lock),
            ("model.json", model),
            ("measurement.json", measurement),
        ):
            with (args.output / name).open("xb") as stream:
                stream.write(raw)
        print("UNSIGNED_UNTESTED_M0_CANDIDATE; no approval or admission")
        return 0
    except ValueError, KeyError, TypeError, AttributeError, OSError, IndexError, RecursionError:
        print("M0_CANDIDATE_REJECTED", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
