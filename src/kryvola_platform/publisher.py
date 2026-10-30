"""Bounded adapters for existing signed publisher manifests, not review approval."""

import re
import tarfile
from dataclasses import replace
from urllib.parse import quote

from .release_set import _MANIFEST, _artifact_digest, _json, _require, _sha

LABELS = {
    "spec": ("spec-publication-v1", "EXPERIMENTAL_CONTRACTS_ONLY"),
    "fabric": ("fabric-publication-v1", "EXPERIMENTAL_CONFORMANCE_ONLY"),
    "ml": ("ml-publication-v1", "EXPERIMENTAL_BASELINE_ONLY"),
    "platform": ("platform-publication-v1", "EXPERIMENTAL_DRIVER_ONLY"),
}


def validate_publication(name, pin, item, trust, verifier):
    policy = trust.publisher
    publication = item.publication
    _require(policy is not None and publication is not None)
    policy = replace(policy)
    assets = dict(publication.assets)
    _require(re.fullmatch("[a-f0-9]{40}", policy.source) is not None)
    _require(_sha(publication.manifest) == policy.manifest_sha256)
    manifest = _json(publication.manifest)
    _require(manifest["source"] == policy.source)
    _require(name == "spec" or policy.source == pin["source_revision"])
    repository = "https://github.com/stanimirivanov/kryvola-" + name
    identity = repository + "/.github/workflows/release.yml@refs/heads/main"
    version = "0.1.0.dev0+g" + policy.source
    oci = name == "engines" and manifest.get("format") == "fake-oci-v1"
    if oci:
        _require(policy.subject == "@oci-manifest")
        _require(manifest["image"] == item.reference and manifest["production_ready"] is False)
        _require(
            item.reference.startswith(
                "ghcr.io/stanimirivanov/kryvola-engines/fake-evaluator@sha256:"
            )
        )
        expected = {"provenance.json", "sbom.json"}
        _require(re.fullmatch("[a-f0-9]{64}", manifest["archive_manifest_sha256"]) is not None)
        _require(re.fullmatch("[a-f0-9]{64}", manifest["dockerfile_sha256"]) is not None)
    elif name == "engines":
        _require(
            manifest["role"] == "fake-evaluator"
            and manifest["distribution"] == "FAKE_ONLY_EXPERIMENTAL"
        )
        _require(policy.subject == "package.tar")
        expected = {"package.tar", "sbom.json", "provenance.json"}
    elif name == "spec":
        _require(manifest["format"] == LABELS[name][0])
        _require(
            manifest["distribution"] == LABELS[name][1] and manifest["production_ready"] is False
        )
        _require(policy.subject == "contracts.tar")
        expected = {"contracts.tar", "provenance.json"}
    else:
        _require(manifest["schema_version"] == LABELS[name][0])
        _require(
            manifest["distribution"] == LABELS[name][1] and manifest["production_ready"] is False
        )
        _require(manifest["version"] == version)
        _require(pin["version"] == "0.1.0-dev0.g" + policy.source)
        wheel = f"kryvola_{name}-{version}-py3-none-any.whl"
        _require(policy.subject == wheel)
        expected = {wheel, "LICENSE", "uv.lock", "sbom.spdx.json", "provenance.json"}
        if name == "platform":
            expected.add("driver.tar")
    _require(set(assets) == set(manifest["subjects"]) == expected)
    for filename, path in assets.items():
        _require(_artifact_digest(path) == manifest["subjects"][filename])
    if not oci:
        expected_reference = (
            repository
            + "/releases/download/experimental-"
            + policy.source
            + "/"
            + quote(policy.subject, safe="")
            + "#sha256="
            + pin["artifact_sha256"]
        )
        _require(item.reference == expected_reference)
        _require(manifest["subjects"][policy.subject] == pin["artifact_sha256"])
        _require(_artifact_digest(assets[policy.subject]) == _artifact_digest(item.artifact))
    _require(assets["provenance.json"].stat().st_size <= 131072)
    statement = _json(assets["provenance.json"].read_bytes())
    _require(statement["_type"] == "https://in-toto.io/Statement/v1")
    _require(statement["predicateType"] == "https://slsa.dev/provenance/v1")
    predicate = statement["predicate"]
    if oci:
        _require(
            statement["subject"]
            == [
                {
                    "name": "ghcr.io/stanimirivanov/kryvola-engines/fake-evaluator",
                    "digest": {"sha256": pin["artifact_sha256"]},
                }
            ]
        )
        _require(
            predicate
            == {
                "source": policy.source,
                "archive_manifest_sha256": manifest["archive_manifest_sha256"],
                "dockerfile_sha256": manifest["dockerfile_sha256"],
                "builder": identity,
                "scope": "FAKE_ONLY_EXPERIMENTAL_NOT_SLSA_LEVEL",
            }
        )
        _require(trust.builder_id == identity and trust.build_type == "fake-oci-v1")
    else:
        definition = predicate["buildDefinition"]
        _require(definition["buildType"] == trust.build_type and bool(trust.build_type))
        _require(
            predicate["runDetails"]["builder"]["id"] == trust.builder_id and bool(trust.builder_id)
        )
        expected_subjects = [{"name": policy.subject, "digest": {"sha256": pin["artifact_sha256"]}}]
        if name == "platform":
            expected_subjects.append(
                {"name": "driver.tar", "digest": {"sha256": manifest["subjects"]["driver.tar"]}}
            )
        _require(statement["subject"] == expected_subjects)
        if name == "spec":
            _require(definition["externalParameters"] == {"source": policy.source})
            with tarfile.open(assets["contracts.tar"]) as archive:
                members = []
                for index, member in enumerate(archive):
                    _require(index < 4096)
                    if member.name == "generated/manifest.json":
                        members.append(member)
                _require(
                    len(members) == 1 and members[0].isfile() and members[0].size == len(_MANIFEST)
                )
                stream = archive.extractfile(members[0])
                _require(stream is not None and stream.read(len(_MANIFEST) + 1) == _MANIFEST)
        elif name == "engines":
            _require(definition["externalParameters"] == {"role": "fake-evaluator"})
            _require(
                definition["resolvedDependencies"][0]
                == {"uri": "git+" + repository, "digest": {"gitCommit": policy.source}}
            )
        else:
            _require(
                definition["externalParameters"]
                == {"repository": repository, "ref": policy.source, "version": version}
            )
            deps = definition["resolvedDependencies"]
            for expected_dep in (
                {"uri": "git+" + repository, "digest": {"gitCommit": policy.source}},
                {"uri": "urn:kryvola:spec-bundle", "digest": {"sha256": _sha(_MANIFEST)}},
            ):
                _require([d for d in deps if d.get("uri") == expected_dep["uri"]] == [expected_dep])
    verifier.verify_publisher(
        publication.manifest, publication.signature_bundle, identity, policy.source
    )
