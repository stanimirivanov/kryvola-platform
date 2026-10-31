"""Explicit M0 non-production acceptance evaluation; historical blocked audit is separate."""

import argparse
import json
import re
import sys
from pathlib import Path

from kryvola_platform import release_set as rs

if __package__:
    from . import m0_acceptance, m0_candidate, m0_composition, review_evidence
else:
    import m0_acceptance
    import m0_candidate
    import m0_composition
    import review_evidence

read = review_evidence.read
require = review_evidence.require
fields = review_evidence.fields


def verify_composition(root, assets, policy, verifier):
    composition = root / "composition"
    report_raw = read(composition / "report.json")
    require(rs._sha(report_raw) == policy["composition_sha256"])
    report = rs._json(report_raw)
    require(report["kind"] == "EXACT_NONPRODUCTION_FIXTURE_COMPOSITION_TESTED")
    require(
        report["cleanup_verified"] is True
        and report["production_ready"] is False
        and report["m0_accepted"] is False
        and report["m1_admitted"] is False
    )
    names = {
        "candidate/" + name
        for name in (
            "candidate.json",
            "lock.json",
            "selection.json",
            "model.json",
            "measurement.json",
        )
    }
    names |= {"live/" + name for name in m0_composition.LIVE}
    require(set(report["subjects"]) == names)
    retained = {name: read(composition / name) for name in sorted(names)}
    require(all(rs._sha(raw) == report["subjects"][name] for name, raw in retained.items()))
    selection_raw = retained["candidate/selection.json"]
    require(rs._sha(selection_raw) == policy["selection_sha256"])
    model, measurement = (
        retained["candidate/" + name] for name in ("model.json", "measurement.json")
    )
    candidate, lock = m0_candidate.assemble(selection_raw, model, measurement, assets, verifier)
    require(
        candidate == retained["candidate/candidate.json"]
        and lock == retained["candidate/lock.json"]
    )
    base = rs._json(candidate)
    require(
        report["candidate_sha256"] == rs._sha(candidate)
        and report["input_lock_sha256"] == rs._sha(lock)
    )
    require(
        report["components"] == base["components"]
        and report["platform_source"] == base["components"]["platform"]["source_revision"]
    )
    conformance = rs._json(retained["live/release-conformance-report.json"])
    releases = m0_acceptance.inputs()[2]  # Independently pinned supported driver configuration.
    require(conformance["packages"] == releases)
    selected = rs._json(selection_raw)["components"]
    for name in ("fabric", "engines"):
        require(releases[name]["source"] == selected[name]["publisher_source"])
        expected_manifest = rs._json(read(assets / name / "manifest.json"))
        if selected[name]["subject"] == "@oci-manifest":
            require(
                expected_manifest["archive_manifest_sha256"]
                == releases[name]["assets"]["manifest.json"]
            )
        else:
            require(
                releases[name]["assets"]
                == {
                    **expected_manifest["subjects"],
                    "manifest.json": selected[name]["manifest_sha256"],
                    "manifest.sigstore.json": rs._sha(
                        read(assets / name / "manifest.sigstore.json")
                    ),
                }
            )
    m0_acceptance.validate_live(
        {name: rs._json(retained["live/" + name]) for name in m0_acceptance.LIVE},
        report["platform_source"],
        releases,
    )
    return candidate, base, report, selection_raw, model, measurement, report_raw


def evaluate(root, assets, policy, verifier, *, now=None):
    # Policy comes from the operator, never the request or publisher.
    policy = rs._json(m0_candidate.encode(policy))
    fields(
        policy,
        "composition_sha256 ratification_sha256 selection_sha256 "
        "ratification_revision review_trust release_policy",
    )
    candidate, base, report, selection_raw, model, measurement, report_raw = verify_composition(
        root, assets, policy, verifier
    )
    selected = rs._json(selection_raw)["components"]
    ratification_raw, subject, admitted, legal_raw = (
        read(root / name)
        for name in (
            "ratification.json",
            "review-packet.json",
            "admitted-candidate.json",
            "legal.json",
        )
    )
    require(rs._sha(ratification_raw) == policy["ratification_sha256"])
    ratification, packet, release, legal = map(
        rs._json, (ratification_raw, subject, admitted, legal_raw)
    )
    fields(
        ratification,
        "version status scope contract_revision candidate_sha256 "
        "composition_sha256 exclusions conditions",
    )
    require(type(ratification["version"]) is int and ratification["version"] == 1)
    require(
        ratification["status"] == "RATIFIED_FOR_M0_NONPRODUCTION"
        and ratification["scope"] == review_evidence.SCOPE
    )
    require(
        ratification["contract_revision"] == rs.SPEC_REVISION
        and ratification["candidate_sha256"] == rs._sha(candidate)
        and ratification["composition_sha256"] == policy["composition_sha256"]
        and ratification["conditions"] == []
    )
    require(
        packet["composition_sha256"] == policy["composition_sha256"]
        and packet["contract_revision"] == rs.SPEC_REVISION
        and packet["exclusions"] == ratification["exclusions"]
    )
    subjects = {
        "candidate.json": candidate,
        "admitted-candidate.json": admitted,
        "selection.json": selection_raw,
        "model.json": model,
        "measurement.json": measurement,
        "ratification.json": ratification_raw,
        "composition-report.json": report_raw,
        "legal.json": legal_raw,
        "generated/manifest.json": rs._MANIFEST,
    }
    for name, raw in subjects.items():
        require(packet["candidate_digests"].get(name) == rs._sha(raw))
    reviews = {
        role: tuple(
            read(root / "reviews" / (role.lower().replace(" ", "-") + suffix))
            for suffix in (".json", ".sigstore.json")
        )
        for role in review_evidence.ROLES
    }
    authenticated = review_evidence.verify_reviews(
        subject, policy["review_trust"], reviews, verifier, now=now
    )
    require(authenticated["blocking_roles"] == [])
    release_policy = policy["release_policy"]
    require(release_policy["intended_use"] == policy["review_trust"]["intended_use"])
    fields(
        legal,
        "version disposition intended_use parameter_set_digest "
        "parameter_security crypto_permissions conditions",
    )
    require(
        type(legal["version"]) is int
        and legal["version"] == 1
        and legal["disposition"] == "REVIEWED_ALLOWED_NONPRODUCTION_FAKE_ONLY"
    )
    require(
        legal["intended_use"] == release_policy["intended_use"]
        and legal["parameter_set_digest"] == base["workload"]["parameter_set_digest"]
        and legal["parameter_security"] == "APPROVED_RESEARCH_BASELINE_ONLY"
        and legal["crypto_permissions"] == "DISTRIBUTION_SERVICE_DENIED"
        and legal["conditions"] == []
    )
    require(
        release["legal"]
        == {
            "disposition": "REVIEWED_ALLOWED",
            "intended_use": legal["intended_use"],
            "evidence_sha256": [rs._sha(legal_raw)],
        }
    )
    require(release["ratification_revision"] == policy["ratification_revision"])
    require(
        isinstance(policy["ratification_revision"], str)
        and re.fullmatch("[a-f0-9]{40}", policy["ratification_revision"]) is not None
    )
    require(
        {k: v for k, v in release.items() if k not in {"legal", "ratification_revision"}}
        == {k: v for k, v in base.items() if k not in {"legal", "ratification_revision"}}
    )
    components, trusts = {}, {}
    for name in m0_candidate.COMPONENTS:
        chosen = selected[name]
        publication_manifest = read(assets / name / "manifest.json")
        publication = rs.PublicationInput(
            publication_manifest,
            read(assets / name / "manifest.sigstore.json"),
            {
                n: m0_candidate.local(assets / name, n)
                for n in rs._json(publication_manifest)["subjects"]
            },
        )
        components[name] = rs.ComponentInput(
            chosen["reference"],
            m0_candidate.local(assets / name, chosen["artifact_filename"]),
            b"",
            b"",
            publication,
        )
        trusted = release_policy["components"][name]
        fields(trusted, "reference builder_id build_type source manifest_sha256 subject")
        trusts[name] = rs.ComponentPolicy(
            trusted["reference"],
            trusted["builder_id"],
            trusted["build_type"],
            b"",
            rs.PublisherPolicy(trusted["source"], trusted["manifest_sha256"], trusted["subject"]),
        )
    fields(release_policy, "candidate_sha256 intended_use reviewer_key components")
    require(set(release_policy["components"]) == set(m0_candidate.COMPONENTS))
    trusted_policy = rs.ReleasePolicy(
        release_policy["candidate_sha256"],
        release_policy["intended_use"],
        release_policy["reviewer_key"].encode("ascii"),
        trusts,
    )
    rs.validate_release_set(
        admitted,
        read(root / "admitted-candidate.sigstore.json"),
        components,
        {rs._sha(raw): raw for raw in (model, measurement, legal_raw)},
        trusted_policy,
        verifier,
    )
    return {
        "kind": "M0_NONPRODUCTION_ACCEPTANCE_EVALUATION",
        "status": "ACCEPTED_FOR_M1_DEVELOPMENT",
        "accepted": True,
        "candidate_sha256": rs._sha(admitted),
        "tested_candidate_sha256": rs._sha(candidate),
        "composition_sha256": policy["composition_sha256"],
        "ratification_sha256": policy["ratification_sha256"],
        "review_packet_sha256": rs._sha(subject),
        "production_ready": False,
        "profile_enabled": False,
        "deployment_authorized": False,
        "m1_admitted": True,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--request", type=Path, required=True)
    parser.add_argument("--assets", type=Path, required=True)
    parser.add_argument("--policy", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = evaluate(
            args.request,
            args.assets,
            rs._json(read(args.policy)),
            rs.Cosign(Path(__file__).resolve().parents[1] / ".tools/cosign"),
        )
        print(json.dumps(result, sort_keys=True))
        return 0
    except Exception:
        print("M0_ACCEPTANCE_REJECTED", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
