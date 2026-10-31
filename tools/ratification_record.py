"""Authenticate a recorded successor against independent policy; never publish or admit."""

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from tempfile import TemporaryDirectory

from kryvola_platform import release_set as rs

if __package__:
    from . import m0_accept, m0_publication, review_evidence
else:
    import m0_accept
    import m0_publication
    import review_evidence

require = review_evidence.require
fields = review_evidence.fields


def read(root, name):
    path = root
    require(root.is_dir() and not root.is_symlink())
    for part in Path(name).parts:
        require(part not in {".", ".."} and not Path(part).is_absolute())
        path = path / part
        require(not path.is_symlink())
    return review_evidence.read(path)


def committed(repository, revision, name):
    """Read bounded regular Git blobs only; no fetch, checkout or foreign code execution."""
    require(re.fullmatch("[a-f0-9]{40}", revision) is not None)
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull, GIT_NO_REPLACE_OBJECTS="1")

    def git(*args):
        return subprocess.run(
            ["git", "--no-replace-objects", "-C", str(repository), *args],
            check=True,
            capture_output=True,
            timeout=10,
            env=env,
        ).stdout

    require(git("cat-file", "-t", revision).strip() == b"commit")
    entry = git("ls-tree", revision, "--", name).decode().strip().split()
    require(
        len(entry) == 4
        and entry[0] in {"100644", "100755"}
        and entry[1] == "blob"
        and entry[3] == name
    )
    require(int(git("cat-file", "-s", entry[2])) <= rs.MAX_METADATA)
    return git("cat-file", "blob", entry[2])


def verify(record_raw, request, assets, policy, spec_repository, verifier, *, now=None):
    # Snapshot independent configuration; never enroll authority from the request.
    policy = rs._json(json.dumps(policy, allow_nan=False).encode())
    fields(
        policy, "record_sha256 predecessor_sha256 ledger_sha256 proposal_revision acceptance_policy"
    )
    for name in ("record_sha256", "predecessor_sha256", "ledger_sha256"):
        review_evidence.sha(policy[name])
    require(rs._sha(record_raw) == policy["record_sha256"])
    record = rs._json(record_raw)
    fields(
        record,
        "version status scope predecessor_sha256 proposal_revision ledger_sha256 "
        "ratification_sha256 packet_sha256 reviews production_ready "
        "profile_enabled m0_accepted m1_admitted",
    )
    require(type(record["version"]) is int and record["version"] == 1)
    require(record["status"] == "RECORDED_SUCCESSOR" and record["scope"] == review_evidence.SCOPE)
    require(
        all(
            record[n] is False
            for n in ("production_ready", "profile_enabled", "m0_accepted", "m1_admitted")
        )
    )
    for name in ("predecessor_sha256", "ledger_sha256", "proposal_revision"):
        require(record[name] == policy[name])
    acceptance = policy["acceptance_policy"]
    require(record["proposal_revision"] == acceptance["ratification_revision"])
    require(record["ratification_sha256"] == acceptance["ratification_sha256"])
    require(record["packet_sha256"] == acceptance["review_trust"]["subject_sha256"])
    retained = {name: read(request, name) for name in sorted(m0_publication.FILES)}
    ledger_raw = read(request, "ledger.json")
    require(rs._sha(ledger_raw) == policy["ledger_sha256"])
    ledger = rs._json(ledger_raw)
    fields(
        ledger,
        "version status components candidate_sha256 input_lock_sha256 report_sha256 "
        "evidence cleanup_verified production_ready m0_accepted m1_admitted",
    )
    require(type(ledger["version"]) is int and ledger["version"] == 1)
    require(
        ledger["status"] == "RECORDED_NONPRODUCTION_QUALIFICATION"
        and ledger["cleanup_verified"] is True
    )
    require(all(ledger[n] is False for n in ("production_ready", "m0_accepted", "m1_admitted")))
    report_raw = retained["composition/report.json"]
    report = rs._json(report_raw)
    require(ledger["report_sha256"] == rs._sha(report_raw) == acceptance["composition_sha256"])
    for name in ("components", "candidate_sha256", "input_lock_sha256"):
        require(ledger[name] == report[name])
    fields(ledger["evidence"], "reference archive_sha256")
    from urllib.parse import urlsplit

    location = urlsplit(ledger["evidence"]["reference"])
    review_evidence.sha(ledger["evidence"]["archive_sha256"])
    require(
        location.scheme == "https"
        and bool(location.hostname)
        and not location.username
        and not location.password
        and not location.query
        and location.fragment == "sha256=" + ledger["evidence"]["archive_sha256"]
    )
    archive = request / "composition/evidence.tar"
    require(not archive.is_symlink() and archive.is_file() and archive.stat().st_size <= 64 << 20)
    require(rs._artifact_digest(archive) == ledger["evidence"]["archive_sha256"])
    for name, expected in {
        "docs/m0-ratification-proposal.json": retained["ratification.json"],
        "docs/m0-composition-qualification.json": ledger_raw,
    }.items():
        require(committed(spec_repository, policy["proposal_revision"], name) == expected)
    predecessor = committed(
        spec_repository, policy["proposal_revision"], "docs/m0-ratification-decision.md"
    )
    require(rs._sha(predecessor) == policy["predecessor_sha256"])
    require(
        type(record["reviews"]) is list and len(record["reviews"]) == len(review_evidence.ROLES)
    )
    require({r["role"] for r in record["reviews"]} == set(review_evidence.ROLES))
    for review in record["reviews"]:
        fields(review, "role decision_sha256 bundle_sha256")
        slug = review["role"].lower().replace(" ", "-")
        for key, suffix in (("decision_sha256", ".json"), ("bundle_sha256", ".sigstore.json")):
            require(review[key] == rs._sha(retained["reviews/" + slug + suffix]))
    # Existing evaluator authenticates every role and publisher and all live predicates.
    with TemporaryDirectory() as temporary:
        root = Path(temporary)
        for name, raw in retained.items():
            target = root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(raw)
        result = m0_accept.evaluate(root, assets, acceptance, verifier, now=now)
    require(
        result["accepted"] is True
        and result["production_ready"] is False
        and result["profile_enabled"] is False
        and result["deployment_authorized"] is False
    )
    return {
        "kind": "AUTHENTICATED_SUCCESSOR_RECORD_ONLY",
        "record_sha256": rs._sha(record_raw),
        "authenticated": True,
        "m0_accepted": False,
        "m1_admitted": False,
        "production_ready": False,
        "profile_enabled": False,
        "deployment_authorized": False,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("record", "request", "assets", "policy", "spec-repository"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    try:
        print(
            json.dumps(
                verify(
                    review_evidence.read(args.record),
                    args.request,
                    args.assets,
                    rs._json(review_evidence.read(args.policy)),
                    args.spec_repository,
                    rs.Cosign(Path(__file__).resolve().parents[1] / ".tools/cosign"),
                ),
                sort_keys=True,
            )
        )
        return 0
    except Exception:
        print("RATIFICATION_RECORD_REJECTED", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
