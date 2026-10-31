"""Versioned solo-owner review gate. No approval defaults or acceptance publication."""

import argparse
import json
import re
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from tempfile import TemporaryDirectory

from kryvola_platform import release_set as rs

if __package__:
    from . import m0_accept, m0_candidate, m0_composition, review_evidence
else:
    import m0_accept
    import m0_candidate
    import m0_composition
    import review_evidence

require = review_evidence.require
fields = review_evidence.fields
MODE = "SOLO_OWNER_AGENTIC_V1"
DOMAINS = ("compatibility", "security", "dependency_licensing", "operations")
FILES = {"composition/report.json"}
FILES |= {
    "composition/candidate/" + n + ".json"
    for n in ("candidate", "lock", "selection", "model", "measurement")
}
FILES |= {"composition/live/" + n for n in m0_composition.LIVE}


def read(root, name):
    require(root.is_dir() and not root.is_symlink())
    path = root
    for part in Path(name).parts:
        require(part not in {".", ".."} and not Path(part).is_absolute())
        path = path / part
        require(not path.is_symlink())
    return review_evidence.read(path)


def github(policy):
    """Authenticated HTTPS via gh; paths derive only from independent operator policy."""
    repo = policy["repository"]
    require(repo in {"stanimirivanov/kryvola-" + n for n in m0_candidate.COMPONENTS})
    number = policy["pull_request"]
    require(type(number) is int and number > 0)

    def fetch(suffix, paginate=False):
        endpoint = (
            f"repos/{repo}/issues/{number}/comments" if suffix else f"repos/{repo}/pulls/{number}"
        )
        command = ["gh", "api", endpoint]
        if paginate:
            command += ["--paginate", "--slurp"]
        raw = subprocess.run(command, capture_output=True, check=True, timeout=30).stdout
        return rs._json(b'{"pages":' + raw + b"}")["pages"] if paginate else rs._json(raw)

    return fetch(""), [r for page in fetch("/comments", True) for r in page]


def approval_body(subject, report, intended_use, revision):
    return (
        f"KRYVOLA_SOLO_OWNER_APPROVAL_V1\nsubject_sha256={subject}\n"
        f"agentic_review_sha256={report}\nintended_use={intended_use}\nreviewed_revision={revision}"
    )


def verify(root, assets, policy, verifier, *, fetch=github, now=None):
    policy = rs._json(m0_candidate.encode(policy))
    fields(
        policy,
        "version governance subject_sha256 agentic_review_sha256 composition_sha256 "
        "selection_sha256 intended_use owner_login repository pull_request approval_comment_id "
        "reviewed_revision valid_until revoked_comment_ids",
    )
    require(
        type(policy["version"]) is int and policy["version"] == 2 and policy["governance"] == MODE
    )
    for name in (
        "subject_sha256",
        "agentic_review_sha256",
        "composition_sha256",
        "selection_sha256",
    ):
        review_evidence.sha(policy[name])
    review_evidence.text(policy["intended_use"])
    require(re.fullmatch(r"[A-Za-z0-9-]{1,39}", policy["owner_login"]) is not None)
    require(re.fullmatch("[a-f0-9]{40}", policy["reviewed_revision"]) is not None)
    require(type(policy["approval_comment_id"]) is int and policy["approval_comment_id"] > 0)
    require(type(policy["revoked_comment_ids"]) is list)
    require(all(type(n) is int and n > 0 for n in policy["revoked_comment_ids"]))
    require(policy["approval_comment_id"] not in policy["revoked_comment_ids"])
    now = now if now is not None else datetime.now(UTC)
    require(now < review_evidence.timestamp(policy["valid_until"]))
    subject_raw, report_raw = read(root, "solo-subject.json"), read(root, "agentic-review.json")
    require(rs._sha(subject_raw) == policy["subject_sha256"])
    require(rs._sha(report_raw) == policy["agentic_review_sha256"])
    subject, report = rs._json(subject_raw), rs._json(report_raw)
    fields(
        subject,
        "version governance scope intended_use candidate_sha256 composition_sha256 "
        "selection_sha256 exclusions production_ready profile_enabled",
    )
    require(
        type(subject["version"]) is int
        and subject["version"] == 2
        and subject["governance"] == MODE
    )
    require(
        subject["scope"] == review_evidence.SCOPE
        and subject["intended_use"] == policy["intended_use"]
    )
    require(subject["production_ready"] is False and subject["profile_enabled"] is False)
    require(type(subject["exclusions"]) is list and bool(subject["exclusions"]))
    for item in subject["exclusions"]:
        review_evidence.text(item)
    fields(
        report,
        "version kind subject_sha256 reviewer repositories checks blockers "
        "residual_risks limitations",
    )
    require(type(report["version"]) is int and report["version"] == 1)
    require(
        report["kind"] == "AGENTIC_REVIEW" and report["subject_sha256"] == policy["subject_sha256"]
    )
    review_evidence.text(report["reviewer"])
    require(sorted(report["repositories"]) == sorted(m0_candidate.COMPONENTS))
    fields(report["checks"], " ".join(DOMAINS))
    for check in report["checks"].values():
        fields(check, "status summary")
        require(check["status"] in {"PASS", "LIMITATION"})
        review_evidence.text(check["summary"])
    require(report["blockers"] == [])
    for name in ("residual_risks", "limitations"):
        require(type(report[name]) is list and bool(report[name]))
        for item in report[name]:
            review_evidence.text(item)
    retained = {name: read(root, name) for name in sorted(FILES)}
    with TemporaryDirectory() as temporary:
        snapshot = Path(temporary)
        for name, raw in retained.items():
            path = snapshot / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
        candidate, base, composition, *_ = m0_accept.verify_composition(
            snapshot, assets, policy, verifier
        )
    require(subject["candidate_sha256"] == rs._sha(candidate))
    for name in ("composition_sha256", "selection_sha256"):
        require(subject[name] == policy[name])
    # The reviewed set remains disabled and legally unresolved. No manufactured
    # legal clearance, parameter approval or signed admitted-candidate is created.
    require(base["legal"]["disposition"] == "UNRESOLVED")
    require(base["legal"]["intended_use"] == policy["intended_use"])
    pull, reviews = fetch(policy)
    require(pull["head"]["sha"] == policy["reviewed_revision"] and pull["draft"] is False)
    owner_reviews = [
        r
        for r in reviews
        if r["user"]["login"] == policy["owner_login"]
        and r["body"].startswith("KRYVOLA_SOLO_OWNER_")
    ]
    require(bool(owner_reviews))
    latest = max(owner_reviews, key=lambda r: r["id"])
    require(latest["id"] == policy["approval_comment_id"])
    require(review_evidence.timestamp(latest["updated_at"]) <= now)
    require(
        latest["body"].strip()
        == approval_body(
            policy["subject_sha256"],
            policy["agentic_review_sha256"],
            policy["intended_use"],
            policy["reviewed_revision"],
        )
    )
    return {
        "kind": "QUALIFIED_SOLO_OWNER_REVIEW",
        "governance": MODE,
        "owner_approved": True,
        "eligible_for_m0_ratification": True,
        "subject_sha256": policy["subject_sha256"],
        "agentic_review_sha256": policy["agentic_review_sha256"],
        "m0_accepted": False,
        "m1_admitted": False,
        "production_ready": False,
        "profile_enabled": False,
        "deployment_authorized": False,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("request", "assets", "policy"):
        parser.add_argument("--" + name, required=True, type=Path)
    args = parser.parse_args()
    try:
        result = verify(
            args.request,
            args.assets,
            rs._json(review_evidence.read(args.policy)),
            rs.Cosign(Path(__file__).resolve().parents[1] / ".tools/cosign"),
        )
        print(json.dumps(result, sort_keys=True))
        return 0
    except Exception:
        print("SOLO_OWNER_REVIEW_REJECTED", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
