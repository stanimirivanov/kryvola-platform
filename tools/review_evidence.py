"""Authenticate local administrative review bytes; never admit a release or infer authority."""

import argparse
import hashlib
import json
import re
import sys
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlsplit

from kryvola_platform.release_set import Cosign, ReleaseError, _json

ROLES = (
    "Spec lead",
    "Fabric lead",
    "Engines lead",
    "ML lead",
    "Platform lead",
    "Security reviewer",
    "Legal reviewer",
    "Operational owner",
)
SCOPE = "M0_CONTRACT_FEASIBILITY_AND_NONPRODUCTION_COMPOSITION"


def require(condition):
    if not condition:
        raise ValueError("REVIEW_EVIDENCE_REJECTED")


def fields(value, names):
    require(type(value) is dict and set(value) == set(names.split()))


def digest(value):
    return hashlib.sha256(value).hexdigest()


def sha(value):
    require(isinstance(value, str) and re.fullmatch("[a-f0-9]{64}", value) is not None)


def text(value):
    require(isinstance(value, str) and 0 < len(value.strip()) <= 2048)


def timestamp(value):
    require(
        isinstance(value, str)
        and re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", value) is not None
    )
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)


def read(path):
    require(path.is_file() and not path.is_symlink() and path.stat().st_size <= 131072)
    return path.read_bytes()


def verify_reviews(subject, trust, evidence, verifier, *, now=None):
    """Trust is operator-owned; evidence maps roles to exact (decision, bundle) bytes."""
    # Snapshot nested mappings before calling external verification.
    trust = _json(json.dumps(trust, allow_nan=False).encode())
    evidence = dict(evidence)
    now = now if now is not None else datetime.now(UTC)
    require(now.tzinfo is not None)
    fields(
        trust,
        "version subject_sha256 intended_use valid_until roles "
        "revoked_evidence_sha256 revoked_key_sha256",
    )
    require(type(trust["version"]) is int and trust["version"] == 1)
    sha(trust["subject_sha256"])
    require(digest(subject) == trust["subject_sha256"])
    text(trust["intended_use"])
    require(now < timestamp(trust["valid_until"]))
    packet = _json(subject)
    fields(
        packet, "version scope contract_revision candidate_digests composition_sha256 exclusions"
    )
    require(type(packet["version"]) is int and packet["version"] == 1 and packet["scope"] == SCOPE)
    require(re.fullmatch("[a-f0-9]{40}", packet["contract_revision"]) is not None)
    require(type(packet["candidate_digests"]) is dict and bool(packet["candidate_digests"]))
    for name, value in packet["candidate_digests"].items():
        text(name)
        sha(value)
    if packet["composition_sha256"] is not None:
        sha(packet["composition_sha256"])
    require(type(packet["exclusions"]) is list)
    for exclusion in packet["exclusions"]:
        text(exclusion)
    require(len(packet["exclusions"]) == len(set(packet["exclusions"])))
    for field in ("revoked_evidence_sha256", "revoked_key_sha256"):
        require(type(trust[field]) is list)
        for value in trust[field]:
            sha(value)
    require(type(trust["roles"]) is dict and set(trust["roles"]) == set(evidence) == set(ROLES))
    decisions = {}
    for role in ROLES:
        authority = trust["roles"][role]
        fields(authority, "identity authority public_key evidence_sha256 predecessor_sha256")
        for name in ("identity", "authority"):
            text(authority[name])
        sha(authority["evidence_sha256"])
        predecessor = authority["predecessor_sha256"]
        if predecessor is not None:
            sha(predecessor)
        raw, bundle = evidence[role]
        decision = _json(raw)
        fields(
            decision,
            "version role identity authority decision review_url subject_sha256 "
            "intended_use issued_at expires_at conditions supersedes_sha256",
        )
        require(type(decision["version"]) is int and decision["version"] == 1)
        require(digest(raw) == authority["evidence_sha256"])
        require(digest(raw) not in trust["revoked_evidence_sha256"])
        require(
            decision["role"] == role
            and decision["identity"] == authority["identity"]
            and decision["authority"] == authority["authority"]
        )
        require(
            decision["subject_sha256"] == trust["subject_sha256"]
            and decision["intended_use"] == trust["intended_use"]
        )
        require(decision["supersedes_sha256"] == predecessor and predecessor != digest(raw))
        issued, expires = timestamp(decision["issued_at"]), timestamp(decision["expires_at"])
        require(issued <= now < expires <= timestamp(trust["valid_until"]))
        require(decision["decision"] in {"APPROVE", "REJECT", "CONDITIONAL", "WITHDRAW"})
        url = urlsplit(decision["review_url"])
        require(
            url.scheme == "https"
            and bool(url.hostname)
            and url.username is None
            and url.password is None
        )
        require(type(decision["conditions"]) is list)
        for condition in decision["conditions"]:
            text(condition)
        require(
            bool(decision["conditions"])
            if decision["decision"] != "APPROVE"
            else not decision["conditions"]
        )
        key = authority["public_key"].encode("ascii")
        require(digest(key) not in trust["revoked_key_sha256"])
        verifier.verify(raw, bundle, key)
        decisions[role] = decision["decision"]
    return {
        "kind": "AUTHENTICATED_REVIEW_EVIDENCE_ONLY",
        "subject_sha256": trust["subject_sha256"],
        "decisions": decisions,
        "blocking_roles": [role for role in ROLES if decisions[role] != "APPROVE"],
        "m0_accepted": False,
        "m1_admitted": False,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--subject", type=Path, required=True)
    parser.add_argument("--trust", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument(
        "--cosign", type=Path, default=Path(__file__).resolve().parents[1] / ".tools/cosign"
    )
    args = parser.parse_args()
    try:
        evidence = {
            role: tuple(
                read(args.evidence / (role.lower().replace(" ", "-") + suffix))
                for suffix in (".json", ".sigstore.json")
            )
            for role in ROLES
        }
        result = verify_reviews(
            read(args.subject), _json(read(args.trust)), evidence, Cosign(args.cosign)
        )
        print(json.dumps(result, sort_keys=True))
        return 1 if result["blocking_roles"] else 0
    except (
        ValueError,
        TypeError,
        KeyError,
        AttributeError,
        OSError,
        UnicodeError,
        RecursionError,
        ReleaseError,
    ):
        print("REVIEW_EVIDENCE_REJECTED", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
