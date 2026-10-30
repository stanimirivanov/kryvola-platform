"""Guarded detached M0 publication; preparation never supplies approvals or publishes."""

import argparse
import io
import json
import re
import sys
import tarfile
from pathlib import Path
from tempfile import TemporaryDirectory

from kryvola_platform import release_set as rs

if __package__:
    from . import m0_accept, m0_candidate, m0_composition, release, review_evidence
else:
    import m0_accept
    import m0_candidate
    import m0_composition
    import release
    import review_evidence

IDENTITY = "https://github.com/stanimirivanov/kryvola-platform/.github/workflows/m0-acceptance.yml@refs/heads/main"
FILES = {
    "ratification.json",
    "review-packet.json",
    "legal.json",
    "admitted-candidate.json",
    "admitted-candidate.sigstore.json",
}
FILES |= {
    "reviews/" + role.lower().replace(" ", "-") + suffix
    for role in review_evidence.ROLES
    for suffix in (".json", ".sigstore.json")
}
FILES |= {
    "composition/candidate/" + name
    for name in ("candidate.json", "lock.json", "selection.json", "model.json", "measurement.json")
}
FILES |= {"composition/live/" + name for name in m0_composition.LIVE}
FILES.add("composition/report.json")
require = review_evidence.require
read = review_evidence.read
encode = m0_candidate.encode


def source_pin(source):
    require(isinstance(source, str) and re.fullmatch("[a-f0-9]{40}", source) is not None)


def prepare(request, assets, policy_raw, source, output, verifier):
    source_pin(source)
    require(not output.exists())
    # Evaluate a snapshot of allowlisted public evidence, excluding arbitrary extras.
    retained = {name: read(request / name) for name in sorted(FILES)}
    with TemporaryDirectory() as directory:
        root = Path(directory)
        for name, raw in retained.items():
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
        result = m0_accept.evaluate(root, assets, rs._json(policy_raw), verifier)
    require(
        result["accepted"] is True
        and result["production_ready"] is False
        and result["profile_enabled"] is False
        and result["deployment_authorized"] is False
    )
    archive_bytes = io.BytesIO()
    with tarfile.open(fileobj=archive_bytes, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for name, raw in retained.items():
            member = tarfile.TarInfo(name)
            member.size, member.mode = len(raw), 0o644
            archive.addfile(member, io.BytesIO(raw))
    archive_raw = archive_bytes.getvalue()
    require(len(archive_raw) <= 16 << 20)
    payload = {
        "format": "m0-acceptance-publication-v1",
        "publisher_source": source,
        "policy_sha256": rs._sha(policy_raw),
        "evaluation": result,
        "evidence_sha256": rs._sha(archive_raw),
        "subjects": {name: rs._sha(raw) for name, raw in retained.items()},
    }
    payload_raw = encode(payload)
    require(len(payload_raw) <= rs.MAX_METADATA)
    output.mkdir(exist_ok=False)
    (output / "evidence.tar").write_bytes(archive_raw)
    (output / "acceptance.json").write_bytes(payload_raw)
    return rs._sha(payload_raw)


def verify(folder, assets, policy_raw, source, expected_sha256, verifier):
    source_pin(source)
    require(re.fullmatch("[a-f0-9]{64}", expected_sha256) is not None)
    require(
        {p.name for p in folder.iterdir()}
        == {"acceptance.json", "acceptance.sigstore.json", "evidence.tar"}
    )
    raw = read(folder / "acceptance.json")
    require(rs._sha(raw) == expected_sha256)
    payload = rs._json(raw)
    review_evidence.fields(
        payload, "format publisher_source policy_sha256 evaluation evidence_sha256 subjects"
    )
    require(
        payload["format"] == "m0-acceptance-publication-v1"
        and payload["publisher_source"] == source
    )
    require(payload["policy_sha256"] == rs._sha(policy_raw) and set(payload["subjects"]) == FILES)
    archive_path = folder / "evidence.tar"
    require(
        archive_path.is_file()
        and not archive_path.is_symlink()
        and archive_path.stat().st_size <= 16 << 20
    )
    require(rs._artifact_digest(archive_path) == payload["evidence_sha256"])
    verifier.verify_publisher(raw, read(folder / "acceptance.sigstore.json"), IDENTITY, source)
    with TemporaryDirectory() as directory:
        root = Path(directory)
        seen = set()
        with tarfile.open(archive_path) as archive:
            for member in archive:
                require(
                    member.name in FILES
                    and member.name not in seen
                    and member.isfile()
                    and member.size <= rs.MAX_METADATA
                )
                seen.add(member.name)
                stream = archive.extractfile(member)
                if stream is None:
                    raise ValueError("MISSING_PUBLIC_EVIDENCE")
                value = stream.read(rs.MAX_METADATA + 1)
                require(rs._sha(value) == payload["subjects"][member.name])
                path = root / member.name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(value)
        require(seen == FILES)
        # A valid publisher signature is insufficient: reauthenticate all reviews,
        # freshness/revocation, composition and signed candidate under current trust.
        result = m0_accept.evaluate(root, assets, rs._json(policy_raw), verifier)
    require(result == payload["evaluation"] and result["accepted"] is True)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["prepare", "verify"])
    parser.add_argument("--request", type=Path)
    parser.add_argument("--assets", type=Path, required=True)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--source", required=True)
    parser.add_argument("--folder", type=Path, required=True)
    parser.add_argument("--sha256")
    args = parser.parse_args()
    try:
        verifier = rs.Cosign(Path(__file__).resolve().parents[1] / ".tools/cosign")
        policy = read(args.policy)
        if args.command == "prepare":
            require(args.request is not None and args.sha256 is None)
            require(
                release.git("rev-parse", "HEAD") == args.source
                and not release.git("status", "--porcelain")
            )
            print(prepare(args.request, args.assets, policy, args.source, args.folder, verifier))
        else:
            require(args.sha256 is not None and args.request is None)
            print(
                json.dumps(
                    verify(args.folder, args.assets, policy, args.source, args.sha256, verifier),
                    sort_keys=True,
                )
            )
        return 0
    except Exception:
        print("M0_PUBLICATION_REJECTED", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
