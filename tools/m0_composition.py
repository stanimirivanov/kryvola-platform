"""Exact experimental composition qualification; no acceptance or publication authority."""

import argparse
import importlib.metadata
import importlib.util
import json
import sys
import tarfile
import tempfile
from pathlib import Path
from zipfile import ZipFile

from kryvola_platform import release_set as rs

if __package__:
    from . import (
        m0_acceptance,
        m0_candidate,
        network_benchmark,
        workflow_assets,
    )
    from . import release as publication
else:
    import m0_acceptance
    import m0_candidate
    import network_benchmark
    import release as publication
    import workflow_assets

ROOT = Path(__file__).resolve().parents[1]
LIVE = tuple(sorted(m0_acceptance.LIVE)) + ("network-observations.jsonl",)
require = m0_candidate.require
read = m0_candidate.read
encode = m0_candidate.encode


def installed(name, wheel, source):
    distribution = importlib.metadata.distribution("kryvola-" + name)
    require(distribution.version == "0.1.0.dev0+g" + source)
    direct = distribution.read_text("direct_url.json")
    require(direct is None or not json.loads(direct).get("dir_info", {}).get("editable", False))
    package = "kryvola_" + name
    spec = importlib.util.find_spec(package)
    expected_origin = Path(str(distribution.locate_file(package + "/__init__.py")))
    require(
        spec is not None
        and spec.origin is not None
        and Path(spec.origin).resolve() == expected_origin.resolve()
    )
    require(not expected_origin.parent.is_symlink())
    require(not any(p.is_symlink() for p in expected_origin.parent.rglob("*")))
    with ZipFile(wheel) as archive:
        names = [
            n for n in archive.namelist() if n.startswith(package + "/") and not n.endswith("/")
        ]
        require(bool(names) and len(names) == len(set(names)))
        for name in names:
            entry = archive.getinfo(name)
            require(entry.file_size <= 16 << 20)
            target = Path(str(distribution.locate_file(name)))
            require(
                not target.is_symlink()
                and target.is_file()
                and target.read_bytes() == archive.read(entry)
            )
        actual = {
            package + "/" + p.relative_to(expected_origin.parent).as_posix()
            for p in expected_origin.parent.rglob("*")
            if p.is_file() and "__pycache__" not in p.parts
        }
        require(actual == set(names))


def driver(archive):
    # Compare every allowed tracked driver byte, not a hand-picked config subset.
    names = publication.git("ls-files", "-z").split("\0")
    expected = {n for n in names if n and n.split("/")[0] in publication.DRIVER_INPUTS}
    seen = set()
    with tarfile.open(archive) as tar:
        for index, entry in enumerate(tar):
            require(index < 4096 and (entry.isfile() or entry.isdir()))
            if entry.isdir():
                continue
            require(entry.name in expected and entry.name not in seen and entry.size <= 16 << 20)
            seen.add(entry.name)
            target = ROOT / entry.name
            require(
                target.is_file() and not target.is_symlink() and target.stat().st_size == entry.size
            )
            stream = tar.extractfile(entry)
            require(stream is not None and stream.read((16 << 20) + 1) == target.read_bytes())
    require(seen == expected)


def preflight(bundle, assets, verifier):
    selection_raw = read(bundle / "selection.json")
    candidate, lock = m0_candidate.assemble(
        selection_raw,
        read(bundle / "model.json"),
        read(bundle / "measurement.json"),
        assets,
        verifier,
    )
    require(candidate == read(bundle / "candidate.json") and lock == read(bundle / "lock.json"))
    selection, candidate_value = rs._json(selection_raw), rs._json(candidate)
    chosen = selection["components"]
    source = m0_acceptance.source_commit()  # Clean checkout; never forge Git metadata.
    require(source == chosen["platform"]["source_revision"])
    driver(assets / "platform/driver.tar")
    for name in ("fabric", "ml", "platform"):
        installed(name, assets / name / chosen[name]["subject"], chosen[name]["publisher_source"])
    publication.run(
        sys.executable,
        "-I",
        "-c",
        "from kryvola_ml.baseline.fixture import verify_fixture; "
        "assert verify_fixture()['cases'] == 100",
        cwd=ROOT,
    )
    locked = workflow_assets.pins()
    for name in ("fabric", "engines"):
        require(locked[name]["source"] == chosen[name]["publisher_source"])
        # Existing runtime consumes these package bytes; signatures and all sidecars
        # must also match the selected, already verified publication.
        if name == "engines" and chosen[name]["subject"] == "@oci-manifest":
            oci = rs._json(read(assets / name / "manifest.json"))
            require(oci["archive_manifest_sha256"] == locked[name]["assets"]["manifest.json"])
        else:
            expected = dict(rs._json(read(assets / name / "manifest.json"))["subjects"])
            expected.update(
                {
                    "manifest.json": chosen[name]["manifest_sha256"],
                    "manifest.sigstore.json": rs._sha(
                        read(assets / name / "manifest.sigstore.json")
                    ),
                }
            )
            require(locked[name]["assets"] == expected)
    # Runtime assets are separately installed by explicit setup; never fall back.
    workflow_assets.verify()
    for name in ("fabric", "engines"):
        for filename, digest in locked[name]["assets"].items():
            require(workflow_assets.digest(workflow_assets.OUTPUT / name / filename) == digest)
    return source, locked, rs._sha(candidate), rs._sha(lock), candidate_value


def engine_oci(bundle, verifier):
    chosen = rs._json(read(bundle / "selection.json"))["components"]["engines"]
    if chosen["subject"] != "@oci-manifest":
        return
    image = chosen["reference"]
    run = network_benchmark.integration.run
    args = [
        verifier.executable,
        "verify",
        "--certificate-identity",
        "https://github.com/stanimirivanov/kryvola-engines/.github/workflows/release.yml@refs/heads/main",
        "--certificate-oidc-issuer",
        "https://token.actions.githubusercontent.com",
        "--certificate-github-workflow-sha",
        chosen["publisher_source"],
        "--certificate-github-workflow-trigger",
        "workflow_dispatch",
        image,
    ]
    run(args, timeout=60).check_returncode()
    run(["docker", "pull", image], timeout=600).check_returncode()
    result = run(["docker", "image", "inspect", image])
    result.check_returncode()
    image_config = json.loads(result.stdout)[0]["Config"]
    require(
        image_config["User"] == "65532:65532"
        and image_config["Entrypoint"] == ["/opt/kryvola/engine"]
    )
    created = run(["docker", "create", image])
    created.check_returncode()
    container = created.stdout.decode().strip()
    require(bool(container))
    try:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run(["docker", "cp", container + ":/opt/kryvola/.", root]).check_returncode()
            with tarfile.open(workflow_assets.OUTPUT / "engines/package.tar") as archive:
                require(
                    sorted(p.name for p in root.iterdir()) == ["Cargo.lock", "LICENSE", "engine"]
                )
                for name in ("engine", "LICENSE", "Cargo.lock"):
                    stream = archive.extractfile(name)
                    if stream is None:
                        raise ValueError("MISSING_IMAGE_ARCHIVE_FILE")
                    require(not (root / name).is_symlink())
                    require(stream.read(32 << 20) == (root / name).read_bytes())
    finally:
        run(["docker", "rm", container]).check_returncode()
    run(
        [
            "docker",
            "run",
            "--rm",
            "--read-only",
            "--network=none",
            "--tmpfs",
            "/tmp",
            image,
            "conformance",
        ],
        timeout=600,
    ).check_returncode()


def qualify(bundle, assets, output, verifier):
    require(not output.exists())
    source, releases, candidate_sha, lock_sha, candidate = preflight(bundle, assets, verifier)
    engine_oci(bundle, verifier)
    prior = set((ROOT / "build/integration").glob("*"))
    completed = []
    network_benchmark.execute(completed=lambda folder: completed.append(folder))
    require(len(completed) == 1 and not network_benchmark.integration.ACTIVE.exists())
    folder = completed[0]
    require(
        folder not in prior
        and folder.resolve().parent == (ROOT / "build/integration").resolve()
        and not folder.is_symlink()
    )
    records = {name: rs._json(read(folder / name)) for name in m0_acceptance.LIVE}
    m0_acceptance.validate_live(records, source, releases)
    # Recheck after the live gates so mutable local inputs cannot silently drift.
    again = preflight(bundle, assets, verifier)
    require(again[:4] == (source, releases, candidate_sha, lock_sha))
    require(not network_benchmark.integration.ACTIVE.exists())
    retained = {
        "candidate/" + p.name: read(bundle / p.name)
        for p in (
            bundle / "candidate.json",
            bundle / "lock.json",
            bundle / "selection.json",
            bundle / "model.json",
            bundle / "measurement.json",
        )
    }
    retained.update({"live/" + name: read(folder / name) for name in LIVE})
    report = {
        "kind": "EXACT_NONPRODUCTION_FIXTURE_COMPOSITION_TESTED",
        "candidate_sha256": candidate_sha,
        "input_lock_sha256": lock_sha,
        "platform_source": source,
        "components": candidate["components"],
        "cleanup_verified": True,
        "production_ready": False,
        "m0_accepted": False,
        "m1_admitted": False,
        "subjects": {name: rs._sha(raw) for name, raw in retained.items()},
    }
    output.mkdir(exist_ok=False)
    for name, raw in retained.items():
        path = output / name
        path.parent.mkdir(exist_ok=True)
        path.write_bytes(raw)
    (output / "report.json").write_bytes(encode(report))
    # One durable-copy artifact; no upload, retention expiry or acceptance is inferred.
    with tarfile.open(output / "evidence.tar", "w", format=tarfile.USTAR_FORMAT) as archive:
        for path in sorted(
            p for p in output.rglob("*") if p.is_file() and p.name != "evidence.tar"
        ):
            entry = tarfile.TarInfo(path.relative_to(output).as_posix())
            entry.size, entry.mode = path.stat().st_size, 0o644
            with path.open("rb") as stream:
                archive.addfile(entry, stream)
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--assets", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        qualify(args.bundle, args.assets, args.output, rs.Cosign(ROOT / ".tools/cosign"))
        print("EXACT_COMPOSITION_TESTED; approvals and acceptance remain pending")
    except Exception:
        print("M0_COMPOSITION_REJECTED", file=sys.stderr)
        sys.exit(1)
