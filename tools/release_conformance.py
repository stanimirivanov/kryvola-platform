"""Fail-closed admission of the experimental composition; no production release permit."""

import argparse
import importlib.metadata
import importlib.util
import json
import os
import shutil
import sys
import tomllib
from pathlib import Path
from tempfile import TemporaryDirectory
from zipfile import ZipFile

from jsonschema import ValidationError

from kryvola_platform.inventory import validate_inventory

if __package__:
    from . import architecture, integration, workflow_assets
else:
    import architecture
    import integration
    import workflow_assets

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "build/release-conformance/spec-evidence.json"
CASES = (
    "unsigned",
    "wrong-signature",
    "asset-drift",
    "schema",
    "sibling-source",
    "mutable-image",
    "control-payload",
    "temporal-payload",
    "production",
    "upstream-failure",
)


class ProbeRejected(ValueError):
    """Only an intended guard failure, after successful mutation setup."""


def read(path):
    if path.is_symlink() or path.stat().st_size > 65536:
        raise ValueError("CONFORMANCE_METADATA_LIMIT")
    return json.loads(path.read_bytes())


def policy(root=ROOT):
    value = read(root / "config/release-conformance.json")
    lock = read(root / "spec.lock.json")
    if (
        type(value["run_id"]) is not int
        or type(value["attempt"]) is not int
        or value
        != {
            "repository": "stanimirivanov/kryvola-spec",
            "source": lock["revision"],
            "run_id": 40484284554,
            "attempt": 1,
            "jobs": {
                "verify": "Run pnpm check",
                "native": "Run pnpm native:check",
                "canonical": "Run pnpm check:canonical",
            },
        }
    ):
        raise ValueError("CONFORMANCE_SPEC_POLICY")
    return value


def upstream(value, trust):
    run, jobs = value["run"], value["jobs"]
    if (
        run["id"] != trust["run_id"]
        or run["run_attempt"] != trust["attempt"]
        or run["head_sha"] != trust["source"]
        or run["conclusion"] != "success"
        or run["status"] != "completed"
        or run["event"] != "push"
        or run["head_branch"] != "main"
        or run["repository"]["full_name"] != trust["repository"]
        or run["path"] != ".github/workflows/ci.yml"
        or jobs["total_count"] != len(trust["jobs"])
        or len(jobs["jobs"]) != len(trust["jobs"])
    ):
        raise ValueError("CONFORMANCE_UPSTREAM_RUN")
    if {j["name"] for j in jobs["jobs"]} != set(trust["jobs"]):
        raise ValueError("CONFORMANCE_UPSTREAM_JOBS")
    for job in jobs["jobs"]:
        steps = [s for s in job["steps"] if s["name"] == trust["jobs"][job["name"]]]
        if (
            job["status"] != "completed"
            or job["conclusion"] != "success"
            or job["head_sha"] != trust["source"]
            or job["run_attempt"] != trust["attempt"]
            or len(steps) != 1
            or steps[0]["conclusion"] != "success"
        ):
            raise ValueError("CONFORMANCE_UPSTREAM_CHECK")
    return {
        "repository": trust["repository"],
        "source": trust["source"],
        "run_id": trust["run_id"],
        "attempt": trust["attempt"],
        "jobs": trust["jobs"],
    }


def fetch():
    trust = policy()
    base = f"repos/{trust['repository']}/actions/runs/{trust['run_id']}/attempts/{trust['attempt']}"
    value = {}
    for key, endpoint in (("run", base), ("jobs", base + "/jobs?per_page=100")):
        result = integration.run(["gh", "api", endpoint], timeout=30)
        result.check_returncode()
        value[key] = json.loads(result.stdout)
    value["run"] = {
        k: value["run"][k]
        for k in (
            "id",
            "run_attempt",
            "head_sha",
            "conclusion",
            "status",
            "event",
            "head_branch",
            "path",
            "repository",
        )
    }
    value["run"]["repository"] = {"full_name": value["run"]["repository"]["full_name"]}
    for job in value["jobs"]["jobs"]:
        job["steps"] = [{"name": s["name"], "conclusion": s["conclusion"]} for s in job["steps"]]
    upstream(value, trust)
    EVIDENCE.parent.mkdir(parents=True, exist_ok=True)
    EVIDENCE.write_text(json.dumps(value, sort_keys=True))


def installed(root, locked, assets):
    component = locked["fabric"]
    version = "0.1.0.dev0+g" + component["source"]
    dist = importlib.metadata.distribution("kryvola-fabric")
    if dist.version != version:
        raise ValueError("CONFORMANCE_INSTALLED_VERSION")
    wheel = next(name for name in component["assets"] if name.endswith(".whl"))
    with ZipFile(assets / "fabric" / wheel) as archive:
        expected = {
            n for n in archive.namelist() if n.startswith("kryvola_fabric/") and not n.endswith("/")
        }
        for name in expected:
            target = Path(str(dist.locate_file(name)))
            if target.is_symlink() or target.read_bytes() != archive.read(name):
                raise ValueError("CONFORMANCE_INSTALLED_BYTES")
        package = Path(str(dist.locate_file("kryvola_fabric")))
        actual = {
            "kryvola_fabric/" + p.relative_to(package).as_posix()
            for p in package.rglob("*")
            if p.is_file() and "__pycache__" not in p.parts
        }
        if expected != actual:
            raise ValueError("CONFORMANCE_INSTALLED_FILES")
    lock = tomllib.loads((root / "uv.lock").read_text())
    packages = [p for p in lock["package"] if p["name"] == "kryvola-fabric"]
    if (
        len(packages) != 1
        or packages[0]["version"] != version
        or packages[0]["wheels"][0]["hash"] != "sha256:" + component["assets"][wheel]
    ):
        raise ValueError("CONFORMANCE_UV_BINDING")


def admit(root=ROOT, assets=None, evidence=EVIDENCE):
    from importlib.resources import files

    from kryvola_fabric.control import check_control_size, decode_control

    architecture.verify_contracts(root)
    if architecture.dependency_errors(root, "kryvola-platform"):
        raise ValueError("CONFORMANCE_SOURCE_DEPENDENCY")
    integration.configuration(read(root / "compose.yaml"))
    validate_inventory(root / "config/foundation.json")
    spec = upstream(read(evidence), policy(root))
    assets = assets or workflow_assets.OUTPUT
    locked = workflow_assets.verify(root, assets, root / "config/fake-workflow/releases.json")
    installed(root, locked, assets)
    payload = files("kryvola_fabric.conformance").joinpath("public-request.bin").read_bytes()
    decode_control("ExecuteRequest", payload, temporal=True)
    check_control_size(b"x" * 32768, temporal=True)
    return {
        "kind": "EXPERIMENTAL_FIXTURE_SET_CONFORMANT",
        "production_ready": False,
        "full_five_component_candidate": "NOT_SUBMITTED",
        "spec_checks": spec,
        "packages": locked,
        "platform_commit": integration.run(["git", "-C", ROOT, "rev-parse", "HEAD"])
        .stdout.decode()
        .strip(),
    }


def probe(case):
    from kryvola_fabric.control import check_control_size

    with TemporaryDirectory() as temporary:
        root = Path(temporary)
        for name in ("config", "src"):
            shutil.copytree(ROOT / name, root / name)
        for name in ("spec.lock.json", "pyproject.toml", "uv.lock", "compose.yaml"):
            shutil.copyfile(ROOT / name, root / name)
        assets = root / "assets"
        shutil.copytree(workflow_assets.OUTPUT, assets)
        executable = "cosign"
        (root / ".tools").mkdir()
        try:
            os.link(ROOT / ".tools" / executable, root / ".tools" / executable)
        except OSError:
            shutil.copyfile(ROOT / ".tools" / executable, root / ".tools" / executable)
        evidence = root / "spec-evidence.json"
        shutil.copyfile(EVIDENCE, evidence)
        if case == "unsigned":
            (assets / "fabric/manifest.sigstore.json").unlink()
        elif case == "wrong-signature":
            target = assets / "fabric/manifest.sigstore.json"
            target.write_bytes((assets / "engines/manifest.sigstore.json").read_bytes())
            pins = read(root / "config/fake-workflow/releases.json")
            pins["fabric"]["assets"]["manifest.sigstore.json"] = workflow_assets.digest(target)
            (root / "config/fake-workflow/releases.json").write_text(json.dumps(pins))
        elif case == "asset-drift":
            (assets / "engines/package.tar").write_bytes(b"modified-package")
        elif case == "schema":
            (root / "src/kryvola_platform/_spec/limits.json").write_text("{}")
        elif case == "sibling-source":
            path = root / "pyproject.toml"
            path.write_text(path.read_text().replace('url = "https:', 'path = "../sibling/https:'))
        elif case == "mutable-image":
            value = read(root / "compose.yaml")
            value["services"]["ray"]["image"] = "rayproject/ray:latest"
            (root / "compose.yaml").write_text(json.dumps(value))
        elif case in {"control-payload", "temporal-payload"}:
            pass
        elif case == "production":
            value = read(root / "config/foundation.json")
            value["production_ready"] = True
            (root / "config/foundation.json").write_text(json.dumps(value))
        elif case == "upstream-failure":
            value = read(evidence)
            value["jobs"]["jobs"][0]["conclusion"] = "failure"
            evidence.write_text(json.dumps(value))
        rejected = False
        try:
            if case in {"control-payload", "temporal-payload"}:
                check_control_size(
                    b"x" * (32769 if case == "temporal-payload" else 65537),
                    temporal=case == "temporal-payload",
                )
            else:
                admit(root, assets, evidence)
        except Exception as error:
            codes = {
                "unsigned": "WORKFLOW_ASSET_FILE",
                "wrong-signature": "WORKFLOW_PUBLISHER_REJECTED",
                "asset-drift": "WORKFLOW_ASSET_CHANGED",
                "sibling-source": "CONFORMANCE_SOURCE_DEPENDENCY",
                "mutable-image": "UNSAFE_SERVICE_BOUNDARY",
                "control-payload": "CONTROL_TOO_LARGE",
                "temporal-payload": "CONTROL_TOO_LARGE",
                "upstream-failure": "CONFORMANCE_UPSTREAM_CHECK",
            }
            rejected = (
                isinstance(error, ValueError)
                and case in codes
                and str(error) == codes[case]
                or case == "schema"
                and isinstance(error, ValueError)
                and str(error).startswith("contracts: modified generated artifact")
                or case == "production"
                and isinstance(error, ValidationError)
                and list(error.path) == ["production_ready"]
            )
            if not rejected:
                raise
        if rejected:
            raise ProbeRejected(case)


def controls():
    admission = admit()  # Anti-vacuity: a broken baseline cannot make all negatives pass.
    spec = importlib.util.spec_from_file_location(
        "admission_checks", ROOT / "tests/integration/test_release_admission.py"
    )
    if spec is None or spec.loader is None:
        raise ValueError("MISSING_ADMISSION_CONTROLS")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return {**admission, "negative_controls": module.qualify(CASES, ROOT)}


def finish(stack, fake, admission):
    if (
        fake["kind"] != "PUBLIC_FAKE_ENGINE_SELFTEST"
        or fake["production_ready"] is not False
        or fake["profile_enabled"] is not False
        or fake["releases"] != admission["packages"]
    ):
        raise ValueError("CONFORMANCE_COMPOSITION_CHANGED")
    images = {}
    config = integration.configuration()
    ids = stack.compose("ps", "--all", "--quiet").stdout.decode().split()
    for identifier in ids:
        result = integration.run(
            [
                "docker",
                "inspect",
                "--format",
                '{"service":{{json (index .Config.Labels "com.docker.compose.service")}},'
                '"reference":{{json .Config.Image}},"id":{{json .Image}}}',
                identifier,
            ]
        )
        result.check_returncode()
        actual = json.loads(result.stdout)
        expected = config["services"][actual["service"]]["image"]
        image = integration.run(
            [
                "docker",
                "image",
                "inspect",
                "--format",
                '{"id":{{json .Id}},"digests":{{json .RepoDigests}}}',
                expected,
            ]
        )
        image.check_returncode()
        resolved = json.loads(image.stdout)
        if (
            actual["reference"] != expected
            or actual["id"] != resolved["id"]
            or expected not in resolved["digests"]
            or actual["service"] in images
        ):
            raise ValueError("CONFORMANCE_RUNTIME_IMAGE")
        images[actual["service"]] = actual
    if set(images) != set(config["services"]):
        raise ValueError("CONFORMANCE_MISSING_SERVICE")
    report = {
        **admission,
        "images": images,
        "live_checks": "PUBLISHED_NATIVE_FAKE_AND_TEMPORAL_REPLAY_PASSED",
    }
    with (stack.folder / "release-conformance-report.json").open("x", encoding="utf-8") as stream:
        json.dump(report, stream, sort_keys=True)
    print("EXPERIMENTAL_RELEASE_CONFORMANCE_PASSED")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["fetch", "check", "admit", "controls", "probe"])
    parser.add_argument("--case", choices=CASES)
    args = parser.parse_args()
    if args.command == "fetch":
        fetch()
    elif args.command == "check":
        policy()
    elif args.command == "admit":
        admit()
    elif args.command == "controls":
        controls()
    else:
        if args.case is None:
            parser.error("--case required")
        probe(args.case)
    print("RELEASE_CONFORMANCE_CHECK_PASSED")


if __name__ == "__main__":
    try:
        main()
    except ProbeRejected as error:
        print("RELEASE_CONFORMANCE_REJECTED " + str(error), file=sys.stderr)
        sys.exit(1)
    except Exception:
        print("RELEASE_CONFORMANCE_ERROR", file=sys.stderr)
        sys.exit(2)
