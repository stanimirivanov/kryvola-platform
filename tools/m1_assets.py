"""Dedicated M1 published-input admission; never admits frozen M0 fixtures."""

import hashlib
import json
import re
import subprocess
import tarfile
import urllib.parse
import urllib.request
from pathlib import Path
from zipfile import ZipFile

if __package__:
    from .install_release import tool
else:
    from install_release import tool

ROOT = Path(__file__).resolve().parents[1]
LOCK = ROOT / "config/m1.lock.json"
OUTPUT = ROOT / "build/m1-assets"
ROLES = {"fabric", "engines", "ml"}
SERVICES = {"postgres", "s3", "redpanda", "temporal", "temporal-cli", "ray", "python", "s3-client"}
SPEC_FIELDS = {
    "repository",
    "revision",
    "contract_version",
    "artifact_root",
    "manifest_sha256",
    "native_artifact_root",
    "native_manifest_sha256",
}


def require(value, code="M1_LOCK_REJECTED"):
    if not value:
        raise ValueError(code)


def sha(path):
    require(
        not path.is_symlink() and path.is_file() and path.stat().st_size <= 128 << 20,
        "M1_ASSET_CHANGED",
    )
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def spec(value, role):
    require(
        set(value) == SPEC_FIELDS
        and value["repository"] == "https://github.com/stanimirivanov/kryvola-spec"
    )
    require(re.fullmatch("[a-f0-9]{40}", value["revision"]))
    require(
        all(
            re.fullmatch("[a-f0-9]{64}", value[k])
            for k in ("manifest_sha256", "native_manifest_sha256")
        )
    )
    require(
        value["contract_version"] == "0.1.0-preview.10"
        and value["artifact_root"] == ("src/kryvola_ml/_spec" if role == "ml" else "contracts/spec")
        and value["native_artifact_root"]
        == ("src/kryvola_ml/_wire" if role == "ml" else "contracts/native")
    )


def load(path=LOCK):
    value = json.loads(path.read_bytes())
    require(
        set(value) == {"schema_version", "components", "services", "permissions", "compatibility"}
    )
    require(value["schema_version"] == "platform-m1-lock-v1" and set(value["components"]) == ROLES)
    require(set(value["services"]) == SERVICES)
    require(
        all(
            re.fullmatch(r"[^\s@]+@sha256:[a-f0-9]{64}", image)
            for image in value["services"].values()
        )
    )
    for role, item in value["components"].items():
        require(set(item) == {"source", "identity", "spec", "assets"})
        require(re.fullmatch("[a-f0-9]{40}", item["source"]))
        workflow = "m1-release.yml" if role == "engines" else "release.yml"
        require(
            item["identity"]
            == f"https://github.com/stanimirivanov/kryvola-{role}/.github/workflows/{workflow}@refs/heads/main"
        )
        spec(item["spec"], role)
        require(
            {"manifest.json", "manifest.sigstore.json", "provenance.json"} <= set(item["assets"])
        )
        tag = ("experimental-" if role == "ml" else "m1-") + item["source"]
        for name, asset in item["assets"].items():
            require(re.fullmatch(r"[a-zA-Z0-9_.+\-]+", name) and name not in {".", ".."})
            require(
                set(asset) == {"sha256", "url"} and re.fullmatch("[a-f0-9]{64}", asset["sha256"])
            )
            require(
                asset["url"]
                == f"https://github.com/stanimirivanov/kryvola-{role}/releases/download/{tag}/"
                + urllib.parse.quote(name, safe="")
            )
    permission = value["permissions"]
    require(
        set(permission)
        == {"profile", "owner", "run_id", "source", "cpu_sha256", "image_sha256", "owner_sha256"}
    )
    require(
        permission["profile"] == "OWNER_APPROVED_DEVELOPMENT_ONLY"
        and permission["owner"] == "stanimirivanov"
    )
    require(
        permission["source"] == value["components"]["engines"]["source"]
        and re.fullmatch(r"[1-9][0-9]*", permission["run_id"])
    )
    require(
        all(
            re.fullmatch("[a-f0-9]{64}", permission[k])
            for k in ("cpu_sha256", "image_sha256", "owner_sha256")
        )
    )
    compatibility = value["compatibility"]
    require(set(compatibility) == {"engines_spec", "fabric_ml_spec", "control_assets"})
    require(compatibility["engines_spec"] == value["components"]["engines"]["spec"])
    require(compatibility["fabric_ml_spec"] == value["components"]["fabric"]["spec"])
    require(
        all(
            value["components"]["ml"]["spec"][key] == compatibility["fabric_ml_spec"][key]
            for key in SPEC_FIELDS - {"artifact_root", "native_artifact_root"}
        )
    )
    require(
        set(compatibility["control_assets"]) == {"descriptor.bin", "schemas.json", "limits.json"}
    )
    require(all(re.fullmatch("[a-f0-9]{64}", x) for x in compatibility["control_assets"].values()))
    return value


def publisher(folder, component):
    subprocess.run(
        [
            str(tool("cosign")),
            "verify-blob",
            "--bundle",
            str(folder / "manifest.sigstore.json"),
            "--certificate-identity",
            component["identity"],
            "--certificate-oidc-issuer",
            "https://token.actions.githubusercontent.com",
            "--certificate-github-workflow-sha",
            component["source"],
            "--certificate-github-workflow-trigger",
            "workflow_dispatch",
            str(folder / "manifest.json"),
        ],
        check=True,
        capture_output=True,
        timeout=60,
    )


def verify(locked, root=OUTPUT, *, verifier=publisher):
    # Complete integrity pass before any verifier or released program can run.
    for role, item in locked["components"].items():
        for name, asset in item["assets"].items():
            require(sha(root / role / name) == asset["sha256"], "M1_ASSET_CHANGED")
    manifests = {}
    for role, item in locked["components"].items():
        folder = root / role
        manifest = json.loads((folder / "manifest.json").read_bytes())
        require(
            manifest.get("schema_version")
            == {
                "fabric": "fabric-m1-publication-v1",
                "ml": "ml-publication-v1",
                "engines": "engines-m1-v2",
            }[role],
            "M1_PROFILE_REJECTED",
        )
        require(
            manifest["source"] == item["source"]
            and manifest["production_ready"] is False
            and (role == "ml" or manifest["spec"] == item["spec"]),
            "M1_PROFILE_REJECTED",
        )
        require(
            set(item["assets"])
            == set(manifest["subjects"]) | {"manifest.json", "manifest.sigstore.json"}
        )
        require(
            all(
                digest == item["assets"][name]["sha256"]
                for name, digest in manifest["subjects"].items()
            )
        )
        provenance = json.loads((folder / "provenance.json").read_bytes())
        require(
            provenance["predicate"]["runDetails"]["builder"]["id"]
            == item["identity"].removeprefix("https://github.com/")
        )
        definition = provenance["predicate"]["buildDefinition"]
        require(
            definition["externalParameters"]["ref" if role == "ml" else "source"] == item["source"]
        )
        if role == "ml":
            require(manifest["distribution"] == "EXPERIMENTAL_BASELINE_ONLY")
            for uri, field in (
                ("urn:kryvola:spec-bundle", "manifest_sha256"),
                ("urn:kryvola:native-bundle", "native_manifest_sha256"),
            ):
                require(
                    {"uri": uri, "digest": {"sha256": item["spec"][field]}}
                    in definition["resolvedDependencies"]
                )
        else:
            require(definition["externalParameters"]["spec"] == item["spec"])
        for claim in provenance["subject"]:
            require(manifest["subjects"][claim["name"]] == claim["digest"]["sha256"])
        manifests[role] = manifest
    engine = root / "engines"
    approval = json.loads((engine / "owner-approval.json").read_bytes())
    permission = locked["permissions"]
    require(
        manifests["engines"]["state"] == "APPROVED"
        and manifests["engines"]["distribution"] == permission["profile"]
    )
    require(
        all(
            approval[k] == permission[k]
            for k in ("source", "owner", "run_id", "cpu_sha256", "image_sha256", "owner_sha256")
        )
    )
    require(
        approval["intended_use"] == "development_distribution"
        and approval["independent_review"] is False
        and approval["production_ready"] is False
    )
    require(manifests["engines"]["subjects"]["cpu-runtime.tar"] == permission["cpu_sha256"])
    (owner,) = engine.glob("kryvola_owner-*.whl")
    require(sha(owner) == permission["owner_sha256"])
    require(
        json.loads((engine / "image-subject.json").read_bytes())["config_sha256"]
        == permission["image_sha256"]
    )
    image = json.loads((engine / "image.json").read_bytes())["image"]
    require(
        re.fullmatch(
            r"ghcr.io/stanimirivanov/kryvola-engines/cpu-engine@sha256:[a-f0-9]{64}", image
        )
    )
    for role, item in locked["components"].items():
        verifier(root / role, item)
    for role in ("fabric", "ml"):
        for wheel in (root / role).glob("*.whl"):
            with ZipFile(wheel) as archive:
                for name, expected in locked["compatibility"]["control_assets"].items():
                    relative = (
                        f"kryvola_fabric/_spec/{name}"
                        if role == "fabric"
                        else f"kryvola_ml/{'_spec' if name == 'limits.json' else '_wire'}/{name}"
                    )
                    require(
                        hashlib.sha256(archive.read(relative)).hexdigest() == expected,
                        "M1_CONTRACT_MISMATCH",
                    )
    return locked


def fetch(locked, root=OUTPUT):
    for role, item in locked["components"].items():
        folder = root / role
        folder.mkdir(parents=True, exist_ok=True)
        for name, asset in item["assets"].items():
            path = folder / name
            if path.exists():
                require(sha(path) == asset["sha256"], "M1_ASSET_CHANGED")
                continue
            with urllib.request.urlopen(asset["url"], timeout=60) as response:
                data = response.read((128 << 20) + 1)
            require(
                len(data) <= 128 << 20 and hashlib.sha256(data).hexdigest() == asset["sha256"],
                "M1_ASSET_CHANGED",
            )
            path.write_bytes(data)
    return verify(locked, root)


def extract(path, destination):
    with tarfile.open(path) as archive:
        names = set()
        for member in archive.getmembers():
            require(
                member.isfile() and 0 <= member.size <= 128 << 20 and member.name not in names,
                "M1_ARCHIVE_REJECTED",
            )
            target = Path(member.name)
            require(not target.is_absolute() and ".." not in target.parts, "M1_ARCHIVE_REJECTED")
            names.add(member.name)
        archive.extractall(destination, filter="data")
