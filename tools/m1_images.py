"""Build local role images from verified published artifacts, never sibling source."""

import hashlib
import json
import re
import shutil
import subprocess
import tarfile
import tempfile
import tomllib
import uuid
from contextlib import contextmanager
from pathlib import Path
from zipfile import ZipFile

if __package__:
    from . import m1_assets as assets
    from . import m1_identity, m1_owner_packages
else:
    import m1_assets as assets
    import m1_identity
    import m1_owner_packages

UV = (
    "ghcr.io/astral-sh/uv:0.12.5@sha256:"
    "e85be844203885286c60ffad8a858d48afb6c5a5c237ca0e67f12e74b8f174b1"
)


def config_digest(path):
    """Adapt Engines' Docker-save identity check; inspect IDs vary by backend."""
    with tarfile.open(path, "r:") as stream:
        members = stream.getmembers()
        assets.require(len(members) <= 128, "M1_IMAGE_CONFIG")

        def read(name, limit):
            found = [member for member in members if member.name == name]
            assets.require(len(found) == 1, "M1_IMAGE_CONFIG")
            member = found[0]
            assets.require(member.isfile() and 0 < member.size <= limit, "M1_IMAGE_CONFIG")
            data = stream.extractfile(member)
            if data is None:
                raise ValueError("M1_IMAGE_CONFIG")
            result = data.read(limit + 1)
            assets.require(len(result) == member.size, "M1_IMAGE_CONFIG")
            return result

        manifest = json.loads(read("manifest.json", 64 << 10))
        assets.require(isinstance(manifest, list) and len(manifest) == 1, "M1_IMAGE_CONFIG")
        name = manifest[0]["Config"]
        match = re.fullmatch(r"(?:blobs/sha256/([0-9a-f]{64})|([0-9a-f]{64})\.json)", name)
        assets.require(match is not None, "M1_IMAGE_CONFIG")
        if match is None:
            raise ValueError("M1_IMAGE_CONFIG")
        raw = read(name, 1 << 20)
        digest = hashlib.sha256(raw).hexdigest()
        assets.require(digest == (match[1] or match[2]), "M1_IMAGE_CONFIG")
        config = json.loads(raw)
        assets.require(
            config["os"] == "linux"
            and config["architecture"] == "amd64"
            and config["rootfs"]["type"] == "layers",
            "M1_IMAGE_CONFIG",
        )
        return digest


def image_config(image):
    with tempfile.TemporaryDirectory(prefix="m1-image-config-") as tmp:
        path = Path(tmp) / "image.tar"
        subprocess.run(
            ["docker", "image", "save", "--output", str(path), image],
            check=True,
            capture_output=True,
            timeout=120,
        )
        return config_digest(path)


def requirements(lock, path):
    packages = tomllib.loads(lock.read_text())["package"]
    selected, pending = {}, ["blake3", "jsonschema", "protobuf"]
    while pending:
        name = pending.pop()
        if name in selected:
            continue
        (package,) = [p for p in packages if p["name"] == name]
        selected[name] = package
        pending += [d["name"] for d in package.get("dependencies", [])]
    path.write_text(
        "\n".join(
            f"{name}=={p['version']} " + " ".join("--hash=" + w["hash"] for w in p["wheels"])
            for name, p in sorted(selected.items())
        )
        + "\n"
    )


@contextmanager
def prepare(locked):
    assets.verify(locked)
    m1_identity.install()
    fabric, engine, ml = (assets.OUTPUT / role for role in ("fabric", "engines", "ml"))
    images = {}
    tags = []
    try:
        with tempfile.TemporaryDirectory(prefix="m1-published-context-") as tmp:
            root = Path(tmp)
            for role in ("runtime", "owner", "ray"):
                folder = root / role
                folder.mkdir()
                if role == "ray":
                    for name in ("ray.Dockerfile", "ray.lock"):
                        shutil.copyfile(fabric / name, folder / name)
                    for wheel in fabric.glob("kryvola_fabric_ray-*.whl"):
                        shutil.copyfile(wheel, folder / wheel.name)
                    recipe = (folder / "ray.Dockerfile").read_text()
                    recipe += (
                        "\nUSER root\nRUN chmod o+rx /home/ray\n"
                        "USER 65532:65532\nENV HOME=/tmp USER=m1-compute\n"
                    )
                else:
                    archive = next(
                        fabric.glob(("runtime-" if role == "runtime" else "owner-") + "*.tar")
                    )
                    assets.extract(archive, folder / role)
                    shutil.copy2(m1_identity.TOOLS / "spire-agent", folder / "spire-agent")
                    if role == "runtime":
                        for wheel in fabric.glob("kryvola_fabric_workflow-*.whl"):
                            shutil.copyfile(wheel, folder / wheel.name)
                        shutil.copyfile(fabric / "workflow.lock", folder / "requirements.txt")
                    else:
                        m1_owner_packages.stage(folder / "owner-debs")
                        for wheel in [*engine.glob("kryvola_owner-*.whl"), *ml.glob("*.whl")]:
                            shutil.copyfile(wheel, folder / wheel.name)
                        requirements(ml / "uv.lock", folder / "requirements.txt")
                    recipe = f"""FROM {UV} AS uv
    FROM {locked["services"]["python"]}
    COPY --from=uv /uv /usr/local/bin/uv
    COPY requirements.txt /opt/packages/requirements.txt
RUN uv venv --python /usr/local/bin/python3 /opt/venv
RUN uv pip sync --python /opt/venv/bin/python --require-hashes \\
    --only-binary :all: /opt/packages/requirements.txt
    COPY *.whl /opt/packages/
    RUN uv pip install --python /opt/venv/bin/python --no-index --no-deps /opt/packages/*.whl
    COPY {role}/ /opt/{"fabric" if role == "runtime" else "owner"}/
    COPY spire-agent /opt/m1/spire-agent
    ENV PATH=/opt/venv/bin:$PATH PYTHONDONTWRITEBYTECODE=1
    """
                    if role == "owner":
                        recipe += (
                            "COPY owner-debs/ /opt/owner-debs/\n"
                            "RUN dpkg -i /opt/owner-debs/*.deb && rm -rf /opt/owner-debs\n"
                            "RUN groupadd --gid 3001 m1-owner && useradd --uid 3001 "
                            "--gid 3001 --home-dir /owner --no-create-home "
                            "--shell /usr/sbin/nologin m1-owner\n"
                        )
                (folder / "Dockerfile").write_text(recipe)
                tag = "kryvola-m1-" + role + ":" + uuid.uuid4().hex
                tags.append(tag)
                subprocess.run(
                    ["docker", "build", "--platform", "linux/amd64", "-t", tag, str(folder)],
                    check=True,
                    timeout=900,
                )
                images[role] = subprocess.check_output(
                    ["docker", "image", "inspect", tag, "--format", "{{.Id}}"], text=True
                ).strip()
        images["engine"] = json.loads((engine / "image.json").read_bytes())["image"]
        subprocess.run(["docker", "pull", images["engine"]], check=True, timeout=180)
        yield images
    finally:
        for tag in tags:
            subprocess.run(["docker", "image", "rm", tag], check=False, capture_output=True)


def fixture(destination):
    (wheel,) = (assets.OUTPUT / "ml").glob("*.whl")
    with ZipFile(wheel) as archive:
        value = json.loads(archive.read("kryvola_ml/_wire/fixtures.json"))["ExecuteRequest"]
    destination.write_text(json.dumps(value))
