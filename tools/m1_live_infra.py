"""Pinned live Cilium/SPIRE fixture inputs; no mutable image may reach apply."""

import copy
import hashlib
import json
import re
import subprocess
import tarfile
import time
import urllib.request
from contextlib import contextmanager
from pathlib import Path

import yaml

if __package__:
    from . import m1_assets, m1_cluster
else:
    import m1_assets
    import m1_cluster

ROOT = Path(__file__).resolve().parents[1]
LOCK = ROOT / "config/isolation/infra.lock.json"
TOOLS = ROOT / "build/m1-isolation-tools"


def install():
    locked = json.loads(LOCK.read_bytes())
    TOOLS.mkdir(parents=True, exist_ok=True)
    for name, pin in {"helm": locked["helm"], **locked["charts"]}.items():
        path = TOOLS / (name + ".tgz")
        if not path.exists():
            with urllib.request.urlopen(pin["url"], timeout=60) as response:
                raw = response.read((64 << 20) + 1)
            if len(raw) > 64 << 20 or hashlib.sha256(raw).hexdigest() != pin["sha256"]:
                raise ValueError("M1_INFRA_ARCHIVE_PIN")
            path.write_bytes(raw)
        if m1_assets.sha(path) != pin["sha256"]:
            raise ValueError("M1_INFRA_ARCHIVE_PIN")
        if name == "helm":
            with tarfile.open(path) as archive:
                member = archive.getmember("linux-amd64/helm")
                if not member.isfile() or member.size > 128 << 20:
                    raise ValueError("M1_INFRA_TOOL_PIN")
                stream = archive.extractfile(member)
                if stream is None:
                    raise ValueError("M1_INFRA_TOOL_PIN")
                executable = TOOLS / "helm"
                executable.write_bytes(stream.read())
                executable.chmod(0o700)
    for name, pin in locked["crds"].items():
        path = TOOLS / name
        if not path.exists():
            with urllib.request.urlopen(pin["url"], timeout=45) as response:
                raw = response.read((1 << 20) + 1)
            if len(raw) > 1 << 20:
                raise ValueError("M1_INFRA_CRD_PIN")
            path.write_bytes(raw)
        if m1_assets.sha(path) != pin["sha256"]:
            raise ValueError("M1_INFRA_CRD_PIN")
    helm()


def helm():
    path = TOOLS / "helm"
    if m1_assets.sha(path) != json.loads(LOCK.read_bytes())["helm"]["binary_sha256"]:
        raise ValueError("M1_INFRA_TOOL_PIN")
    return path


def podspecs(document):
    kind = document.get("kind")
    if kind == "Pod":
        yield document["spec"]
    elif kind in {"Deployment", "StatefulSet", "DaemonSet", "Job", "ReplicaSet"}:
        yield document["spec"]["template"]["spec"]
    elif kind == "CronJob":
        yield document["spec"]["jobTemplate"]["spec"]["template"]["spec"]


def image_refs(documents):
    return {
        container["image"]
        for document in documents
        for spec in podspecs(document)
        for key in ("containers", "initContainers", "ephemeralContainers")
        for container in spec.get(key, [])
    }


def pin_documents(documents, pins):
    result = copy.deepcopy(documents)
    for document in result:
        if document.get("kind") in {"ClusterSPIFFEID", "ClusterStaticEntry"}:
            raise ValueError("M1_INFRA_BROAD_IDENTITY")
        for spec in podspecs(document):
            for key in ("containers", "initContainers", "ephemeralContainers"):
                for container in spec.get(key, []):
                    image = container["image"]
                    if "@sha256:" not in image:
                        image = pins.get(image, "")
                    if not re.fullmatch(r"[^\s@]+@sha256:[a-f0-9]{64}", image):
                        raise ValueError("M1_INFRA_IMAGE_PIN")
                    container["image"] = image
    return result


def render_raw(name):
    locked = json.loads(LOCK.read_bytes())
    archive = TOOLS / (name + ".tgz")
    if m1_assets.sha(archive) != locked["charts"][name]["sha256"]:
        raise ValueError("M1_INFRA_ARCHIVE_PIN")
    raw = subprocess.check_output(
        [
            str(helm()),
            "template",
            "m1-infra",
            str(archive),
            "--namespace",
            "kube-system" if name == "cilium" else "spire",
            "--include-crds",
            "--kube-version",
            "1.37.0",
            "--values",
            str(ROOT / f"config/isolation/{name}.values.json"),
        ],
        stderr=subprocess.PIPE,
        timeout=60,
    )
    if len(raw) > 16 << 20:
        raise ValueError("M1_INFRA_RENDER_LIMIT")
    return [
        value
        for value in yaml.safe_load_all(raw)
        if value and not (value.get("metadata", {}).get("annotations") or {}).get("helm.sh/hook")
    ]


def render(name):
    return pin_documents(render_raw(name), json.loads(LOCK.read_bytes())["images"])


def registered_nodes(node, count):
    for _ in range(60):
        items = json.loads(m1_cluster.kubectl(node, "get", "nodes", "-o", "json").stdout)["items"]
        if len(items) == count:
            return items
        time.sleep(2)
    raise ValueError("M1_NODE_REGISTRATION")


# The admission-only gate remains unchanged. This separate context installs the
# real enforcers in an owned cluster; it never labels kind nodes as hardened hosts.


@contextmanager
def live_cluster():
    import secrets

    m1_cluster.local_only()
    documents = {name: render(name) for name in ("cilium", "spire")}
    configuration = {
        "kind": "Cluster",
        "apiVersion": "kind.x-k8s.io/v1alpha4",
        "networking": {"disableDefaultCNI": True},
        "nodes": [{"role": "control-plane"}, *[{"role": "worker"} for _ in range(3)]],
    }
    with m1_cluster.cluster(
        "m1-boundary-" + secrets.token_hex(6), configuration=configuration
    ) as node:
        nodes = registered_nodes(node, 4)
        ordered = sorted(nodes, key=lambda n: n["metadata"]["name"])
        for item, domain in zip(ordered, ("control", "compute", "owner", "data"), strict=True):
            m1_cluster.kubectl(
                node,
                "patch",
                "node",
                item["metadata"]["name"],
                "--type=merge",
                "-p",
                json.dumps(
                    {
                        "metadata": {
                            "labels": {"kryvola.io.node-restriction.kubernetes.io/domain": domain}
                        },
                        "spec": {"taints": []},
                    }
                ),
            )
        for name in ("cilium", "spire"):
            if name == "spire":
                for crd, pin in json.loads(LOCK.read_bytes())["crds"].items():
                    path = TOOLS / crd
                    if m1_assets.sha(path) != pin["sha256"]:
                        raise ValueError("M1_INFRA_CRD_PIN")
                    m1_cluster.kubectl(
                        node, "apply", "--server-side", "-f", "-", payload=path.read_bytes()
                    )
            m1_cluster.kubectl(
                node,
                "apply",
                "--server-side",
                "--field-manager=m1-isolation",
                "-f",
                "-",
                payload=json.dumps(
                    {"apiVersion": "v1", "kind": "List", "items": documents[name]}
                ).encode(),
            )
            for resource in documents[name]:
                if resource["kind"] in {"Deployment", "DaemonSet", "StatefulSet"}:
                    rollout(node, resource, name)
        yield node


def rollout(node, resource, name):
    try:
        m1_cluster.kubectl(
            node,
            "rollout",
            "status",
            resource["kind"].lower() + "/" + resource["metadata"]["name"],
            "-n",
            resource["metadata"].get("namespace", "kube-system" if name == "cilium" else "spire"),
            "--timeout=300s",
            timeout=320,
        )
    except subprocess.CalledProcessError:
        print(
            m1_cluster.kubectl(node, "get", "pods", "-A", "-o", "wide").stdout.decode(), flush=True
        )
        print(
            m1_cluster.kubectl(
                node, "get", "events", "-A", "--field-selector", "type=Warning"
            ).stdout.decode(),
            flush=True,
        )
        for label in ("app.kubernetes.io/component=agent", "app.kubernetes.io/name=spire-agent"):
            result = m1_cluster.kubectl(
                node,
                "logs",
                "-n",
                "spire",
                "-l",
                label,
                "--all-containers",
                "--tail=20",
                check=False,
            )
            print(result.stdout.decode(), result.stderr.decode(), flush=True)
        raise


if __name__ == "__main__":
    install()
