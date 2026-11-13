"""Owned local kind API-admission checks; no application or dataplane qualification."""

import argparse
import copy
import hashlib
import json
import os
import platform
import re
import secrets
import subprocess
import tempfile
import urllib.request
from contextlib import contextmanager
from pathlib import Path

if __package__:
    from . import m1_assets
    from . import m1_preproduction as profile
else:
    import m1_assets
    import m1_preproduction as profile

ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "build/m1-cluster-tools"
PINS = json.loads((ROOT / "deploy/m1/admission-tools.json").read_bytes())


def tool(name):
    path = TOOLS / name
    if m1_assets.sha(path) != PINS[name]["sha256"]:
        raise ValueError("M1_CLUSTER_TOOL_PIN")
    return path


def install():
    if (platform.system(), platform.machine()) != ("Linux", "x86_64"):
        raise ValueError("M1_CLUSTER_LINUX_AMD64_ONLY")
    TOOLS.mkdir(parents=True, exist_ok=True)
    for name, item in PINS.items():
        if name == "node":
            continue
        path = TOOLS / name
        if not path.exists():
            with urllib.request.urlopen(item["url"], timeout=60) as response:
                raw = response.read((64 << 20) + 1)
            if len(raw) > 64 << 20 or hashlib.sha256(raw).hexdigest() != item["sha256"]:
                raise ValueError("M1_CLUSTER_TOOL_PIN")
            path.write_bytes(raw)
        tool(name)
    (TOOLS / "kind").chmod(0o700)


def command(*args):
    return subprocess.check_output(
        [str(tool("kind")), *map(str, args)],
        stderr=subprocess.PIPE,
        timeout=240,
        env=dict(os.environ) | {"KIND_EXPERIMENTAL_PROVIDER": "docker"},
    )


@contextmanager
def cluster(name):
    if not re.fullmatch("m1-boundary-[a-f0-9]{12}", name):
        raise ValueError("M1_CLUSTER_NAME")
    if name in command("get", "clusters").decode().split():
        raise ValueError("M1_CLUSTER_EXISTS")
    parent = ROOT / "build/m1-clusters"
    parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=name + "-", dir=parent) as directory:
        marker = Path(directory) / "owner.json"
        owner = {"cluster": name, "token": secrets.token_hex(24)}
        marker.write_text(json.dumps(owner))
        kubeconfig = Path(directory) / "kubeconfig"
        try:
            command(
                "create",
                "cluster",
                "--name",
                name,
                "--image",
                PINS["node"],
                "--kubeconfig",
                kubeconfig,
                "--wait",
                "120s",
            )
            yield name + "-control-plane"
        finally:
            if marker.is_symlink() or json.loads(marker.read_bytes()) != owner:
                raise ValueError("M1_CLUSTER_OWNERSHIP")
            command("delete", "cluster", "--name", name, "--kubeconfig", kubeconfig)


def kubectl(node, *args, payload=None, check=True):
    return subprocess.run(
        [
            "docker",
            "exec",
            "-i",
            node,
            "kubectl",
            "--kubeconfig",
            "/etc/kubernetes/admin.conf",
            *args,
        ],
        input=payload,
        capture_output=True,
        check=check,
        timeout=120,
    )


def qualify():
    # A local Docker-only fixture; never consult or apply to the user's kubeconfig.
    endpoint = os.environ.get("DOCKER_HOST")
    if not endpoint:
        context = json.loads(subprocess.check_output(["docker", "context", "inspect"], timeout=15))
        endpoint = context[0]["Endpoints"]["docker"]["Host"]
    if not endpoint.startswith("unix://"):
        raise ValueError("M1_LOCAL_CLUSTER_ONLY")
    profile.validate(json.loads(profile.MANIFEST.read_bytes()))
    image = m1_assets.load()["services"]["python"]
    document = profile.build({role: image for role in ("runtime", "ray", "owner")})
    name = "m1-boundary-" + secrets.token_hex(6)
    accepted, rejected = 0, 0
    with cluster(name) as node:
        node_user = ["--as=system:node:" + node, "--as-group=system:nodes"]
        # Anti-vacuity: the node identity can change an ordinary own-node label.
        kubectl(node, "label", "node", node, "kryvola.io/admission-probe=allowed", *node_user)
        denied = kubectl(
            node,
            "label",
            "node",
            node,
            "kryvola.io.node-restriction.kubernetes.io/domain=owner",
            *node_user,
            check=False,
        )
        if denied.returncode == 0 or b"not allowed to modify labels" not in denied.stderr:
            raise ValueError("M1_NODE_RESTRICTION_NEGATIVE_FAILED")
        for file in ("cilium-crd.yaml", "spire-crd.yaml"):
            kubectl(node, "create", "-f", "-", payload=tool(file).read_bytes())
        for crd in ("ciliumnetworkpolicies.cilium.io", "clusterspiffeids.spire.spiffe.io"):
            kubectl(node, "wait", "--for=condition=Established", "crd/" + crd, "--timeout=60s")
        # PodTemplates and policy objects do not launch applications/controllers.
        kubectl(node, "apply", "-f", "-", payload=json.dumps(document).encode())
        for template in (x for x in document["items"] if x["kind"] == "PodTemplate"):
            pod: dict = {
                "apiVersion": "v1",
                "kind": "Pod",
                "metadata": template["metadata"]
                | {"labels": template["template"]["metadata"]["labels"]},
                "spec": template["template"]["spec"],
            }
            raw = json.dumps(pod).encode()
            kubectl(node, "create", "--dry-run=server", "-f", "-", payload=raw)
            accepted += 1
            for mutation in ("privileged", "hostNetwork", "hostPath"):
                bad = copy.deepcopy(pod)
                if mutation == "privileged":
                    bad["spec"]["containers"][0]["securityContext"].update(
                        privileged=True, allowPrivilegeEscalation=True
                    )
                elif mutation == "hostNetwork":
                    bad["spec"]["hostNetwork"] = True
                else:
                    bad["spec"]["volumes"].append({"name": "host", "hostPath": {"path": "/"}})
                result = kubectl(
                    node,
                    "create",
                    "--dry-run=server",
                    "-f",
                    "-",
                    payload=json.dumps(bad).encode(),
                    check=False,
                )
                if result.returncode == 0 or b"violates PodSecurity" not in result.stderr:
                    raise ValueError("M1_ADMISSION_NEGATIVE_FAILED")
                rejected += 1
        for domain in ("owner", "control", "compute", "data"):
            result = kubectl(node, "get", "pods", "-n", "m1-" + domain, "-o", "json")
            if json.loads(result.stdout)["items"]:
                raise ValueError("M1_UNEXPECTED_APPLICATION")
    if name in command("get", "clusters").decode().split():
        raise ValueError("M1_CLUSTER_CLEANUP")
    report = {
        "kind": "M1_DISPOSABLE_API_ADMISSION",
        "accepted": accepted,
        "rejected": rejected,
        "applications_started": False,
        "dataplane_qualified": False,
        "identity_qualified": False,
        "owned_cluster_removed": True,
        "protected_node_label_denied": True,
    }
    (ROOT / "build/m1-admission-report.json").write_text(json.dumps(report, indent=2) + "\n")
    print("M1_KUBERNETES_API_ADMISSION_AND_CLEANUP_PASSED")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("install", "ci"))
    args = parser.parse_args()
    {"install": install, "ci": qualify}[args.action]()
