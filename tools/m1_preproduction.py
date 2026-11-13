"""Fixed preproduction boundary profile; rendering/admission never deploys applications."""

import argparse
import hashlib
import json
import re
from pathlib import Path

if __package__:
    from . import m1_assets
else:
    import m1_assets

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "deploy/m1/boundaries.json"
ENGINE = (
    "ghcr.io/stanimirivanov/kryvola-engines/cpu-engine@sha256:"
    "f1408e7c9acb0fc29a9533fc16f9106976ab325237f29169f66f8fb3eaef2cd8"
)
ROLES = {
    "runtime": ("control", 2001),
    "workflow": ("control", 2002),
    "messaging": ("control", 2003),
    "compute": ("compute", 65532),
    "owner": ("owner", 3001),
}
SECRETS = {
    "runtime": ["database", "s3.json", "policy.json"],
    "workflow": ["database-release", "release.json", "tokens.json"],
    "messaging": ["database-events", "kafka.json", "ca.crt", "events.crt", "events.key"],
}
# Exact peers/ports only. Identity-provider traffic uses the CSI Unix socket.
PEERS = {
    "runtime": [("control", "postgres", 5432), ("data", "storage", 8333)],
    "workflow": [
        ("control", "runtime", 8443),
        ("control", "temporal", 7233),
        ("control", "postgres", 5432),
        ("compute", "compute", 8265),
    ],
    "messaging": [("control", "postgres", 5432), ("data", "broker", 9092)],
    "compute": [("control", "runtime", 8443)],
    "owner": [("control", "runtime", 8443)],
    "temporal": [("control", "postgres", 5432)],
}


def object_(kind, name, spec=None, namespace=None, api="v1"):
    value = {"apiVersion": api, "kind": kind, "metadata": {"name": name}}
    if namespace:
        value["metadata"]["namespace"] = namespace
    if spec is not None:
        value["spec"] = spec
    return value


def peer(domain, role):
    return {
        "namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "m1-" + domain}},
        "podSelector": {"matchLabels": {"kryvola.io/role": role}},
    }


def rule(domain, role, port, direction):
    return {direction: [peer(domain, role)], "ports": [{"protocol": "TCP", "port": port}]}


def build(images=None):
    if images is None:
        images = {r: "$M1_" + r.upper() + "_IMAGE" for r in ("runtime", "ray", "owner")}
    if set(images) != {"runtime", "ray", "owner"} or any(
        not re.fullmatch(r"[^\s@]+@sha256:[a-f0-9]{64}", image)
        and image != "$M1_" + role.upper() + "_IMAGE"
        for role, image in images.items()
    ):
        raise ValueError("M1_DEPLOYMENT_IMAGES_REJECTED")
    locked = m1_assets.load()
    binding = {
        "cpu_sha256": locked["permissions"]["cpu_sha256"],
        "image": ENGINE,
        "source": locked["components"]["engines"]["source"],
    }
    raw = (json.dumps(binding, sort_keys=True, separators=(",", ":")) + "\n").encode()
    if (
        hashlib.sha256(raw).hexdigest()
        != locked["components"]["engines"]["assets"]["image.json"]["sha256"]
    ):
        raise ValueError("M1_ENGINE_IMAGE_BINDING")
    backends = {"postgres": "control", "temporal": "control", "storage": "data", "broker": "data"}
    domains = {r: d for r, (d, _) in ROLES.items()} | backends
    items = []
    for domain in ("owner", "control", "compute", "data"):
        ns = "m1-" + domain
        item = object_("Namespace", ns)
        item["metadata"]["labels"] = {
            "pod-security.kubernetes.io/enforce": "restricted",
            "pod-security.kubernetes.io/enforce-version": "v1.37",
            "kryvola.io/domain": domain,
        }
        items.append(item)
        items.append(
            object_(
                "ResourceQuota",
                "bounded",
                {
                    "hard": {
                        "pods": "8",
                        "requests.cpu": "8",
                        "limits.cpu": "16",
                        "requests.memory": "8Gi",
                        "limits.memory": "16Gi",
                        "requests.ephemeral-storage": "2Gi",
                        "limits.ephemeral-storage": "4Gi",
                        "persistentvolumeclaims": "4",
                        "requests.storage": "4Gi",
                        "secrets": "8",
                        "services": "8",
                    }
                },
                ns,
            )
        )
        items.append(
            object_(
                "NetworkPolicy",
                "default-deny",
                {
                    "podSelector": {},
                    "policyTypes": ["Ingress", "Egress"],
                    "ingress": [],
                    "egress": [],
                },
                ns,
                "networking.k8s.io/v1",
            )
        )
        # Standard NetworkPolicy cannot express an overriding host/metadata deny.
        items.append(
            object_(
                "CiliumNetworkPolicy",
                "deny-host-metadata",
                {
                    "endpointSelector": {},
                    "egressDeny": [
                        {"toEntities": ["host", "remote-node", "kube-apiserver"]},
                        {
                            "toCIDR": [
                                "169.254.0.0/16",
                                "100.100.100.200/32",
                                "fd00:ec2::254/128",
                                "fe80::/10",
                            ]
                        },
                    ],
                },
                ns,
                "cilium.io/v2",
            )
        )
        scripts = object_("ConfigMap", "m1-launch", namespace=ns)
        scripts["immutable"] = True
        scripts["data"] = {
            name: (ROOT / "config/m1" / name).read_text() for name in ("launch.py", "service.py")
        }
        items.append(scripts)
    for role, (domain, uid) in ROLES.items():
        ns = "m1-" + domain
        sa = object_("ServiceAccount", role, namespace=ns)
        sa["automountServiceAccountToken"] = False
        items.append(sa)
        labels = {"kryvola.io/role": role}
        volumes = [
            {"name": "workload", "csi": {"driver": "csi.spiffe.io", "readOnly": True}},
            {"name": "launch", "configMap": {"name": "m1-launch", "defaultMode": 292}},
            {"name": "scratch", "emptyDir": {"medium": "Memory", "sizeLimit": "256Mi"}},
            {"name": "state", "emptyDir": {"medium": "Memory", "sizeLimit": "8Mi"}},
        ]
        mounts = [
            {"name": "workload", "mountPath": "/run/workload", "readOnly": True},
            {"name": "launch", "mountPath": "/run/m1-launch", "readOnly": True},
            {"name": "scratch", "mountPath": "/tmp"},
            {"name": "state", "mountPath": "/run/m1-state"},
        ]
        if role in SECRETS:
            volumes.append(
                {
                    "name": "role-config",
                    "secret": {
                        "secretName": "m1-" + role + "-config",
                        "defaultMode": 288,
                        "items": [{"key": k, "path": k} for k in SECRETS[role]],
                    },
                }
            )
            mounts.append({"name": "role-config", "mountPath": "/run/m1-secrets", "readOnly": True})
        if role in {"compute", "owner"}:
            volumes.append(
                {
                    "name": "private",
                    "persistentVolumeClaim": {
                        "claimName": "m1-"
                        + ("attempt-private" if role == "compute" else "owner-custody")
                    },
                }
            )
            mounts.append(
                {
                    "name": "private",
                    "mountPath": "/run/execution" if role == "compute" else "/owner",
                }
            )
        commands = [
            (
                role,
                images["owner" if role == "owner" else "runtime"],
                ["python", "/run/m1-launch/service.py", role],
            )
        ]
        if role == "messaging":
            commands[0] = (
                role,
                images["runtime"],
                [
                    "/opt/fabric/bin/fabric-runtime",
                    "--messaging",
                    "/run/m1-secrets/database-events",
                    "/run/m1-secrets/kafka.json",
                ],
            )
        if role == "compute":
            commands = [
                ("engine", ENGINE, ["/opt/kryvola/kryvola-cpu-engine", "/run/execution"]),
                (
                    "ray",
                    images["ray"],
                    [
                        "ray",
                        "start",
                        "--head",
                        "--include-dashboard=true",
                        "--dashboard-host=0.0.0.0",
                        "--num-cpus=1",
                        "--object-store-memory=100000000",
                        "--disable-usage-stats",
                        "--block",
                    ],
                ),
            ]
            volumes.append({"name": "shm", "emptyDir": {"medium": "Memory", "sizeLimit": "256Mi"}})
            mounts.append({"name": "shm", "mountPath": "/dev/shm"})
        containers = [
            {
                "name": name,
                "image": image,
                "command": ["python3", "/run/m1-launch/launch.py", *argv],
                "securityContext": {
                    "allowPrivilegeEscalation": False,
                    "readOnlyRootFilesystem": True,
                    "capabilities": {"drop": ["ALL"]},
                },
                "resources": {
                    "requests": {"cpu": "100m", "memory": "256Mi", "ephemeral-storage": "32Mi"},
                    "limits": {
                        "cpu": "2",
                        "memory": "3Gi" if role == "compute" else "1Gi",
                        "ephemeral-storage": "512Mi",
                    },
                },
                "volumeMounts": mounts,
            }
            for name, image, argv in commands
        ]
        if role == "workflow":
            containers[0]["env"] = [{"name": "M1_TASK_QUEUE", "value": "m1-preproduction"}]
        template = object_("PodTemplate", role, namespace=ns)
        template["template"] = {
            "metadata": {"labels": labels},
            "spec": {
                "serviceAccountName": role,
                "automountServiceAccountToken": False,
                "enableServiceLinks": False,
                "nodeSelector": {
                    "kryvola.io/domain": domain,
                    "kryvola.io/core-dumps": "disabled",
                    "kryvola.io/swap": "disabled",
                },
                "securityContext": {
                    "runAsNonRoot": True,
                    "runAsUser": uid,
                    "runAsGroup": uid,
                    "fsGroup": uid,
                    "seccompProfile": {"type": "RuntimeDefault"},
                },
                "containers": containers,
                "volumes": volumes,
            },
        }
        items.append(template)
        identity = "worker" if role == "compute" else role
        items.append(
            object_(
                "ClusterSPIFFEID",
                "m1-" + role,
                {
                    "className": "m1-preproduction",
                    "spiffeIDTemplate": "spiffe://m1.test/" + identity,
                    "ttl": "45s",
                    "admin": False,
                    "downstream": False,
                    "namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": ns}},
                    "podSelector": {"matchLabels": labels},
                    "workloadSelectorTemplates": ["k8s:sa:" + role],
                },
                api="spire.spiffe.io/v1alpha1",
            )
        )
        dns = {
            "to": [
                {
                    "namespaceSelector": {
                        "matchLabels": {"kubernetes.io/metadata.name": "kube-system"}
                    },
                    "podSelector": {"matchLabels": {"k8s-app": "kube-dns"}},
                }
            ],
            "ports": [{"protocol": p, "port": 53} for p in ("UDP", "TCP")],
        }
        incoming = [
            rule(other_domain, other, port, "from")
            for other, peers in PEERS.items()
            for target_domain, target, port in peers
            if target == role and target_domain == domain
            for other_domain in [domains[other]]
        ]
        items.append(
            object_(
                "NetworkPolicy",
                role,
                {
                    "podSelector": {"matchLabels": labels},
                    "policyTypes": ["Ingress", "Egress"],
                    "ingress": incoming,
                    "egress": [dns, *[rule(d, r, p, "to") for d, r, p in PEERS[role]]],
                },
                ns,
                "networking.k8s.io/v1",
            )
        )
    for target, domain in backends.items():
        incoming = [
            rule(domains[source], source, port, "from")
            for source, peers in PEERS.items()
            for dest, role, port in peers
            if dest == domain and role == target
        ]
        items.append(
            object_(
                "NetworkPolicy",
                target,
                {
                    "podSelector": {"matchLabels": {"kryvola.io/role": target}},
                    "policyTypes": ["Ingress", "Egress"],
                    "ingress": incoming,
                    "egress": [
                        dns,
                        *[rule(d, r, port, "to") for d, r, port in PEERS.get(target, [])],
                    ],
                },
                "m1-" + domain,
                "networking.k8s.io/v1",
            )
        )
    return {"apiVersion": "v1", "kind": "List", "items": items}


def validate(value, images=None):
    # This is an exact fixed profile, not a general-purpose Kubernetes validator.
    if value != build(images):
        raise ValueError("M1_DEPLOYMENT_REJECTED")
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("check", "render", "template"))
    for role in ("runtime", "ray", "owner"):
        parser.add_argument("--" + role + "-image")
    args = parser.parse_args()
    images = {r: getattr(args, r + "_image") for r in ("runtime", "ray", "owner")}
    if args.action == "check":
        validate(json.loads(MANIFEST.read_bytes()))
        print("M1_PREPRODUCTION_BOUNDARIES_VALID; no deployment or dataplane qualification")
    elif args.action == "template":
        print(json.dumps(build(), indent=2, sort_keys=True))
    else:
        if any(v is None or v.startswith("$") for v in images.values()):
            parser.error("render requires three independently selected digest-pinned role images")
        print(json.dumps(build(images), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
