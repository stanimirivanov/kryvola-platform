"""Independent boundary assertions and mutations of the fixed preproduction profile."""

import copy
import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
IMAGES = {
    role: "example.invalid/" + role + "@sha256:" + "a" * 64 for role in ("runtime", "ray", "owner")
}


class PreproductionTests(unittest.TestCase):
    def test_separate_roles_have_no_ambient_or_compute_authority(self):
        from tools import m1_preproduction as p

        value = p.build(IMAGES)
        p.validate(value, IMAGES)
        pods = [x for x in value["items"] if x["kind"] == "PodTemplate"]
        self.assertEqual(len(pods), 5)
        self.assertEqual(
            len(
                {
                    (x["metadata"]["namespace"], x["template"]["spec"]["serviceAccountName"])
                    for x in pods
                }
            ),
            5,
        )
        for pod in pods:
            spec = pod["template"]["spec"]
            self.assertFalse(spec["automountServiceAccountToken"])
            self.assertIn("kryvola.io.node-restriction.kubernetes.io/domain", spec["nodeSelector"])
            self.assertEqual(
                spec["nodeSelector"]["kryvola.io.node-restriction.kubernetes.io/core-dumps"],
                "disabled",
            )
            self.assertEqual(
                spec["nodeSelector"]["kryvola.io.node-restriction.kubernetes.io/swap"], "disabled"
            )
            self.assertTrue(spec["securityContext"]["runAsNonRoot"])
            for container in spec["containers"]:
                self.assertFalse(container["securityContext"]["allowPrivilegeEscalation"])
                self.assertEqual(container["securityContext"]["capabilities"], {"drop": ["ALL"]})
                self.assertTrue(container["securityContext"]["readOnlyRootFilesystem"])
                self.assertIn("/run/m1-launch/launch.py", container["command"])
                self.assertFalse(
                    any(v["mountPath"] == "/opt/m1" for v in container["volumeMounts"])
                )
                self.assertIn("memory", container["resources"]["limits"])
                self.assertIn("ephemeral-storage", container["resources"]["limits"])
            scratch = next(v for v in spec["volumes"] if v["name"] == "scratch")
            self.assertEqual(scratch["emptyDir"], {"medium": "Memory", "sizeLimit": "256Mi"})
            if pod["metadata"]["namespace"] == "m1-compute":
                self.assertFalse(any("secret" in v for v in spec["volumes"]))
                self.assertFalse(any("owner" in json.dumps(v) for v in spec["volumes"]))
                self.assertNotIn("envFrom", spec["containers"][0])
        compute = next(x for x in pods if x["metadata"]["name"] == "compute")
        engine = next(c for c in compute["template"]["spec"]["containers"] if c["name"] == "engine")
        self.assertEqual(engine["image"], p.ENGINE)

    def test_every_boundary_mutation_is_rejected(self):
        from tools import m1_preproduction as p

        baseline = p.build(IMAGES)
        mutations = (
            lambda d: d["items"].append({"kind": "RoleBinding"}),
            lambda d: next(x for x in d["items"] if x["kind"] == "PodTemplate")["template"][
                "spec"
            ].update(hostNetwork=True),
            lambda d: next(x for x in d["items"] if x["kind"] == "PodTemplate")["template"]["spec"][
                "containers"
            ][0]["securityContext"].update(privileged=True),
            lambda d: next(
                x
                for x in d["items"]
                if x["kind"] == "PodTemplate" and x["metadata"]["name"] == "compute"
            )["template"]["spec"]["volumes"].append(
                {"name": "stolen", "secret": {"secretName": "owner"}}
            ),
            lambda d: next(x for x in d["items"] if x["kind"] == "NetworkPolicy")["spec"].update(
                egress=[{}]
            ),
            lambda d: next(x for x in d["items"] if x["kind"] == "CiliumNetworkPolicy")["spec"].pop(
                "egressDeny"
            ),
            lambda d: next(x for x in d["items"] if x["kind"] == "ClusterSPIFFEID")["spec"].update(
                admin=True
            ),
        )
        for mutate in mutations:
            with self.subTest(mutate=mutate):
                value = copy.deepcopy(baseline)
                mutate(value)
                with self.assertRaisesRegex(ValueError, "M1_DEPLOYMENT_REJECTED"):
                    p.validate(value, IMAGES)
        with self.assertRaises(ValueError):
            p.build(IMAGES | {"runtime": "runtime:latest"})

    def test_required_backend_ingress_is_narrow_and_metadata_is_denied(self):
        from tools import m1_preproduction as p

        value = p.build(IMAGES)
        policies = {
            x["metadata"]["name"]: x for x in value["items"] if x["kind"] == "NetworkPolicy"
        }
        for target in ("postgres", "temporal", "storage", "broker"):
            self.assertTrue(policies[target]["spec"]["ingress"])
            for rule in policies[target]["spec"]["ingress"]:
                self.assertIn("namespaceSelector", rule["from"][0])
                self.assertIn("podSelector", rule["from"][0])
                self.assertTrue(rule["ports"])
        denial = next(x for x in value["items"] if x["kind"] == "CiliumNetworkPolicy")
        self.assertIn("169.254.0.0/16", denial["spec"]["egressDeny"][1]["toCIDR"])
        with self.assertRaises(ValueError):
            p.build({})

    def test_launcher_disables_core_dumps_for_native_children(self):
        result = subprocess.check_output(
            [
                sys.executable,
                str(ROOT / "config/m1/launch.py"),
                sys.executable,
                "-c",
                "import resource;print(resource.getrlimit(resource.RLIMIT_CORE))",
            ]
        )
        self.assertEqual(result.strip(), b"(0, 0)")
