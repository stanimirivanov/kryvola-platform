"""The synthetic qualification overlay must preserve the worker's trust boundary."""

import unittest


class IsolationProfileTests(unittest.TestCase):
    def test_worker_keeps_csi_identity_nonroot_and_no_secret_mount(self):
        from tools import m1_isolation_profile as m

        image = "fixture@sha256:" + "a" * 64
        documents = m.build(dict(runtime=image, owner=image, ray=image))
        worker = next(
            x for x in documents if x["kind"] == "Pod" and x["metadata"]["name"] == "compute"
        )
        spec = worker["spec"]
        self.assertEqual(spec["serviceAccountName"], "compute")
        self.assertFalse(spec["automountServiceAccountToken"])
        self.assertEqual(spec["securityContext"]["runAsUser"], 65532)
        self.assertTrue(
            any(v.get("csi", {}).get("driver") == "csi.spiffe.io" for v in spec["volumes"])
        )
        self.assertFalse(any("secret" in v or "hostPath" in v for v in spec["volumes"]))
        self.assertEqual(
            set(spec["nodeSelector"]), {"kryvola.io.node-restriction.kubernetes.io/domain"}
        )
        for container in spec["containers"]:
            mounts = [m["mountPath"] for m in container["volumeMounts"]]
            self.assertEqual(len(mounts), len(set(mounts)))
            self.assertEqual(container["command"][:2], ["python3", "/run/m1-launch/launch.py"])
            self.assertTrue(container["securityContext"]["readOnlyRootFilesystem"])
            self.assertFalse(container["securityContext"]["allowPrivilegeEscalation"])
            self.assertEqual(container["securityContext"]["capabilities"], {"drop": ["ALL"]})
        self.assertTrue(any(x["kind"] == "CiliumNetworkPolicy" for x in documents))
        identities = [x for x in documents if x["kind"] == "ClusterSPIFFEID"]
        self.assertTrue(identities)
        for identity in identities:
            self.assertEqual(
                identity["metadata"].get("labels", {}).get("spire.spiffe.io/class-name"),
                identity["spec"]["className"],
            )

    def test_storage_growth_fits_both_internal_and_artifact_collections(self):
        import tomllib

        from tools import m1_assets
        from tools import m1_isolation_cluster as m

        docs = m.backends(m1_assets.load())
        pod = next(x for x in docs if x["kind"] == "Pod" and x["metadata"]["name"] == "storage")
        config = next(
            x
            for x in docs
            if x["kind"] == "ConfigMap" and x["metadata"]["name"] == "storage-growth"
        )
        growth = tomllib.loads(config["data"]["master.toml"])["master"]["volume_growth"]["copy_1"]
        command = pod["spec"]["containers"][0]["command"]
        slots = int(next(x.split("=", 1)[1] for x in command if x.startswith("-volume.max=")))
        self.assertLessEqual(2 * growth, slots)
        self.assertTrue(
            any(
                v.get("configMap", {}).get("name") == "storage-growth"
                for v in pod["spec"]["volumes"]
            )
        )
        self.assertTrue(
            any(
                v["mountPath"] == "/etc/seaweedfs" and v["readOnly"]
                for v in pod["spec"]["containers"][0]["volumeMounts"]
            )
        )


class DatabaseReadinessTests(unittest.TestCase):
    def test_temporary_unix_server_cannot_satisfy_database_readiness(self):
        import subprocess
        from unittest.mock import patch

        from tools import m1_isolation_cluster as m

        adapter = m.Cluster.__new__(m.Cluster)
        phase = ["temporary"]
        calls = []

        def execute(*args):
            calls.append(args)
            if args[3] == "pg_isready" and "-h" in args and "127.0.0.1" in args:
                if phase[0] == "temporary":
                    phase[0] = "final"
                    raise subprocess.CalledProcessError(1, args)
                return b"accepting connections"
            return b"1"  # the initial Unix socket already answers SQL

        with patch.object(adapter, "execute", side_effect=execute), patch.object(m.time, "sleep"):
            adapter.wait_database()
        self.assertEqual(phase[0], "final")
        self.assertEqual(len(calls), 2)
