"""Disposable admission fixtures must not target an existing cluster."""

import unittest
from unittest.mock import patch


class ClusterTests(unittest.TestCase):
    def test_existing_name_is_never_created_or_deleted(self):
        from tools import m1_cluster as c

        with patch.object(c, "command", return_value=b"m1-boundary-0123456789ab\n") as run:
            with self.assertRaisesRegex(ValueError, "M1_CLUSTER_EXISTS"):
                with c.cluster("m1-boundary-0123456789ab"):
                    self.fail("must not enter")
        self.assertEqual(len(run.call_args_list), 1)

    def test_partial_creation_and_body_failure_delete_only_owned_name(self):
        from tools import m1_cluster as c

        for where in ("create", "body"):
            commands = []

            def run(*args, commands=commands, where=where, **kwargs):
                commands.append(args)
                if args[:2] == ("create", "cluster") and where == "create":
                    raise RuntimeError("controlled")
                return b""

            with patch.object(c, "command", side_effect=run):
                with self.assertRaisesRegex(RuntimeError, "controlled"):
                    with c.cluster("m1-boundary-0123456789ab"):
                        raise RuntimeError("controlled")
            self.assertEqual(commands[-1][:2], ("delete", "cluster"))
            self.assertIn("m1-boundary-0123456789ab", commands[-1])

    def test_live_configuration_is_owned_and_passed_to_kind(self):
        import json
        from pathlib import Path

        from tools import m1_cluster as c

        configuration = {
            "kind": "Cluster",
            "apiVersion": "kind.x-k8s.io/v1alpha4",
            "networking": {"disableDefaultCNI": True},
            "nodes": [{"role": "control-plane"}, {"role": "worker"}],
        }
        commands = []

        def run(*args):
            commands.append(args)
            return b""

        with patch.object(c, "command", side_effect=run):
            with c.cluster("m1-boundary-0123456789ab", configuration=configuration):
                created = next(args for args in commands if args[:2] == ("create", "cluster"))
                path = Path(created[created.index("--config") + 1])
                self.assertEqual(json.loads(path.read_bytes()), configuration)
            self.assertFalse(path.exists())

    def test_arbitrary_names_are_rejected_before_any_cli(self):
        from tools import m1_cluster as c

        with patch.object(c, "command") as run:
            for name in ("production", "m1-boundary-../../", "kind"):
                with self.assertRaises(ValueError):
                    with c.cluster(name):
                        self.fail("must not enter")
            run.assert_not_called()
