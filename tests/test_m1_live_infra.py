"""Only reviewed immutable infrastructure images may reach the disposable cluster."""

import unittest


class InfrastructurePinsTests(unittest.TestCase):
    def test_mutable_or_unknown_images_fail_before_apply(self):
        from tools import m1_live_infra as m

        pod = {
            "kind": "Pod",
            "metadata": {},
            "spec": {"containers": [{"name": "test", "image": "test:v1"}]},
        }
        with self.assertRaisesRegex(ValueError, "M1_INFRA_IMAGE_PIN"):
            m.pin_documents([pod], {})
        pinned = "test@sha256:" + "a" * 64
        result = m.pin_documents([pod], {"test:v1": pinned})
        self.assertEqual(result[0]["spec"]["containers"][0]["image"], pinned)
        self.assertEqual(pod["spec"]["containers"][0]["image"], "test:v1")
        with self.assertRaisesRegex(ValueError, "M1_INFRA_IMAGE_PIN"):
            m.pin_documents([pod], {"test:v1": "test:latest"})

    def test_chart_cannot_seed_broad_workload_identities(self):
        from tools import m1_live_infra as m

        with self.assertRaisesRegex(ValueError, "M1_INFRA_BROAD_IDENTITY"):
            m.pin_documents([{"kind": "ClusterSPIFFEID", "metadata": {"name": "default"}}], {})

    def test_waits_for_all_node_registrations_before_placement(self):
        import json
        from types import SimpleNamespace
        from unittest.mock import patch

        from tools import m1_live_infra as m

        responses = [
            SimpleNamespace(stdout=json.dumps({"items": [{}]}).encode()),
            SimpleNamespace(stdout=json.dumps({"items": [{}, {}, {}, {}]}).encode()),
        ]
        with (
            patch.object(m.m1_cluster, "kubectl", side_effect=responses) as command,
            patch.object(m.time, "sleep"),
        ):
            self.assertEqual(len(m.registered_nodes("owned", 4)), 4)
        self.assertEqual(command.call_count, 2)
