"""Isolation evidence requires successful real controls and specific denials."""

import copy
import json
import unittest


class IsolationEvidenceTests(unittest.TestCase):
    def test_missing_controls_transport_errors_and_unexpected_denials_fail(self):
        from tools import m1_isolation as m

        value = {
            "positive": {name: True for name in m.POSITIVES},
            "denied": {name: m.EXPECTED[name] for name in m.EXPECTED},
            "inventory": {
                "uid": 65532,
                "effective_capabilities": 0,
                "owner_library": False,
                "forbidden_files_absent": True,
            },
        }
        m.validate(value)
        for mutate in (
            lambda d: d["positive"].pop("artifact_after"),
            lambda d: d["positive"].update(artifact_before=False),
            lambda d: d["positive"].update(artifact_before=1),
            lambda d: d["denied"].update(foreign_tenant="TIMEOUT"),
            lambda d: d["denied"].update(foreign_tenant="404"),
            lambda d: d["denied"].update(metadata="CONNECTION_REFUSED"),
            lambda d: d["inventory"].update(owner_library=True),
            lambda d: d["inventory"].update(owner_library=0),
            lambda d: d["inventory"].update(effective_capabilities=False),
            lambda d: d["inventory"].update(uid=0),
            lambda d: d.update(untrusted_extra="private payload"),
        ):
            with self.subTest(mutate=mutate):
                wrong = copy.deepcopy(value)
                mutate(wrong)
                with self.assertRaisesRegex(ValueError, "M1_ISOLATION_EVIDENCE"):
                    m.validate(wrong)

    def test_secret_scanning_precedes_report_acceptance(self):
        from tools import m1_isolation as m

        secret = b"sensitive-fixture-nonce-123456"
        import base64

        for value in (secret, secret.hex().encode(), base64.b64encode(secret)):
            with self.assertRaisesRegex(ValueError, "PROHIBITED_ISOLATION_MATERIAL"):
                m.scan(json.dumps({"code": value.decode()}).encode(), [secret])


class CampaignScopeTests(unittest.TestCase):
    def test_registry_credential_preserves_workflow_epoch(self):
        from types import SimpleNamespace

        from tools.m1_isolation_case import Campaign

        policies = []
        campaign = Campaign.__new__(Campaign)
        campaign.boot = "public-boot"
        campaign.tokens = []
        campaign.adapter = SimpleNamespace(publish=policies.append)
        operation = dict(tenant_scope="tenant", operation_id="operation", workflow_epoch="7")
        campaign.registry(operation, ["GET_OPERATION"])
        grant = policies[-1]["registry_grants"][0]
        self.assertEqual(grant["scope"], operation)
        self.assertNotIn("idempotency_key", grant)


class EvidencePublicationTests(unittest.TestCase):
    def test_rejects_secret_or_incomplete_evidence_before_creating_report(self):
        import tempfile
        from pathlib import Path

        from tools import m1_isolation as m

        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "report.json"
            with self.assertRaises(ValueError):
                m.record("local", {}, [b"private-canary"], destination=output)
            self.assertFalse(output.exists())
            valid = dict(
                positive=dict.fromkeys(m.POSITIVES, True),
                denied=m.EXPECTED,
                inventory=dict(
                    uid=65532,
                    effective_capabilities=0,
                    owner_library=False,
                    forbidden_files_absent=True,
                ),
            )
            with self.assertRaisesRegex(ValueError, "PROHIBITED_ISOLATION_MATERIAL"):
                m.record(
                    "local",
                    valid,
                    [b"private-canary"],
                    destination=output,
                    accidental_leak="private-canary",
                )
            self.assertFalse(output.exists())


class LocalOwnershipTests(unittest.TestCase):
    def test_unowned_helper_is_never_removed_and_owned_helper_is_removed(self):
        from types import SimpleNamespace
        from unittest.mock import Mock

        from tools.m1_isolation_local import Local

        adapter = Local.__new__(Local)
        adapter.stack = SimpleNamespace(token="own-token")
        for token in ("foreign-token", "own-token"):
            adapter.run = Mock(
                return_value=SimpleNamespace(
                    returncode=0,
                    stdout=json.dumps(
                        [{"Config": {"Labels": {"io.kryvola.m1.invocation": token}}}]
                    ).encode(),
                )
            )
            if token == "foreign-token":
                with self.assertRaisesRegex(ValueError, "M1_HELPER_OWNERSHIP"):
                    adapter.remove("helper")
                self.assertEqual(adapter.run.call_count, 1)
            else:
                adapter.remove("helper")
                self.assertEqual(adapter.run.call_args.args[0], ["rm", "-f", "helper"])


class ClusterMetadataOwnershipTests(unittest.TestCase):
    def test_failed_creation_never_removes_an_existing_name(self):
        import subprocess
        from types import SimpleNamespace
        from unittest.mock import patch

        from tools import m1_isolation_cluster as m

        result = SimpleNamespace(stdout=b"")
        adapter = SimpleNamespace(node="owned-control-plane", images={"runtime": "fixture"})
        nodes = SimpleNamespace(stdout=b'{"items":[{"metadata":{"name":"owned-worker"}}]}')
        for fail in ("create", "start"):
            calls = []

            def command(args, *, calls=calls, fail=fail, **kwargs):
                calls.append(args)
                if args[:2] == ["docker", fail]:
                    raise subprocess.CalledProcessError(1, args)
                return (
                    SimpleNamespace(stdout=b"owned-container-id")
                    if args[:2] == ["docker", "create"]
                    else result
                )

            with (
                patch.object(m.m1_cluster, "kubectl", return_value=nodes),
                patch.object(m.subprocess, "run", side_effect=command),
            ):
                with self.assertRaises(subprocess.CalledProcessError):
                    with m.metadata(adapter):
                        self.fail("failed acquisition must not yield")
            removals = [args for args in calls if args[:2] == ["docker", "rm"]]
            self.assertEqual(
                removals, [] if fail == "create" else [["docker", "rm", "-f", "owned-container-id"]]
            )
