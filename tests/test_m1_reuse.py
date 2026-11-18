"""Reusable measurement fixtures must not mix request custody or SQL authority."""

import ast
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch


class ReusableInferenceTests(unittest.TestCase):
    def finalizing_client(self, transport):
        from tools import m1

        class Unavailable(Exception):
            pass

        class Client:
            request = staticmethod(transport)

        source = ast.parse((m1.ROOT / "config/m1/owner_inference.py").read_text())
        node = next(
            n for n in source.body if isinstance(n, ast.ClassDef) and n.name == "FinalizingClient"
        )
        namespace: dict = {
            "client_sdk": SimpleNamespace(Client=Client, SubmissionUnavailable=Unavailable),
            "time": time,
        }
        exec(compile(ast.Module(body=[node], type_ignores=[]), "owner-client", "exec"), namespace)
        return namespace["FinalizingClient"](), Unavailable

    def test_lost_finalize_response_reconciles_the_same_committed_upload(self):
        committed, attempts = {}, []

        def transport(*request):
            attempts.append(request)
            committed.setdefault(request[1], request[2])
            if len(attempts) == 1:
                raise unavailable()
            return committed[request[1]]

        client, unavailable = self.finalizing_client(transport)
        request = (
            "POST",
            "/v1/input-uploads/u/finalize",
            b"exact-manifest",
            "INPUT_UPLOAD_FINALIZE",
            {"upload_id": "u"},
        )
        with patch.object(time, "sleep"):
            self.assertEqual(client.request(*request), b"exact-manifest")
        self.assertEqual(len(committed), 1)
        self.assertEqual(attempts, [request, request])

    def test_finalize_retry_is_bounded_and_does_not_retry_denials_or_other_actions(self):
        for action, unavailable_failure, expected in (
            ("INPUT_UPLOAD_FINALIZE", True, 3),
            ("INPUT_UPLOAD_FINALIZE", False, 1),
            ("APPROVED_OPERATION_ADMIT", True, 1),
        ):
            with self.subTest(action=action, unavailable=unavailable_failure):
                transport = Mock()
                client, unavailable = self.finalizing_client(transport)
                error = unavailable if unavailable_failure else PermissionError
                transport.side_effect = error("fixed failure")
                with patch.object(time, "sleep"), self.assertRaises(error):
                    client.request(
                        "POST", "/v1/input-uploads/u/finalize", b"exact", action, {"upload_id": "u"}
                    )
                self.assertEqual(transport.call_count, expected)

    def test_invalid_request_identity_is_rejected_before_owner_access(self):
        from tools.m1_inference import OwnerSession

        for identity in ("../escape", "", "A" * 16, "a" * 15):
            with self.subTest(identity=identity), self.assertRaises(ValueError):
                OwnerSession(None, "engine", request_id=identity)

    def test_request_lock_rejects_overlap_and_poisoned_fixture(self):
        from tools.m1_inference import serial_request

        with tempfile.TemporaryDirectory() as directory:
            stack = SimpleNamespace(folder=Path(directory))
            with serial_request(stack):
                with self.assertRaises(ValueError):
                    with serial_request(stack):
                        self.fail("overlapping request admitted")
            with self.assertRaisesRegex(RuntimeError, "failed request"):
                with serial_request(stack):
                    raise RuntimeError("failed request")
            with self.assertRaises(ValueError):
                with serial_request(stack):
                    self.fail("failed fixture reused")

    def test_sql_scope_is_exact_and_rejects_injection(self):
        from tools.m1_inference import scope_sql

        scope = {"tenant_scope": "tenant-fixture", "operation_id": "m1-inference-abc"}
        text = scope_sql(scope, "fabric_outbox")
        self.assertIn("fabric_outbox.tenant_scope='tenant-fixture'", text)
        self.assertIn("fabric_outbox.operation_id='m1-inference-abc'", text)
        with self.assertRaises(ValueError):
            scope_sql({**scope, "operation_id": "x' OR true--"})

    def test_failed_shared_request_poisoning_preserves_external_ownership(self):
        from unittest.mock import Mock

        from tools.m1_inference import qualify

        with tempfile.TemporaryDirectory() as directory:
            stack = SimpleNamespace(
                folder=Path(directory), owned=True, configured=True, close=Mock()
            )
            with (
                patch(
                    "tools.m1_inference.m1_assets.load",
                    return_value={"permissions": {"image_sha256": "a" * 64}},
                ),
                patch(
                    "tools.m1_inference.OwnerSession", side_effect=RuntimeError("owner unavailable")
                ),
            ):
                with self.assertRaisesRegex(RuntimeError, "owner unavailable"):
                    qualify(stack=stack, request_id="a" * 16)
            self.assertTrue((stack.folder / "inference-failed").exists())
            stack.close.assert_not_called()

    def test_broker_cursor_skips_other_operations_without_relabeling_them(self):
        from tools.m1_inference import operation_notices

        scope = {"tenant_scope": "tenant-fixture", "operation_id": "new"}
        rows = {4: {**scope, "operation_id": "old"}, 5: scope}
        stack = SimpleNamespace(_m1_notice_cursor=4)
        with patch("tools.m1_inference.broker_record", side_effect=lambda _, n: (rows[n], 20)):
            notice, size, offset = next(operation_notices(stack, scope))
        self.assertEqual((notice, size, offset), (scope, 20, 5))
