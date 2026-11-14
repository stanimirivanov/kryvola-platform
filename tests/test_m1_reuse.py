"""Reusable measurement fixtures must not mix request custody or SQL authority."""

import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


class ReusableInferenceTests(unittest.TestCase):
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
