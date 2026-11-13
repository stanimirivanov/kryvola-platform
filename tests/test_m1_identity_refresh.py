"""The coordinator must replace expired SVIDs and its trust store, not retain them."""

import importlib.util
import types
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, call, patch

spec = importlib.util.spec_from_file_location(
    "m1_service", Path(__file__).resolve().parents[1] / "config/m1/service.py"
)
assert spec and spec.loader
service = importlib.util.module_from_spec(spec)
spec.loader.exec_module(service)


class M1IdentityRefreshTests(unittest.IsolatedAsyncioTestCase):
    async def test_each_heartbeat_replaces_tls_and_proves_runtime_mtls(self):
        first, second = object(), object()
        registry = types.SimpleNamespace(tls=object())
        with (
            patch.object(service, "tls", side_effect=[first, second]),
            patch.object(service, "probe") as probe,
            patch.object(service, "ready") as ready,
            patch.object(
                service.asyncio, "sleep", new=AsyncMock(side_effect=[None, RuntimeError("stop")])
            ),
        ):
            with self.assertRaisesRegex(RuntimeError, "stop"):
                await service.maintain_workload("workflow", registry)
        self.assertIs(registry.tls, second)
        self.assertEqual(
            probe.call_args_list,
            [call("workflow", "runtime", first), call("workflow", "runtime", second)],
        )
        self.assertEqual(ready.call_args_list, [call("workflow"), call("workflow")])
