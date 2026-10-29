"""Offline isolation/lifecycle controls. No Docker services start in these tests."""

import copy
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from unittest.mock import patch

from tools import integration


class IntegrationTests(unittest.TestCase):
    def test_pins_networks_mounts_and_compute_credentials_fail_closed(self):
        model = integration.configuration()
        mutations = []
        for key, value in (
            ("image", "rayproject/ray:latest"),
            ("ports", ["8265:8265"]),
            ("privileged", True),
            ("volumes", ["owner.key:/key"]),
            ("networks", ["compute", "data"]),
            ("environment", {"AWS_SECRET_ACCESS_KEY": "forbidden"}),
        ):
            changed = copy.deepcopy(model)
            changed["services"]["ray"][key] = value
            mutations.append(changed)
        changed = copy.deepcopy(model)
        changed["networks"]["compute"]["internal"] = False
        mutations.append(changed)
        for value in mutations:
            with self.subTest(value=value), self.assertRaises(ValueError):
                integration.configuration(value)

    def test_unowned_projects_and_remote_engines_are_rejected(self):
        for name in ("production", "kryvola-m0-../../", "kryvola-m0-short"):
            with self.assertRaisesRegex(ValueError, "UNOWNED_PROJECT"):
                integration.Stack(name)
        with (
            patch.dict(os.environ, {"DOCKER_HOST": "tcp://remote:2375"}),
            patch.object(
                integration, "ACTIVE", Path(tempfile.gettempdir()) / "missing-kryvola-active.json"
            ),
        ):
            with self.assertRaisesRegex(ValueError, "REMOTE_DOCKER_FORBIDDEN"):
                integration.Stack("kryvola-m0-0123456789ab").prepare()

    def test_output_and_timeout_controls(self):
        with self.assertRaisesRegex(ValueError, "CLI_OUTPUT_LIMIT"):
            integration.run([sys.executable, "-c", "print('x'*65537)"])
        with self.assertRaises(subprocess.TimeoutExpired):
            integration.run([sys.executable, "-c", "import time; time.sleep(10)"], timeout=0.1)

    def test_generated_credentials_are_scoped_and_removed_on_teardown(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "compose.yaml").write_text(json.dumps(integration.configuration()))
            active = root / "build/integration/active.json"

            def simulate(args, **kwargs):
                data = b""
                if args[:3] == ["docker", "context", "inspect"]:
                    data = b'[{"Endpoints":{"docker":{"Host":"unix:///var/run/docker.sock"}}}]'
                if args[:2] == ["docker", "info"]:
                    data = b"linux\n"
                return subprocess.CompletedProcess(args, 0, data, b"")

            with (
                patch.object(integration, "ROOT", root),
                patch.object(integration, "ACTIVE", active),
                patch.object(integration, "run", side_effect=simulate),
                patch.dict(
                    os.environ, {"DOCKER_HOST": "unix:///fixture", "PG_PASSWORD": "ambient-value"}
                ),
            ):
                stack = integration.Stack("kryvola-m0-0123456789ab")
                stack.prepare()
                self.assertTrue(active.is_file())
                self.assertNotIn("PG_PASSWORD", stack.env)
                self.assertNotIn("ambient-value", (stack.folder / "fixture.env").read_text())
                self.assertEqual(len(stack.redactions), 4)
                self.assertTrue((stack.folder / "owner-canary").is_file())
                self.assertNotIn(stack.redactions[-1], (stack.folder / "fixture.env").read_text())
                stack.down()
                self.assertFalse(active.exists())
                self.assertFalse((stack.folder / "s3.json").exists())
                self.assertFalse((stack.folder / "fixture.env").exists())
                self.assertFalse((stack.folder / "owner-canary").exists())

    def test_failure_attempts_cleanup_and_redacts_fixture_tokens(self):
        stack = integration.Stack("kryvola-m0-0123456789ab")
        stack.claimed = True  # Simulate successful preparation before pull failure.
        with (
            patch.object(stack, "prepare"),
            patch.object(stack, "compose", side_effect=ValueError("PULL_FAILED")),
            patch.object(stack, "down") as down,
        ):
            with self.assertRaisesRegex(ValueError, "PULL_FAILED"):
                stack.up()
            down.assert_called_once_with()
        stack.redactions = ["fixture-private-value"]
        output = io.StringIO()
        with (
            patch.object(
                integration,
                "run",
                return_value=subprocess.CompletedProcess([], 1, b"", b"fixture-private-value"),
            ),
            redirect_stderr(output),
        ):
            with self.assertRaises(ValueError):
                stack.compose("up")
        self.assertNotIn("fixture-private-value", output.getvalue())
        self.assertIn("[REDACTED]", output.getvalue())
