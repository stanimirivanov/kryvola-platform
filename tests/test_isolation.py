"""Offline leakage, denial-evidence and configuration controls; no services started."""

import ast
import base64
import copy
import json
import subprocess
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from tools import integration, isolation


class IsolationTests(unittest.TestCase):
    def test_shared_probe_parses_on_the_ray_python_version(self):
        code = (isolation.ROOT / "config/isolation/probe.py").read_text()
        ast.parse(code, feature_version=(3, 12))

    def test_probe_timeout_removes_only_its_owned_helper(self):
        stack = SimpleNamespace(project="kryvola-m0-0123456789ab")
        with patch.object(
            isolation.integration,
            "run",
            side_effect=[
                subprocess.TimeoutExpired("fixture-probe", 20),
                subprocess.CompletedProcess([], 0),
            ],
        ) as run:
            with self.assertRaises(subprocess.TimeoutExpired):
                isolation.probe(stack, "redpanda", "fixture-container", [], 9092)
            self.assertEqual(
                run.call_args.args[0],
                ["docker", "rm", "--force", "kryvola-m0-0123456789ab-probe-redpanda"],
            )

    def test_raw_hex_base64_and_json_escaped_canaries_are_detected(self):
        canary = b"PUBLIC_ISOLATION_CANARY_NOT_A_KEY_fixture1234"
        values = [
            canary,
            canary.hex().upper().encode(),
            json.dumps(
                {"data": base64.b64encode(b"prefix" + canary + b"suffix").decode()}
            ).encode(),
            ('{"value":"' + "".join(f"\\u{n:04x}" for n in canary) + '"}').encode(),
        ]
        for raw in values:
            with self.assertRaisesRegex(ValueError, "PROHIBITED_ISOLATION_MATERIAL"):
                isolation.scan(raw, canary)
        isolation.scan(b'{"data":"ordinary-public-record"}', canary)
        with self.assertRaisesRegex(ValueError, "ISOLATION_SCAN_LIMIT"):
            isolation.scan(b"x" * 262145, canary)

    def test_broken_positive_control_and_incomplete_denials_reject(self):
        targets = [{"role": "owner", "host": "192.0.2.1", "port": 8080}]
        valid = {
            "uid": 1000,
            "positive_control": True,
            "denials": [{"target": "owner", "port": 8080, "denied": True}],
        }
        isolation.validate_probe(valid, targets)
        for field, value in (
            ("uid", 0),
            ("uid", True),
            ("positive_control", False),
            ("denials", []),
            ("denials", [{"denied": False}]),
        ):
            bad = {**valid, field: value}
            with self.assertRaises(ValueError):
                isolation.validate_probe(bad, targets)
        with patch.object(
            isolation.socket, "create_connection", side_effect=ConnectionRefusedError
        ):
            with self.assertRaises(ConnectionRefusedError):
                isolation.listeners(targets)

    def test_owner_compute_boundary_weakening_is_rejected(self):
        original = integration.configuration()
        for field, value in (
            ("user", "0:0"),
            ("read_only", False),
            ("cap_drop", []),
            ("security_opt", []),
            ("environment", {"OWNER_PRIVATE_KEY": "fixture"}),
            ("networks", ["owner", "compute"]),
        ):
            changed = copy.deepcopy(original)
            changed["services"]["owner"][field] = value
            with self.assertRaises(ValueError):
                integration.configuration(changed)
        changed = copy.deepcopy(original)
        changed["services"]["ray"]["volumes"] = original["services"]["owner"]["volumes"]
        with self.assertRaises(ValueError):
            integration.configuration(changed)


if __name__ == "__main__":
    unittest.main()
