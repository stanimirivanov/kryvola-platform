"""Offline profile/accounting controls; real shaping is required by full CI."""

import copy
import hashlib
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tools import network_benchmark as network


def batch():
    return {
        "elapsed_ns": 100,
        "resources": {
            "process_peak_rss_bytes": 8192,
            "container_current_bytes": {"value": 8192, "reason": None},
            "container_lifetime_peak_bytes": {"value": 16384, "reason": None},
        },
        "rows": [
            {
                "index": i,
                "queue_ns": i * 20,
                "finish_ns": i * 20 + 19,
                "upload_ns": 5,
                "download_ns": 5,
                "uploaded_bytes": 65536,
                "downloaded_bytes": 65536,
                "outcome": "SUCCEEDED",
                "max_inflight_payload_bytes": 65536,
                "payload_sha256": hashlib.sha256(bytes([i]) * 65536).hexdigest(),
            }
            for i in range(4)
        ],
    }


class NetworkTests(unittest.TestCase):
    def test_accounting_and_memory_bounds_fail_closed(self):
        network.validate_batch(batch(), 4, "SUCCEEDED")
        for key, value in (
            ("queue_ns", -1),
            ("finish_ns", 101),
            ("download_ns", 99),
            ("uploaded_bytes", 0),
            ("downloaded_bytes", None),
            ("max_inflight_payload_bytes", 65537),
            ("index", True),
        ):
            changed = batch()
            changed["rows"][0][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                network.validate_batch(changed, 4, "SUCCEEDED")

    def test_missing_resource_is_explicit_and_never_zero(self):
        value = batch()
        value["resources"]["container_current_bytes"] = {
            "value": None,
            "reason": "CGROUP_V2_METRIC_UNAVAILABLE",
        }
        network.validate_batch(value, 4, "SUCCEEDED")
        for metric in (
            {"value": None, "reason": None},
            {"value": 0, "reason": None},
            {"value": True, "reason": None},
        ):
            changed = copy.deepcopy(value)
            changed["resources"]["container_current_bytes"] = metric
            with self.assertRaises(ValueError):
                network.validate_batch(changed, 4, "SUCCEEDED")

    def test_cost_rounding_and_incomplete_failure_bytes(self):
        value = batch()
        price = network.cost(10**9, value["rows"])
        self.assertEqual(price["compute_window_nano_usd"], 2_000_000)
        self.assertEqual(price["known_download_payload_nano_usd"], 24415)
        self.assertEqual(price["total_nano_usd"], 2_024_415)
        row = value["rows"][0]
        row.update(
            outcome="IO_FAILURE",
            downloaded_bytes=None,
            uploaded_bytes=None,
            upload_ns=None,
            download_ns=None,
        )
        network.validate_batch({**value, "rows": [row]}, 1, "IO_FAILURE")
        price = network.cost(10**9, value["rows"])
        self.assertIsNone(price["total_nano_usd"])
        self.assertEqual(price["reason"], "FAILED_ATTEMPT_BYTES_UNOBSERVED")
        self.assertGreater(price["compute_window_nano_usd"], 0)

    def test_profile_pin_and_metric_units(self):
        self.assertEqual(network.profiles()["wan"]["bandwidth_decimal_kB_s_each_direction"], 128)
        self.assertEqual(network.memory_snapshot("1.5MiB / 128MiB"), 1572864)
        self.assertEqual(network.memory_snapshot("1.5MB / 128MB"), 1500000)
        for text in ("unavailable", "0B / 0B", "NaNMiB / 1GiB"):
            with self.assertRaises(ValueError):
                network.memory_snapshot(text)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "profiles.json"
            path.write_text('{"wan":{"latency_ms_each_direction":0}}')
            with patch.object(network, "PROFILE", path), self.assertRaises(ValueError):
                network.profiles()

    def test_failure_tears_down_only_the_claimed_stack(self):
        with patch.object(network.integration, "Stack") as factory:
            stack = factory.return_value
            stack.claimed = True
            with (
                patch.object(network.integration.ACTIVE.__class__, "exists", return_value=True),
                patch("tools.fake_workflow.smoke"),
                patch.object(network, "observe", side_effect=ValueError("TEST_FAILURE")),
            ):
                with self.assertRaisesRegex(ValueError, "TEST_FAILURE"):
                    network.execute()
            stack.up.assert_called_once_with()
            stack.down.assert_called_once_with()

    def test_offline_command_starts_no_services(self):
        result = subprocess.run(
            [sys.executable, "tools/benchmark.py", "network-check", "--check-only"],
            cwd=network.ROOT,
            capture_output=True,
            check=True,
            timeout=30,
        )
        self.assertIn(b"no services or measurements", result.stdout)
