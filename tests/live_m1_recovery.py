"""Faults operate on real published services; process errors alone never pass."""

import json
import os
import time
import unittest
from unittest.mock import patch


class M1RecoveryLiveTests(unittest.TestCase):
    def test_execution_and_transport_recovery(self):
        from tools.m1_recovery import CASES, GROUPS, campaign
        from tools.m1_recovery import history as read_history

        selected = os.environ.get("KRYVOLA_M1_RECOVERY_CASE")
        group = os.environ.get("KRYVOLA_M1_RECOVERY_GROUP")
        self.assertFalse(selected and group)
        cases = (
            [selected]
            if selected
            else tuple(c for c in CASES if c.split("-")[0] in GROUPS[group])
            if group
            else CASES
        )
        delayed = set()

        def slow_history(stack, identifier):
            config = stack.folder / "workflow-state/recovery.json"
            candidates = stack.folder / "workflow-state/candidates"
            if (
                config.exists()
                and json.loads(config.read_bytes()) == {"action": "SELECT", "edge": "after"}
                and any(candidates.glob("*/candidate.json"))
                and stack.project not in delayed
            ):
                delayed.add(stack.project)
                # Exceed the published ten-second selection activity deadline.
                # The kill monitor must progress while this observer is blocked.
                time.sleep(16)
            return read_history(stack, identifier)

        with patch("tools.m1_recovery.history", slow_history):
            report = campaign(cases)
        self.assertEqual(len(delayed), int("completion-after" in cases))
        self.assertEqual(len(report["cases"]), len(cases))
        self.assertEqual(report["qualified"], set(cases) == set(CASES))
