"""Faults operate on real published services; process errors alone never pass."""

import os
import unittest


class M1RecoveryLiveTests(unittest.TestCase):
    def test_execution_and_transport_recovery(self):
        from tools.m1_recovery import CASES, GROUPS, campaign

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
        report = campaign(cases)
        self.assertEqual(len(report["cases"]), len(cases))
        self.assertEqual(report["qualified"], set(cases) == set(CASES))
