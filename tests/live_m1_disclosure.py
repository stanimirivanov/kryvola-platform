"""Qualify real transaction, authorization and owner-domain race boundaries."""

import os
import unittest


class DisclosureLiveTests(unittest.TestCase):
    def test_real_disclosure_races(self):
        from tools import m1
        from tools.m1_disclosure import CASES, GROUPS, campaign

        selected = os.environ.get("KRYVOLA_M1_DISCLOSURE_CASE")
        group = os.environ.get("KRYVOLA_M1_DISCLOSURE_GROUP")
        self.assertFalse(selected and group)
        cases = (selected,) if selected else GROUPS[group] if group else CASES
        output = (
            m1.ROOT / "build/m1-disclosure-segments" / group / "m1-disclosure-report.json"
            if group
            else None
        )
        report = campaign(cases, output=output)
        self.assertEqual(len(report["cases"]), len(cases))
        self.assertEqual(report["qualified"], set(cases) == set(CASES))
