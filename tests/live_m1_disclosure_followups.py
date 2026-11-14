"""A real unreachable Ray service produces partial cleanup, then must converge."""

import unittest
from unittest.mock import patch


class DisclosureFollowupLiveTests(unittest.TestCase):
    def test_real_partial_cleanup_reconciles_with_the_same_committed_fence(self):
        from tools import m1_disclosure as disclosure

        original = disclosure.role
        replies = []

        def unavailable_once(stack, **value):
            if value.get("op") != "stop":
                return original(stack, **value)
            if not replies:
                stack.compose("pause", "ray")
                try:
                    result = original(stack, **value)
                    self.assertIs(result["cleanup_complete"], False)
                finally:
                    stack.compose("unpause", "ray")
            else:
                result = original(stack, **value)
            replies.append(result)
            return result

        with patch.object(disclosure, "role", unavailable_once):
            result = disclosure.run_case("registry-outage")
        self.assertGreaterEqual(len(replies), 2)
        self.assertLessEqual(len(replies), 3)
        self.assertEqual({reply["fence"] for reply in replies}, {str(result["fence"])})
        self.assertEqual(result["disclosures"], 0)
        self.assertTrue(result["checks"]["followups"]["cleanup_complete"])
        self.assertTrue(result["checks"]["followups"]["temporal_stopped"])
