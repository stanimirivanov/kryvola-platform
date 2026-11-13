"""Measure actual Temporal protobufs, rejecting oversized or secret-bearing histories."""

import unittest

from temporalio.api.history.v1 import History


def history(data=b'{"operation_id":"inference"}'):
    value = History()
    payload = value.events.add().workflow_execution_started_event_attributes.input.payloads.add()
    payload.metadata["encoding"] = b"json/plain"
    payload.data = data
    return value


class HistoryEvidenceTests(unittest.TestCase):
    def test_reference_only_payload_is_measured(self):
        from tools.m1_history import measure

        value = history()
        payload = value.events[0].workflow_execution_started_event_attributes.input.payloads[0]
        self.assertEqual(measure(value), {"events": 1, "payload_max_bytes": payload.ByteSize()})

    def test_private_or_oversized_payloads_cannot_qualify(self):
        from tools.m1_history import measure

        for data in (b"x" * 32768, b'{"token":"private"}', b'{"nested":{"client_key":"private"}}'):
            with self.assertRaisesRegex(ValueError, "M1_HISTORY"):
                measure(history(data))
        value = history()
        for _ in range(128):
            value.events.add()
        with self.assertRaisesRegex(ValueError, "M1_HISTORY"):
            measure(value)
        value = history(b'"' + b"x" * 25000 + b'"')
        inputs = value.events[0].workflow_execution_started_event_attributes.input
        for _ in range(5):
            inputs.payloads.add().CopyFrom(inputs.payloads[0])
        with self.assertRaisesRegex(ValueError, "M1_HISTORY_CALL_BOUND"):
            measure(value)
