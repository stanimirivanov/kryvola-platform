"""A stalled Temporal peer cannot consume the outer Compose timeout."""

import asyncio
import subprocess
import unittest
from unittest.mock import Mock


class HandoffProcessTests(unittest.TestCase):
    def test_process_deadline_retries_the_identical_notice(self):
        from tools.m1_recovery import handoff

        for code in (75, 142):
            with self.subTest(code=code):
                stack = Mock()
                stack.execute.side_effect = [
                    subprocess.CalledProcessError(code, "owned handoff"),
                    b'["compute-fixed"]',
                ]
                self.assertEqual(handoff(stack, [{"id": "1"}]), ["compute-fixed"])
                self.assertEqual(stack.execute.call_args_list[0], stack.execute.call_args_list[1])

    def test_application_failure_is_not_retried(self):
        from tools.m1_recovery import handoff

        stack = Mock()
        stack.execute.side_effect = subprocess.CalledProcessError(1, "owned handoff")
        with self.assertRaises(subprocess.CalledProcessError):
            handoff(stack, [{"id": "1"}])
        self.assertEqual(stack.execute.call_count, 1)

    def test_exhausted_process_deadlines_fail_the_campaign(self):
        from tools.m1_recovery import handoff

        stack = Mock()
        stack.execute.side_effect = subprocess.CalledProcessError(142, "owned handoff")
        stack.compose.return_value = b""
        with self.assertRaisesRegex(ValueError, "M1_HANDOFF_UNAVAILABLE"):
            handoff(stack, [{"id": "1"}])
        self.assertEqual(stack.execute.call_count, 2)


class TemporalHandoffTests(unittest.IsolatedAsyncioTestCase):
    async def test_unresponsive_peer_is_bounded_and_does_not_claim_a_start(self):
        from tools.m1_recovery import deliver_notifications

        peers = []

        async def blackhole(reader, writer):
            peers.append(writer)
            await reader.read()

        server = await asyncio.start_server(blackhole, "127.0.0.1", 0)
        address = server.sockets[0].getsockname()

        async def connect():
            reader, writer = await asyncio.open_connection(*address)
            try:
                await reader.read(1)
            finally:
                writer.close()
                await writer.wait_closed()

        async def start(*_args):
            self.fail("No client connection completed")

        try:
            with self.assertRaisesRegex(ValueError, "M1_HANDOFF_UNAVAILABLE"):
                await asyncio.wait_for(
                    deliver_notifications(
                        [{"id": "1"}],
                        "queue",
                        connect=connect,
                        start=start,
                        timeout=0.1,
                        attempt_timeout=0.03,
                    ),
                    1,
                )
        finally:
            server.close()
            for peer in peers:
                peer.close()
                await peer.wait_closed()
            await server.wait_closed()

    async def test_delayed_availability_and_lost_ack_keep_the_exact_notice(self):
        from tools.m1_recovery import deliver_notifications

        attempts = 0
        seen = []
        notice = {
            "version": 2,
            "id": "1",
            "kind": "operation_created",
            "tenant_scope": "t",
            "operation_id": "op",
        }

        async def connect():
            nonlocal attempts
            attempts += 1
            if attempts == 1:
                raise OSError("not ready")
            return "connected"

        async def start(client, queue, raw):
            self.assertEqual((client, queue), ("connected", "queue"))
            seen.append(raw)
            if len(seen) == 1:
                raise TimeoutError("ack unavailable")
            return "compute-fixed"

        result = await deliver_notifications(
            [notice], "queue", connect=connect, start=start, timeout=1, attempt_timeout=0.1
        )
        self.assertEqual(result, ["compute-fixed"])
        self.assertEqual(seen[0], seen[1])
        self.assertEqual(attempts, 3)

    async def test_nontransport_failure_is_not_retried(self):
        from tools.m1_recovery import deliver_notifications

        attempts = 0

        async def connect():
            return "connected"

        async def start(*_args):
            nonlocal attempts
            attempts += 1
            raise ValueError("INVALID_COMPUTE_CONTROL")

        with self.assertRaisesRegex(ValueError, "INVALID_COMPUTE_CONTROL"):
            await deliver_notifications(
                [{"id": "1"}], "queue", connect=connect, start=start, timeout=1
            )
        self.assertEqual(attempts, 1)

    async def test_native_sdk_blackhole_is_killed_by_the_process_deadline(self):
        import signal
        import sys

        from tools.m1_recovery import deadline_program

        peers = []

        async def blackhole(reader, writer):
            peers.append(writer)
            await reader.read()

        server = await asyncio.start_server(blackhole, "127.0.0.1", 0)
        host, port = server.sockets[0].getsockname()
        body = f"asyncio.run(Client.connect('{host}:{port}'))"
        program = "import asyncio;from temporalio.client import Client\n" + deadline_program(
            body, seconds=1
        )
        child = await asyncio.create_subprocess_exec(
            sys.executable,
            "-c",
            program,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            await asyncio.wait_for(child.communicate(), 10)
            self.assertEqual(child.returncode, -signal.SIGALRM)
            self.assertGreater(len(peers), 0)
        finally:
            if child.returncode is None:
                child.kill()
                await child.wait()
            server.close()
            for peer in peers:
                peer.close()
                await peer.wait_closed()
            await server.wait_closed()
