"""Real owner custody and inference using admitted published M1 artifacts."""

import json
import secrets
import unittest

from tools import m1


class PublishedM1InferenceTests(unittest.TestCase):
    def test_distinct_requests_reuse_services_with_separate_durable_evidence(self):
        from tools.m1_inference import qualify

        stack = m1.Stack("kryvola-m1-" + secrets.token_hex(6))

        def processes():
            identifiers = stack.compose("ps", "-q").decode().split()
            import subprocess

            return subprocess.check_output(
                ["docker", "inspect", "--format", "{{.Id}} {{.State.StartedAt}}", *identifiers],
                timeout=20,
            ).splitlines()

        try:
            stack.start()
            stack.verify()
            before = sorted(processes())
            first = qualify(stack=stack, request_id="a" * 16)
            with self.assertRaisesRegex(ValueError, "M1_REQUEST_REPLAYED"):
                qualify(stack=stack, request_id="a" * 16)
            second = qualify(stack=stack, request_id="b" * 16)
            self.assertEqual(before, sorted(processes()))
            for key in first["execution"]:
                self.assertNotEqual(first["execution"][key], second["execution"][key], key)
            self.assertEqual(first["frozen_reference_sha256"], second["frozen_reference_sha256"])
            for report in (first, second):
                self.assertIs(report["owner_reference_match"], True)
                self.assertIs(report["logs_clean"], True)
                self.assertEqual(report["broker"]["events"], 2)
            counts = stack.sql(
                "SELECT (SELECT count(*) FROM fabric_executions),"
                "(SELECT count(*) FROM fabric_execution_receipts),"
                "(SELECT count(*) FROM fabric_selected_results),"
                "(SELECT count(*) FROM fabric_disclosure_decisions)"
            )
            self.assertEqual(counts.strip(), b"2|2|2|2")
        finally:
            stack.close()

    def test_real_owner_to_owner_inference_matches_the_frozen_reference(self):
        from tools.m1_inference import qualify

        report = qualify()
        self.assertEqual(report["assurance"], "CONFIDENTIALITY_ONLY")
        self.assertIs(report["owner_reference_match"], True)
        self.assertIs(report["logs_clean"], True)
        self.assertIs(report["bounds_checked"], True)

    def test_owner_image_can_run_the_published_custody_command(self):
        # The real owner agent looks up its wrapping key via Secret Service.
        # A successful import or an invalid-arguments probe cannot prove custody.
        import subprocess

        from tools import m1_assets, m1_images

        with m1_images.prepare(m1_assets.load()) as images:
            source = (m1.ROOT / "config/m1/owner_inference.py").read_text()
            for _ in range(3):
                result = subprocess.run(
                    [
                        "docker",
                        "run",
                        "--rm",
                        "--network",
                        "none",
                        "--user",
                        "3001:3001",
                        "--read-only",
                        "--tmpfs",
                        "/owner:uid=3001,gid=3001,mode=700",
                        "--tmpfs",
                        "/tmp",
                        "--cap-drop",
                        "ALL",
                        "--security-opt",
                        "no-new-privileges:true",
                        images["owner"],
                        "dbus-run-session",
                        "--",
                        "python",
                        "-c",
                        source,
                        m1_assets.load()["permissions"]["image_sha256"],
                        "prepare",
                    ],
                    capture_output=True,
                    timeout=120,
                )
                self.assertEqual(
                    result.returncode, 0, result.stderr.decode(errors="replace")[-1500:]
                )
                frames = [
                    json.loads(line.removeprefix(b"M1_CONTROL:"))
                    for line in result.stdout.splitlines()
                    if line.startswith(b"M1_CONTROL:")
                ]
                self.assertEqual(len(frames), 1)
                self.assertEqual(frames[0]["stage"], "PREPARED")
                self.assertEqual(frames[0]["compute"]["assurance"], "CONFIDENTIALITY_ONLY")
