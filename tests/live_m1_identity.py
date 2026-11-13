"""Real SPIRE regression for long hosted checkout paths; install M1 tools first."""

import json
import re
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tools import m1_identity


class M1HostedIdentityTests(unittest.TestCase):
    def test_long_state_paths_keep_admin_socket_private_and_clean_it_on_exit(self):
        self.exercise(False)

    def test_failure_cleans_long_path_socket_and_processes(self):
        self.exercise(True)

    def exercise(self, fail):
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp) / ("hosted-checkout-" + "x" * 80) / "identity"
            folder.mkdir(parents=True, mode=0o700)
            self.assertGreater(len(str(folder / "server.sock").encode()), 107)
            with tempfile.TemporaryDirectory(prefix="m1-workload-", dir="/tmp") as public:
                socket_folder = Path(public)
                socket_folder.chmod(0o755)
                processes = []
                actual = subprocess.Popen

                def start(*args, **kwargs):
                    process = actual(*args, **kwargs)
                    processes.append(process)
                    return process

                def run():
                    with m1_identity.identity(folder, socket_folder) as endpoint:
                        config = (folder / "server.conf").read_text()
                        match = re.search(r'socket_path = "([^"]+)"', config)
                        self.assertIsNotNone(match)
                        assert match
                        admin = Path(match[1])
                        self.assertLessEqual(len(str(admin).encode()), 107)
                        self.assertEqual(admin.parent.stat().st_mode & 0o777, 0o700)
                        self.assertNotEqual(admin.parent, socket_folder)
                        self.assertTrue(endpoint.is_socket())
                        raw = subprocess.check_output(
                            [
                                str(m1_identity.TOOLS / "spire-agent"),
                                "api",
                                "fetch",
                                "x509",
                                "-socketPath",
                                str(endpoint),
                                "-output",
                                "json",
                            ],
                            timeout=15,
                        )
                        self.assertIn(
                            "spiffe://m1.test/probe",
                            [s["spiffe_id"] for s in json.loads(raw)["svids"]],
                        )
                        if fail:
                            raise RuntimeError("controlled failure")
                        return admin

                with patch.object(m1_identity.subprocess, "Popen", side_effect=start):
                    if fail:
                        with self.assertRaisesRegex(RuntimeError, "controlled failure"):
                            run()
                        config = (folder / "server.conf").read_text()
                        admin = Path(re.findall(r'socket_path = "([^"]+)"', config)[0])
                    else:
                        admin = run()
                self.assertFalse(admin.parent.exists())
                self.assertTrue(processes)
                self.assertTrue(all(p.poll() is not None for p in processes))
