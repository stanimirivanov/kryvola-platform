"""Non-root socket/path probe. Input contains addresses only, never canary material."""

import json
import os
import socket
import sys
from pathlib import Path


def main():
    value = json.loads(sys.stdin.buffer.read(8193))
    if sys.platform != "linux":
        raise ValueError("LINUX_PROBE_REQUIRED")
    if os.geteuid() == 0 or not Path("/etc/hostname").is_file():
        raise ValueError("PROBE_IDENTITY_OR_FILESYSTEM")
    with socket.create_connection(("127.0.0.1", value["positive_port"]), timeout=2):
        pass
    results = []
    for target in value["denied"]:
        denied = False
        try:
            with socket.create_connection((target["host"], target["port"]), timeout=0.5):
                pass
        except TimeoutError, ConnectionRefusedError, PermissionError:
            denied = True
        except OSError as error:
            if error.errno not in {101, 113}:  # Linux ENETUNREACH/EHOSTUNREACH
                raise
            denied = True
        if not denied:
            raise ValueError("FORBIDDEN_CONNECTION_SUCCEEDED")
        results.append({"target": target["role"], "port": target["port"], "denied": True})
    for path in ("/owner/fixture-key", "/var/run/docker.sock"):
        if Path(path).exists():
            raise ValueError("FORBIDDEN_PATH_VISIBLE")
    print(json.dumps({"uid": os.geteuid(), "positive_control": True, "denials": results}))


if __name__ == "__main__":
    main()
