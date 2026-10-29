"""Each actual CLI admission violation must reject; a baseline pass is required first."""

import subprocess
import sys


def qualify(cases, root):
    results = []
    for case in cases:
        result = subprocess.run(
            [sys.executable, "tools/release_conformance.py", "probe", "--case", case],
            cwd=root,
            capture_output=True,
            timeout=90,
            check=False,
        )
        if (
            result.returncode != 1
            or result.stdout
            or result.stderr.strip() != b"RELEASE_CONFORMANCE_REJECTED"
        ):
            raise ValueError("ADMISSION_NEGATIVE_CONTROL_FAILED")
        results.append({"case": case, "exit_code": result.returncode})
    return results
