"""Fixed task invoking the published fake binary's loopback conformance mode."""

import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path
from tempfile import TemporaryFile


def task(intent):
    engine = Path("/tmp/kryvola-fake/engine")
    if hashlib.sha256(engine.read_bytes()).hexdigest() != intent["engine_sha256"]:
        raise ValueError("FAKE_ENGINE_CHANGED")
    with TemporaryFile() as output:
        subprocess.run(
            [str(engine), "conformance"],
            stdout=output,
            stderr=subprocess.DEVNULL,
            check=True,
            timeout=25,
        )
        output.seek(0)
        result = output.read(4097)
    expected = b"FAKE ENGINE loopback conformance passed; no inference or production capability\n"
    if result != expected:
        raise ValueError("FAKE_CONFORMANCE_RESULT")
    return {
        **intent,
        "kind": "PUBLIC_FAKE_ENGINE_SELFTEST",
        "production_ready": False,
        "conformance_stdout_sha256": hashlib.sha256(result).hexdigest(),
    }


def main():
    import ray  # ty: ignore[unresolved-import] - supplied by digest-pinned Ray image

    raw = sys.stdin.buffer.read(1025)
    intent = json.loads(raw)
    if (
        len(raw) > 1024
        or not isinstance(intent, dict)
        or set(intent) != {"intent_digest", "engine_sha256"}
        or not all(isinstance(v, str) and re.fullmatch("[0-9a-f]{64}", v) for v in intent.values())
    ):
        raise ValueError("INVALID_FAKE_TASK")
    ray.init(address="auto", namespace="fake-workflow", log_to_driver=False, logging_level="ERROR")
    try:
        receipt = ray.get(ray.remote(num_cpus=1, max_retries=0)(task).remote(intent), timeout=35)
        print(json.dumps(receipt, sort_keys=True))
    finally:
        ray.shutdown()


if __name__ == "__main__":
    main()
