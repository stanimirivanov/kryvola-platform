"""Run trusted public Linux benchmark workloads or the small supervision self-test."""

import argparse
import sys
import tempfile
from pathlib import Path

from kryvola_platform.benchmark import SPEC, decode, quantiles, read, run, sha


def self_test() -> None:
    assert quantiles(list(range(1, 101)))["values_ns"] == {"p50": 50, "p95": 95, "p99": 99}
    report = decode(SPEC.joinpath("fixtures/profiles/measurement.json").read_bytes())
    context = {k: report[k] for k in ("hardware", "software", "cache_state")}
    context["software"] = [
        dict(report["software"][0], name=n) for n in ("benchmark-harness", "workload")
    ]
    context.update(
        input_sha256=sha(b""),
        stages=["evaluate"],
        samples=2,
        warmups=1,
        concurrency=2,
        timeout_seconds=2,
        budget_seconds=10,
    )
    with tempfile.TemporaryDirectory() as directory:
        result = run(
            context,
            SPEC.joinpath("fixtures/profiles/model.json").read_bytes(),
            b"",
            [sys.executable, "-c", 'print(\'{"stages_ns":{"evaluate":1}}\')'],
            Path(directory) / "run",
        )
        assert result["measured"]["successful"] == 2
    print("Synthetic benchmark self-test passed; no crypto or service qualification.")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["self-test", "run"])
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.action == "self-test":
        self_test()
    else:
        if args.manifest is None or args.output is None:
            parser.error("run requires --manifest and --output")
        job = decode(read(args.manifest))
        if set(job) != {"context", "model", "input", "command"}:
            parser.error("manifest requires exactly context, model, input, command")
        base = args.manifest.resolve().parent
        result = run(
            job["context"],
            read(base / job["model"]),
            read(base / job["input"]),
            job["command"],
            args.output,
        )
        if result["measured"]["failed"]:
            raise SystemExit(1)


if __name__ == "__main__":
    main()
