"""Small synthetic fixtures exercise observations, never crypto feasibility."""

import copy
import json
import sys
import tempfile
import time
import unittest
from pathlib import Path

from jsonschema import ValidationError

from kryvola_platform.benchmark import (
    SPEC,
    _attempt,
    decode,
    quantiles,
    run,
    sha,
    summarize,
    validate,
)


def fixture():
    report = decode(SPEC.joinpath("fixtures/profiles/measurement.json").read_bytes())
    config = {k: report[k] for k in ("hardware", "software", "cache_state")}
    config["software"] = [
        dict(report["software"][0], name=n) for n in ("benchmark-harness", "workload")
    ]
    config.update(
        input_sha256=sha(b""),
        stages=["evaluate", "decode"],
        samples=2,
        warmups=1,
        concurrency=2,
        timeout_seconds=1,
        budget_seconds=5,
    )
    return config, SPEC.joinpath("fixtures/profiles/model.json").read_bytes()


class StatisticsTests(unittest.TestCase):
    def test_nearest_rank_and_sufficiency(self):
        result = quantiles(list(range(1, 101)))
        self.assertEqual(result["values_ns"], {"p50": 50, "p95": 95, "p99": 99})
        self.assertTrue(all(result["descriptive_sample_sufficiency"].values()))
        self.assertIsNone(quantiles([])["values_ns"]["p99"])
        self.assertFalse(quantiles([7])["descriptive_sample_sufficiency"]["p50"])

    def test_failures_remain_in_denominator(self):
        rows = [
            {
                "outcome": "SUCCEEDED",
                "process_ns": 10,
                "local_elapsed_ns": 20,
                "queue_ns": 2,
                "stages_ns": {"evaluate": 4},
            },
            {
                "outcome": "TIMEOUT",
                "process_ns": 100,
                "local_elapsed_ns": 110,
                "queue_ns": 3,
                "stages_ns": None,
            },
            {
                "outcome": "NOT_STARTED_BUDGET",
                "process_ns": None,
                "local_elapsed_ns": 120,
                "queue_ns": 120,
                "stages_ns": None,
            },
        ]
        result = summarize(rows, 10**9, ["evaluate"])
        self.assertEqual((result["requested"], result["failed"]), (3, 2))
        self.assertEqual(result["throughput_microrequests_per_second"], 10**6)
        self.assertEqual(result["process_elapsed"]["samples"], 2)
        self.assertEqual(result["local_submit_to_finish"]["samples"], 3)
        self.assertEqual(result["successful_worker_stages"]["evaluate"]["samples"], 1)
        rows[0]["outcome"] = "EXIT_FAILED"
        self.assertIsNone(
            summarize(rows, 1, ["evaluate"])["successful_worker_stages"]["evaluate"]["values_ns"][
                "p50"
            ]
        )

    def test_metadata_and_bounds(self):
        config, model = fixture()
        validate(config, model, b"")
        for field, value in (
            ("hardware", {}),
            ("software", []),
            ("stages", ["unknown"]),
            ("concurrency", True),
            ("input_sha256", "a" * 64),
            ("samples", 1001),
            ("cache_state", "unknown"),
        ):
            with self.subTest(field=field), self.assertRaises((ValueError, ValidationError)):
                validate({**config, field: value}, model, b"")
        missing = copy.deepcopy(config)
        del missing["hardware"]
        with self.assertRaises(ValueError):
            validate(missing, model, b"")
        with self.assertRaises(ValueError):
            decode(b'{"field":1,"field":2}')


@unittest.skipUnless(sys.platform == "linux", "Linux supervision is exercised on CI")
class SupervisionTests(unittest.TestCase):
    def attempt(self, source):
        config, _ = fixture()
        now = time.monotonic_ns()
        return _attempt([sys.executable, "-c", source], b"", config, 0, now, now + 3 * 10**9)

    def test_partial_failure_and_incomplete_success(self):
        emit = 'print(\'{"stages_ns":{"evaluate":1}}\', flush=True)'
        failure = self.attempt(emit + "; raise SystemExit(2)")
        self.assertEqual(failure["outcome"], "EXIT_FAILED")
        self.assertEqual(failure["stages_ns"], {"evaluate": 1})
        self.assertEqual(self.attempt(emit)["outcome"], "INVALID_TELEMETRY")
        for value in (
            '{"evaluate":true,"decode":1}',
            '{"evaluate":-1,"decode":1}',
            '{"evaluate":1,"decode":1,"unexpected":1}',
        ):
            self.assertEqual(
                self.attempt(f"print('{{\"stages_ns\":{value}}}')")["outcome"], "INVALID_TELEMETRY"
            )

    def test_timeout_output_and_launch_failure(self):
        self.assertEqual(self.attempt("import time; time.sleep(10)")["outcome"], "TIMEOUT")
        self.assertEqual(self.attempt("print('x' * 70000)")["outcome"], "OUTPUT_LIMIT")
        config, _ = fixture()
        now = time.monotonic_ns()
        self.assertEqual(
            _attempt(["/nonexistent"], b"", config, 0, now, now + 10**9)["outcome"], "LAUNCH_FAILED"
        )
        row = _attempt([sys.executable], b"", config, 0, now, now - 1)
        self.assertEqual(row["outcome"], "NOT_STARTED_BUDGET")
        self.assertIsNone(row["process_ns"])

    def test_journal_and_no_overwrite(self):
        config, model = fixture()
        command = [sys.executable, "-c", 'print(\'{"stages_ns":{"evaluate":1,"decode":0}}\')']
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "archive"
            result = run(config, model, b"", command, destination)
            self.assertEqual(result["warmup"]["requested"], 1)
            self.assertEqual(result["measured"]["successful"], 2)
            rows = [
                json.loads(line)
                for line in (destination / "observations.jsonl").read_text().splitlines()
            ]
            self.assertEqual(len(rows), 3)
            self.assertEqual((destination / "model.json").read_bytes(), model)
            self.assertEqual(
                json.loads((destination / "context.json").read_bytes())["model_descriptor_sha256"],
                sha(model),
            )
            with self.assertRaises(FileExistsError):
                run(config, model, b"", command, destination)

    def test_global_budget_and_inherited_pipe_cleanup(self):
        config, model = fixture()
        config.update(samples=4, warmups=0, concurrency=1, budget_seconds=1)
        with tempfile.TemporaryDirectory() as directory:
            result = run(
                config,
                model,
                b"",
                [sys.executable, "-c", "import time; time.sleep(10)"],
                Path(directory) / "budget",
            )
            self.assertEqual(result["measured"]["failed"], 4)
            self.assertGreaterEqual(result["measured"]["outcomes"]["NOT_STARTED_BUDGET"], 1)
        source = (
            'import subprocess,sys; subprocess.Popen([sys.executable,"-c",'
            '"import time; time.sleep(10)"]); '
            'print(\'{"stages_ns":{"evaluate":1,"decode":0}}\', flush=True)'
        )
        self.assertEqual(self.attempt(source)["outcome"], "SUCCEEDED")
