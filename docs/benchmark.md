# Local benchmark observations (M0-PR25)

`uv run --locked python tools/benchmark.py self-test` runs a tiny synthetic Linux
workload; `uv run --locked python tools/verify.py full` runs this plus the unit
suite on CI. Windows supports metadata/statistics tests and fast checks; execution
requires Linux process groups and selectable pipes. No dependencies are added.

Run a trusted public workload using
`uv run --locked python tools/benchmark.py run --manifest job.json --output run-001`.
The operator supplies `job.json` (private harness configuration, not a product wire
contract), with exactly `context`, `model`, `input`, `command`. `model` and `input`
are paths relative to the manifest; `command` is an argument array starting with
an absolute executable path. All arguments, paths, descriptors and metadata must
be public. The runner supplies input bytes on stdin, starts each request in a
fresh temporary directory, discards stderr and retains only validated numeric
stdout telemetry. It executes no shell. Script/data arguments must be absolute.
The isolated environment contains only PATH (`os.defpath`), HOME and TMPDIR;
explicit flags must select workload thread counts/devices.

`context` requires exactly these fields:

| Field | Meaning / bound |
|---|---|
| `hardware`, `software`, `cache_state` | Generated MeasurementReport metadata schemas; unique software names including `benchmark-harness` and `workload` pins; COLD or WARM cache state |
| `input_sha256` | SHA-256 of exact stdin bytes, checked before execution; at most 128 KiB |
| `stages` | Nonempty distinct subset of generated latency stage names |
| `samples`, `warmups`, `concurrency` | Integers 1–1000, 0–100, 1–8 |
| `timeout_seconds`, `budget_seconds` | Integers 1–300 per request and 1–600 for warmups plus measured requests |

The model must validate against the pinned generated ModelDescriptor schema.
Hardware, software/source pins and cache state are operator claims, not attested
facts. Fresh processes do not flush OS/device caches or establish warm engines;
workload adapters must document their cache semantics. The archive adds actual
executable, input, model-descriptor and spec-manifest hashes; software pins must
cover scripts, libraries, datasets and toolchains used by the workload. Mutable
files must remain unchanged during a trusted run.

Each subprocess writes exactly one UTF-8 JSON object, for example
`{"stages_ns":{"decode":120,"evaluate":800}}`. Values are nonnegative integer
nanoseconds no larger than parent-observed process elapsed time. Duplicate fields,
unknown stages and extra fields are rejected; success requires every declared
stage. A nonzero exit may retain a valid partial stage map. Stdout is capped at
64 KiB. Timeouts/output excess kill the owned process group. This is supervision,
not an OS sandbox: memory/CPU/disk isolation, network shaping and cost/resource
accounting belong to M0-PR26 and later qualification. Processes escaping their
session are outside this trusted workload boundary. Run without credentials,
private inputs or keys.

The destination must be new. It contains exact `model.json`, `context.json`, a
flushed `observations.jsonl` journal (one record per completed attempt) and final
`summary.json`. An interrupted run without a summary is incomplete. Warmups have
separate rows/statistics and consume the overall budget. Requests missing that
budget become `NOT_STARTED_BUDGET`, with null process timing. Failed exits,
timeouts, output excess, invalid telemetry and launch failures are explicit
outcomes; the CLI returns nonzero if any measured request fails.

Quantiles use nearest rank, `ceil(p*n/100)`. Every group includes sample counts and
descriptive sufficiency thresholds (p50: 2, p95: 20, p99: 100), not confidence
intervals. Empty groups have null quantiles. Local queue and submit-to-finish
distributions include failures; process timing includes started attempts. Worker
stage statistics explicitly use successful requests only. Throughput is successful
requests / the entire measured wall interval, including failures, queueing and
cleanup; warmup time is separate. Local timing includes process startup. No stage
sums or successful-only measurements represent total service latency. Missing
network/resource/cost metrics remain absent.

This journal is **not a qualified MeasurementReport**, release admission, crypto
evidence or an enabled profile. Complete report generation and real model/engine
qualification require subsequent workload and feasibility PRs.
