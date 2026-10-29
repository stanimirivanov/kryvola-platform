# FHE-Q1 research campaigns (M0-PR34)

This captures two independently initialized attempts of the same engines research
workflow at `f8023959081fa6a1e8169b41ef427630a5da72f3`. Attempt 1 is the already
completed baseline; attempt 2 is a fresh rerun. Platform imports only bounded,
closed-shape numeric JSON and GitHub job metadata. No crypto implementation,
private key, ciphertext, proof object or restricted executable is copied here.
TFHE/SP1 execution stays in engines' RESEARCH_ONLY CI; distribution/service denials
and legal/parameter review remain unchanged.

## Profile and reproduction

The profile pins source, workflow run/attempts, both experiment lockfiles, dependency
policy, frozen ML fixture lock, proof mode profile and Rust toolchain file. The
native report must bind the exact frozen 100-case ML fixture, TFHE 1.8.1,
Rust 1.98.1 and two Rayon threads; SP1 must bind SDK 6.9.0 and public-only Core mode.
The capture requires completed exact-source native/SP1/aggregate jobs, verifies
source-file SHA-256s through GitHub, extracts executed reports (never configuration
checks), and writes lossless numeric JSON plus metadata/digest manifests. ANSI
build output and complete build logs are discarded; log digests and job IDs remain
for audit. Unexpected report fields, malformed numeric values and changed corpus
bytes reject rather than becoming observations. No capture is overwritten.

The source-bound captures are checked into `evidence/feasibility/fhe-q1/` so the
observations survive Actions log retention. They are reviewed research evidence,
not a signed measurement attestation or production MeasurementReport. GitHub API,
repository/source review and the importing host remain trust assumptions.
A malicious producer/host is outside this numeric import boundary.
The checked-in `summary.json` retains the derived variance alongside the raw
captures; the unit gate requires an exact offline replay and two successful
captures. A missing attempt is still representable as INCONCLUSIVE during analysis,
but cannot silently satisfy this completed campaign's regression gate.

Both [baseline attempt 1](https://github.com/stanimirivanov/kryvola-engines/actions/runs/40863854972/attempts/1)
and [fresh attempt 2](https://github.com/stanimirivanov/kryvola-engines/actions/runs/40863854972/attempts/2)
completed successfully. Their native binaries and frozen statement bindings agree,
while their key contexts differ. Summed circuit evaluation took approximately
78.663 s and 136.590 s; owner totals were 81.314 s and 139.930 s. These are batch
observations on uncontrolled CI hosts, not latency targets. The four separate
Core prove observations were approximately 120.6–121.5 s. Exact integer data,
sample denominators and rational variance remain in the checked-in summary.

```sh
# Read-only replay/analysis of the checked-in numeric captures; no crypto or network:
uv run --locked --extra conformance python tools/benchmark.py run --profile config/benchmarks/fhe-q1.json
# Inspect configuration only, without reading captures or starting services:
uv run --locked --extra conformance python tools/benchmark.py run --profile config/benchmarks/fhe-q1.json --check-only
```

An optional `--output NEW_DIRECTORY` selects a fresh report directory; the default
is a unique ignored `build/campaigns/<id>`. Existing destinations are refused.
Original `run --manifest ... --output ...` workloads remain supported. Analysis
never triggers CI. For a reviewed new source/attempt profile, explicitly rerun the
engines workflow, then import each completed attempt with `--capture-attempt N`.
Capture uses GitHub CLI/read access and must not be confused with local crypto
execution or automatic publication. Profile/source changes require new captures;
never relabel old results or edit timestamps to make them match.

## Interpretation

- TFHE stages retain key generation, owner encoding/encryption and decryption,
  process dispatch, native decoding/encoding and evaluation-key expansion. Owner
  total and dispatch have enforced accounting relationships. Each attempt has one
  new key context and 100 correlated public two-input/two-output uint8 cases; the
  key contexts and workflow job IDs must differ across attempts. Program, parameter
  and fixture bindings must agree. Ciphertext hashes can differ with fresh encryption.
- Per-case nearest-rank quantiles are descriptive within each key context. They
  are not 100 independent campaigns, confidence bounds or an end-to-end SLO.
  The summed case-evaluation time is derived from those 100 observations and is
  already included in dispatch; it must not be added to dispatch a second time.
  Between-attempt variance uses exact rational sample variance (ddof=1, two
  observations); units are ns squared for durations. Proof-byte variance is bytes
  squared. Different binaries/hosts are recorded and prevent qualification claims.
- Serialized input/output expansion compares envelopes against the 200 logical
  uint8 values per batch. Actual owner/evaluator peak RSS is separate from
  reservation estimates. Neither proves a hard allocator budget or noise margin.
- Compact PKE validity proof timings/sizes belong to their two-value experiment.
  Separate SP1 Core samples prove only the fixed public-metadata relation. Core is
  not assumed zero knowledge. Prove/verify/total and local FIFO queue accounting
  remain distinct; total includes experiment setup/checks and is not service latency.
  Compilation is outside the producer's measured native windows. No FHE evaluation
  proof, private-witness export or disabled recursion/SNARK mode is enabled.
- Missing key upload, authorized key-cache misses, actual crypto transport and
  owner-to-owner latency are explicit nulls with reasons. Fake orchestration timings
  and the separate HTTP network fixture are not spliced into a crypto latency.
  PBS/GPU counters remain unavailable; proof RSS and monetary billing are unknown.
- Requested/failed/incomplete campaigns remain in the denominator. Missing capture
  or insufficient owner/proof samples yields INCONCLUSIVE, with no numeric zero
  substituted. Invalid source/hash/accounting/statement bindings reject. Production
  and profile flags remain false even when native correctness succeeds.

The canonical full gate replays the corpus/statistics and existing platform checks
on CI. Unit tests cover exact variance, sample insufficiency, failure accounting,
configuration-only output, cache/proof mismatches, NaN/noninteger data, duplicate
reports, tampering and CLI separation. No heavy work runs on the desktop.

The implementation reuses the existing M0-PR25 nearest-rank/statistics convention,
[GitHub run-attempt metadata](https://docs.github.com/en/rest/actions/workflow-runs)
and Python's exact rational arithmetic for the
[sample-variance convention](https://github.com/python/cpython/blob/main/Doc/library/statistics.rst).
These standard-library/CLI adapters add no Python/crypto dependency. This is an
internal research harness, not a new public protocol or contract authority.
