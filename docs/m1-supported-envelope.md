# M1 supported envelope

The versioned [measured snapshot](../evidence/m1-supported-envelope.json) reports
the locked local Compose path for the frozen FHE-Q1 unsigned-byte pair circuit.
Its supported scope is **asynchronous local development, serial requests, fresh
owner keys**. It does not activate `config/foundation.json` or qualify production.
Correctness means equality with that circuit's frozen reference; assurance remains
`CONFIDENTIALITY_ONLY`, with cryptographic computation integrity `UNPROVEN`.

Reproduce after the existing M1 installation, from clean committed source:

```sh
uv run --locked python -m tools.m1_envelope measure build/m1-supported-envelope.json --pairs 2
uv run --locked python -m tools.m1_envelope check build/m1-supported-envelope.json
uv run --locked python -m tools.m1_envelope check evidence/m1-supported-envelope.json
```

Measurement runs real published-artifact owner-to-owner requests and preserves
R2's twelve-volume storage headroom. Each fresh stack contributes one COLD and
one WARM_SERVICES request. Neither label claims a flushed OS/image cache or a warm
key cache. Request nanoseconds exclude setup, audits and telemetry; serial campaign
throughput includes those costs. Stage distributions describe request boundaries,
not isolated native CPU stages. Memory is container-lifetime cgroup peak including
tmpfs; byte counts are serialized artifacts rather than network traffic.

Reports separate **measured**, **unsupported**, **inconclusive** and **externally
unapproved** results. p95 needs twenty successful samples per state. Fewer samples
remain inconclusive even when their observed quantile is fast. Objectives are
15 seconds cold and 5 seconds warm; measured misses retain asynchronous-only scope.
Any failed/unrun request makes the envelope inconclusive and the CLI gate fail.
Unknown key-cache behavior and native/wire measurements stay visible as gaps.
Production activation remains externally unapproved; existing owner approval for
development distribution is preserved without adding independent-reviewer rules.

The M1 CI job checks this snapshot, runs a fresh one-pair campaign, and uploads its
report with embedded observations. Passing that gate proves completeness and the
observed local functional path, not latency/SLO success. It retains failure records
before exiting nonzero. Checks recompute summaries and decisions, reject duplicate
requests or missing stages, bind exact release/profile/reference/policy/harness
bytes, and require the exact committed harness contents. These are reproducibility checks
on controlled runner evidence, not an independent signature or integrity proof.

To refresh the committed snapshot after a harness or release change, commit the
new source first, measure to `build/`, then copy the resulting JSON to
`evidence/m1-supported-envelope.json` and commit it. The producer SHA is retained
as provenance; committed harness contents, rather than feature-commit ancestry,
must match so the check survives squash/rebase merges. R3's current
snapshot sample counts and conclusions are in the JSON; no p95 success is implied.
