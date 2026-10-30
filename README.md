# kryvola-platform

[M0 acceptance audits](docs/m0-acceptance.md) retain exact source/artifact evidence
and mandatory blockers. The current result is BLOCKED; audit success does not
approve M0, M1 or production.

Python platform inventory and qualification harness. This is an initial M0 foundation, with no production execution or security qualification. Existing Apache-2.0 licensing is preserved.

## Setup and verification

Prerequisites: Python 3.14.7 and uv 0.12.5. Python is pinned in `.python-version`; Rust is pinned in `rust-toolchain.toml` where applicable. Run from this repository root:

```sh
uv sync --locked
uv run --locked python tools/verify.py fast
uv run --locked python tools/install_cosign.py
uv run --locked python tools/verify.py full
uv run --locked python -m kryvola_platform config/foundation.json
```

`fast` runs formatting/lint/type/provenance/dependency and offline fixture checks. `full` adds isolated positive/negative controls, contract tests, a wheel build and the [local Docker service qualification](docs/local-services.md). Missing tools or files fail the command. Apply Python formatting with `uv run --locked ruff format .` and lint fixes with `uv run --locked ruff check --fix .`; rerun affected checks after changes.

Fast checks need no service credentials or databases; full checks create isolated local fixtures with fresh test credentials and tear them down. `spec.lock.json` pins immutable generated spec artifacts; a sibling checkout is unnecessary. Generated structural types are not native decoders or authorization. [Architecture and enforcement](docs/architecture.md), [progress](docs/progress.md), and the source references below describe limits.

## M0 release-set inputs

`release_set.validate_release_set` and `inventory.validate_release_inventory`
admit local integration inputs against independently supplied `ReleasePolicy`,
`ComponentPolicy` and checksum-pinned `Cosign` configuration. The separately
versioned spec preview.10 `ReleaseCandidate` format is used; the foundation API
and `config/foundation.json` remain disabled. `config/release-candidate.json` is
an unresolved synthetic **rejection example**, with no default trust keys.

The [release-set boundary](docs/release-set.md) specifies signing mode, provenance
fields, artifact references, limits and remaining qualification work. Full checks
install the pinned standalone verifier explicitly and exercise real signatures
with ephemeral test keys. Keep the full build/signature gate on CI when local
resources are busy; focused tests intentionally skip that integration case.

## Authoritative context

M0-PR26 adds [shaped transfer/resource observations](docs/network-benchmark.md).
`uv run --locked python tools/benchmark.py network-check --check-only` is offline;
the full command and full harness qualify fresh local fixtures, run actual
latency/bandwidth/disconnect cases and tear down their owned stack.

- [Design v2](https://github.com/stanimirivanov/kryvola-spec/blob/647986b9ba9cb2c6d3b853046272e3869b6fea5e/docs/kryvola-design-v2.md)
- [Implementation plan v2](https://github.com/stanimirivanov/kryvola-spec/blob/647986b9ba9cb2c6d3b853046272e3869b6fea5e/docs/kryvola-implementation-plan-v2.md)
- [Schema-stack amendment](https://github.com/stanimirivanov/kryvola-spec/blob/647986b9ba9cb2c6d3b853046272e3869b6fea5e/docs/adr/0001-schema-authoring.md): Redocly for OpenAPI; Effect v4 / TypeScript 7 author other contracts. Generated JSON/native structural projections keep this repository's approved runtime intact.

Platform composes released artifacts from the other repositories; it does not own their cryptographic implementations. Unqualified profiles remain disabled. Kubernetes/Ray/broker identities cannot hold private decryption keys. No cloud, service or secret is provisioned by foundation checks.

The [local benchmark runner](docs/benchmark.md) collects bounded subprocess
observations and descriptive statistics. It does not qualify a MeasurementReport
or enable a cryptographic profile. Heavy verification runs on CI.

Next planned work: KRY-006 resource/network controls and real workload benchmarks,
followed by KRY-010 the fake-engine local stack once prerequisites are satisfied.

M0-PR31 adds the [published public fake workflow](docs/fake-workflow.md).
Install Cosign, run `uv run --locked python tools/workflow_assets.py install`, then
`uv sync --locked --extra conformance` before the full gate. Full checks use
`uv run --locked --extra conformance python tools/verify.py full`; fast checks
still start no services. The standalone traversal is `tools/integration.py smoke`.

The [M0-PR32 conformance gate](docs/release-conformance.md) additionally needs
`uv run --locked --extra conformance python tools/release_conformance.py fetch`
after setup. Full checks now finish with `tools/integration.py ci`, which runs
admission/negative controls and the existing live checks in one owned stack.

M0-PR33 adds the [local isolation gate](docs/isolation.md), including a fourth
internal owner network and synthetic non-key canary. Full checks run it on the
same owned stack; `tools/integration.py isolation` provides the standalone gate.
Linux full runs require a non-root host UID/GID; development IDs are not production
workload identities. Only public isolation reports are retained.

The [M0-PR34 research campaign harness](docs/campaigns.md) replays pinned numeric
engine observations with `tools/benchmark.py run --profile config/benchmarks/fhe-q1.json`.
Full CI validates the captures and existing live gates; fast profile checks
provision nothing. Research evidence remains inconclusive for production latency.
