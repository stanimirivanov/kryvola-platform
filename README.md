# kryvola-platform

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

`fast` runs formatting/lint/type/provenance/dependency checks. `full` adds isolated positive/negative controls, contract tests and a wheel build. Missing tools or files fail the command. Apply Python formatting with `uv run --locked ruff format .` and lint fixes with `uv run --locked ruff check --fix .`; rerun affected checks after changes.

No service credentials or local databases are required for this scope. `spec.lock.json` pins immutable generated spec artifacts; a sibling checkout is unnecessary. Generated structural types are not native decoders or authorization. [Architecture and enforcement](docs/architecture.md), [progress](docs/progress.md), and the source references below describe limits.

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

- [Design v2](https://github.com/stanimirivanov/kryvola-spec/blob/647986b9ba9cb2c6d3b853046272e3869b6fea5e/docs/kryvola-design-v2.md)
- [Implementation plan v2](https://github.com/stanimirivanov/kryvola-spec/blob/647986b9ba9cb2c6d3b853046272e3869b6fea5e/docs/kryvola-implementation-plan-v2.md)
- [Schema-stack amendment](https://github.com/stanimirivanov/kryvola-spec/blob/647986b9ba9cb2c6d3b853046272e3869b6fea5e/docs/adr/0001-schema-authoring.md): Redocly for OpenAPI; Effect v4 / TypeScript 7 author other contracts. Generated JSON/native structural projections keep this repository's approved runtime intact.

Platform composes released artifacts from the other repositories; it does not own their cryptographic implementations. Unqualified profiles remain disabled. Kubernetes/Ray/broker identities cannot hold private decryption keys. No cloud, service or secret is provisioned by foundation checks.

The [local benchmark runner](docs/benchmark.md) collects bounded subprocess
observations and descriptive statistics. It does not qualify a MeasurementReport
or enable a cryptographic profile. Heavy verification runs on CI.

Next planned work: KRY-006 resource/network controls and real workload benchmarks,
followed by KRY-010 the fake-engine local stack once prerequisites are satisfied.
