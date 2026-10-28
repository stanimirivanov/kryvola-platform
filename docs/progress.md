# Foundation progress

## M0-PR25 — reproducible local observations

Issue: #5. Adds the bounded Linux subprocess benchmark runner, spec-validated
metadata, raw attempt journal, separate warmup/measured statistics, explicit
failures and descriptive sample sufficiency. No crypto profile is qualified.
Formatting/lint fixes, fast checks and focused metadata/statistics tests run
locally; Linux supervision, the synthetic self-test and full signature/build
checks run on CI. These CI checks are configured, not claimed to have passed.
Resource/network controls and real workload feasibility remain pending.

## M0-PR17 — immutable integration inputs

Issue: #3. Consumes generated spec preview.10 at
`1a5b57a590487ba116913050af8041f5e5f1fb52` and adds a separate release-set validator.
It checks exact component/artifact/schema/source bindings, selected signing keys,
builder/provenance identity, model/report consistency and reviewed legal scope.
The existing foundation inventory remains disabled; the checked-in synthetic
release candidate remains unresolved and cannot be admitted.

Local policy tests and fast formatting/lint/type/provenance checks are observed
separately from real cryptographic acceptance: the real Cosign signed fixture,
wrong-key/changed-byte negatives and wheel build are mandatory full CI checks.
Observed locally: fast checks and 12 tests passed; the signature integration test
was skipped locally and its CI result has not been observed.
No real published artifacts, SBOMs, crypto qualification, service deployment or
production profile activation is claimed. PR24/32 retain publication qualification.

## Initial scaffold

Issue: #1. Scope: initial M0 repository scaffold, 25 October 2026.

- Implemented: python platform inventory and qualification harness, versioned spec consumption, isolated architecture controls and diagnostics.
- Verified locally: frozen setup, full foundation checks, isolated negative controls, package/native builds and diagnostics.
- Configured but unverified remotely: the GitHub Actions workflow; branch protection/required checks remain maintainer configuration.
- Not claimed: complete M0 acceptance, full Engine API interoperability, cryptographic feasibility, latency measurements, independent security review or deployment.
- Deferred: later roadmap runtime/crypto features. A disabled capability is an explicit incomplete milestone, not an alternate implementation.
- Next: KRY-006 reproducible benchmark harness, followed by KRY-010 the fake-engine local stack once contract prerequisites are satisfied.

The authoritative [plan](https://github.com/stanimirivanov/kryvola-spec/blob/647986b9ba9cb2c6d3b853046272e3869b6fea5e/docs/kryvola-implementation-plan-v2.md) remains in force. Review and update only the affected roadmap evidence; no later milestone is marked complete by this scaffold.

## Observed acceptance evidence

On Windows with Python 3.14.7 / uv 0.12.5, `uv run --locked python tools/verify.py full` passed: Ruff formatting/lint, ty type checks, spec provenance and dependency checks, 7 Python tests, and disabled/unqualified inventory validation and Python wheel build.

A new disposable environment passed `uv sync --locked --no-editable`. The installed wheel loaded from that environment rather than the source checkout, and its packaged data/diagnostic worked. Diagnostics: `uv run --locked python -m kryvola_platform config/foundation.json`.

Root AGENTS.md discovery through nested working directories and local documentation links were checked. Existing LICENSE bytes are unchanged. Schema source commit and manifest digests are recorded in `spec.lock.json`; no sibling checkout is required.

Blocked foundation work: none. Deferred roadmap items and remote CI/maintainer settings above remain explicit; this evidence does not qualify a production crypto engine, state machine or deployment.

Final harness-only normalization of package names and direct local URI dependencies was verified with Ruff, ty and the Python suite. Native code and package runtime content were unchanged after their passing build/clean-install checks.
