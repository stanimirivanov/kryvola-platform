# Foundation progress

## M0-PR37 — detached acceptance audits

Issue #19 adds the [M0 acceptance audit](m0-acceptance.md), immutable upstream
review/fixture pins and a detached five-source evidence inventory generated from
the tested platform commit. Full checks emit it only after the existing owned
live conformance/isolation gates and cleanup. The default acceptance command fails
for current mandatory gaps; explicit audit mode only verifies a blocked record.
Negative controls cover changed evidence, stale/false live claims, missing
controls, output tampering and cleanup order. No synthetic candidate is promoted.

Result: BLOCKED. Ratification sign-offs, scoped legal/parameter approval and a
signed tested five-component release set (including ML/platform artifacts) remain
missing. Optional exclusions stay separate. M0/M1 acceptance and production remain
disabled; a merged implementation PR cannot supply specialist approval. Local
checks and full pre-PR CI/artifact evidence are recorded in the PR.

## M0-PR26 — shaped transfer/resource observations

Issue #9 adds pinned synthetic LAN/WAN profiles, a bounded public HTTP fixture,
actual Toxiproxy delay/bandwidth/disconnect/retry cases and raw chunk/queue/stage
observations. Process peaks, cgroup and Docker memory methods remain distinct;
unknown metrics/failed bytes remain explicit. Crypto expansion, owner work and
key-cache behavior are not applicable. An illustrative rate card preserves failed
attempts and incomplete cost coverage. Full branch CI must pass before opening
the PR; evidence is recorded there. No network capacity or private inference
qualification follows from this local journal.

## M0-PR29 — isolated local service fixtures

Issue #7 adds digest-pinned PostgreSQL, SeaweedFS, Redpanda, Temporal, Ray and
Toxiproxy fixtures, separate internal networks, fresh SQL/S3 identities and no
published ports or compute mounts. Full checks require real service operations,
S3 version/range/conditional/race behavior, container recreation, restarts and
scoped cleanup. Offline tests cover isolation, lifecycle, output/deadline and
credential-redaction controls. Actual integration evidence is recorded in the PR
after branch CI passes; configuration alone is not qualification. No production
profile, crypto release, workflow behavior or network benchmark is enabled.

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

A new disposable environment passed `uv sync --locked --no-editable`. The installed wheel loaded from that environment rather than the source checkout, and its packaged data/diagnostic worked. Diagnostics: `uv run --locked python -m kryvola_platform config/foundation.json`.

Root AGENTS.md discovery through nested working directories and local documentation links were checked. Existing LICENSE bytes are unchanged. Schema source commit and manifest digests are recorded in `spec.lock.json`; no sibling checkout is required.

Blocked foundation work: none. Deferred roadmap items and remote CI/maintainer settings above remain explicit; this evidence does not qualify a production crypto engine, state machine or deployment.

Final harness-only normalization of package names and direct local URI dependencies was verified with Ruff, ty and the Python suite. Native code and package runtime content were unchanged after their passing build/clean-install checks.

## M0-PR31 — published fake workflow

Issue #11 composes the approved published fabric wheel and fake-engine archive
through Redpanda, Temporal and Ray, with version/hash-checked public trigger and
receipt artifacts, actual history replay, and separate SQL harness evidence.
The [scope and gates](fake-workflow.md) explicitly identify the native binary's
loopback self-test and unresolved external dispatch/crypto/registry work. No
production profile or release-set qualification is enabled.

Observed locally: both publishers succeeded; actual keyless manifest verification,
asset/source/spec pins, formatting/lint/types and 38 Python tests passed (five
Linux/full-signature checks deferred to CI). Full service traversal and final
pre-PR CI evidence are recorded in the PR. No local services were started.

## M0-PR32 — experimental release-set conformance

Issue #13 adds the explicit [conformance gate](release-conformance.md): exact
upstream spec attempt/job evidence, admitted installed package bytes/UV pins,
ten separate CLI rejection probes, actual native fake/replay checks and runtime
image content identities. Full checks share one owned stack. The workflow moves
to integration.yml with the existing foundation/verify identity and triggers.
Five-component candidate admission and production qualification remain separate;
the report explicitly records NOT_SUBMITTED and production_ready=false.

Observed locally: actual upstream metadata and package signatures admitted;
all ten CLI probes rejected; formatting/lint/types and 44 Python tests passed
(five Linux/full-signature checks deferred to CI). Full live pre-PR verification
and retained evidence are recorded in the PR. No local Docker stack was started.

## M0-PR33 — local owner/compute separation

Issue #15 adds a non-root owner fixture on a fourth internal network, a generated
synthetic non-key canary mounted only there, positive-controlled raw-IP denial
probes, actual actor file/configuration checks and raw/encoded leakage scans over
actual broker records, Temporal history and service logs. Normal/failure teardown
removes the canary and namespace helpers. [Scope and gates](isolation.md) explicitly
limit these development identities and tests; no actual owner key or production
security qualification is introduced.

Observed locally: formatting/lint/types and offline controls passed. The full
pre-PR CI result and retained isolation report are recorded in the PR. No local
Docker services or heavy native builds were started.

## M0-PR34 — fixed-source research campaigns

Issue #17 adds the pinned [FHE-Q1 campaign harness](campaigns.md) and numeric
captures from two independent engine workflow attempts, preserving research-only
execution in the owning repository and all crypto distribution/service denials.
The adapter validates source/lock/fixture and numeric/proof accounting, retains
raw observations and failures, and computes exact descriptive variance separately
for native FHE, compact validity and public-metadata Core proof experiments.
Missing transport/cache/end-to-end stages and sparse owner/proof samples remain
explicitly INCONCLUSIVE; production/profile flags stay false.

Observed: both complete engines workflow attempts passed; two fresh key contexts,
200 correlated circuit observations and four separate Core samples are captured.
The checked-in summary replays exactly, retaining all missing-stage reasons and
INCONCLUSIVE qualification. The final pre-PR platform CI result is recorded in the PR.
No crypto binary, owner key, ciphertext or proof object is imported into platform.
