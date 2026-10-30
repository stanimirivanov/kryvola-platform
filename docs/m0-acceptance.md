# Detached M0 acceptance audit (M0-PR37)

The current result is **BLOCKED**, not accepted. Spec PR36 explicitly preserves
pending named sign-offs; a signed tested five-component release candidate, scoped
legal/parameter approval and ML/platform release artifacts remain unsubmitted.
Two signed experimental packages and successful fake/isolation fixtures cannot
fill those gaps. Production/profile activation and M1 admission remain false.

The checked-in `config/m0-acceptance.json` pins immutable ratification, crypto-review
and public ML fixture metadata. Imported files in `evidence/m0/` are evidence, not
foreign implementation code or public contract definitions. Existing contract
provenance and campaign validators check the consumed preview.10 bundle and real
numeric campaigns. No new dependency, wire schema, approval key or permission is added.

```sh
# Offline input consistency only; no acceptance or artifact generation:
uv run --locked --extra conformance python tools/m0_acceptance.py --check
# On a clean committed checkout, emit a detached BLOCKED bundle and exit 1:
uv run --locked --extra conformance python tools/m0_acceptance.py
# Explicit evidence audit, not acceptance; valid BLOCKED evidence exits 0:
uv run --locked --extra conformance python tools/m0_acceptance.py --audit-only
```

Each generation creates a fresh ignored `build/m0/<id>/` directory. `lock.json`
records all five exact source identities, contract manifest/fixture identities,
review revisions, expected published package subjects, actual live image identities
when available, source/tool/input hashes and live-report digests. Its kind is
`M0_EVIDENCE_INVENTORY_NOT_ACCEPTED_RELEASE_SET`: ML has a public fixture manifest,
platform a tested driver source, and neither is relabelled a signed release artifact.
Package signatures are only described as checked by the live fixture gate when
that gate's current-run reports are present. No-live audits explicitly lack that check.

`report.json` retains mandatory blockers separately from optional GPU/alternative
proof exclusions. Unmeasured latency or memory is never zero. The platform commit
is resolved from Git at execution time, with dirty/untracked source rejected, so
the checked-in policy never needs its own future commit hash. The manifest binds
the exact lock/report bytes; `--verify DIRECTORY` detects corruption and exits 1
for BLOCKED status, while adding `--audit-only` returns 0 for a valid blocked audit.
No output directory is overwritten. Missing/corrupt inputs, stale source or invalid
live controls exit 2 and do not become a successful audit.

Full checks retain the existing package-signature, conformance-negative, native
fake/replay, network/image and isolation gates. The owned `integration.py ci` path
passes its exact report directory to the audit only after all gates and cleanup
succeed; it never selects the newest directory by glob. `--live DIRECTORY` is
restricted to owned `build/integration` output and binds all report source IDs,
package subjects, image identities and required controls. Tests cover stale source,
false production/composition claims, incomplete negatives, isolation failure and
cleanup-before-emission. Standalone network checks retain their previous behavior.

CI uploads the detached bundle alongside the public live reports. Live digests use
paths relative to `build/`, matching that artifact layout. These are host/CI-trusted
research observations and integrity checks, not signed attestations, independent
security review or authenticated human approval. `--audit-only` is not a green M0
acceptance gate. The current evidence profile deliberately has no success promotion
path; future acceptance requires reviewed inputs, authentic sign-offs and the
existing independently configured signed admission in `release_set.py`.

Do not publish this inventory as a spec ReleaseCandidate or replace the synthetic
`config/release-candidate.json` contract example with it. No accepted artifact is
emitted while mandatory evidence is absent. Retained CI artifacts have seven-day
retention, so download/archive them for review; this is not durable release storage.
Withdrawal/supersession must produce a new disposition referencing the previous
bundle digest rather than editing an earlier bundle. No release tag, deployment
or production publication occurs. M0 remains open until actual ratification and
complete composition acceptance are supplied.

[Review evidence authentication](review-evidence.md) supplies a separate local
input verifier with independently configured reviewer keys and exact subject/use
pins. No actual reviewer authority or approval has been supplied. Its result does
not change this audit's mandatory blockers or add an M0 acceptance path.

[Unsigned candidate assembly](m0-candidate.md) resolves independently selected
published inputs into a separate candidate and detached lock. It leaves legal
and ratification pending and composition untested; this audit remains blocked.

## Explicit acceptance evaluation (M0-CLOSE-PR12)

The historical audit, its pinned pending inputs and BLOCKED bundles are unchanged.
A separate `--evaluate` path can assess actual supplied approvals and tested
composition evidence. No default policy, keys, ratification or approval is seeded.
The current pending inputs still cannot satisfy this path. It emits an evaluation
JSON to stdout only; signed final publication remains PR13 work.

```sh
uv run --locked --extra conformance python tools/m0_acceptance.py --evaluate REQUEST_DIRECTORY --assets VERIFIED_ASSETS --policy OPERATOR_POLICY
```

Do not combine evaluation with audit/generation/verify flags. Failure exits 2;
no output artifact or acceptance state is written. An accepted result permits
M1 development under the reviewed non-production scope only. It always retains
production_ready=false, profile_enabled=false and deployment_authorized=false.
It is an evaluation over explicitly trusted inputs, not a reusable deployment token.

REQUEST_DIRECTORY contains the unmodified PR10 composition directory plus:
ratification.json, review-packet.json, legal.json, admitted-candidate.json,
admitted-candidate.sigstore.json, and reviews/ROLE-SLUG.json/.sigstore.json as in
review-evidence.md. The PR10 report and every retained input/report hash must pass;
the candidate is reassembled from publisher inputs and its original pending lock
must match. Source, package/image, negative-control, isolation and cleanup predicates
are checked again. Current independently pinned driver configuration must match;
this evaluator cannot qualify arbitrary incompatible or stale driver profiles.

The operator policy supplies composition_sha256, ratification_sha256,
selection_sha256, ratification_revision, review_trust and release_policy. The
review_trust is the independent enrollment/freshness/revocation policy documented
in review-evidence.md. release_policy supplies candidate_sha256, intended_use,
reviewer_key (PEM) and five components, each with reference, builder_id, build_type,
source, manifest_sha256 and subject. These trust choices must not be constructed
from incoming evidence. Intended use must agree with authenticated role decisions.

The new ratification payload is a local administrative JSON successor with exactly:
version=1, status=RATIFIED_FOR_M0_NONPRODUCTION, scope (the closure scope),
contract_revision, candidate_sha256 (tested unsigned candidate), composition_sha256
(PR10 report), exclusions and empty conditions. It must be independently pinned
and approved by all eight roles. It is not a reinterpretation of the pending spec
Markdown record; preserve that history and obtain an explicit actual successor.

The review packet uses the existing PR8 shape. Its composition digest and exclusions
must match the ratification. candidate_digests must bind candidate.json,
admitted-candidate.json, selection.json, model.json, measurement.json,
ratification.json, composition-report.json, legal.json and generated/manifest.json.
Additional reviewed ownership/native/evidence subjects may be included. All eight
current authenticated decisions must be unconditional APPROVE. Conditions,
withdrawals, expiry, missing roles or stale subjects block acceptance.

legal.json has version=1, disposition=REVIEWED_ALLOWED_NONPRODUCTION_FAKE_ONLY,
intended_use, parameter_set_digest, parameter_security=APPROVED_RESEARCH_BASELINE_ONLY,
crypto_permissions=DISTRIBUTION_SERVICE_DENIED and empty conditions. This summary
is bound into the packet signed by the legal/security/other reviewers; it does not
grant TFHE/SP1 distribution/service rights or production parameter approval.
The admitted candidate may differ from the tested unsigned candidate only in its
ratification revision and scoped reviewed legal evidence reference. Existing signed
release-set admission checks its independent reviewer signature and all publishers.

To avoid circular hashes: first fix tested candidate/report, legal summary and
ratification bytes; then admitted candidate bytes; then the review packet; then
reviewer decisions/signatures. None contains its own future hash. Do not use a
signed decision's hash as legal.json's hash or put packet hashes into the ratification.
Policy pins and signatures remain separate. Evidence authenticity does not establish
reviewer expertise; offline withdrawal/freshness limits remain those of PR8.

[Guarded acceptance publication](m0-publication.md) describes the disabled-by-default
manual workflow and re-evaluation of downloaded signed evidence. Publication still
requires supplied approvals and independent operator enablement; none is inferred
from this evaluator or a merge.
