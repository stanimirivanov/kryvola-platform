# Guarded M0 acceptance publication

M0-CLOSE-PR13 supplies publication infrastructure only. Actual approvals remain
pending; no acceptance payload is generated from current pending inputs, and no
workflow is dispatched by this change. Historical BLOCKED audit behavior remains.

## Before any publication

Obtain the actual reviewed successor, eight authenticated unconditional decisions,
scoped legal/parameter disposition, exact tested composition and signed candidate
required by m0-acceptance.md. Independently configure current operator trust; never
use policy/key material supplied by the request artifact itself. Only public
review summaries and evidence may be staged: redact confidential material before
review/signing, never rewrite signed bytes afterwards. No real keys/approvals or
trust defaults are checked into this repository.

Preparation requires the clean committed publication checkout and explicit inputs:

```sh
uv run --locked --extra conformance python tools/m0_publication.py prepare --request REQUEST --assets VERIFIED_ASSETS --policy OPERATOR_POLICY --source FULL_PUBLICATION_SHA --folder FRESH_OUTPUT
```

The existing evaluator runs over an allowlisted snapshot before any output is
created. Only successful authenticated evaluation permits acceptance.json and
evidence.tar to be written. These remain unsigned local preparation until the
manual publisher signs them. Payloads bind exact policy bytes, original approved
review/ratification/candidate/report evidence and publication source. The archive
uses bounded regular files only; extra keys, logs and arbitrary request files are
excluded. Interrupted writes require inspection and a fresh output, not overwrite.

## Manual workflow remains disabled by default

A maintainer must explicitly configure M0_ACCEPTANCE_PUBLICATION_ENABLED=true and
M0_ACCEPTANCE_POLICY_JSON as independently enrolled operator policy, and configure
the m0-acceptance environment's reviewer/access protection. Environment approval
and dispatch never replace the eight specialist signatures or candidate approval.
This implementation changes no repository/environment settings or variables.

After supplying actual approvals, stage same-repository artifact
m0-acceptance-inputs with request/ and assets/ directories in a selected run.
Independently compute/review the expected acceptance payload SHA-256 for the exact
publication commit and policy bytes. Dispatch .github/workflows/m0-acceptance.yml
on main with input_run_id and payload_sha256. No push/PR triggers this workflow.

The read-only job evaluates and compares the independently supplied digest. Only
the dependent environment-protected publish job has contents-write/OIDC. It signs
with pinned Cosign, verifies exact workflow/issuer/source/dispatch identity, and
re-evaluates the evidence before creating a fresh draft prerelease. Only three
explicit files upload; existing tags/releases are refused. Failed drafts/partial
uploads require inspection and supersession, not blind replacement. Server-side
immutability and environment settings remain maintainer responsibilities.

## Downloaded verification and retention

Retain acceptance.json, acceptance.sigstore.json and evidence.tar together in a
durable operator-approved store. Original publisher artifact inputs remain separate
and independently pinned; the metadata archive does not embed downloaded binaries
or independent operator policy. CI's seven-day transfer retention is not durable
acceptance storage. Signed GitHub release publication is a later authorized action.

```sh
uv run --locked --extra conformance python tools/m0_publication.py verify --assets VERIFIED_ASSETS --policy OPERATOR_POLICY --source EXPECTED_PUBLICATION_SHA --folder DOWNLOADED_ACCEPTANCE --sha256 EXPECTED_PAYLOAD_SHA256
```

Install the existing pinned Cosign tool explicitly first. Verification requires
independent expected source/digest and the exact current policy snapshot bytes.
Policy changes, expiry or revocation fail closed; there is no ignore-review mode.
A policy renewal requires a new payload/publication rather than silently updating
an old result. Keyless verification may access public trust roots/logs. Extraction
rejects extra/missing/duplicate/traversal/link/oversized entries; original reviewer
signatures and release-set admission are rechecked, not inferred from a publisher's
accepted label. A withdrawal must identify the previous payload digest and update
operator trust/revocations; preserve historical artifacts.

This remains a non-production M0 baseline for reviewed M1 development. Production
profiles and deployment stay disabled. Local tests use synthetic temporary evidence
and mocked publication signatures; live OIDC publication requires the future
approved manual run. No actual acceptance is asserted by this implementation.
