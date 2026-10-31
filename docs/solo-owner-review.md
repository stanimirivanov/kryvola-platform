# Solo-owner agentic M0 review

SOLO_OWNER_AGENTIC_V1 is a separate v2 administrative gate implementing the owner's
simplified governance direction (Spec ADR 0004). **Actual owner approval is pending.**
No owner login, comment, policy or positive report is seeded. Historical eight-role
records and validators remain unchanged and cannot silently accept this format.

```sh
uv run --locked --extra conformance python tools/solo_m0_review.py --request REQUEST --assets VERIFIED_ASSETS --policy OPERATOR_POLICY
```

REQUEST contains the existing exact composition directory plus solo-subject.json
and agentic-review.json. No legal.json, eight role decisions, admitted candidate
or reviewer private key is required. All publisher signatures, independently
pinned artifacts, current driver compatibility, live controls, cleanup and
retained subject hashes are checked using the same composition verifier as the
legacy evaluator. Input files are bounded non-symlink files snapshotted before
verification. Publisher binaries remain separate independently pinned inputs.

## Exact administrative fields

solo-subject.json: version=2, governance=SOLO_OWNER_AGENTIC_V1, existing M0 scope,
intended_use, candidate_sha256 (tested unsigned candidate), composition_sha256,
selection_sha256, nonempty exclusions, production_ready=false, profile_enabled=false.

agentic-review.json: version=1, kind=AGENTIC_REVIEW, subject_sha256, reviewer,
repositories (exactly spec/fabric/engines/ml/platform), checks, blockers (empty),
nonempty residual_risks and limitations. checks has compatibility, security,
dependency_licensing and operations, each with status PASS or LIMITATION and a
nonempty summary. Record actual evidence checked, findings and limitations. An
agent's label or a green test alone does not establish specialist expertise.

OPERATOR_POLICY: version=2, governance=SOLO_OWNER_AGENTIC_V1, subject_sha256,
agentic_review_sha256, composition_sha256, selection_sha256, intended_use,
owner_login, repository (one Kryvola repository), pull_request, approval_comment_id,
reviewed_revision (full commit), valid_until (UTC YYYY-MM-DDTHH:MM:SSZ) and
revoked_comment_ids (integer IDs). All hashes/authority choices come independently
from the operator, never from incoming files. The owner comment ID is supplied only
after the owner posts the actual decision. Until then the gate must fail closed.

## One explicit owner comment

Prepare subject, then report, then freeze the review PR revision. The owner reads
both and posts this exact comment with actual values, personally, when ready:

```text
KRYVOLA_SOLO_OWNER_APPROVAL_V1
subject_sha256=EXACT_SUBJECT_SHA256
agentic_review_sha256=EXACT_REPORT_SHA256
intended_use=EXACT_INTENDED_USE
reviewed_revision=EXACT_REVIEWED_COMMIT
```

A comment works for a solo author; GitHub forbids approving one's own PR through
an approving review. The read-only gh adapter checks the live PR head and paginated
comments. It requires the pinned comment from the enrolled owner to be the latest
owner comment beginning KRYVOLA_SOLO_OWNER_. Generic comments, merges and requests
to implement work are not approvals. Do not ask an agent to post approval under
the owner's identity; GitHub cannot distinguish which actor used the same account.

A later KRYVOLA_SOLO_OWNER_WITHDRAW comment, changed approval body or head, deleted
approval, expired policy, missing input or invalid signature rejects. Keep an
independent current revocation list too: deleting a withdrawal can hide it from
the API; revocation must not rely solely on surviving comments. The gate reads a
current API snapshot, not an immutable audit history or atomic transaction across
all responses. GitHub access failure rejects rather than trusting cached input.
Changed subjects require a new review and renewed approval.

## Outcome and limits

Success emits QUALIFIED_SOLO_OWNER_REVIEW and eligibility for later M0 ratification.
It creates no persistent state, acceptance artifact or M1/production authorization.
The unsigned candidate stays UNQUALIFIED/disabled and legal UNRESOLVED; the owner
accepts the documented non-production scope and residual risk, not invented legal
clearance or parameter certification. TFHE/SP1 distribution/service remains DENY.

The existing acceptance evaluator, signed release-candidate protocol, successor
checker and acceptance publisher retain their legacy semantics. They do not
consume this v2 path. A subsequent solo-governance ratification must be a new
record citing the reviewed hashes and owner decision, not an edit to signed or
frozen history. Acceptance publication remains disabled and requires a separately
authorized versioned implementation. This change does not retroactively qualify
a newly released driver or alter the previously tested five-component set.

Exit 0 requires all checks and a real current owner approval. Exit 2 prints only
SOLO_OWNER_REVIEW_REJECTED. No signing, posting, tool installation, network access
other than read-only GitHub/public signature verification, or clock override is
performed. Tests fabricate owner comments; existing real-Cosign tests continue to
cover publisher and legacy reviewer signature boundaries.

GitHub comment CRLF line endings are normalized to LF before exact approval-field
comparison; signed JSON and subject/report bytes are never normalized. Comment
history uses bounded explicit REST pagination (100 per page, at most ten pages)
compatible with gh 2.46 without --slurp. An over-limit history fails closed rather
than accepting a partial history or missing a later withdrawal.
