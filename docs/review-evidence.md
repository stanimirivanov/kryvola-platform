# Authenticated M0 review evidence

`tools/review_evidence.py` checks signed reviewer decisions against independently
supplied operator trust. It uses the existing checksum-pinned Cosign pinned-key
verifier; no cryptographic primitive, runtime dependency or public wire schema is
added. No reviewer identity, key or approval is seeded in the repository. All
checked-in ratification, legal and security dispositions remain pending.

This is a versioned local administrative envelope over exact bytes, not canonical
protocol signing. Sign each decision JSON file with Cosign sign-blob and retain its
Sigstore bundle. Whitespace changes invalidate its signature and evidence pin.
Never infer reviewer authority from a package publisher, repository ownership,
review URL, a merge or a request to implement work.

## Inputs and authority

The review packet is JSON with exactly: version (1), scope
(M0_CONTRACT_FEASIBILITY_AND_NONPRODUCTION_COMPOSITION), contract_revision (full
commit), candidate_digests (nonempty map of names to SHA-256), composition_sha256
(SHA-256 or null before composition), exclusions (distinct nonempty descriptions).
The packet binds the exact contract/profile/ownership and relevant artifact and
policy subjects; its independently selected digest is authoritative for this
verification. Authentication does not validate the underlying candidate semantics
or complete composition: later ratification/acceptance must do that separately.

The separate operator-owned trust JSON has exactly: version (1), subject_sha256,
intended_use, valid_until (UTC YYYY-MM-DDTHH:MM:SSZ), roles,
revoked_evidence_sha256, revoked_key_sha256. The two revocation fields are arrays
of SHA-256 strings. Each of the eight roles from the spec closure convention must
have its own explicit entry: identity, authority, public_key (PEM text),
evidence_sha256 (latest exact decision bytes), predecessor_sha256 (null or exact
predecessor digest). Explicit entries may authorize one person/key for multiple
roles; one signature cannot silently substitute for a differently scoped role.
Do not derive this file or its keys from the incoming review packet or evidence.

Each signed decision JSON has exactly: version (1), role, identity, authority,
decision (APPROVE/REJECT/CONDITIONAL/WITHDRAW), review_url (HTTPS), subject_sha256,
intended_use, issued_at, expires_at, conditions, supersedes_sha256. Identity,
authority, use, packet and predecessor must match independent trust. Non-approval
decisions require nonempty reasons/conditions; unconditional approval requires an
empty conditions list. Expiry is exclusive; future-issued evidence is rejected.
Decision expiry cannot exceed the operator trust expiry. Revoked keys/evidence,
stale decisions, missing roles and duplicate JSON fields fail closed.

Operator trust must be kept current through an authenticated administrative
channel. Offline signature verification cannot discover unprovided withdrawals
or establish reviewer expertise. The bounded trust validity window limits stale
snapshot use; it is not an automatic revocation service. Successor decisions must
retain earlier bytes and explicitly bind the predecessor selected by the operator.
This tool validates the current pointer, not an entire authenticated history.

## Verification

Place decisions/bundles in a directory as ROLE-SLUG.json and
ROLE-SLUG.sigstore.json, for example security-reviewer.json and
security-reviewer.sigstore.json. Slugs are the exact role names lowercased with
spaces replaced by hyphens. Install the existing pinned verifier explicitly with
`uv run --locked python tools/install_cosign.py`, then run:

```sh
uv run --locked --extra conformance python tools/review_evidence.py --subject REVIEW_PACKET --trust OPERATOR_TRUST --evidence REVIEW_DIRECTORY
```

No installation, downloads, approval record writes or clock override occur in the
CLI. Exit 0 authenticates eight unconditional decisions only; exit 1 retains
blocking rejection/conditional/withdrawal decisions; exit 2 rejects invalid,
incomplete or unauthenticated input with a fixed diagnostic. Results always retain
m0_accepted=false and m1_admitted=false. They are inputs to subsequent PR11/12,
not acceptance artifacts. Production/profile activation and specialist permission
remain separate. Preserve the pending spec record and use an explicit successor.

Tests run through existing Python discovery/full verification; synthetic signer
fixtures grant no real project authority. KRYVOLA_RELEASE_SIGNATURE_TESTS=1 enables
real pinned-Cosign positive/wrong-key controls alongside offline negative cases.

## Recorded successor verification (M0-REL-PR4.2)

`tools/ratification_record.py` consumes the Spec PR4.1 RECORDED_SUCCESSOR interface
and delegates authentication and composition/candidate semantics to the existing
acceptance evaluator. Proposed records are rejected. A successful result is
AUTHENTICATED_SUCCESSOR_RECORD_ONLY with M0/M1 admission, production/profile and
deployment flags false; it writes no approval, acceptance artifact or state.

```sh
uv run --locked --extra conformance python tools/ratification_record.py --record RECORD_JSON --request REQUEST_DIRECTORY --assets VERIFIED_ASSETS --policy RECORD_POLICY --spec-repository TRUSTED_SPEC_GIT
```

All uppercase arguments are operator-supplied paths. RECORD_POLICY contains exactly
record_sha256, predecessor_sha256, ledger_sha256, proposal_revision and
acceptance_policy. The nested policy is the independently configured policy from
m0-acceptance.md, not policy supplied by the record/request. Its ratification_revision
must equal proposal_revision; its current review trust pins the packet and decisions.
No key, role authority, policy or approval is seeded or enrolled by this command.

REQUEST_DIRECTORY is the existing acceptance request plus ledger.json and the
original composition/evidence.tar. The ledger must match the actual report and
archive hashes. The eight record decision/bundle references must match the exact
bytes supplied to the evaluator. All allowlisted evaluation inputs are copied to
a temporary snapshot before evaluation; it is removed on return. Original asset
paths remain independently pinned inputs to the existing publisher checks.

TRUSTED_SPEC_GIT is an operator-trusted local Git repository with the independently
pinned proposal commit already present. Nothing is fetched or checked out. Git
reads that commit's regular, size-bounded blobs at these fixed paths:

- docs/m0-ratification-proposal.json must equal request/ratification.json;
- docs/m0-composition-qualification.json must equal request/ledger.json;
- docs/m0-ratification-decision.md must match the independent predecessor digest.

The working tree may differ: only committed object bytes count. Ambient GIT_*
settings and replacement objects are disabled. Repository origin identity and
acquisition remain operator responsibilities; object equality is not independent
provenance authentication. No Spec implementation is imported or executed.

This defines proposal_revision as the frozen payload commit, not the later commit
recording decisions. It preserves PR4.1's acyclic ordering. These proposal files
are future PR4.3 inputs; missing commit/files fail closed. The approved record is
never a subject of its own packet. The archive is hashed without extraction; the
retention URL is not fetched and retention/immutability are not guaranteed here.

Exit 0 verifies this record against the current supplied trust snapshot; exit 2
returns RATIFICATION_RECORD_REJECTED without original diagnostic contents. Expiry,
withdrawal/revocation, conditional/rejected decisions and publisher/candidate
failures propagate from existing verification. Offline verification cannot discover
unprovided revocations. Any changed subjects require renewed affected decisions.
Actual reviews, qualification and acceptance publication remain pending.
