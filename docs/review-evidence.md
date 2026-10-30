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
