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
