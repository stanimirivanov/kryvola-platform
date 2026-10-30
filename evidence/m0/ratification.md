# M0 contract and profile ratification candidate

M0 decision: **BLOCKED_PENDING_SIGNOFFS**.

Prepared 30 October 2026 for M0-PR36 / issue #35. This is a concrete review
record, not an approval, a five-repository release set or production qualification.
The ratification revision is the eventual merged PR commit; it is separate from
the tested contract source below. No record must contain its own future hash.
M0 remains open and M1 baseline acceptance remains blocked.

## Frozen candidate

Contract source: `1a5b57a590487ba116913050af8041f5e5f1fb52` in kryvola-spec,
version `0.1.0-preview.10`. No contract, signed-format, wire tag, native codec or
consumer pin changes in this PR. Source files and every output still pass the
existing provenance/generation gates; the manifest hashes identify exact bytes.

| Record                                   | SHA-256                                                          |
| ---------------------------------------- | ---------------------------------------------------------------- |
| generated/manifest.json                  | 2df957464b4832b37624a61436786207042be1fde24dfc5c5e0d518d66882f35 |
| bindings/manifest.json                   | 8cc787ffa59de095ac2df92db453e8a84f57c2e0f2e57c4127bbc01c68486bc9 |
| generated/fixtures/fhe-q1-assurance.json | 267dee8330668952adf11fe00cd96d0c5a45217d17b714e4266485dfb6c48eb0 |
| docs/ownership.md                        | b62be8e8f41fea699990e8dcae305197577f0702a3e0befaa73248d8eeb85128 |

The FHE-Q1 fixture stays disabled and UNREVIEWED, with empty review evidence,
unresolved legal/parameter references, owner-only keys, public model, UNPROVEN
evaluation integrity and PUBLIC_DATA_ONLY witness claims. Canonical/JCS and wire
agreement do not authorize disclosure or qualify cryptographic parameters.
Native ciphertext layouts remain engine-owned. The v2 modular arithmetic candidate
does not reinterpret legacy signed bytes. Semantic review changes must reopen
affected spec/consumer/conformance work before acceptance.

## Evidence ledger and limits

These are independently scoped evidence references, not a tested five-component
release composition. A later head or PR merge cannot silently replace them.

| Scope                                                        | Immutable source / verification                                                                                                                                                                                                                                                                                                                               | Disposition                                                                                                                                                  |
| ------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Contract, Rust/Python/C++ canonical and native wire fixtures | spec `1a5b57a590487ba116913050af8041f5e5f1fb52`; [successful run 40484284554](https://github.com/stanimirivanov/kryvola-spec/actions/runs/40484284554)                                                                                                                                                                                                        | Fixture conformance; no independent crypto audit                                                                                                             |
| Attempt/release models                                       | Same spec source, `models/attempts`, `models/release`, `pnpm check:state`                                                                                                                                                                                                                                                                                     | Finite-state safety and required mutant counterexamples; no live SQL/Temporal/Ray or restore proof                                                           |
| Public ML fixture                                            | ML `dcba320678eb454047e29c8a42417ffe8d94a323`; [manifest and model card](https://github.com/stanimirivanov/kryvola-ml/tree/dcba320678eb454047e29c8a42417ffe8d94a323/fixtures/fhe-q1)                                                                                                                                                                          | 100 synthetic unsigned modular cases; not a predictive model/accuracy claim                                                                                  |
| Experimental workflow/conformance                            | platform `e811c113d0adb958cdcfb4d4be2f20b74f547055`; [run 40918640516](https://github.com/stanimirivanov/kryvola-platform/actions/runs/40918640516)                                                                                                                                                                                                           | Published fabric `f02281ffa78decb6acd032c102359bf758f92a3a` and fake engine `f8023959081fa6a1e8169b41ef427630a5da72f3`; not five-component release admission |
| Local isolation controls                                     | platform `a4398f298776c571b15e60ec877c10dfdaeff752`; [run 40926202439](https://github.com/stanimirivanov/kryvola-platform/actions/runs/40926202439)                                                                                                                                                                                                           | Synthetic non-key canary, development identities and denial controls; not malicious-host security qualification                                              |
| Two crypto campaigns                                         | platform `571c8eb1ac87a985d3aaa9a6d04bce596b00312b`; [numeric corpus](https://github.com/stanimirivanov/kryvola-platform/tree/571c8eb1ac87a985d3aaa9a6d04bce596b00312b/evidence/feasibility/fhe-q1), summary SHA-256 `5f7ed5054ffb5c6c462743650632b804a76ff6372de136608b0684b8590535d3`                                                                       | Research INCONCLUSIVE for service latency; no fabricated upload/cache/transport stages                                                                       |
| Crypto decisions                                             | engines `a60dd541cf3bd18389d99cba3a7126e02a479963`; [M0-PR35 report](https://github.com/stanimirivanov/kryvola-engines/blob/a60dd541cf3bd18389d99cba3a7126e02a479963/docs/m0-feasibility.md), [final implementation CI 40954617607](https://github.com/stanimirivanov/kryvola-engines/actions/runs/40954617607) at `08b570b36e49421cd0a1d41171f49d58f0d083e9` | Bounded research only; production private inference NO_GO; parameter/security/legal review PENDING                                                           |

Actual circuit evaluation sums were 78.663/136.590 s per 100 correlated cases;
owner totals 81.314/139.930 s. Two fresh key contexts and four Core samples cannot
establish service-tail distributions. Compact input validity is not FHE evaluation
proof; Core public-metadata proofs are NOT_ZERO_KNOWLEDGE and the prover sees its
inputs. GPU and other export modes remain unavailable/disabled/unmeasured.
TFHE/SP1 distribution/service permissions remain DENY. Research RSS observations,
the 512 MiB review ceiling and virtual-address limits are not production memory
guarantees; prover-process-group RSS remains unqualified.

## Provisional M1 objectives

Retain [design v2 section 11.2](kryvola-design-v2.md)'s warm owner-to-owner p95 ≤5 s
and cold p95 ≤15 s as **PROPOSED, UNMEASURED** objectives, not accepted SLOs or
research results. They apply only to a subsequently selected public model/shape/
parameter profile at declared concurrency, including required input evidence,
queueing, transport, persistence, release and owner decryption. Record key/program
cache conditions explicitly; the current report's COLD/WARM label covers both,
so mixed states cannot be labelled WARM. Measure LAN/WAN on controlled hardware.
Start qualification at concurrency one; higher concurrency needs its own
memory/capacity evidence. A 100-case batch is not one such owner request.

The present circuit experiment does not establish either target or justify a
smaller/warm deadline by dividing batch time. If the selected M1 profile misses its
measured budget, expose asynchronous service only or reject under its consent/
deadline policy. Async is a delivery class, not permission to bypass security,
authorization, legal or evidence gates. M1 functional work may use disabled fixture
candidates; integrated baseline acceptance still requires explicit M0 ratification.

## Named decisions required

No nominations or authenticated sign-offs have been supplied. Repository identity
is an implementation responsibility, not a named reviewer. Under [ADR 0003](adr/0003-release-governance.md),
passing tests, user requests to implement work, and merges establish no specialist
approval. Each reviewer must bind their identity, authority, review URL, decision,
contract source and the exact candidate/ownership digests above. Legal decisions
must specify intended use; operational review must preserve provisional targets.
One named person may cover multiple repository roles only when explicitly recorded.

| Role              | Named reviewer | Authenticated review | Decision |
| ----------------- | -------------- | -------------------- | -------- |
| Spec lead         | NOT_NOMINATED  | MISSING              | PENDING  |
| Fabric lead       | NOT_NOMINATED  | MISSING              | PENDING  |
| Engines lead      | NOT_NOMINATED  | MISSING              | PENDING  |
| ML lead           | NOT_NOMINATED  | MISSING              | PENDING  |
| Platform lead     | NOT_NOMINATED  | MISSING              | PENDING  |
| Security reviewer | NOT_NOMINATED  | MISSING              | PENDING  |
| Legal reviewer    | NOT_NOMINATED  | MISSING              | PENDING  |
| Operational owner | NOT_NOMINATED  | MISSING              | PENDING  |

After nominations, obtain authenticated decisions over this fixed record; record
rejection/conditions as well as approvals. Review expertise/authority remains a
human gate. Substantive semantic, parameter, evidence or boundary changes invalidate
affected approvals. Do not edit this record to APPROVED merely to pass tooling.

## Verification and acceptance boundary

`node tools/check-ratification.mjs` checks this pending record, exact local
manifest/profile/ownership bytes and required missing-review rows. Its negative
tests run in `pnpm check`; successful consistency validation is not ratification.
No approval-authentication mechanism or new public wire contract is introduced.

Existing gates: `pnpm check`, `pnpm check:release`, `pnpm check:canonical`,
`pnpm check:state`, and `pnpm native:check`. The old plan's `check:interop` spelling
is absent: `native:check` is the actual cross-language wire/loopback gate. The release
checker accepts only the existing UNQUALIFIED preview record; it does not verify
named approvals or admit a release set. Heavy Docker gates stay on CI. Prior CI at
the exact unchanged candidate and new branch verification are separate evidence.

Acceptance is blocked until named owner/security decisions and scoped legal/
operational dispositions are recorded, remaining material exclusions are accepted
or resolved, and the ratification revision is explicitly approved. M0-PR37 must
not convert this pending document into a successful release-set/M1 admission.
