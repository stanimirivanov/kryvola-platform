# M0 measured crypto decisions (M0-PR35)

**Continue bounded research; NO-GO for production private inference.** Parameter,
security and legal ratification remain pending. This decision admits only the
experiments below; it grants no distribution, service, planner capability or
private-witness approval. No production latency/memory guarantee is established.

## Evidence and reproducibility

The retained [numeric summary](../evidence/m0/campaign-summary.json) comes from
[platform PR18's immutable merge](https://github.com/stanimirivanov/kryvola-platform/tree/571c8eb1ac87a985d3aaa9a6d04bce596b00312b/evidence/feasibility/fhe-q1).
SHA-256: `5f7ed5054ffb5c6c462743650632b804a76ff6372de136608b0684b8590535d3`.
It contains the raw numeric observations, job IDs/log digests, library/binary
identities, exact rational variance and source-file pins. The upstream profile and
raw capture manifests remain at that revision. No keys, ciphertexts, proof objects
or executables are imported.

Both [attempt 1](https://github.com/stanimirivanov/kryvola-engines/actions/runs/40863854972/attempts/1)
and [attempt 2](https://github.com/stanimirivanov/kryvola-engines/actions/runs/40863854972/attempts/2)
passed native/SP1/aggregate CI at engines source
`f8023959081fa6a1e8169b41ef427630a5da72f3`. Each initializes a distinct FHE key
context. Library/lock/profile/fixture and binary identities agree. Hardware and OS
caches were uncontrolled. These are two owner campaigns, not 200 independent runs;
the 100 circuit cases per key context are correlated. Four Core samples do not
establish tail distributions. The original campaign qualification is INCONCLUSIVE.

The offline gate pins the imported bytes and a deterministic path/content digest
of the 28 experiment and runner files at that engine revision. Added/removed source,
parameter/profile/fixture/lock edits invalidate this decision until reviewed new
campaigns replace the evidence. Ignored Cargo target outputs are excluded. This is
reviewed evidence under repository/CI/import-host trust, not signed measurement
attestation or independent cryptographic/security review.

## Decisions and supported experimental envelope

| Experiment | Decision | Exact scope and exclusions |
| --- | --- | --- |
| Frozen TFHE uint8 circuit | GO_RESEARCH_ONLY | One owner batch at a time, two Rayon threads, 100 public cases, two uint8 inputs/outputs per case. Zero integer mismatches over 200 output values per attempt and required workload-binding negative. No model-quality, noise-margin or private inference qualification. |
| TFHE compact input | GO_RESEARCH_ONLY | Two-value compact PKE input-validity experiment, six negatives and zero mismatches. Local unqualified CRS; verified load/expansion required. No inference, evaluation or key-ownership proof. |
| SP1 Core public metadata | GO_PUBLIC_RESEARCH_ONLY | Local CPU prover, one active request, two FIFO-admitted requests per campaign, two workers, 1,000,000 guest cycles and the fixed ELF/VK/journal identities in the gate. Real Core verification and seven negatives per sample. Public inputs only. |
| Private inference / production | NO_GO | Parameter/security/legal review, authenticated owner bindings, production isolation, resource enforcement and complete service measurements remain blockers. |
| Service latency | INCONCLUSIVE | Upload, authorized key-cache miss, actual crypto transfer and owner-to-owner latency are unmeasured. Fake orchestration/network timings cannot fill them. |
| GPU / PBS statistics | UNAVAILABLE | GPU benchmark not executed; PBS feature disabled. No speedup/count/noise claim. |
| Compressed / Groth16 / PLONK | UNMEASURED_DISABLED | Recursion/setup/export privacy and verifier artifacts unqualified. RISC Zero remains DEFERRED; no cross-zkVM comparison. |

The TFHE 1.8.1 candidate is
`V1_4_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128`, parameter commitment
`cda9e129d55cc6a17060d8913f6e0d554c5a990e62c967514db86bf57a524674`.
It fixes LWE 918, GLWE 1, polynomial size 2048, message/carry moduli 4/4,
PBS base/level 23/1, KS base/level 4/4, TUniform noise and Big encryption key.
The uint8 circuit performs wrapping arithmetic on the frozen public
[ML fixture](../experiments/tfhe/fixture.lock.json), not a general neural model.
Compact inputs additionally use the pinned PKE/CAST ZKV2 candidates named in
[compact.rs](../experiments/tfhe/src/compact.rs). Their upstream annotations and
`2M128` names are not Kryvola security approval. See the existing
[parameter/security references](tfhe-codec.md) and [compact limitations](tfhe-compact.md).

## Measured cost and memory

| Observation | Attempt 1 | Attempt 2 |
| --- | ---: | ---: |
| Sum of 100 circuit evaluation timings | 78.663 s | 136.590 s |
| Owner total, including setup/dispatch/decrypt | 81.314 s | 139.930 s |
| Owner peak RSS | 194195456 bytes | 194129920 bytes |
| Evaluator peak RSS | 335818752 bytes | 335560704 bytes |
| Compact proof generation / verification | 0.411 / 0.229 s | 0.743 / 0.406 s |

Times are rounded for display; raw integer nanoseconds and variance are retained.
Evaluation totals are already inside dispatch/owner total and must not be added
again. Key generation, encoding, expansion and decryption remain separate in the
evidence. Each batch serializes 60228265 evaluation-key bytes and 13221800 bytes
each for input/output envelopes: 66109 serialized bytes per logical uint8 value,
including framing. Compact two-value sizes are 16659 bytes unproven, 18714 proven,
132202 after expansion, plus CRS/public/evaluation keys; these are not batch sizes.

The TFHE review ceiling is **512 MiB peak RSS per process**, checked against both
observed owner/evaluator maxima, not summed as simultaneous memory. This is an
admission criterion for this evidence, not allocator enforcement or a guarantee
for another workload. Existing OS limits remain 4 GiB virtual address space per
process, 128 MiB per file, 600 CPU seconds and 600 s owner wall time. Serialized
key/batch limits remain 64/32 MiB and the expansion admission ceiling 1 GiB. The
482607104-byte evaluation reservation is an estimate, not RSS. No higher workload
count/concurrency, sustained memory-growth or adversarial allocator claim is supported.

SP1 6.9.0 Core proving took 120.597–121.511 s, verification 0.149–0.151 s and
proofs 2778109 bytes for a 174-byte public journal. Per-process total was
394.370–396.018 s, including experimental setup and negative controls; compilation
was outside the timing window. Local FIFO queue time is not a service queue SLO.
Core is **NOT_ZERO_KNOWLEDGE** and the local prover sees all inputs. Private
witnesses and remote provers are excluded. [SP1 limits](sp1-relation.md) distinguish
the 2 TiB sparse JIT file and virtual address space from physical memory. Host/
process-group RSS is unmeasured/unqualified; the sampled 1 GiB guest-child monitor
does not establish a host-prover budget. Cost per request and billing are unknown.

## Gates and follow-up

`uv run --locked python tools/qualification.py` emits the research decisions
offline. The canonical fast/native/full harness invokes it. Existing strict TFHE,
compact and proof-mode parsers check correctness/accounting; new negative controls
reject changed evidence/source/parameters, missing accuracy, exceeded memory/size/
time bounds and unsupported production/privacy/GPU claims. No dependency is added.
Run focused tests with `uv run --locked python -m unittest tests.test_qualification -v`;
the full gate remains `uv run --locked python tools/verify.py full` (heavy work on CI).

Before any promotion: obtain scoped parameter/security/legal review; qualify
authenticated owner/key-domain bindings and malicious-worker isolation; measure
real cold/warm key/transport/end-to-end paths on controlled hardware with enough
independent samples; establish adversarial memory/noise limits; review exact proof
privacy/setup and resource sandboxing. Until then, TFHE/SP1 local research stays
RESEARCH_ONLY, distribution/service DENY, legal review PENDING and production
profiles disabled. This task does not close the remaining KRY-007/008 or M0 gates.
