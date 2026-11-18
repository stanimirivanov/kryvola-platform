# Measured cold/warm service campaigns (M1-PR36-R2)

Run `uv run --locked python -m tools.m1_campaign --pairs 2` after M1 installation
from a clean committed checkout. Source identity is checked before and after.
It writes `build/m1-campaign-<nonce>.json`; any failed or unrun observation makes
the command exit nonzero. One to twenty serial pairs are allowed. Each pair owns
a fresh verified stack, measures its first request as COLD, then measures another
as WARM_SERVICES without restarting services. Both have fresh owner keys. New
pairs avoid accumulating evaluation keys beyond the existing tenant quota.

Monotonic nanoseconds cover owner preparation, admission/uploads, provisioning,
dispatch through committed release, and authorized owner opening. These are
boundary intervals, not isolated native CPU stage measurements. Setup, evidence
audit and telemetry are outside request latency; serial campaign throughput
includes them. Container memory is its lifetime cgroup-v2 peak (including tmpfs),
not incremental per-request RSS. Input/output counts are serialized artifact
bytes, not total transport bytes. Host OS/image caches are uncontrolled; Engine
key-cache hits/misses are unobserved, never inferred from warm service labels.

Raw observations retain exact release/image, plan/key-context, frozen-reference
and harness bindings. Summaries use existing nearest-rank quantiles with explicit
sample sufficiency (p95 needs twenty successes). Missing evidence and failures
cannot qualify as successful samples. Correctness remains against the frozen
FHE-Q1 circuit with CONFIDENTIALITY_ONLY integrity limitations. This campaign
does not publish a supported envelope or assert an SLO; that remains R3.
