# Shaped transfer observations (M0-PR26)

`uv run --locked python tools/benchmark.py network-check --check-only` validates
the pinned profiles offline. Without that flag the command owns a fresh local
fixture stack, runs all M0-PR29 qualification checks, measures the network cases,
and tears down in `finally`. It refuses an already active stack. `full` invokes
this combined path once, rather than starting two stacks. Heavy checks run on
branch CI before opening a PR.

The public transfer fixture uses pinned Python 3.14.7 slim, UID 65532, a read-only
root, no credentials, and only its read-only script mount on the internal data
network. No application dependency is added. The toy HTTP server has four
64 KiB slots and a single request handler, rejects oversize Content-Length before
reading a body, and never receives user data or private witnesses. It is a
bounded test utility, not a new Kryvola transport/crypto engine or production HTTP
server. The existing S3 tests still use the pinned AWS CLI; its internal chunk
sizes are not misrepresented as observations.

`config/network-profiles/profiles.json` is SHA-256 pinned in the controller.
LAN means no injected toxic; WAN means symmetric 120 ms latency and 128 decimal
kB/s per direction using the existing Toxiproxy 2.13.0 image. The
[pinned bandwidth implementation](https://github.com/Shopify/toxiproxy/blob/v2.13.0/toxics/bandwidth.go)
uses bytes per millisecond, not KiB/s. These are same-host bridge emulations, not
physical LAN/WAN capacity observations. Runtime proxy configuration is retained.
Three fresh-connection pings and four sequential chunk upload/download pairs are
recorded per profile. The gate checks injected delay and a conservative transfer
duration floor, not exact timing or service SLOs. No percentiles or statistical
sufficiency are claimed from these small samples.

Each raw row binds payload SHA-256, actual bulk bytes, upload/download duration,
queue delay from common batch admission, completion offset, outcome and maximum
outstanding application payload. One request is active at a time; the observed
payload bound is 64 KiB. This is not a bound on all interpreter/kernel memory.
Parent process duration includes Docker exec and Python startup; the profile
window additionally includes ping/resource/stat observation overhead. Stage sums
are not substituted for complete latency. Object slots are reused across profiles;
connections are fresh, and OS caches are uncontrolled. There is no key cache.

The disconnect case disables the proxy, retains one actual I/O failure, restores
the route and makes exactly one retry of the same chunk. Both attempts and the
measured recovery gap remain in the journal. Bytes of a failed operation remain
unknown, including possible partial writes; they never silently become zero.
Unexpected failures in the successful profiles reject the gate. The dedicated
proxy and its toxics are removed after observation, including failure paths.

Client/server process peaks are Linux `ru_maxrss` converted from KiB to bytes.
Cgroup v2 memory.current and memory.peak are recorded with explicit unavailable
reasons; the latter is a **container-lifetime** peak spanning earlier observations.
Snapshots include observer processes. Docker snapshots for transfer/proxy retain
raw strings and approximate cache-adjusted usage parsed with explicit decimal and
binary units. [Docker's CLI subtracts inactive cache](https://docs.docker.com/reference/cli/docker/container/stats/);
it is not a process-RSS or byte-exact peak measure. No metric is synthesized from
another measurement or converted from missing to zero. Docker host attributes,
source commit, profile/worker/controller hashes and image digests bind the run;
these are observed/operator-controlled metadata, not hardware attestation.

The JSON report remains under the owned ignored fixture directory after teardown.
An append-only JSONL journal preserves completed raw batches before validation;
failed runs without a final report remain incomplete. CI retains only these two
public synthetic measurement files for seven days, including partial journals on
failure, using a commit-pinned upload action. Credential/configuration files are
excluded by explicit filename patterns.
It is a private experiment journal, not a qualified MeasurementReport. Serialized
byte counts and the rate card cover **bulk chunk bodies only**, excluding digest
receipts, headers, ping/control messages, TCP overhead and retransmissions. Crypto
expanded bytes and owner work are null with not-applicable reasons; they are not
zero-cost encrypted inference measurements.

The pinned rate card is explicitly illustrative: USD nanounits per allocated
transfer/proxy container-second in the measurement window and per GiB of bulk
download bodies. Integer arithmetic rounds each component upward. Both running
containers and failed-attempt/recovery time are included; initial stack startup,
other fixtures and protocol overhead are outside this model. Known payload cost
is retained as a lower bound when failed bytes are unknown; total cost is then
null with a reason. This is neither a vendor bill nor a full job-cost estimate.
No production profile, workload security or capacity promise is enabled.
