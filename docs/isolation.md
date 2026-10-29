# Local owner/compute isolation (M0-PR33)

This gate exercises development container boundaries using a random synthetic
`NOT_A_KEY` canary. It never generates, imports, encrypts with, or decrypts with a
real owner key. The result is `LOCAL_SYNTHETIC_ISOLATION_ONLY` with
`production_qualified=false`; it is not a security audit or production identity,
key-custody, side-channel or container-escape qualification.

The owner uses a fourth internal bridge network, a read-only root, no capabilities,
no-new-privileges and a read-only single-file canary mount. The file is mode 0400,
readable by the host-derived non-root development UID/GID used inside that owner
container. Ray explicitly uses UID/GID 1000. These numeric IDs are development
identities, not authenticated workload identities; they can coincide on some hosts.
Mount and network separation are the enforced boundaries. Linux fixture runs
require a non-root host UID/GID and a normal local Docker daemon; rootless/userns
remapping is not qualified. The Docker host/daemon and test driver are trusted.

The owner endpoint reads the canary and returns only its hash. A positive check
inside the actual owner proves file and endpoint access. The canary value is
never put into environment variables, control messages, task descriptors or
reports. Only the owner receives its mount. Generated canary and credential files
are removed after scoped Docker teardown and on partial preparation failure.
Canary redaction also applies to harness failure diagnostics.

## Live checks

Compute attempts direct raw-IP connections to owner, broker administration,
Temporal, SQL and Toxiproxy management listeners. Broker/workflow network namespaces
also attempt owner and cross-domain management connections. Every listener must
be reachable from the trusted host immediately before and after denial checks;
each probing namespace must successfully connect to its own local service.
DNS failure or an absent listener cannot pass as network isolation.

Ray runs the fixed probe in its own container. Broker/workflow network checks use
short-lived, non-root, read-only Python helpers sharing the target's network
namespace, with no mounts, secrets or Docker socket. This tests the namespace
boundary rather than claiming an application-specific identity/authorization
policy. Helpers have unique owned names and are removed even on timeouts.
Separate shell checks run in the actual actor containers, prove an ordinary file
is readable, and require owner/Docker paths to be absent. Runtime configuration
and mounts are inspected for owner material; actual actor UIDs are reported without
pretending the existing workflow image is non-root.

The gate scans the actual Redpanda record, actual Temporal history and up to 200
log lines per owner/compute/broker/workflow service (256 KiB maximum each) for raw,
hexadecimal, base64 and JSON-escaped
canary material. It does not claim to detect arbitrary encryption, encoding,
fragmentation or unknown sensitive data. Raw histories, logs, canary bytes and
canary hashes are never retained/uploaded. Reports contain identities, target-role
names/ports, positive-control status and denial results only.

## Gates and evidence

Use the existing M0-PR31/32 package, Cosign and upstream-evidence setup. Then:

```sh
uv run --locked --extra conformance python tools/integration.py isolation
uv run --locked --extra conformance python tools/verify.py full
```

Standalone isolation owns a fresh stack and runs the public fake workflow so real
records/history exist to inspect. Full checks share the existing single stack
with service qualification, fake traversal, network measurements and release
conformance. Fast checks start no services. CI retains only
`build/integration/<project>/isolation-report.json` alongside existing public reports.
Abrupt host/runner termination still requires owned cleanup; normal/failure paths
remove generated fixture files and owned resources.

The implementation adapts [Docker bridge isolation](https://docs.docker.com/engine/network/drivers/bridge/)
and [network namespace/container restrictions](https://docs.docker.com/engine/containers/run/)
through existing pinned Python images and standard-library probes, with no new
runtime dependency. Same-network peers and the trusted host can still connect;
there is no claim of mTLS, production ingress authorization, SPIRE/Kubernetes
policy, malicious-host protection, speculative-execution resistance or crypto
custody. Those remain the later security and deployment milestones.
