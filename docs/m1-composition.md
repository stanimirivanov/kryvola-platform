# Locked local M1 services

M1-PR30 / Platform #48 composes the published M1 runtime in a dedicated
`compose.m1.yaml`. [The integration decision](decisions/0001-published-m1-local-composition.md)
records identities, adapters and the narrowly assessed Spec-pin difference.
The frozen M0 Compose file, candidate and Python conformance environment are
unchanged.

Requires Linux x86_64, a nonroot operator, local rootful Docker with Compose,
OpenSSL, Python 3.14.7 and uv 0.12.5. No cloud account is used. Pulls and role-image
assembly need registry/package-network access; running services have internal
networks and no published host ports.

```sh
uv sync --locked
uv run --locked python tools/install_release.py
uv run --locked python tools/m1.py install
uv run --locked python tools/m1.py check
uv run --locked python -m unittest discover -s tests -p live_m1_identity.py -v
uv run --locked python tools/m1.py ci
# Optional foreground session; Ctrl-C performs the same owned cleanup:
uv run --locked python tools/m1.py up
```

`check` is offline and starts nothing. `install` fetches exact selected release
URLs, checks every SHA256 and verifies Sigstore publisher identity, dispatch
source and provenance. It also installs checksum-pinned local SPIRE binaries.
Missing/changed inputs fail; there is no M0 or synthetic-service fallback.
`ci` assembles temporary role images from admitted artifacts, starts real
PostgreSQL, SeaweedFS/S3, Redpanda, Temporal, Ray, Fabric runtime/messaging/workflow,
owner and the published native Engine API. It applies the published Fabric SQLx
migrations and the pinned Temporal image's supported schema tooling. The owner
native wheel is installed only in its own role image; Platform's frozen M0
conformance dependency remains untouched.

The gate tests runtime mTLS health and exact server SPIFFE identity, the actual
Engine RPC's CREATED state with no outputs, real Ray readiness, worker startup,
14 successful Fabric migrations, a public S3 round trip and broker mTLS readiness.
It then deliberately exits through its failure/finally path and verifies that
its project's containers, networks and volumes are gone. Public results are
written to `build/m1-report.json`; credentials and SPIRE state are removed.
Only the invocation's exact ownership marker and matching Docker labels authorize
cleanup. No global prune or external project cleanup is performed. A mismatched
marker/label stops cleanup so an operator can investigate.

The lock includes immutable source revisions, exact package/archive/signature
hashes, image digests, separate schema pins, and the signed solo-owner development
approval for Engines publication run 43389242347. This is development distribution,
not independent legal/security review or production permission. Release URLs may
be mutable at GitHub; accepted bytes, publisher source and OCI references are
pinned independently.

No inference is executed, no owner decryption key is initialized, and no release
or submission grant is seeded. The empty policy fails closed. The owner container
is a local custody/SDK startup boundary; actual keyring and operator-grant setup
belongs to the later end-to-end qualification. Its ready state does not assert
recoverable custody or successful opening. Similarly the startup Engine assignment
has no usable input/output credentials. The full M1 milestone and production
qualification remain incomplete after this task.

SPIRE admin and workload sockets use separate short directories under `/tmp`,
independent of checkout depth and `TMPDIR`. The admin directory stays mode 0700;
only the workload directory is mounted into roles. Keys and database state stay
in the private owned invocation folder. The real long-path identity regression
checks attestation and process/socket cleanup on normal and exceptional exits.
# Fabric publication for M1-PR33

The Fabric M1 release at `32d8528fd7a183b992643acb53e861fccc30bcb6`
was published by the existing main-only
[run 43449820501](https://github.com/stanimirivanov/kryvola-fabric/actions/runs/43449820501).
All 17 downloaded assets passed Fabric's inventory/source/subject verifier and
keyless publisher verification, followed by Platform's complete three-component
admission. `config/m1.lock.json` records every exact hash and immutable URL.
The manifest SHA-256 is
`c5316123f78844241a8a645474bede443b1ed6a176622e2707ae37d7c8ecbf02`;
the runtime archive is
`2fc6409289853dc61f8553878a2253c1333143a945970ac366de7148e5e639da`;
the owner archive is
`8c7a4e0e0224ec54e0c028f2eabed6108cf9e16df868f1ce881c527ebeb01114`.
Engines and ML pins, the frozen M0 environment, and the existing Spec
compatibility assessment are unchanged. The published Ray worker now passes
the real native-Engine status preflight that failed with `58fe2aa`.
This preflight proves wire compatibility; it does not qualify successful inference.

