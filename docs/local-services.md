# Local service fixtures (M0-PR29)

`uv run --locked python tools/integration.py check` checks configuration offline;
it starts no services. `up` provisions a fresh uniquely named local Docker Compose
project and runs real health/semantic/restart checks, leaving it running after
success. `down` removes that owned project's containers, networks and named
volumes, checks that none remain, and deletes generated credential files.
`tools/verify.py full` runs up/down after existing signature, benchmark and wheel
checks. Branch-push CI runs the complete gate before PR creation.

Requirements: Linux/amd64 Docker engine, Compose v2 with `--wait`, approximately
6 GiB available Docker memory and space for the pinned images. Host Python stays
3.14.7; Ray uses the Python 3.12 runtime inside its own image. No Ray wheel or AWS
SDK is added to application dependencies. Remote Docker TCP/SSH endpoints are
rejected. Docker Desktop's local Linux-engine context is supported by the runner;
heavy integration runs belong on CI while the developer machine is busy.

`compose.yaml` intentionally uses the JSON subset of YAML so offline guards need
no additional parser dependency. Pins below were resolved from registry
Linux/amd64 manifests on 29 October 2026; the authoritative digests are in Compose.

| Fixture | Selected release | Licensing/fit |
|---|---|---|
| PostgreSQL | 17 image family, resolved digest | PostgreSQL licence; Temporal databases only |
| Temporal server/admin-tools | 1.32.1 | MIT; supported explicit SQL-schema setup |
| SeaweedFS | 4.51 | Apache-2.0; conditional S3 adoption requires live checks |
| Redpanda | 26.2.2 | Source-available BSL/RCL scope; not permissive-OSS classification |
| Ray | 2.59.0, Python 3.12 | Apache-2.0; trusted fixture task only |
| Toxiproxy | 2.13.0 | MIT; data-network proxy for later shaping tests |
| AWS CLI | 2.34.23 | Apache-2.0 CLI/SDK; standard signed S3 calls, no custom SigV4 implementation |

These licences describe the primary projects, not every package in their images.
Image-wide licence/security qualification remains separate from fixture testing.

The Temporal schema script adapts the supported
[samples-server pattern](https://github.com/temporalio/samples-server/tree/dd5a3b5e88f8a89c044c31bf094ddc5a20d0a778/compose).
Its MIT notice is preserved in `config/local-services/NOTICE.temporal`. Deprecated
auto-setup images are excluded. This is fixture adoption, not legal approval for
distribution or a production deployment of these images.

Control (PostgreSQL/Temporal), data (S3/broker/proxy/client), and compute (Ray)
networks are distinct internal bridges. No host port is published, including Ray
management/client/dashboard ports. Ray has no mounts or credential environment.
SQL and S3 use distinct fixture identities with newly generated credentials under
ignored `build/integration`; only S3 IAM configuration is mounted into its server.
The S3 client mounts public test payloads only. There is no Docker-socket, owner
key, cloud credential or user-home mount. Runtime inspection verifies port and
network boundaries. This is trusted-host fixture isolation, **not mTLS/authz or
production zero-trust qualification**; broker/Ray/Temporal APIs are not exposed to
untrusted clients. A Docker administrator remains trusted.

Tests require actual PostgreSQL queries, a broker produce/consume, Temporal
namespace persistence, and a real Ray remote task. S3 checks require version IDs,
both versions after overwrite, version-specific byte ranges, conditional create,
matching/stale conditional updates, and a two-writer conditional-create race with
exactly one winner. Unsupported operations fail qualification. A real proxy route
is tested without claiming network shaping or latency measurements. S3 container
recreation checks volume-backed metadata/content; PostgreSQL/broker/Temporal and
Ray restart checks distinguish durable fixture data from ephemeral Ray state.
This is a bounded single-node observation, not a multi-filer consistency proof.

Subprocess/readiness deadlines and accepted-output sizes are bounded; these are
trusted commands, not an OS sandbox. No raw resolved configuration is logged;
bounded command errors redact generated tokens. The active project marker uses
exclusive creation and refuses overwriting another run. Failed startup/checks
attempt scoped teardown. If Docker itself becomes unavailable, retain the marker
and retry `down` once it recovers. No workflow, crypto engine, owner SDK, model
approval, service SLO or production profile is activated. M0-PR26 owns shaping and
resource/cost measurements; later fabric work owns durable workflow behavior.
