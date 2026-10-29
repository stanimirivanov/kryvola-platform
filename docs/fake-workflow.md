# Published fake workflow (M0-PR31)

This explicitly fake, public-only driver traverses Redpanda -> Temporal -> Ray ->
the released fake evaluator. It uses the actual published fabric wheel and native
fake binary, not sibling source or rebuilt substitutes. All production/profile
flags remain false. It is not production ingress, authorization, a physical
operation registry, encrypted inference or a release-set qualification gate.

## Semantics and ownership

A small immutable public object triggers the engine's fixed `conformance` command.
The driver sends only references and a bounded generated ExecuteRequest over the
broker and into the published Temporal FixtureWorkflow. Its idempotency key binds
the public trigger's complete version/hash reference. The released engine exposes
loopback self-test mode rather than an external server: Ray invokes that command,
which runs its own real bounded Engine API RPC conformance cases internally. The
public trigger is not passed off as encrypted input, and the published request's
synthetic ciphertext references are never fetched or advertised as valid crypto.
This limitation is explicit in `artifact_scope=PUBLIC_TRIGGER_AND_SELFTEST_RECEIPT_ONLY`.
M1 still owns external Engine API dispatch, physical fences, artifact decoding,
recovery, authorization and committed result release.

Temporal alone owns the fixture's durable intent/completion. A fixed Ray task
receives two digests, checks the binary bytes and invokes only its fixed self-test
command. No user closures, S3 credentials, owner keys or blob payloads are sent to
Ray. No Docker socket is mounted into it. The trusted host driver uses Docker exec
and a direct internal Temporal IP on a Linux Docker host; no service ports or
network boundaries are added. The host retains fixture-only object-store access.

The trigger and fake self-test receipt are conditionally created in the versioned
fixture bucket and read back by exact version with byte-length/SHA-256 checks.
SQL's separate `postgres.m0_fake_runs` table stores only the harness evidence JSON,
which is read back and compared. It is not the future production registry or an
execution/disclosure authority. Actual workflow history is replayed before success
is reported. Only a public, explicitly fake trace is uploaded from CI; no credentials,
raw history, object data, or signing keys are uploaded.

## Package trust and setup

`config/fake-workflow/releases.json` independently pins the exact source and every
asset SHA-256 from the two approved experimental publications. Installation fails
on changed bytes. Cosign additionally verifies the exact main-branch release
workflow identity, GitHub OIDC issuer, source SHA and workflow_dispatch trigger,
with certificate/transparency verification enabled. Signed subjects, fabric spec
binding, experimental labels and native archive/binary bindings must agree.
This two-component fixture admission is separate from M0-PR17's five-component
candidate policy and the later M0-PR32 release-set gate; it grants no production
qualification or general package authorization.

Run from a fresh Linux x86_64 checkout with local Docker:

```sh
uv sync --locked
uv run --locked python tools/install_cosign.py
uv run --locked python tools/workflow_assets.py install
uv sync --locked --extra conformance
uv run --locked --extra conformance python tools/integration.py smoke
```

The optional dependency is a hash-pinned HTTPS release wheel; no local-path or
sibling source dependency is added. Existing uv/SDK/Protobuf pins are retained.
The signature check precedes the optional SDK installation in CI. A consumed
package must be reviewed and pinned before its code is trusted; a mutable tag
name alone is insufficient.

Offline gates (after setup) provision nothing:

```sh
uv run --locked --extra conformance python tools/verify.py fast
uv run --locked --extra conformance python -m unittest discover -s tests -v
```

`uv run --locked --extra conformance python tools/verify.py full` runs service
qualification, this fake workflow and the existing network measurements in one
owned stack, then tears down its containers/networks/volumes and removes generated
credential files. The standalone smoke command owns and tears down its own fresh
stack. Public reports are retained under `build/integration/<project>/`.
Abrupt host/runner termination still requires owned-fixture cleanup; no production
recovery claim is made. Heavy/live checks run on CI rather than the busy desktop.

The integration adapts Redpanda's existing rpk claim-check transport and consumes
Temporal's Worker/Replayer and Ray task APIs through thin test adapters. It adds
no Kafka client dependency or custom scheduler. Fabric is Apache-2.0; its optional
Temporal SDK is MIT and runs in the Python 3.14 control environment. Ray stays in
its existing pinned Python 3.12 image; no host Ray dependency is added.
