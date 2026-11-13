# M1 compromised-worker qualification

Use the existing Linux x86_64/rootful local Docker prerequisites from
[M1 composition](m1-composition.md), with the locked development environment. Never use a
production Docker daemon or Kubernetes context.

```sh
uv sync --locked
uv run --locked python tools/install_release.py
uv run --locked python tools/m1.py install
uv run --locked python tools/m1_cluster.py install
uv run --locked python tools/m1_live_infra.py
uv run --locked python tools/m1_isolation_local.py
uv run --locked python tools/m1_isolation_cluster.py
```

Both gates fail closed on missing artifacts, tools, positive controls, identity,
network enforcement, unexpected statuses or leaked fixture material. Cleanup
removes only their owned local resources. Public reports are
`build/m1-local-isolation.json` and `build/m1-cluster-isolation.json`; their input
hashes and source identify the exact qualification. Never upload fixture folders,
Workload API output, private kubeconfigs, or unfiltered debug logs.

The worker attempts foreign-tenant reads using a valid own-tenant credential,
privileged cancellation, output-grant issuance, and a registry read using a stolen
valid coordinator credential under the worker identity. Expected errors are
exact `403 FORBIDDEN`, not a malformed body, nonexistent route or expired token.
Operation snapshots must remain unchanged; legitimate coordinator cancellation
then proves the privileged route is usable. Canonical manifests come from the
published ML SDK, and the real finalized artifact is read with current-fence
credentials before and after the attacks. Fixtures use public synthetic bytes.

The worker inventory checks UID/capabilities, actual failed root/mount mutations,
absence of the owner library, owner volume, release/database credentials, API
service-account token and Docker socket. A live owner-side canary is checked
independently. Metadata, broker administration and database tests distinguish
application authorization, network enforcement and missing credentials.

Read [the qualification decision](decisions/0003-compromised-worker-qualification.md)
for the explicit overlay and trusted-host limits. These reports do not certify
host core/swap hardening, physical separation, real private-key custody, or the
complete owner-to-owner inference path. PR31's separate API-admission gate and
all M0 checks remain required.
