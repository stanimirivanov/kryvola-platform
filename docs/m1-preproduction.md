# M1 preproduction boundaries

M1-PR31 / Platform #52 adds a fixed boundary profile; it does not deploy or qualify
preproduction services. [ADR-0002](decisions/0002-preproduction-boundary-profile.md)
records trust boundaries and judgment calls. M1-PR32 owns real compromised-worker
network/authorization probes, and PR33 owns successful inference qualification.

```sh
uv run --locked python tools/m1_preproduction.py check
uv run --locked python tools/m1_cluster.py install
uv run --locked python tools/m1_cluster.py ci
```

`check` is offline and provisions nothing. `install` downloads checksum-pinned
Linux x86_64 kind and official CRD schemas into ignored `build/`. `ci` requires
local Docker and creates a unique, disposable Kubernetes 1.37.0 kind cluster. It
uses kubectl inside the digest-pinned node with that node's own admin config;
it never reads the operator's ambient kubeconfig or targets a cloud cluster.
The privileged kind node is test infrastructure, not an application template.

The API gate creates namespaces/policies/PodTemplates and registers CRD schemas.
It does not install Cilium, SPIRE or application controllers, start application
Pods, generate keys, or run inference. Five positive server dry runs and fifteen
Pod Security denials must pass, then the owned cluster is deleted. The public
`build/m1-admission-report.json` explicitly distinguishes API admission from
unperformed dataplane/identity qualification. Full verification includes this gate;
CI runs it in parallel with the existing verification and M1 startup jobs.

Edit the generator, not the generated projection. Regenerate and verify with:

```sh
uv run --locked python tools/m1_preproduction.py template > deploy/m1/boundaries.json
uv run --locked python tools/m1_preproduction.py check
```

The checked-in projection contains image parameters and is not a deploy command.
After independently verifying wrapper-image provenance against PR30's published
M1 artifacts, an operator can render reviewable, immutable image references:

```sh
uv run --locked python tools/m1_preproduction.py render \
  --runtime-image "$M1_RUNTIME_IMAGE" --ray-image "$M1_RAY_IMAGE" \
  --owner-image "$M1_OWNER_IMAGE" > build/m1-preproduction.json
```

All three refs require `@sha256:` digests; the Engine ref is bound to the signed
M1 image metadata pin. This renderer does not attest externally supplied wrapper
images. Rendering neither enables the development profile for production nor
applies any resource.

Before instantiating these templates, a trusted operator/provisioner must supply:

- Cilium 1.20.4 (or a separately reviewed compatible version) enforcing policy,
  and SPIRE/CSI/controller-manager infrastructure with class `m1-preproduction`,
  Kubernetes workload attestation and a read-only `agent.sock` CSI mount. No host
  UID selector is used for preproduction identity. No application SA gets API RBAC.
- Distinct nodes for `kryvola.io.node-restriction.kubernetes.io/domain=owner|control|compute|data`, audited and
  labeled `kryvola.io.node-restriction.kubernetes.io/core-dumps=disabled` and `kryvola.io.node-restriction.kubernetes.io/swap=disabled`. Disable
  piped host core collection; zero core limits can otherwise be ignored. Encrypt
  persistent custody/attempt storage and keep node debug/administrative access
  outside workload authority. The admission test does not attest these node facts.
- The published, pinned PostgreSQL/S3/Redpanda/Temporal services and supported
  migrations, DNS/services matching the profile's namespace and `kryvola.io/role`
  selectors, and audited per-role configuration Secrets. Backend ingress is
  explicitly limited to required callers. Broker-admin credentials are absent.
- An isolated `m1-attempt-private` claim/assignment for each physical compute Pod,
  with private UID-65532 files and no owner/release secrets. The trusted launcher
  must stamp unique per-attempt names/routing before concurrent use. Ray and
  Engine share this Pod so the private Engine socket is local, not a remote PVC
  socket. Scratch and shared memory are bounded tmpfs; native runner limits remain.
- The separate `m1-owner-custody` volume and real owner OS keyring integration.
  No plaintext owner keys, unlock passphrases or owner storage are mounted into
  compute/control. No empty credential defaults or permissive grants are created.

Required enforcement sources: [Kubernetes restricted Pod Security](https://kubernetes.io/docs/concepts/security/pod-security-standards/),
[NetworkPolicy semantics](https://kubernetes.io/docs/concepts/services-networking/network-policies/),
[SPIFFE CSI](https://github.com/spiffe/spiffe-csi),
[Cilium deny policies](https://docs.cilium.io/en/stable/security/policy/language/),
and [Linux core handling](https://man7.org/linux/man-pages/man5/core.5.html).

Domain/core/swap node labels use the protected NodeRestriction prefix. Operators
must enable the Node authorizer and NodeRestriction admission plugin and assign
these labels only after auditing nodes. The disposable API gate verifies that
a node identity can change an ordinary own-node label but cannot forge the
protected owner label. This does not attest the underlying physical node facts.
