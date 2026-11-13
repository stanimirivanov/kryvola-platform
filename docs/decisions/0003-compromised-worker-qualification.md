# Compromised-worker qualification with live enforcement

M1-PR32 extends PR31's admission-only profile with actual Cilium enforcement,
SPIRE node/pod attestation, CSI identity delivery, and published Fabric runtime
calls. Neither admission success nor an unreachable target is isolation evidence.
The independent local and Kubernetes gates require valid coordinator and artifact
operations before and after attacks, exact application denials, and live denied
target controls. The immutable M1 component pins remain unchanged.

The local gate instruments the actual Engine filesystem and uses trusted probe
containers sharing its network namespace and UID. Local SPIRE's Unix UID attestor
cannot distinguish those helpers from Engine; the host/Docker operator remains
trusted. Postgres transport is reachable locally, so that negative must fail with
`no password supplied`, rather than a connection error. Metadata is a synthetic
noncredential endpoint on the private data network. Broker administration probes
use a bounded relay to the real healthy broker admin API.

The Kubernetes gate installs checksum-pinned official Helm/Cilium/SPIRE charts,
CRDs and digest-pinned images in an owned four-node KIND cluster. PyYAML 6.0.3
(MIT, development dependency) safely parses the verified chart output. Chart
identity seeds are disabled; only PR31's namespace/role/service-account
registrations are applied, with matching cache-selection class labels. SPIRE also
binds the Pod UID and attested node.
Kubelet certificates are verified by their DNS SAN using the node hostname; the
trusted SPIRE agents use the node network for hostname resolution. The chart's
insecure skip default is not used.
There is no ambient kubeconfig or deployment to an existing cluster.

`tools/m1_isolation_profile.py` is an explicit **synthetic-data test overlay**, not
a deployment profile: it retains the reviewed identities, security contexts,
core-limit launcher and exact application network rules. It substitutes bounded
memory volumes for real custody/attempt claims, launches the published worker
image under instrumentation, and adds a trusted instrumenter in the same compute
Pod. The native Engine container's filesystem is checked separately. Coordinator
and owner helpers consume published images; actual Fabric, Postgres and S3 serve
the authorization and artifact cases. The owner reads a fresh public canary from
its private volume; compute must have neither that volume nor the owner library.
No FHE private key is generated, copied into compute, or placed in logs.

KIND nodes share the host kernel. The overlay removes only the audited core/swap
node-selector predicates and never forges their labels or changes host sysctls.
Domain placement is logical, not physical isolation. Physical separation, swap,
piped core collectors, host root, Docker administrators and production custody
remain **unqualified trusted-host assumptions**. The unchanged deployment profile
continues to require audited host labels. PR33 owns real encrypted inference.

The cluster metadata control binds a public sentinel to `169.254.169.254` only
inside the disposable compute node's network namespace. The same worker must
reach it before policies; Cilium must subsequently block it even with an
adversarial ordinary allow policy. Its listener remains healthy afterward.
A synthetic broker admin listener provides the cluster network control; broker
implementation/credential enforcement is covered by the local real-broker gate.
Postgres network denial is distinct from the local credential denial.

Only structural, source/input-bound reports are emitted. Credentials, canaries,
PEM private keys and encoded representations are scanned before report writes;
runtime denials must be present and redacted. Evidence is not a general proof
against arbitrary native code or an entire production threat model. A compromised
host or trusted fixture authority can defeat these boundaries.

This exceeds the plan's initial 300–450 LOC estimate because PR31 installed only
schemas: live CNI, SPIRE/CSI and their pinned installation/cleanup are necessary to
exercise the planned preproduction boundary. They do not add a production
orchestration product or change the authoritative milestone's acceptance criteria.

Qualification exposed missing local Ray privilege restrictions and nondeterministic
Seaweed collection growth within the fixture's two slots. Compose now enforces
read-only roots, dropped capabilities, no-new-privileges and a zero core limit for
both workers, with bounded Ray scratch. Seaweed grows one volume per collection
in both fixtures; the existing volume/storage limits are preserved. Neither fix
changes a published component or grants new application authority.

References: [Cilium KIND installation](https://docs.cilium.io/en/stable/installation/kind/),
[SPIRE hardened charts](https://github.com/spiffe/helm-charts-hardened),
[controller cache/class behavior](https://github.com/spiffe/spire-controller-manager/blob/v0.8.0/docs/spire-controller-manager-config.md),
and [Seaweed growth configuration](https://github.com/seaweedfs/seaweedfs/wiki/Optimization-for-Many-Small-Buckets).
