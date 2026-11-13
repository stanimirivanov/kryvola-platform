# ADR-0002: Use a fixed, restricted preproduction boundary profile

Status: Proposed in Platform #52
Date: 2026-11-13

M1-PR31 defines deployment boundaries before M1-PR32's compromised-worker probes
and M1-PR33's actual inference qualification. Compose startup cannot establish
Kubernetes isolation. No preproduction application deployment is authorized here.

Generate the fixed Kubernetes profile from `tools/m1_preproduction.py`; commit its
reproducible projection in `deploy/m1/boundaries.json`. Exact-profile validation
rejects additions as well as changed rules. It is intentionally not a general
Kubernetes policy validator. Independent tests assert role isolation, mandatory
controls and narrow backend ingress; a real local API gate validates resources
against Kubernetes and the exact published Cilium/SPIRE CRD schemas.

Separate owner, control, compute and data namespaces use restricted Pod Security,
default deny, resource quotas and explicit peer/port permissions. Five service
accounts have no ambient API token or RBAC grants. Runtime, workflow and messaging
receive distinct, explicitly selected Secret keys. Compute receives no Secret
volume, owner volume, database or broker credentials. Ray and its per-assignment
Engine share one compute Pod and private attempt volume: their Unix socket must
be local to the same node/kernel, and they form one compute trust domain. A trusted
provisioner must instantiate a fresh Pod/claim for each physical execution.

Adopt SPIFFE CSI delivery instead of workload hostPath mounts. ClusterSPIFFEID
registrations bind namespace, role labels and service account to the existing
runtime/workflow/worker/owner policy identities, with 45-second SVIDs and no admin
or downstream authority. SPIRE/CSI/controller infrastructure is an external trusted
prerequisite, not a privileged workload bundled into this application profile.

Require Cilium's overriding host/metadata deny in addition to standard
NetworkPolicy allow lists. Standard NetworkPolicy alone does not express the same
host-traffic restriction. Cilium and its enforcing dataplane must be installed
before application Pods are instantiated. The local admission fixture installs
only CRDs, not a Cilium dataplane or an identity controller: its report explicitly
marks dataplane and identity qualification false. PR32 owns those live probes.

Read-only roots, dropped capabilities, seccomp, finite per-container resources,
256Mi memory-backed scratch and a core-limit launcher restrict each role. Require
operator-audited, separate domain nodes labeled for disabled swap/core collection.
A zero RLIMIT_CORE alone is insufficient with a piped host core collector; the
profile must not schedule onto unaudited nodes. Labels attest an external node
configuration. NodeRestriction-protected keys prevent kubelet self-labeling;
require the Node authorizer and NodeRestriction admission. This PR neither changes host sysctls nor proves physical node
isolation. Owner custody uses only the owner-domain volume/keyring integration.

The renderer requires three independently selected digest-pinned wrapper images;
there is no mutable/default application image. Their provenance must be verified
by the operator from PR30's published artifact assembly before rendering. The
Engine OCI reference is independently bound to the existing signed M1 image
metadata hash. Rendered references alone do not prove wrapper-image provenance.
No component repin, release, grant, keyring initialization or production approval
is introduced.

Use a unique local kind cluster, private kubeconfig and exact kind/node/schema
pins for disposable admission. Never use an ambient Kubernetes context. Real
server dry runs must admit all five role Pods and reject privileged, host-network
and host-mount controls specifically through Pod Security. Rejecting an internally
inconsistent spec is not evidence for that control. Cleanup targets only the
claimed generated cluster, including partial-creation and test-failure paths.
