# ADR-0001: Compose published M1 artifacts in separate local roles

Status: Proposed in Platform #48
Date: 2026-11-13

M1-PR30 requires published runtime artifacts, exact permission and schema pins,
real service startup, supported migrations and cleanup. Frozen M0 fixtures and
successful inference qualification have separate scopes.

Use `config/m1.lock.json` as the independent admission policy for the published
Fabric, ML and owner-approved development Engines artifacts. Verify all bytes
before invoking publisher verification or released programs. Each role image
installs only its published wheel/archive and hash-locked binary dependencies;
no sibling source checkout is an input. Temporary local image addresses are
recorded by the runner rather than substituted for publisher image identities.
The Engine image uses its signed immutable registry reference.

Retain the actual distinct Spec revisions: Fabric/ML a5277f8 and Engines 52a5098.
The previously recorded compatibility assessment on Platform #48 found all 103
common root and 24 common native files unchanged, with only additive HTTP/schema
contracts. Admission also compares the actual published Fabric/ML descriptor,
schemas and limits bytes. This approves this release combination only, not a
range of Spec versions or an unreviewed future repin.

Use ephemeral host SPIRE with Unix peer-UID attestation for the Linux/rootful
Docker fixture. The server keys stay in a private invocation folder; workloads
receive only the public Workload API socket. Runtime, coordinator, owner and
compute have distinct Unix/SPIFFE identities with 45-second renewable SVIDs,
within the published runtime's 60-second bound. The bootstrap token and UID selectors
are local fixture mechanisms, replaced by deployment-specific attestation in
M1-PR31. Separate fresh PostgreSQL accounts, S3 identities and broker mTLS client
certificates keep startup credentials apart. Compute receives none of those
credentials or the owner volume. Capabilities are limited to volume initialization
with CHOWN; no container receives the Docker socket or host networking.

The published runtime exposes an ephemeral loopback mTLS listener; an opaque
bounded TCP relay makes it reachable inside the internal control network without
terminating or reinterpreting authentication. A second loopback relay lets the
published coordinator use the real Ray dashboard through its existing API.

The Engine API is per-assignment, not a generic daemon. Start one public golden
assignment with no valid bearer grants, then query its real status over its
private Unix socket. Do not call Execute. The owner role loads its actual native
library and SDK with private storage and its own identity; it does not create
owner keys or pretend an OS keyring is initialized. Later inference/custody gates
must supply real operator authorization and keyring integration.

Alternatives rejected: rebuilding sibling implementations would bypass published
provenance; reusing M0 fake roles would not test M1 services; granting permissive
startup capabilities or claiming a successful inference from health checks would
misrepresent qualification. No production profile is enabled by this decision.

Consequences: the local adapter and qualification code exceed the original
400–500 line estimate because published services have distinct startup, identity
and packaging interfaces. They remain one coherent PR30 integration boundary;
cryptographic implementation and successful inference stay in their owning tasks.
