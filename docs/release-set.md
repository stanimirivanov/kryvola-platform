# M0 integration input admission

M0-PR17 admits inputs for integration testing. It never deploys services, imports
or executes artifacts, enables profiles or asserts production readiness. The
foundation inventory stays separate. The generated spec preview.10 schema at
`1a5b57a590487ba116913050af8041f5e5f1fb52` defines the release-candidate format;
no platform-authored wire schema is introduced.

## Trust and bindings

`ReleasePolicy` is supplied by a trusted caller, independently of candidate data.
It selects an exact candidate SHA-256, intended use and reviewer public key, plus
five `ComponentPolicy` entries selecting exact artifact references, builder IDs,
build types and signing public keys. There are no default keys and no policy
loader that trusts a candidate's own assertions. Key enrollment, custody, rotation,
revocation and freshness remain operator responsibilities. Success returns no
authorization token and changes no state.

The candidate must remain `M0_CONTRACT_CANDIDATE`, `UNQUALIFIED`,
`production_ready=false` and `profile_enabled=false`. Its reviewer signature binds
the exact bytes, five component pins, contract bundle, model/report hashes and
`REVIEWED_ALLOWED` legal disposition for the independently selected intended use.
Legal evidence bytes must match every declared digest. Authenticating a review
assertion does not establish the reviewer's expertise or legal correctness.

Each local artifact is hashed, then matched to its independently selected subject
and signed [in-toto/SLSA provenance](https://slsa.dev/spec/v1.2/build-provenance).
This initial publisher-adapter profile requires:

- Statement type `https://in-toto.io/Statement/v1` and predicate type
  `https://slsa.dev/provenance/v1`, with exactly one subject/name/SHA-256.
- The configured `buildType` and `runDetails.builder.id`.
- Exact `externalParameters` containing only `repository`, full-commit `ref`,
  and `version`; source repositories are the five Kryvola GitHub repositories.
- One resolved dependency with URI `git+` followed by that repository URL and
  `digest.gitCommit` equal to the pin. One dependency with URI
  `urn:kryvola:spec-bundle` must bind the consumed manifest SHA-256. Duplicate or
  conflicting entries for these URIs fail. Other SLSA extension fields are ignored.

These are policy checks on authenticated builder assertions, not a SLSA level or
proof of dependency completeness. Other publisher formats need explicit adapters.
OCI subjects require `REGISTRY/REPOSITORY@sha256:DIGEST`; tagged references fail.
Package/bundle HTTPS references require the exact version as a path segment and
`#sha256=DIGEST`, without query strings or credentials. No reference is fetched.
The later PR24/32 gates verify real published images/packages, OCI structures,
SBOMs and publication workflows; opaque local blob admission does not replace them.

Model/report bytes are hashed and structurally validated. Workload, contract,
source, model, evidence-policy and engine-build bindings must agree across records.
Full measurement semantics, crypto parameters, benchmark reproducibility and
cryptographic feasibility remain owning-spec and later qualification gates.

## Signature mode and limits

The standalone verifier is [Cosign v3.1.3](https://github.com/sigstore/cosign/releases/tag/v3.1.3)
(Apache-2.0), pinned by official release-asset SHA-256 for Linux x64 and
rechecked before execution. Installation is an explicit build/CI action, never
part of admission. It adds no Python dependency. The
[pinned-key blob interface](https://github.com/sigstore/cosign/blob/v3.1.3/doc/cosign_verify-blob.md)
uses a local public key and Sigstore bundle with `--insecure-ignore-tlog --offline`.
That mode intentionally provides **no** Fulcio/OIDC identity, transparency-log or
trusted-timestamp guarantee. It is not keyless verification. Public keys are
supplied independently, never selected from bundle metadata. Future keyless
publication gates must enforce exact issuer/identity and their required log policy.

Candidate, provenance, evidence and signature metadata are capped at 128 KiB each;
public keys at 8 KiB. JSON requires strict UTF-8, unique keys and finite values.
Artifacts are regular non-symlink files, streamed in 1 MiB chunks up to 1 GiB each.
Every verifier subprocess has a 30-second timeout, a private temporary HOME and
no ambient cloud/OIDC credentials. Output is captured and suppressed; public
failure codes contain no original validation diagnostics or exception chains.
This is not an OS sandbox. The executable, policy and filesystem remain trusted.
Callers must keep digest identities and reverify bytes at later use; checked paths
are not durable handles and may change after this function returns.

## Verification

Focused local checks use `uv run --locked python tools/verify.py fast` and
`uv run --locked python -m unittest discover -s tests -v`. Policy tests mock the
crypto call explicitly. The full harness sets `KRYVOLA_RELEASE_SIGNATURE_TESTS=1`,
requires the installed pinned binary, and tests actual signed-fixture acceptance,
wrong-key rejection and altered candidate/provenance rejection. Synthetic private
keys exist only in a temporary CI directory and are removed afterward.

Explicit setup: `uv run --locked python tools/install_cosign.py`, then
`uv run --locked python tools/verify.py full`. The existing PR workflow runs this
gate plus the wheel build without cloud credentials. CI results are not inferred
from configuration. The checked-in unresolved example cannot pass admission.

## Existing publisher admission (M0-CLOSE-PR7)

Components may explicitly select `PublisherPolicy` with independently configured
publication source, exact signed-manifest SHA-256 and selected subject filename.
`PublicationInput` supplies that manifest/signature and the exact local subject
files. Empty component key/provenance/signature fields select this mode only when
the trusted policy explicitly names a publisher. Mixed modes fail. The release
candidate still requires its separate reviewer signature and existing legal gate;
publisher authentication is not specialist approval or M0 acceptance.

The adapter recognizes spec, fabric, ML, platform and fake-engine manifests without
pretending their provenance has a separate signature. The signed manifest binds
all artifact/provenance hashes. It checks exact repository/workflow, GitHub issuer,
source and workflow_dispatch, plus expected subject, builder/build type, labels
and source/contract dependencies. Existing pinned-key provenance admission remains
unchanged. Existing workflow asset verification now uses the same isolated keyless
Cosign boundary, retaining its independently pinned files and role checks.

Keyless verification uses checksum-pinned Cosign with isolated credentials and
public trust-root/log access; it is not an offline verification guarantee. There
is no caller-selected issuer, regex identity or ignore-log switch in this mode.
The verifier never installs tools or downloads release artifacts.

Wheel candidates use the explicit SemVer label `0.1.0-dev0.g<FULL_SHA>` while their
signed producer version remains `0.1.0.dev0+g<FULL_SHA>`; neither signed record is
rewritten. References must be the exact source-addressed GitHub asset URL with
percent-encoded filename and SHA-256 fragment. Spec publication commits may differ
from the frozen contract source: the bundled generated manifest must match the
consumed contract bytes. Contract/native adoption checks remain separate.

Fake OCI mode uses subject `@oci-manifest`: the supplied local artifact is the
exact raw registry manifest whose SHA-256 is the independently selected image
digest, not a Docker-save tar or image config. The signed OCI record binds that
reference and archive/Dockerfile hashes. This authenticates the publisher's
relationship assertion; it does not pull/run an image or independently verify the
related archive. Existing engine OCI verification and later composition gates must
check archive contents, image signatures and digest-pulled conformance before use.
Fake archive admission remains supported and cannot authorize crypto-role archives.

Tests exercise producer shapes and routing with mocked keyless results; actual
GitHub OIDC/log verification requires published inputs and network access. Missing,
wrong or unauthenticated inputs cannot become acceptance through these adapters.
