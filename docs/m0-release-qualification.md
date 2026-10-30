# M0 release-to-qualification operator procedure

This procedure connects existing component publishers, unsigned candidate assembly
and exact composition qualification. M0, legal/security decisions and ratification
remain pending. Following these steps does not authorize publication or acceptance.
Run only the stages separately authorized by the operator; the commands below are
instructions for a future run, not evidence that any stage has completed.

## 1. Agree inputs before running tools

Obtain an independently selected intended use, exact five-component selection,
public model descriptor and matching synthetic measurement report. Record full
source revisions, artifact references and SHA-256 digests, publisher sources,
manifest digests, selected subjects, builder IDs and build types as specified in
[candidate inputs](m0-candidate.md). Do not derive trusted policy from incoming
manifests or replace these inputs with the synthetic rejection example in config.

Identify a non-root Linux x86_64 qualification host with Docker/Compose, registry
and GitHub access, Python 3.14.7 and uv 0.12.5. Arrange an operator-approved durable
evidence destination. Missing access, artifacts or storage are blocking inputs,
not reasons to skip checks. Keep credentials, private keys and confidential review
material outside the public input/evidence directories.

Reviewer identities/authority, independent trust enrollment, scoped legal and
parameter/security decisions, operational disposition and final ratification are
separate pending inputs. Candidate assembly and qualification can gather evidence
for review; neither supplies those decisions. TFHE/SP1 distribution/service
permissions stay DENY. This route supports the public fake-engine baseline only.

## 2. Prepare and verify component publications

Each of the five repositories already has `.github/workflows/release.yml`.
Dispatch is main-only and runs qualification followed by publication. **These
workflows are not qualification-only dry runs.** Do not dispatch them without
explicit authorization to publish component artifacts. No push or PR dispatches
them. Final acceptance has a different, disabled-by-default workflow described in
[acceptance publication](m0-publication.md); leave it disabled and undispatched.

Use each repository's publication instructions and pinned toolchains. Local build
qualification is distinct from a signed published component: locally generated
test signatures do not substitute for the publisher's GitHub OIDC evidence.
Missing Spec, ML or Platform releases must be supplied before candidate assembly;
independently check whether existing Fabric/Engines releases are compatible.
Do not republish an existing tag or overwrite assets to repair a failed release.

After authorized publication, download every exact manifest subject plus
manifest.json and manifest.sigstore.json into separate component directories.
Use independently selected full source revisions and manifest/subject hashes;
do not select mutable latest tags or trust a package-supplied key. For an archive
selection the local asset root has spec/, fabric/, engines/, ml/ and platform/.
Keep the original assets available for re-verification throughout the procedure.

Existing consumer verification commands, from the corresponding repository root:

```sh
# Spec: install the pinned verifier first with node tools/release.mjs install.
node tools/release.mjs verify DOWNLOADED_SPEC_ASSETS FULL_SPEC_PUBLICATION_SHA
# Fabric, ML and Platform: install with uv run --locked python tools/install_release.py.
uv run --locked python tools/release.py verify --folder DOWNLOADED_COMPONENT_ASSETS --source FULL_PUBLICATION_SHA
# Engines archive: install with uv run --locked python tools/release.py install.
uv run --locked python tools/release.py verify --output DOWNLOADED_ENGINE_ASSETS --publish-check
```

Uppercase arguments are operator-supplied placeholders, not checked-in files.
Engine verification also needs independent expected source/manifest/subject pins
in the candidate selection; its standalone CLI does not take an expected-source
argument. Candidate assembly enforces those pins. For OCI, follow the separate
engine publication instructions and [candidate layout](m0-candidate.md); raw
registry manifest bytes, image signatures and the linked archive are required.
Do not substitute a Docker-save archive. Prefer the compatible archive route
unless OCI is explicitly selected and its additional qualification is arranged.

## 3. Freeze the compatible Platform checkout and environment

Use a clean Git checkout at the selected Platform release's exact full source
revision, independently verified against the publication. The signed driver.tar
must match its allowed tracked files. An extracted driver alone has no Git source
identity and cannot replace this checkout. Inspect before proceeding:

```sh
git rev-parse HEAD
git status --porcelain=v1
```

Compare HEAD with the independently selected Platform source and require empty
status. Preserve unrelated work; use a separate clean checkout when necessary.
Do not edit files, regenerate locks or install sibling implementation source in
this checkout. Keep selection inputs, downloaded assets and output outside it or
in its existing ignored build/ directory; output parents must already exist.

Compare selected Fabric/Engines sources and all runtime asset hashes against
config/fake-workflow/releases.json. The Fabric wheel dependency is also pinned in
pyproject.toml and uv.lock. Service images and upstream spec evidence have their
own existing pins. An incompatible selection needs a reviewed pin/dependency
change and a new Platform release before qualification; never rewrite the signed
driver or its pins during the run. Spec's consumed contract source can differ
from its publication source, as documented in [candidate inputs](m0-candidate.md).

From the exact Platform checkout, prepare the locked environment and tools:

```sh
uv sync --locked --extra conformance
uv run --locked --extra conformance python tools/install_cosign.py
uv run --locked --extra conformance python tools/workflow_assets.py install
uv run --locked --extra conformance python tools/release_conformance.py fetch
uv run --locked --extra conformance python tools/verify.py fast
```

Installation/download steps access the network but publish nothing. The fetch
needs gh access to the pinned upstream run; missing/deleted evidence fails closed.
These setup commands neither install the selected ML/Platform release wheels nor
qualify a five-component set. The ordinary full CI fixture gate is also a separate
claim; successful CI is not this candidate's composition report.

After all uv project setup, replace the project installation with the three
independently verified selected wheels, without resolving new dependencies:

```sh
uv pip install --python .venv/bin/python --no-deps --reinstall FABRIC_WHEEL ML_WHEEL PLATFORM_WHEEL
uv pip check --python .venv/bin/python
```

Wheel arguments are exact local paths under the verified asset root, not globs.
The current locked conformance dependencies include the baseline ML dependencies;
if selected wheel requirements do not fit, stop for a reviewed lock/release update.
Do not resolve unpinned dependencies to make the run pass. No editable install or
source build is an acceptable substitute for the selected wheel bytes.

From this point use .venv/bin/python directly. An ordinary uv run/uv sync can
restore the editable project and invalidate the selected installed environment.
If resynchronization occurs, repeat installation and all subsequent qualification
steps with fresh outputs. The qualifier checks versions, import origins and exact
installed package resources, not just pip metadata.

## 4. Assemble the unsigned candidate, then qualify it

Use absolute paths for operator inputs/assets and fresh output destinations so
there is no ambiguity about which retained bytes were used. From the same exact
Platform checkout and prepared environment:

```sh
.venv/bin/python tools/m0_candidate.py --selection OPERATOR_SELECTION --model MODEL_JSON --measurement MEASUREMENT_JSON --assets ASSET_DIRECTORY --output FRESH_CANDIDATE_DIRECTORY
.venv/bin/python tools/m0_composition.py --bundle FRESH_CANDIDATE_DIRECTORY --assets ASSET_DIRECTORY --output FRESH_EVIDENCE_DIRECTORY
```

Run the second command only after the first succeeds. Assembly verifies publisher
bindings and writes the unsigned, untested candidate/lock. It does not execute
downloaded components. Only public models and explicitly fake SYNTHETIC_FIXTURE
measurements with NONE evidence are supported; real crypto campaigns stay separate.

Composition reassembles the candidate and checks the clean source, driver,
installed wheels and independently installed runtime assets before provisioning.
It runs the existing network/fake traversal, replay, conformance, admission
negative controls and isolation pipeline. OCI selections add image/archive checks.
Success requires cleanup and post-run re-verification; do not reuse old reports
or run a standalone smoke test as a substitute. See [composition](m0-composition.md)
for the exact scope and limitations.

## 5. Retain results and stop before acceptance

Preserve the successful composition directory, report.json and evidence.tar with
the exact candidate inputs and original publisher assets. Independently record
their hashes, component sources and run identity in the review inventory. Copy
only authorized public evidence to the agreed durable store; do not rely on the
seven-day CI transfer retention. Retain binaries/assets separately where needed
for later verification: the composition archive does not embed them.

A successful qualification remains m0_accepted=false and m1_admitted=false.
It establishes host-trusted non-production observations, not authenticated human
review, real inference, production security or service latency qualification.
Next, reviewers need a new packet bound to this exact composition and a successor
ratification preserving the pending history. The null-composition pending packet
cannot approve these future bytes. See [acceptance inputs](m0-acceptance.md) and
[review authentication](review-evidence.md). Do not prepare, sign or publish an
acceptance artifact while required approvals are pending.

## Failure recovery

- Missing/invalid signatures, hashes, inputs or upstream evidence: stop and retain
  the failure context; obtain independently verified replacements or reviewed
  successor evidence. Never weaken verification or trust incoming policy.
- Pin/package/source mismatch: resolve through a scoped reviewed change and new
  publication if needed. A changed selection invalidates affected candidate and
  qualification evidence; assemble and run again.
- Live/cleanup failure: no successful composition is established. Inspect the
  owned run and cleanup state before retrying; do not delete unrelated services.
- Interrupted output or partial publication: retain and inspect partial state,
  use fresh output paths and supersede releases through the authorized process.
  Never overwrite output directories, tags or signed evidence.
- Changed approved subjects: obtain a new packet and affected decisions. Passing
  tests, a merge or a publisher signature never supplies legal/security approval.
