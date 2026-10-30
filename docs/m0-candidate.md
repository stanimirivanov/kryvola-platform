# Exact unsigned M0 candidate assembly

`tools/m0_candidate.py` resolves five independently selected publisher inputs into
new candidate/lock bytes. It does not sign, test, publish, ratify or accept the
composition. The existing synthetic config/release-candidate.json is never edited.
No real five-component selection or missing approval is invented by the tool.

## Inputs

Provide an operator-owned selection JSON, separately obtained model/measurement
files, and local downloaded publication assets. No network download or sibling
checkout is used. Existing keyless verification may access public trust roots/logs.
Install the pinned verifier with `tools/install_cosign.py` before verification.

Selection has exactly version (integer 1), intended_use (nonempty description),
model_sha256, measurement_sha256 and components. Components must contain exactly
spec, fabric, engines, ml and platform. Every component explicitly supplies:

- source_revision, version, artifact_sha256: candidate component identity.
- reference: exact immutable subject reference.
- artifact_filename: basename of the local selected artifact.
- publisher_source, manifest_sha256, subject: independent publisher policy pins.
- builder_id, build_type: expected provenance identity and type.

None of these trust choices is inferred from incoming publisher metadata. Use the
existing publisher adapter's format/version/reference rules from release-set.md.
Spec source/version remain the consumed contract revision/version; the separate
publisher source may be newer. Other sources must match publisher provenance.
Wheel versions map to the documented SemVer candidate labels.

Under ASSET_DIRECTORY, each component directory contains manifest.json,
manifest.sigstore.json and every exact manifest subject filename. Names must be
safe basenames and files cannot be symlinks. OCI evidence uses the normalized
filenames from the engine publication documentation; artifact_filename identifies
the raw registry manifest bytes, not a Docker-save archive. Its reference must
match the independently pinned raw manifest SHA-256 exactly.

All publisher signatures and subject hashes are verified with existing adapters.
Model and measurement hashes must match selection, and generated schema/workload,
model-file, contract and engine-build bindings must agree. Only public-model,
explicit fake-engine SYNTHETIC_FIXTURE reports with NONE evidence are supported.
Software entries may name engine-image and benchmark-harness only; real crypto
or service measurements cannot be imported or relabelled. Research campaign data
remains separate immutable evidence. Fake engine archives additionally require
only engine/LICENSE/Cargo.lock, matched two-build binary hashes and no TFHE/SP1
SDK dependency. Assembly never executes the downloaded engine or driver.

## Invocation and output

```sh
uv run --locked --extra conformance python tools/m0_candidate.py --selection OPERATOR_SELECTION --model MODEL_JSON --measurement MEASUREMENT_JSON --assets ASSET_DIRECTORY --output FRESH_OUTPUT_DIRECTORY
```

Output's parent must exist; the output directory must be new. Before creating it,
all input bindings and publishers must pass. Failed/interrupted filesystem writes
may leave a partial directory: retain/inspect it and use a fresh destination,
never overwrite it or treat an incomplete lock bundle as accepted evidence.

Output preserves exact selection/model/measurement bytes and emits deterministic
candidate.json and lock.json. The lock hashes those inputs, the candidate and
verified publisher manifests/signatures/subjects. It contains no local paths,
credentials, timestamps or self-referential future hash. Identical verified bytes
produce identical output; signatures themselves may differ across publications.
Keep original assets independently pinned for later re-verification at use.

The candidate stays UNQUALIFIED/disabled, ratification_revision=null and legal
UNRESOLVED with no evidence inferred. The detached lock explicitly records
composition_tests=NOT_RUN and m0_accepted/m1_admitted=false. Existing reviewer/legal
admission gates are not bypassed: this is their future unsigned input, not a
successful call to validate_release_set. PR10 tests the exact composition; PR11-13
supply authenticated ratification and final acceptance/publication.

OCI assembly checks signed publisher relationship assertions and supplied registry
manifest bytes only. Image signatures, archive/image byte comparison, pulling and
conformance remain later composition/engine-verification gates. Consumer-installed
contract/resource qualification also remains PR10 work. No live artifact set is
assembled until actual independently selected published inputs are supplied.
