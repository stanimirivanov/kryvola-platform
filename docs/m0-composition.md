# Exact M0 composition qualification

`tools/m0_composition.py` tests an explicitly selected unsigned candidate. It
reassembles and compares its candidate/lock and re-verifies every publisher before
provisioning. No synthetic config example, release pin or signed driver file is
rewritten. M0/legal/security approval remains pending.

## Setup and compatibility

Use the independently verified clean Git checkout at the candidate's exact
platform source. The signed driver archive must match every allowed tracked file
in that checkout. Install the selected platform, ML and fabric wheels non-editably
in the qualification environment, with their independently locked dependencies.
The qualifier checks versions, imported package locations, full wheel resources
and absence of extra installed files, and reproduces the installed ML fixture.
It never installs candidate packages or falls back to sibling source.

The existing driver embeds its tested fabric/engine publication pins and service
image configuration. They must match the selected candidate and verified runtime
assets exactly. An incompatible set fails before provisioning; changing those
pins needs a separately reviewed platform release, not a qualification-time patch.
Perform the existing explicit Cosign, workflow-assets and upstream-evidence setup
from README first. Candidate assembly itself does not supply those downloads.

Spec contracts are checked by assembly and the existing live conformance gate.
Archive engine candidates test the exact extracted binary in the Ray traversal.
OCI candidates must additionally bind the embedded signed archive manifest: their
image signature, digest-pulled runtime settings and /opt/kryvola files are checked
against that archive, and read-only network-disabled conformance runs. OCI images
are never substituted for unrelated Ray/container image identities.

```sh
uv run --locked --extra conformance python tools/m0_composition.py --bundle CANDIDATE_DIRECTORY --assets VERIFIED_ASSET_DIRECTORY --output FRESH_EVIDENCE_DIRECTORY
```

The existing owned network/fake-workflow/replay/isolation/conformance pipeline runs
without importing old reports. Its completion callback occurs only after cleanup
succeeds. Report source/package/image identities, all admission negative controls,
isolation denials and fake/development labels must pass the existing audit's live
validator. Only the newly created owned run directory is eligible. Candidate,
installed-package and publisher inputs are checked again after the live run.

## Retention and limits

A new output directory retains the exact candidate/selection/model/measurement and
input lock, four validated live reports and the network observation journal. A
report binds all retained bytes to candidate/lock hashes and component identities,
and evidence.tar packages the retained files for durable copying. No credentials,
downloaded binaries, engine artifacts or raw service logs are copied into it.
The original input lock stays untested historical evidence; the new report records
the successful run without relabelling it as acceptance.

Preserve evidence.tar in an operator-approved durable store; local creation does
not upload it or grant retention beyond CI's existing seven days. Later acceptance
publication can retain this exact artifact. Failed checks/cleanup emit no success
bundle. Interrupted output writes may leave a partial directory; inspect it and
use a fresh destination. Never reuse partial output as verified evidence.

Results remain non-production, m0_accepted=false and m1_admitted=false. This is
host-trusted qualification, not signed attestation, independent security review or
real inference. Actual live qualification requires Docker, registry/network access,
real independently selected releases and a non-root host. Missing setup, artifacts
or approvals cannot be replaced with synthetic success. The current implementation
has offline lifecycle/negative coverage; no live five-component set is seeded.
