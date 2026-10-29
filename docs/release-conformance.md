# Experimental release-set conformance (M0-PR32)

The gate admits the actual M0-PR31 fixture composition: released fabric/engine
packages, the vendored spec bundle, platform driver and pinned third-party
service images. Its success label is `EXPERIMENTAL_FIXTURE_SET_CONFORMANT`.
`production_ready=false` and `full_five_component_candidate=NOT_SUBMITTED` remain
explicit. This does not replace M0-PR17's independently reviewed, signed
five-component ReleaseCandidate policy or qualify ML/crypto/production releases.
There is no fabricated legal approval or synthetic success fallback.

## Evidence and admission

- Actual keyless package signatures retain M0-PR31's independently pinned bytes,
  exact publisher identity, source/trigger, signed subjects and schema binding.
  Installed fabric package files must match the admitted wheel exactly (excluding
  Python bytecode caches); the UV version and wheel hash must match that release.
- Local generated projections remain verified against `spec.lock.json`. Contract,
  native-wire, canonical and both bounded state-model checks are bound to the
  successful spec run 40484284554, attempt 1, source
  `1a5b57a590487ba116913050af8041f5e5f1fb52`. At this source `pnpm check` invokes
  `check-state.mjs`, which imports the release-state checker; native/canonical
  jobs run their own gates. The gate rejects missing/skipped/failed jobs/steps,
  wrong source/attempt/repository/workflow or incomplete job listings.
- The read-only fetch step queries the exact GitHub run attempt over authenticated
  HTTPS. This is GitHub-hosted execution evidence, not a signed state-model proof,
  rerun of sibling source, SLSA assertion or live production-state qualification.
  Missing/deleted upstream evidence fails closed; refresh requires explicit review
  of the policy/source pins. Local files and the driver host remain trusted.
- Current published native fake-engine conformance and actual Temporal history
  replay run through the existing live fixture. The correct packaged descriptor
  must decode and declared transport byte limits must apply.
- Every runtime service must exist exactly once and its configured digest reference,
  container image ID and resolved image RepoDigest must agree. Third-party fixture
  images use reviewed digest admission; their publisher signatures are not asserted.
  All Kryvola packages must be signed. An unsigned production/OCI candidate gains
  no permit through this fixture-only profile.
- Optional dependencies and conditional UV sources now receive the same local/git/
  workspace-source rejection as core dependencies. Static guards do not prove
  arbitrary dynamic code behavior; no sibling implementation is imported or built.

## Gates and negative controls

After the M0-PR31 package/Cosign setup, fetch upstream metadata explicitly:

```sh
uv run --locked --extra conformance python tools/release_conformance.py fetch
uv run --locked --extra conformance python tools/verify.py fast
uv run --locked --extra conformance python tools/integration.py ci
```

The fetch requires GitHub CLI access to public spec workflow metadata. CI scopes
its read-only GH_TOKEN to that single step; it is absent from service execution.
Fast checks validate local policy and provision/download nothing. Full checks use
`uv run --locked --extra conformance python tools/verify.py full`, whose final
stage invokes the same `integration.py ci` command. The network-check command now
also requires the fetched evidence and runs the admission controls.

The CLI first admits a valid baseline, then runs ten separate failing probes:
unsigned package, wrong publisher signature (with updated transport hash to reach
real verification), changed package, changed schema, sibling source, mutable image,
control/Temporal payload overflow, production claim and failed upstream evidence.
Each must reach its intended guard and exit 1 with its case-specific rejection
code; setup errors exit 2. Parser/import errors or an always broken baseline do
not count as successful negative controls. Probes work on
private temporary copies and never modify admitted artifacts or installed code.
No OIDC tokens/private signing keys are created by this gate.

One owned stack then runs service qualification, published fake traversal, replay,
network measurements and runtime image checks. The public report records exact
packages, spec run/jobs, negative exits and runtime image identities before normal
teardown. Credentials and raw payloads are excluded. The full gate runs on CI;
no desktop Docker stack or heavy native build is needed.

The workflow moves from `ci.yml` to `integration.yml`, retaining workflow name
`foundation`, job `verify`, triggers, permissions and concurrency. There is one
full run per trigger rather than a duplicate workflow. Branch protection is not
changed; any external rule tied to the old workflow file path needs maintainer
review. Existing check names remain unchanged.

The gate reuses GitHub Actions run/job metadata, Cosign, Python wheel/UV identities
and the existing validators. No new runtime dependency, scheduler, state model or
cryptographic protocol is introduced. State exploration remains owned by spec;
M1 retains real physical fencing, recovery, authorization and release work.
