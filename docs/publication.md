# Experimental platform driver publication

The manual main-only `.github/workflows/release.yml` publishes a platform wheel
and `driver.tar` with tracked tools, config, public evidence, src, tests, docs,
Compose, spec lock, project/dependency metadata, license and Python pin. Build
outputs, downloaded assets, reports, credentials and Git internals are excluded
by an explicit archive input list. The archive is the driver layout; the wheel
provides installed runtime code. No package layout or dependency pin changes.

The pattern adapts the ML/fabric publishers: two staged wheel builds use the
commit timestamp and source-addressed PEP 440 version; two committed driver
archives must also match. The explicit wheel and driver are checked outside the
source checkout, with imports forced from the wheel. Spec resources must match,
and architecture, integration/config, workflow-assets, release-conformance and
M0 input checks must succeed. These checks provision nothing and keep M0 blocked.
Driver extraction rejects traversal, links, duplicate paths and excessive sizes.

```sh
uv sync --locked --extra conformance
uv run --locked python tools/install_release.py
# Clean committed checkout; fresh build/publication:
uv run --locked --extra conformance python tools/release.py qualify
```

Cosign 3.1.3 and Syft 1.55.0 are checksum-pinned Linux x64 build tools (Apache-2.0),
not runtime dependencies. The signed manifest binds wheel, driver, license, lock,
SPDX wheel scan and in-toto/SLSA-shaped provenance. It makes no SLSA-level or
complete installed dependency SBOM claim. Qualification checks real signatures,
wrong keys and altered manifests; local keys/signatures are never published.

The release workflow additionally installs existing checksum-pinned tools and
published conformance assets and runs `tools/verify.py full` before qualification.
Live Docker checks and source-sensitive detached audit generation run in that
clean Git checkout: the source archive intentionally contains no fabricated Git
identity. A downloaded driver can run offline checks from its extracted layout;
for live audit generation, obtain the independently verified exact source checkout
and follow the existing full setup. This publication does not remove those gates.

Only the publish job receives contents-write/OIDC. It verifies exact workflow,
issuer, source SHA and dispatch trigger, then creates a fresh commit-addressed
experimental prerelease via a draft. Existing tags/releases are refused; failed
drafts require maintainer inspection. Server-side immutability is a maintainer
setting. No push/PR triggers publication. Withdraw/supersede instead of replacing.

Download all assets, independently choose the expected full source and run:

```sh
uv run --locked python tools/release.py verify --folder DOWNLOADED_ASSETS --source FULL_COMMIT_SHA
```

Install the pinned verifier first. No caller-selected signing key is exposed by
this consumer CLI. Reverify at use and retain independent artifact/dependency pins.
Publications remain experimental: they grant no acceptance, legal/security
approval, profile activation, or production deployment permission.
