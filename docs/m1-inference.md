# Real local M1 inference qualification

Issue #56 implements M1-PR33 in the agreed milestone plan. The local driver uses
the admitted published Fabric, ML and Engines artifacts in `config/m1.lock.json`.
The host keeps its frozen M0 environment; M1 libraries run in their installed
role images. No sibling source build substitutes for a published artifact.

After the existing M1 installation procedure, run:

```sh
uv run --locked python tools/m1_inference.py
uv run --locked python -m unittest discover -s tests -p live_m1_inference.py -v
```

The second command includes three disposable owner sessions to guard headless
keyring initialization. The canonical full gate and the existing M1 CI job run
the live suite. The driver owns one randomly named Compose project and cleans
its containers, identities and volumes on success or failure.

## Execution and owner boundaries

The owner domain initializes and checks actual Secret Service custody with the
published owner agent, restores its opaque key through the published owner wheel,
and signs exact compute and release approvals. The SDK registers the key context,
uploads and finalizes the real evaluation key and encrypted pair, and admits the
approved operation. Its model binding commits the published frozen program bytes.

An actual broker notification and durable inbox receipt precede Temporal start.
The published workflow registers the physical execution, dispatches a real Ray
job to the native CPU Engine, selects its verified output and commits release.
The SDK observes release and fetches exact authorized output; the owner agent
independently verifies authorization and opens it over its same-UID local socket.
One owner-private pair from the frozen FHE-Q1 corpus is compared with the frozen
reference. The owner also checks all 100 reference cases against the packaged
golden corpus. The report contains neither the chosen pair nor decrypted bytes.

Private owner material stays in the owner container. Core dumps and process
dumping are disabled before key generation. The keyring uses a private D-Bus
session, encrypted disposable storage and its own control directory. The owner
image installs a checksum-pinned Debian helper closure offline; it does not use
the operator's personal keyring. Headless initialization follows
[GNOME's daemon implementation](https://github.com/GNOME/gnome-keyring/blob/48.0/daemon/gkd-main.c)
and the [documented Secret Service headless pattern](https://github.com/git-ecosystem/git-credential-manager/blob/main/docs/secretservice-headless.md).

The trusted local operator supplies short-lived exact workload capabilities and
per-execution assignments. The coordinator gets private mode-0600 copies of its
CLI configuration. A bounded metadata export carries the Ray candidate across
the worker/workflow UID boundary; worker assignment credentials are not exposed
to the workflow through the shared worker directory.

The fixture bounds owner/Engine memory at 1 GiB, tenant artifacts at 128 MiB and
storage at eight 32 MiB volumes. This accommodates the actual roughly 60 MB
evaluation key and multipart staging. Read-only roots, worker identities,
network boundaries and live authorization checks remain enforced.

## Public evidence and limits

`build/m1-inference-report.json` records exact release-manifest pins, running image
identities and the separately verified Engine OCI configuration digest, the
workflow/execution/disclosure identities, receipt and
release commitments, the frozen reference pin, and observed history/event bounds.
The driver checks Temporal completion independently from SQL release persistence.
It inspects actual protobuf histories and broker records, and scans complete
bounded service logs and histories for credential/private-key material. Owner-only
scanning also checks private canaries, witness representations and ciphertext
markers without exporting those markers. Negative controls guard the scanners.

The consent declares unproven integrity and explicitly permits unverified release.
`CONFIDENTIALITY_ONLY` appears in approvals, receipts, release, owner SDK output
and the report. These checks qualify the observed local path; they do not add
cryptographic computation-integrity proof, latency guarantees or the recovery and
disclosure fault campaigns assigned to M1-PR34 and later tasks.
