# M1 cancellation and disclosure races

M1-PR35 / issue #60 applies the bounded release state model to actual published
M1 services and owner-local encrypted inference. It changes no release policy,
component implementation, dependency version, release pin or production profile.

After the existing M1 installation, install the test oracle explicitly:

```sh
uv run --locked python tools/m1_disclosure.py install
uv run --locked python -m unittest discover -s tests -p live_m1_disclosure.py -v
```

The oracle comes from the exact Spec revision and manifest already pinned by the
verified Fabric release. Both downloaded files are checksum-verified; neither a
moving branch nor a sibling implementation supplies runtime behavior. The
existing Apache-2.0 state-model pattern requires no new dependency. Model epoch
zero denotes the installed workflow's first epoch (one); physical execution
names are abstracted to the model's first execution. Oracle agreement is bounded
test evidence, not cryptographic proof or a production guarantee.
`cancel-request` projects request initiation, not a required HTTP 202 response.
`verify` projects native signed-receipt/authorization checks, never public
`EVIDENCE_VERIFIED` or a compute proof. `reconcile` projects independent SQL
read-back of the fenced durable state; no unexecuted workflow readmission is
inserted into a trace.

## Cases and evidence

| Case | Real boundary and required outcome |
|---|---|
| cancel-before | Age the admission client beyond the configured 45-second SVID lifetime before dispatch. Refresh its real identity for cancellation while selection is held before SQL commit; require a committed fence, rejection of old-fence selection, and no selection/disclosure. |
| cancel-after | Hold selection after its commit, before its activity acknowledgement. Winning cancellation retires the attempt and prevents a disclosure despite the retained selection. |
| cancel-transaction | Lock the empty operation-barrier table, observe the cancellation SQL waiter and absence of acknowledgement, then release the transaction and require committed fencing before acknowledgement. |
| registry-outage | Pause the actual runtime while the owner calls cancellation. No acknowledgement or fence can appear while it is unavailable. Unpause and reconcile the same idempotency key through the public SDK. |
| admin-terminate | At committed selection, use the published fence-first administrative recovery helper, actual Ray cleanup and Temporal termination. Require the fence and rejection of the stale candidate. |
| release-before-cancel | Open a legitimately released result inside the owner before cancellation. Fencing preserves the one existing disclosure identity and output; it cannot retract bytes already disclosed. |
| revoke-before | Revoke the actual signed approval using the native coordinator command while selection acknowledgement is held. Release fails with no disclosure. |
| revoke-after | Open the committed result, revoke its approval, then require a fresh authorized SDK fetch to fail. The historical disclosure remains immutable. |
| owner-reconnect | Fetch real encrypted output, damage ciphertext or substitute its signature and require owner-local rejection. SIGSTOP the actual owner key-service process, verify its stopped state and require opening failure; SIGCONT and open the exact original result against the frozen reference. |
| rollover-recovery | Signal the real workflow while prepare is held, require two Continue-As-New runs and one released output, then fence administrative recovery. Independently reject the old valid candidate and a candidate proposing a different output; the disclosure identity/output remain unchanged. |

Only owned, randomly named disposable Compose projects are affected. The worker
never receives owner private keys or plaintext. Signed documents and bounded
metadata cross the fixture's operator channel; ciphertext and plaintext opening
stay inside the owner UID. Negative opens require successful encrypted fetch
before rejection, and reconnect requires a real positive frozen-reference check.
The unavailable key service is resumed in a finally block.

Held activity retries cannot bypass a barrier in the same worker process. An
independent process-generation marker allows the existing PR34 restart cases to
retry after genuine process death. Markers publish complete bytes atomically.
Native runtime errors and missing evidence fail qualification; no exception by
itself counts as successful fault injection.

## Reports, gates and limits

`build/m1-disclosure-report.json` binds source, harness, lock, exact component
release manifests and the oracle digest. Per-case SQL counts, retired attempts,
fences, disclosure identity/output pairs, actual workflow histories, object HEAD
observations, live retention pins and installed image identities corroborate the
outcome. Bounded complete logs/history pass the existing host and still-live
owner canary audits, including the scanner's negative control.

`KRYVOLA_M1_DISCLOSURE_CASE` selects one diagnostic case. CI instead runs three
groups (`cancellation`, `identity`, `owner`) on independent runners. Group reports
remain explicitly unqualified; the aggregate gate rejects missing, duplicate,
incomplete or stale segments and qualifies only their complete ten-case union.
The standard full verifier retains all previous checks and adds this live gate;
its `KRYVOLA_M1_SEPARATE_JOB=1` CI profile delegates the M1 live campaigns to their
dedicated jobs.

The result remains `CONFIDENTIALITY_ONLY`. Recovery here covers real
Continue-As-New, completed-workflow fencing and refusal of stale replacement; it
does not claim an arbitrary new owner approval or readmission after completion.
Owner availability is tested by stopping its real key-service process, not by
destroying durable custody. Already legitimately disclosed bytes cannot be
erased from a recipient. Host/power failures, production activation and measured
performance remain outside this campaign; PR36 owns the supported envelope.

The live campaign and its corroborating negative controls exceed the original
line estimate because actual owner, SQL, Temporal, Ray and native authorization
boundaries must stay in one independently runnable qualification change.
