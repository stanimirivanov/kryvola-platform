# M1 execution and transport recovery

M1-PR34 / issue #58 extends the real published-artifact qualification from
[M1-PR33](m1-inference.md). No component release, cryptographic implementation,
release policy or frozen M0 dependency is replaced. Faults run only in owned,
randomly named disposable local Compose projects; no cloud service is affected.

After the existing M1 installation procedure, the complete gate is:

```sh
uv run --locked python -m unittest discover -s tests -p live_m1_recovery.py -v
```

The default runs all 16 cases. `KRYVOLA_M1_RECOVERY_CASE` selects one case for
local diagnosis; `KRYVOLA_M1_RECOVERY_GROUP` selects one of the four fixed CI
groups. Such segment reports explicitly remain `qualified: false`. CI runs the
four groups on separate runners, then verifies and joins their reports. A
missing, duplicated, stale or contradictory segment fails the aggregate gate.
The canonical full command retains all previous gates and adds this campaign.
Local runs may set `KRYVOLA_M1_RECOVERY_WORKERS=2` after a serial warm-up; the
runner requires at least 16 GiB of Docker memory and four CPUs. Each case still
owns its own isolated services and cleanup. Hosted profiles default to one stack
per runner. Object HEAD checks use at most two concurrent clients within the
existing S3-client memory limit.

Notification handoff bounds Temporal connection and start RPC attempts to three
seconds, with an eight-second retry budget. A ten-second OS deadline terminates
only the disposable handoff process if native SDK cancellation stalls. The host
retries that process once with the exact same notification; the published bridge's
deterministic workflow ID and duplicate-rejection policy preserve reattachment.
Non-transport failures propagate immediately. Exhausted transport retries fail the
campaign and report only service running/exit/OOM state, never success evidence.
This addresses the PR #59 artifact-job hang without increasing the outer Compose
timeout or changing fault assertions. The failed hosted run did not retain enough
service diagnostics to attribute the original transport stall to a specific
backend failure.

Dispatch, selection and post-publication worker barriers are watched by a
dedicated controller thread started before notification handoff. It verifies the
existing SQL/Jobs/native-state boundary, kills the real container, and verifies
its exit before restarting or releasing the barrier. The main observer exports
real candidates while waiting, then reads history after the verified restart.
This prevents a slow history RPC from consuming the selection activity's
ten-second deadline and missing its first attempt. The live durability gate
deliberately delays one post-candidate history read by sixteen seconds; it still
requires the kill, activity retry, one selection and one disclosure.

## Fault boundaries and required outcomes

| Fault | Before | After | Required corroboration |
|---|---|---|---|
| Duplicate notification | Concurrent handoffs before the workflow-start acknowledgement | Replay after acknowledgement/completion | Actual broker records and the published start API reattach to one workflow. Two separately registered physical evaluations have separate execution identities and at most one selected result. |
| Lost notification | Hold the inbox transaction boundary, kill messaging and delete the actual Kafka record before inbox commit | Kill messaging and delete the record after its inbox commit | PostgreSQL reconciliation retains the logical operation and inbox progress; handoff from the durable notification reference completes release. |
| Reordered notification | Overlapping handoffs before their acknowledgements | Sequential acknowledged handoffs | Replay actual selected/created notifications through Kafka in reverse order; selected notices never start compute and the created notice reattaches to the existing workflow. |
| Dispatch bridge death | Kill the workflow/dispatch process before Ray accepts POST | Kill after Ray accepts POST but before the bridge returns acknowledgement | Real Ray Jobs state distinguishes absent/accepted submission. Temporal retries reattach to the same physical execution and release once. |
| Worker death | Hold receipt commit after actual native output finalization, require Engine RUNNING, then kill its container | Kill after an immutable output and signed receipt exist | Before receipt commit, the real workflow fails terminally without selection or disclosure. After publication, the retained candidate permits one release without the worker. |
| Lost activity completion | Kill the workflow worker before SQL selection commits | Kill after selection commits but before completion reaches Temporal | A recorded activity retry and terminal history corroborate exactly one current selection and disclosure. |
| Corrupted artifact | Overwrite the staged canonical manifest before finalization | Overwrite a finalized input chunk | SDK rejection before admission, or terminal workflow failure after admission, without selection or disclosure. |
| Oversized artifact | Enlarge the staged manifest beyond the 32 KiB bound | Enlarge a finalized input chunk beyond its declared length | Same fail-closed outcomes; the check requires changed real object metadata and durable state, not merely a thrown process error. |

Before/after names refer to the specific boundary in this table, rather than to
arbitrary sleep durations. The dispatch and selection barriers wrap real
published calls in the trusted local workflow adapter. They never substitute a
successful response. Unused primary-execution capabilities are refreshed immediately before handoff
with a 45-second lifetime, within the existing 60-second bound. Already consumed
one-shot capabilities and owner-submission grants are never extended. This keeps
fixture initialization from being mistaken for an injected transport fault.
Marker files survive process death so a restarted worker
retries the actual call. Real PostgreSQL transactions block inbox writes or receipt commit for
the corresponding pre-commit cases. Kafka truncation removes the notification itself;
SQL remains the authority for the operation. Restarts target only the killed
container, without rerunning one-shot schema/identity initialization services.

The duplicate-physical-work fixture intentionally registers and evaluates an
additional execution with its own namespace, credentials and output binding.
Duplicate notification delivery itself must not create another logical workflow.
No lost execution is silently relaunched under its previous execution identity.

## Evidence and limits

`build/m1-recovery-report.json` binds source, harness, lock and exact release
manifests to per-case terminal history, observed retry attempts, SQL execution /
receipt / current-selection / disclosure counts, immutable and staging object
HEAD observations, live retention pins and actual installed image identities.
Engine identity checks use its actual OCI configuration digest. Native state is
captured immediately before worker death, and after terminal workflow completion
in other admitted cases; a killed worker's observed RUNNING state does not claim
it remains alive. Separate output-upload bindings corroborate physical execution
identities. The controller
checks native broker records and live SQL; an exception by itself never passes.

Histories and logs retain the existing bounds. Logs are scanned on the host and
inside the still-live owner domain with actual private canaries and a scanner
negative control. Even a rejected pre-admission upload keeps that owner session
alive for the audit. Public reports contain no keys, credentials, artifact blobs
or plaintext witnesses. All invocations clean up their own containers and volumes
on success or failure; partial evidence does not qualify an unfinished campaign.

The result remains `CONFIDENTIALITY_ONLY`. The separate PR33 gate checks actual
owner-local decryption against the frozen reference; this campaign checks durable
execution and transport invariants. It does not qualify machine
power loss, host/kernel failures, production deployment, latency, cancellation or
disclosure races. M1-PR35 owns the latter races; M1-PR36 owns measured envelopes.
