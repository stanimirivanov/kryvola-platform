"""Real cancellation/disclosure races over the immutable M1 release set."""

import argparse
import hashlib
import inspect
import json
import re
import secrets
import subprocess
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
from pathlib import Path

if __package__:
    from . import m1, m1_assets
    from . import m1_inference as live
    from . import m1_recovery as recovery
else:
    import m1
    import m1_assets
    import m1_inference as live
    import m1_recovery as recovery

CASES = (
    "cancel-before",
    "cancel-after",
    "cancel-transaction",
    "registry-outage",
    "admin-terminate",
    "release-before-cancel",
    "revoke-before",
    "revoke-after",
    "owner-reconnect",
    "rollover-recovery",
)
ORACLE = m1.ROOT / "build/m1-state/release.oracle.json"
GROUPS = {
    "cancellation": CASES[:4],
    "identity": ("admin-terminate", "release-before-cancel", "rollover-recovery"),
    "owner": ("revoke-before", "revoke-after", "owner-reconnect"),
}


def require(value):
    if not value:
        raise ValueError("M1_DISCLOSURE_EVIDENCE")


def install():
    """Use the manifest already pinned by the verified Fabric release, not HEAD."""
    spec = m1_assets.load()["components"]["fabric"]["spec"]
    root = spec["repository"].replace("https://github.com/", "https://raw.githubusercontent.com/")
    # artifact_root is Fabric's vendoring destination; Spec publishes generated/.
    root += "/" + spec["revision"] + "/generated/"

    def fetch(path):
        with urllib.request.urlopen(root + path, timeout=60) as response:
            raw = response.read((4 << 20) + 1)
        require(len(raw) <= 4 << 20)
        return raw

    manifest = fetch("manifest.json")
    require(hashlib.sha256(manifest).hexdigest() == spec["manifest_sha256"])
    expected = json.loads(manifest)["files"]["state/v1/release.oracle.json"]
    raw = fetch("state/v1/release.oracle.json")
    require(hashlib.sha256(raw).hexdigest() == expected)
    ORACLE.parent.mkdir(parents=True, exist_ok=True)
    ORACLE.write_bytes(raw)
    (ORACLE.parent / "manifest.json").write_bytes(manifest)


def oracle():
    manifest = (ORACLE.parent / "manifest.json").read_bytes()
    spec = m1_assets.load()["components"]["fabric"]["spec"]
    require(hashlib.sha256(manifest).hexdigest() == spec["manifest_sha256"])
    raw = ORACLE.read_bytes()
    require(
        hashlib.sha256(raw).hexdigest()
        == json.loads(manifest)["files"]["state/v1/release.oracle.json"]
    )
    value = json.loads(raw)
    require(value["format"] == "kryvola-state-oracle-v1" and value["model"] == "release")
    return value


def check_trace(model, steps):
    node = model["initial"]
    for action, outcome in steps:
        edges = [
            (a, o, n)
            for a, o, n in model["nodes"][node]["edges"]
            if model["actions"][a] == action and model["outcomes"][o] == outcome
        ]
        require(len(edges) == 1)
        node = edges[0][2]
    return node


def validate_case(value):
    case = value["case"]
    require(case in CASES and value["boundary_observed"] is True and value["logs_clean"] is True)
    require(1 <= value["history_events"] <= 128 and value["objects"] >= 3 and value["pins"] >= 1)
    require(value["selections"] in (0, 1) and value["disclosures"] in (0, 1))
    require(value["executions"] == value["receipts"] == 1)
    require(len(value["ledger"]) == value["disclosures"])
    if case.startswith("cancel-") or case in {"registry-outage", "admin-terminate"}:
        require(value["fence"] >= 2 and value["retired"] >= 1 and value["acknowledged"] is True)
        require(value["stale_status"] == 409 and value["disclosures"] == 0)
        require(value["workflow_status"] in {"CANCELED", "TERMINATED", "FAILED"})
        require(value["selections"] == (1 if case in {"cancel-after", "admin-terminate"} else 0))
        require(value["before"]["selections"] == value["selections"])
        require(value["before"]["disclosures"] == 0)
        if case in {"cancel-transaction", "registry-outage"}:
            require(value["checks"]["no_early_ack"] is True)
    elif case == "revoke-before":
        require(value["checks"]["revoked"] is True and value["selections"] == 1)
        require(value["disclosures"] == 0 and value["workflow_status"] == "FAILED")
    else:
        require(value["selections"] == value["disclosures"] == 1)
        require(value["checks"]["opened"] is True)
        require(value["ledger"] == value["before"]["ledger"])
        if case == "owner-reconnect":
            require(value["checks"]["keyring_stopped"] is True)
            for name in ("malformed", "substituted", "unavailable"):
                require(value["checks"][name] == {"rejected": True, "fetched": True})
        if case == "revoke-after":
            require(value["checks"]["revoked"] is True and value["checks"]["read_denied"] is True)
        if case == "release-before-cancel":
            require(value["fence"] >= 2 and value["acknowledged"] is True)
        if case == "rollover-recovery":
            require(value["workflow_runs"] == 2 and value["fence"] >= 2)
            require(value["checks"]["successor_epoch"] == "2" and value["stale_status"] == 409)
    return value


def bindings():
    paths = (
        "tools/m1_disclosure.py",
        "tools/m1_inference.py",
        "tools/m1_recovery.py",
        "config/m1/owner_inference.py",
        "config/m1/service.py",
        "compose.m1.yaml",
    )
    return {
        "platform_source": subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=m1.ROOT, text=True
        ).strip(),
        "harness_sha256": hashlib.sha256(
            b"".join((m1.ROOT / p).read_bytes() for p in paths)
        ).hexdigest(),
        "lock_sha256": hashlib.sha256((m1.ROOT / "config/m1.lock.json").read_bytes()).hexdigest(),
        "oracle_sha256": hashlib.sha256(ORACLE.read_bytes()).hexdigest(),
        "release_manifests": {
            k: v["assets"]["manifest.json"]["sha256"]
            for k, v in m1_assets.load()["components"].items()
        },
    }


def validate_report(value):
    require(value.get("schema_version") == "platform-m1-disclosure-v1")
    require(value.get("assurance") == "CONFIDENTIALITY_ONLY")
    require(all(value.get(k) == v for k, v in bindings().items()))
    cases = value["cases"]
    require(len({v["case"] for v in cases}) == len(cases))
    require(set(v["case"] for v in cases) == set(value["requested_cases"]))
    require(value["qualified"] is (set(v["case"] for v in cases) == set(CASES)))
    model = oracle()
    for case in cases:
        validate_case(case)
        require(case["workflow_runs"] == (2 if case["case"] == "rollover-recovery" else 1))
        require(case["engine_config_sha256"] == m1_assets.load()["permissions"]["image_sha256"])
        require(
            set(case["images"])
            == {
                "runtime",
                "workflow",
                "messaging",
                "ray",
                "engine",
                "owner",
                "postgres",
                "temporal",
                "storage",
                "broker",
            }
        )
        require(all(re.fullmatch(r"sha256:[0-9a-f]{64}", d) for d in case["images"].values()))
        check_trace(model, case["trace"])
    return value


def role_program(value):
    """Executed in the installed trusted workflow role; never returns credentials."""
    import asyncio
    import http.client
    import importlib.util
    import json
    import subprocess
    from datetime import timedelta
    from pathlib import Path

    Registry = importlib.import_module("kryvola_fabric.compute_activities").Registry
    recovery = importlib.import_module("kryvola_fabric.compute_recovery")
    stop_compute, temporal_stopper = recovery.stop_compute, recovery.temporal_stopper
    DATA_CONVERTER = importlib.import_module("kryvola_fabric.compute_workflow").DATA_CONVERTER
    local_jobs = importlib.import_module("kryvola_fabric.ray_dispatch").local_jobs
    from temporalio.client import Client

    spec = importlib.util.spec_from_file_location("fixture", "/opt/m1/service.py")
    assert spec is not None and spec.loader is not None
    service = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(service)
    if value["op"] == "revoke":
        (private,) = Path("/tmp").glob("m1-release-*/database-release")
        result = subprocess.run(
            [
                "/opt/fabric/bin/fabric-runtime",
                "--revoke-release-approval",
                str(private),
                value["digest"],
            ],
            capture_output=True,
            timeout=8,
        )
        assert result.returncode == 0
        return {"revoked": True}

    def token(action, scope):
        return json.loads(Path("/run/m1-secrets/tokens.json").read_bytes())[action]

    if value["op"] == "request":
        client = http.client.HTTPSConnection(
            "runtime", 8443, context=service.tls("workflow"), timeout=5
        )
        try:
            client.connect()
            certificate = client.sock.getpeercert()
            assert certificate is not None
            assert [x for x in certificate["subjectAltName"] if x[0] == "URI"] == [
                ("URI", "spiffe://m1.test/runtime")
            ]
            client.request(
                "POST",
                value["path"],
                json.dumps(value["body"]).encode(),
                {
                    "Authorization": "Bearer " + token(value["action"], None),
                    "Content-Type": "application/json",
                },
            )
            response = client.getresponse()
            raw = response.read(32769)
            assert len(raw) <= 32768
            return {"status": response.status, "body": json.loads(raw) if raw else None}
        finally:
            client.close()

    async def run():
        client = await Client.connect(
            "temporal:7233", data_converter=DATA_CONVERTER, connect_timeout=timedelta(seconds=3)
        )
        if value["op"] == "rollover":
            await client.get_workflow_handle(value["id"]).signal(
                "rollover", rpc_timeout=timedelta(seconds=3)
            )
            return {"signalled": True}
        assert value["op"] == "stop"
        registry = Registry(
            "runtime", 8443, service.tls("workflow"), "spiffe://m1.test/runtime", token
        )

        async def cleanup(_barrier):
            reply = await asyncio.to_thread(
                local_jobs(), "POST", "/api/jobs/" + value["namespace"] + "/stop", {}
            )
            assert isinstance(reply, dict) and type(reply["stopped"]) is bool

        return await stop_compute(
            registry,
            value["scope"],
            value["mode"],
            "disclosure-race",
            cleanup,
            temporal_stopper(client),
        )

    return asyncio.run(run())


def role(stack, **value):
    program = (
        "import signal,json,sys\nsignal.signal(signal.SIGALRM,signal.SIG_DFL)\n"
        "signal.alarm(25)\n"
        + inspect.getsource(role_program)
        + "\nprint(json.dumps(role_program(json.load(sys.stdin))))\n"
    )
    return json.loads(
        stack.execute("workflow", "python", "-c", program, payload=live.canonical(value))
    )


def issue(operator, action, native, actual, *, scoped=False):
    scope = {k: actual["attempt"][k] for k in ("tenant_scope", "operation_id", "workflow_epoch")}
    scope.update(attempt_epoch="1" if scoped else None, fence="1" if scoped else None)
    token = operator.grant("registry_grants", {"scope": scope, "actions": [native]}, "workflow")
    path = operator.stack.folder / "secrets/tokens.json"
    tokens = json.loads(path.read_bytes())
    tokens[action] = token
    live.secret_file(path, tokens)
    operator.save()
    return scope


def owner_reply(owner, operator):
    while True:
        reply = owner.receive()
        if reply["stage"] != "GRANT":
            return reply
        owner.send({"token": operator.owner_grant(reply)})


def cancel(owner, operator):
    owner.send({"command": "cancel", "idempotency_key": "disclosure-race"})
    return owner_reply(owner, operator)


def snapshot(stack):
    return json.loads(
        stack.sql("""
        SELECT json_build_object(
          'executions',(SELECT count(*) FROM fabric_executions),
          'receipts',(SELECT count(*) FROM fabric_execution_receipts),
          'fence',COALESCE((SELECT max(fence)::int FROM fabric_operation_barriers),0),
          'retired',(SELECT count(*) FROM fabric_attempts WHERE retired),
          'selections',(SELECT count(*) FROM fabric_selected_results),
          'disclosures',(SELECT count(*) FROM fabric_disclosure_decisions),
          'ledger',(SELECT COALESCE(json_agg(json_build_array(disclosure_id,output_manifest_digest)
                         ORDER BY disclosure_id),'[]') FROM fabric_disclosure_decisions),
          'pins',(SELECT count(*) FROM fabric_artifact_pins
                  WHERE expires_unix_ms > extract(epoch FROM clock_timestamp())*1000))
    """)
    )


def delivery(stack, operator):
    decision = json.loads(
        stack.sql(
            "SELECT json_build_object('release',convert_from(canonical_authorization,'UTF8')::json,"
            "'release-signature',convert_from(canonical_signature,'UTF8')::json,"
            "'id',disclosure_id) FROM fabric_disclosure_decisions"
        )
    )
    return {
        **{k: decision[k] for k in ("release", "release-signature")},
        "scope": {
            "schema_version": "1",
            "disclosure_id": decision["id"],
            **{
                k: decision["release"][k]
                for k in ("tenant_scope", "recipient", "output_manifest_digest")
            },
        },
        "open-policy": {
            **operator.coordinator,
            "release_digest": decision["release-signature"]["payload_digest"],
            "authority": "runtime:8443",
            "server_spiffe_id": "spiffe://m1.test/runtime",
        },
    }


def candidate(stack, actual):
    path = stack.folder / "workflow-state/candidates" / actual["namespace"] / "candidate.json"
    if not path.exists():
        recovery.export_candidate(stack, actual)
    return json.loads(path.read_bytes())


def wait_boundary(stack, actual, config):
    marker = stack.folder / "workflow-state/barrier-reached"
    until = time.monotonic() + 45
    while time.monotonic() < until:
        try:
            candidate(stack, actual)
        except subprocess.CalledProcessError:
            pass
        if marker.exists():
            require(json.loads(marker.read_bytes()) == config)
            return
        time.sleep(0.02)
    raise ValueError("M1_DISCLOSURE_MISSING_BOUNDARY")


def wait_terminal(stack, actual, identifier):
    def terminal():
        try:
            candidate(stack, actual)
        except subprocess.CalledProcessError:
            pass
        value = recovery.history(stack, identifier)
        require(value["status"] in {"COMPLETED", "FAILED", "CANCELED", "TERMINATED"})
        return value

    return stack.wait(terminal, seconds=75)


def trace(value):
    case = value["case"]
    selected = [("select:0:1-1", "SELECTED")]
    cancelled = [
        ("cancel-request", "CANCEL_PENDING"),
        ("cancel-commit", "CANCEL_COMMITTED"),
        ("cancel-ack", "CANCELLED"),
    ]
    released = selected + [
        ("verify", "VERIFIED"),
        ("authorize-release", "RELEASE_AUTHORIZED"),
        ("release:0", "GRANTED"),
    ]
    if case.startswith("cancel-") or case == "registry-outage":
        return (selected if value["selections"] else []) + cancelled + [("release:0", "REJECTED")]
    if case == "admin-terminate":
        return selected + [
            ("recover", "RECOVERING"),
            ("reconcile", "RECONCILED"),
            ("release:0", "REJECTED"),
        ]
    if case == "revoke-before":
        return selected + [
            ("verify", "VERIFIED"),
            ("revoke", "REVOKED"),
            ("authorize-release", "REJECTED"),
        ]
    if case == "revoke-after":
        return released + [("revoke", "REVOKED")]
    if case == "release-before-cancel":
        return released + cancelled
    if case == "rollover-recovery":
        return (
            [("continue-as-new", "CONTINUED")]
            + released
            + [("recover", "RECOVERING"), ("reconcile", "RECONCILED")]
        )
    return released


def run_case(case):
    require(case in CASES)
    locked = m1_assets.load()
    stack = m1.Stack("kryvola-m1-" + secrets.token_hex(6))
    owner, paused = None, False
    locks = ExitStack()
    checks, acknowledged, stale_status = {}, False, None
    config = None
    try:
        stack.start()
        stack.verify()
        if case.startswith("cancel-") or case == "registry-outage":
            config = {"action": "SELECT", "edge": "after" if case == "cancel-after" else "before"}
        elif case in {"admin-terminate", "revoke-before"}:
            config = {"action": "SELECT", "edge": "after"}
        elif case == "rollover-recovery":
            config = {"action": "GET", "edge": "before"}
        if config:
            (stack.folder / "workflow-state/recovery.json").write_bytes(live.canonical(config))
        owner = live.OwnerSession(stack, locked["permissions"]["image_sha256"], mode="disclosure")
        prepared = owner.receive()
        require(prepared["stage"] == "PREPARED")
        operator = live.Operator(stack, prepared)
        require(owner_reply(owner, operator)["stage"] == "ADMITTED")
        live.phase("DISCLOSURE_ADMITTED:" + case)
        actual = live.provision(stack, operator, locked)
        pending = {
            g["token_sha256"]
            for lane in ("registry_grants", "grants", "output_grants", "receipt_grants")
            for g in operator.policy.get(lane, [])
        }
        recovery.refresh_unspent(operator, pending)
        identifier = recovery.handoff(stack, [recovery.notices(stack)[0]])[0]
        live.phase("DISCLOSURE_STARTED:" + case)
        if config:
            wait_boundary(stack, actual, config)
            live.phase("DISCLOSURE_BOUNDARY:" + case)
        before = snapshot(stack)
        if config and config["action"] == "SELECT":
            require(before["selections"] == int(config["edge"] == "after"))
            require(before["disclosures"] == 0)

        if case == "rollover-recovery":
            require(role(stack, op="rollover", id=identifier)["signalled"] is True)
            (stack.folder / "workflow-state/barrier-release").touch()
        if case == "registry-outage":
            stack.compose("pause", "runtime")
            paused = True
            require(cancel(owner, operator)["stage"] == "CANCEL_UNAVAILABLE")
            require(snapshot(stack)["fence"] == 0)
            checks["no_early_ack"] = True
            stack.compose("unpause", "runtime")
            paused = False
        if case.startswith("cancel-") or case == "registry-outage":
            if case == "cancel-transaction":
                lock = recovery.DatabaseLock(stack, "fabric_operations")
                locks.callback(lock.close)
                with ThreadPoolExecutor(max_workers=1) as pool:
                    response = pool.submit(cancel, owner, operator)
                    until = time.monotonic() + 3

                    def cancellation_waiter():
                        return int(
                            stack.sql(
                                "SELECT count(*) FROM pg_stat_activity "
                                "WHERE wait_event_type='Lock' "
                                "AND query LIKE '%fabric_operations%' AND query LIKE '%FOR UPDATE%'"
                            )
                        )

                    while not cancellation_waiter() and time.monotonic() < until:
                        time.sleep(0.02)
                    require(
                        lock.observe()[0] > 0 and cancellation_waiter() > 0 and not response.done()
                    )
                    checks["no_early_ack"] = True
                    locks.close()
                    reply = response.result(timeout=10)
            else:
                reply = cancel(owner, operator)
            if reply["stage"] == "CANCEL_UNAVAILABLE":
                reply = cancel(owner, operator)
            state = snapshot(stack)
            require(reply["stage"] == "CANCEL" and reply["outcome"] == "CANCELLED")
            require(int(reply["fence"]) == state["fence"] >= 2 and state["retired"] >= 1)
            acknowledged = True
            scope = issue(operator, "CANCEL", "CANCEL_OPERATION", actual)
            stopped = role(
                stack, op="stop", mode="cancel", scope=scope, namespace=actual["namespace"]
            )
            require(
                stopped["outcome"] == "CANCELLED"
                and stopped["temporal_stopped"] is True
                and stopped["cleanup_complete"] is True
            )
        elif case == "admin-terminate":
            scope = issue(operator, "ADMIN_RECOVERY", "ADMIN_RECOVERY", actual)
            stopped = role(
                stack, op="stop", mode="terminate", scope=scope, namespace=actual["namespace"]
            )
            require(
                stopped["outcome"] == "RECOVERY_FENCED"
                and stopped["temporal_stopped"] is True
                and stopped["cleanup_complete"] is True
            )
            require(snapshot(stack)["fence"] == int(stopped["fence"]) >= 2)
            acknowledged = True
        elif case == "revoke-before":
            checks.update(
                role(stack, op="revoke", digest=prepared["release"]["envelope"]["payload_digest"])
            )
            require(
                stack.sql("SELECT count(*) FROM fabric_revoked_release_approvals").strip() == b"1"
            )
        if config:
            (stack.folder / "workflow-state/barrier-release").touch()
        observed = wait_terminal(stack, actual, identifier)
        live.phase("DISCLOSURE_TERMINAL:" + observed["status"])

        if snapshot(stack)["fence"] >= 2:
            issue(operator, "SELECT", "RESULT_SELECT", actual, scoped=True)
            candidate = json.loads(
                (
                    stack.folder
                    / "workflow-state/candidates"
                    / actual["namespace"]
                    / "candidate.json"
                ).read_bytes()
            )
            stale_status = role(
                stack, op="request", action="SELECT", path="/v1/results/select", body=candidate
            )["status"]
        if case in {
            "release-before-cancel",
            "revoke-after",
            "owner-reconnect",
            "rollover-recovery",
        }:
            require(observed["status"] == "COMPLETED")
            before = snapshot(stack)
            require(before["disclosures"] == 1)
            envelope = delivery(stack, operator)
            if case == "owner-reconnect":
                for fault in ("malformed", "substituted", "unavailable"):
                    probe = json.loads(live.canonical(envelope))
                    if fault == "substituted":
                        sig = probe["release-signature"]["signature"]
                        probe["release-signature"]["signature"] = (
                            "A" if sig[0] != "A" else "B"
                        ) + sig[1:]
                    owner.send({**probe, "fault": fault})
                    reply = owner_reply(owner, operator)
                    require(
                        reply["stage"] == "REJECTED"
                        and reply["fault"] == fault
                        and reply["fetched"] is True
                    )
                    checks[fault] = {"rejected": True, "fetched": True}
                    live.phase("DISCLOSURE_OWNER_REJECTED:" + fault)
                    if fault == "unavailable":
                        require(reply["keyring_stopped"] is True)
                        checks["keyring_stopped"] = True
            owner.send(envelope)
            reply = owner_reply(owner, operator)
            require(reply["stage"] == "OPENED" and reply["owner_reference_match"] is True)
            checks["opened"] = True
            live.phase("DISCLOSURE_OWNER_OPENED:" + case)
            if case == "release-before-cancel":
                reply = cancel(owner, operator)
                require(reply["stage"] == "CANCEL" and reply["outcome"] == "CANCELLED")
                require(snapshot(stack)["fence"] == int(reply["fence"]) >= 2)
                acknowledged = True
            elif case == "revoke-after":
                checks.update(
                    role(
                        stack, op="revoke", digest=prepared["release"]["envelope"]["payload_digest"]
                    )
                )
                require(
                    stack.sql("SELECT count(*) FROM fabric_revoked_release_approvals").strip()
                    == b"1"
                )
                owner.send({**envelope, "fault": "revoked"})
                reply = owner_reply(owner, operator)
                require(reply["stage"] == "REJECTED" and reply["fetched"] is False)
                checks["read_denied"] = True
            elif case == "rollover-recovery":
                scope = issue(operator, "ADMIN_RECOVERY", "ADMIN_RECOVERY", actual)
                stopped = role(
                    stack, op="stop", mode="terminate", scope=scope, namespace=actual["namespace"]
                )
                require(
                    stopped["outcome"] == "RECOVERY_FENCED" and stopped["cleanup_complete"] is True
                )
                checks["successor_epoch"] = stopped["successor_epoch"]
                issue(operator, "SELECT", "RESULT_SELECT", actual, scoped=True)
                candidate = json.loads(
                    (
                        stack.folder
                        / "workflow-state/candidates"
                        / actual["namespace"]
                        / "candidate.json"
                    ).read_bytes()
                )
                candidate["output_manifest_digest"] = "0" * 64
                stale_status = role(
                    stack, op="request", action="SELECT", path="/v1/results/select", body=candidate
                )["status"]

        final = snapshot(stack)
        objects = recovery.objects(stack)
        owner.send({"audit_only": True})
        images = recovery.audit(stack, owner, operator, observed)
        config_digest = recovery.installed_engine_config(
            stack.env["M1_ENGINE_IMAGE"], images["engine"]
        )
        require(config_digest == locked["permissions"]["image_sha256"])
        value = {
            "case": case,
            **final,
            "before": before,
            "checks": checks,
            "acknowledged": acknowledged,
            "stale_status": stale_status,
            "boundary_observed": True,
            "workflow_status": observed["status"],
            "workflow_runs": observed["workflow_runs"],
            "history_events": observed["observed"]["events"],
            "objects": objects["immutable"],
            "object_inventory_sha256": objects["sha256"],
            "images": images,
            "engine_config_sha256": config_digest,
            "logs_clean": True,
        }
        value["trace"] = trace(value)
        check_trace(oracle(), value["trace"])
        return validate_case(value)
    finally:
        if paused:
            stack.compose("unpause", "runtime")
        locks.close()
        try:
            if owner:
                owner.close()
        finally:
            stack.close()


def campaign(cases=CASES, *, output=None):
    require(len(set(cases)) == len(cases) and set(cases) <= set(CASES))
    m1_assets.verify(m1_assets.load())
    report = {
        "schema_version": "platform-m1-disclosure-v1",
        "assurance": "CONFIDENTIALITY_ONLY",
        **bindings(),
        "qualified": False,
        "requested_cases": list(cases),
        "cases": [],
    }
    path = output or m1.ROOT / "build/m1-disclosure-report.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(live.canonical(report) + b"\n")
    for case in cases:
        live.phase("DISCLOSURE_START:" + case)
        report["cases"].append(run_case(case))
        path.write_bytes(live.canonical(report) + b"\n")
        live.phase("DISCLOSURE_COMPLETE:" + case)
    report["qualified"] = set(cases) == set(CASES)
    validate_report(report)
    path.write_bytes(live.canonical(report) + b"\n")
    return report


def verify_segments(folder):
    paths = sorted(Path(folder).rglob("m1-disclosure-report.json"))
    require(len(paths) == len(GROUPS))
    reports = [validate_report(json.loads(path.read_bytes())) for path in paths]
    require(
        {frozenset(r["requested_cases"]) for r in reports}
        == {frozenset(v) for v in GROUPS.values()}
    )
    cases = [case for report in reports for case in report["cases"]]
    require(len(cases) == len(CASES) and {v["case"] for v in cases} == set(CASES))
    return validate_report(
        {**reports[0], "requested_cases": list(CASES), "qualified": True, "cases": cases}
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("install", "run", "check", "verify-segments"))
    parser.add_argument("--segments")
    args = parser.parse_args()
    if args.action == "install":
        install()
    elif args.action == "verify-segments":
        if args.segments is None:
            parser.error("verify-segments requires --segments")
        print(json.dumps(verify_segments(args.segments), sort_keys=True))
    elif args.action == "check":
        validate_report(json.loads((m1.ROOT / "build/m1-disclosure-report.json").read_bytes()))
    else:
        campaign()


if __name__ == "__main__":
    main()
