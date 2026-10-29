"""Local development isolation checks; no actual owner key or production assurance."""

import asyncio
import base64
import hashlib
import importlib.util
import ipaddress
import json
import re
import socket
from pathlib import Path

if __package__:
    from . import integration
else:
    import integration

ROOT = Path(__file__).resolve().parents[1]


def scan(raw, canary):
    if len(raw) > 262144:
        raise ValueError("ISOLATION_SCAN_LIMIT")
    candidates = [raw]

    def strings(value):
        if isinstance(value, str):
            candidates.append(value.encode())
        elif isinstance(value, dict):
            for key, child in value.items():
                strings(key)
                strings(child)
        elif isinstance(value, list):
            for child in value:
                strings(child)

    try:
        strings(json.loads(raw))
    except ValueError, UnicodeError:
        pass  # Plain service logs are not JSON; raw/encoded scanning still applies.
    for candidate in candidates:
        if canary in candidate or canary.hex().encode() in candidate.lower():
            raise ValueError("PROHIBITED_ISOLATION_MATERIAL")
        for token in re.findall(rb"[A-Za-z0-9+/_-]{16,}={0,2}", candidate):
            try:
                decoded = base64.b64decode(token, altchars=b"-_", validate=True)
            except ValueError:
                continue
            if canary in decoded:
                raise ValueError("PROHIBITED_ISOLATION_MATERIAL")


def listeners(targets):
    for target in targets:
        # Reachability before AND after probes prevents dead targets counting as isolation.
        with socket.create_connection((target["host"], target["port"]), timeout=2):
            pass


def validate_probe(result, targets):
    if (
        type(result.get("uid")) is not int
        or result["uid"] <= 0
        or result.get("positive_control") is not True
        or result.get("denials")
        != [{"target": t["role"], "port": t["port"], "denied": True} for t in targets]
    ):
        raise ValueError("ISOLATION_PROBE_RESULT")


def probe(stack, role, identifier, targets, port):
    code = (ROOT / "config/isolation/probe.py").read_text()
    payload = json.dumps({"positive_port": port, "denied": targets}).encode()
    if role == "ray":
        result = stack.execute(role, "python", "-c", code, payload=payload, timeout=20)
    else:
        name = stack.project + "-probe-" + role
        try:
            result = integration.run(
                [
                    "docker",
                    "run",
                    "--rm",
                    "--name",
                    name,
                    "--label",
                    "com.docker.compose.project=" + stack.project,
                    "--label",
                    "com.docker.compose.service=isolation-probe",
                    "--network",
                    "container:" + identifier,
                    "--user",
                    "65532:65532",
                    "--read-only",
                    "--cap-drop",
                    "ALL",
                    "--security-opt",
                    "no-new-privileges:true",
                    "--memory",
                    "64m",
                    "--pids-limit",
                    "32",
                    "-i",
                    "--entrypoint",
                    "python",
                    integration.configuration()["services"]["owner"]["image"],
                    "-c",
                    code,
                ],
                payload=payload,
                timeout=20,
            )
            result.check_returncode()
        finally:
            # Only our unique generated name; --rm normally already removed it.
            integration.run(["docker", "rm", "--force", name], timeout=10)
    value = json.loads(result.stdout)
    validate_probe(value, targets)
    return value


async def history_bytes(address, workflow_id):
    from temporalio.client import Client

    client = await Client.connect(address + ":7233", namespace="fixture")
    history = await client.get_workflow_handle(workflow_id).fetch_history()
    return history.to_json().encode()


def qualify(stack, fake):
    canary = (stack.folder / "owner-canary").read_bytes()
    if not canary.startswith(b"PUBLIC_ISOLATION_CANARY_NOT_A_KEY_"):
        raise ValueError("NON_KEY_CANARY_REQUIRED")
    ids = stack.compose("ps", "--all", "--quiet").stdout.decode().split()
    inspected, addresses, identifiers = {}, {}, {}
    for identifier in ids:
        result = integration.run(["docker", "inspect", identifier])
        result.check_returncode()
        value = json.loads(result.stdout)[0]
        role = value["Config"]["Labels"]["com.docker.compose.service"]
        scan(json.dumps(value["Config"]).encode(), canary)
        if role != "owner" and any(
            m["Destination"] == "/owner/fixture-key" or Path(m["Source"]).name == "owner-canary"
            for m in value["Mounts"]
        ):
            raise ValueError("OWNER_FILE_MOUNT_LEAK")
        if role in {"owner", "ray", "redpanda", "temporal", "postgres", "toxiproxy"}:
            networks = value["NetworkSettings"]["Networks"]
            if len(networks) != 1:
                raise ValueError("ISOLATION_NETWORK_CROSSOVER")
            addresses[role] = str(ipaddress.IPv4Address(next(iter(networks.values()))["IPAddress"]))
            identifiers[role] = identifier
        inspected[role] = {"configured_user": value["Config"]["User"] or "image-default"}
    if set(inspected) != set(integration.NETWORKS):
        raise ValueError("ISOLATION_MISSING_SERVICE")
    expected = hashlib.sha256(canary).hexdigest()
    positive = (
        "import hashlib,urllib.request; from pathlib import Path; "
        "a=hashlib.sha256(Path('/owner/fixture-key').read_bytes()).hexdigest(); "
        "b=urllib.request.urlopen('http://127.0.0.1:8080',timeout=2).read().decode(); "
        "assert a==b; print(a)"
    )
    owner = stack.ready("owner", "python", "-c", positive)
    if owner.stdout.strip().decode() != expected:
        raise ValueError("OWNER_POSITIVE_CONTROL")
    targets = [
        {"role": role, "host": addresses[role], "port": port}
        for role, port in (
            ("owner", 8080),
            ("redpanda", 9644),
            ("temporal", 7233),
            ("postgres", 5432),
            ("toxiproxy", 8474),
        )
    ]
    listeners(targets)
    results = {}
    for role, port, denied in (
        ("ray", 6379, targets),
        ("redpanda", 9092, [t for t in targets if t["role"] in {"owner", "temporal", "postgres"}]),
        ("temporal", 7233, [t for t in targets if t["role"] in {"owner", "redpanda", "toxiproxy"}]),
    ):
        results[role] = probe(stack, role, identifiers[role], denied, port)
        # Check the actual actor filesystem, not the helper container's filesystem.
        checked = stack.execute(
            role,
            "/bin/sh",
            "-c",
            "test -r /etc/hostname && test ! -e /owner/fixture-key "
            "&& test ! -S /var/run/docker.sock && id -u",
        )
        results[role]["actor_uid"] = int(checked.stdout.strip())
    listeners(targets)
    topic = stack.project + "-fake"
    record = stack.execute(
        "redpanda", "rpk", "topic", "consume", topic, "-n", "1", "-o", "start", "-f", "%v"
    ).stdout
    scan(record, canary)
    workflow_id = fake["trace"][2]["workflow_id"]
    scan(asyncio.run(history_bytes(addresses["temporal"], workflow_id)), canary)
    for role in ("owner", "ray", "redpanda", "temporal"):
        logs = stack.compose(
            "logs", "--no-color", "--tail", "200", role, output_limit=262144
        ).stdout
        scan(logs, canary)
    report = {
        "kind": "LOCAL_SYNTHETIC_ISOLATION_ONLY",
        "production_qualified": False,
        "canary_type": "SYNTHETIC_NON_KEY",
        "owner_positive_control": True,
        "identities": inspected,
        "probes": results,
        "scanned": [
            "broker-record",
            "temporal-history",
            "owner-logs",
            "ray-logs",
            "broker-logs",
            "workflow-logs",
        ],
    }
    spec = importlib.util.spec_from_file_location(
        "isolation_checks", ROOT / "tests/integration/test_isolation.py"
    )
    if spec is None or spec.loader is None:
        raise ValueError("MISSING_ISOLATION_CHECKS")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.qualify(report)
    with (stack.folder / "isolation-report.json").open("x", encoding="utf-8") as stream:
        json.dump(report, stream, sort_keys=True)
    stack.boundary()
    print("LOCAL_OWNER_COMPUTE_ISOLATION_PASSED")
    return report
