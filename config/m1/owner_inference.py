"""Owner-only live qualification; stdout carries bounded control metadata only."""

import base64
import ctypes
import importlib
import importlib.util
import json
import os
import re
import resource
import secrets
import subprocess
import sys
import time
from importlib.resources import files
from pathlib import Path

ROOT = Path("/owner/qualification")
SLOT = "inference"
AGENT = Path("/opt/owner/bin/kryvola-owner-agent")
sdk = importlib.import_module("kryvola_ml.sdk.submission")
owner_sdk = importlib.import_module("kryvola_ml.sdk.owner")
client_sdk = importlib.import_module("kryvola_ml.sdk.client")
hashing = importlib.import_module("blake3")
PHASE = "PREPARE"
SECRET_MARKERS = []
VALUES = ()


def canonical(value):
    return client_sdk.canonical(value)


def emit(value):
    raw = canonical(value)
    if len(raw) > 32768:
        raise ValueError("M1_OWNER_CONTROL_BOUND")
    print("M1_CONTROL:" + raw.decode(), flush=True)


def receive():
    raw = sys.stdin.buffer.readline(32770)
    if len(raw) > 32769 or not raw.endswith(b"\n"):
        raise ValueError("M1_OWNER_CONTROL_BOUND")
    return json.loads(raw)


def run(args, data=None):
    result = subprocess.run(args, input=data, capture_output=True, timeout=75)
    if result.returncode:
        # These fixed local commands report paths/error codes, never stdin secrets.
        sys.stderr.buffer.write(result.stderr[:2048])
        raise ValueError("M1_OWNER_COMMAND_FAILED")
    return result.stdout


def write(suffix, data):
    path = ROOT / (SLOT + "." + suffix)
    path.write_bytes(data if isinstance(data, bytes) else canonical(data))
    path.chmod(0o600)


def fixture(name, kind=None):
    value = json.loads(files("kryvola_ml").joinpath("_spec/fixtures/" + name).read_bytes())
    return next(x["value"] for x in value["objects"] if x["kind"] == kind) if kind else value


def session():
    global PHASE
    PHASE = "SESSION"
    ROOT.mkdir(mode=0o700)
    for variable, name in (
        ("XDG_RUNTIME_DIR", "session"),
        ("XDG_DATA_HOME", "data"),
        ("XDG_CACHE_HOME", "cache"),
    ):
        path = ROOT / name
        path.mkdir(mode=0o700)
        os.environ[variable] = str(path)
    run(
        [
            "gnome-keyring-daemon",
            "--daemonize",
            "--replace",
            "--unlock",
            "--components=secrets",
            "--control-directory",
            str(ROOT / "session/keyring"),
        ],
        secrets.token_hex(32).encode(),
    )
    until = time.monotonic() + 15
    while b"boolean true" not in run(
        [
            "dbus-send",
            "--session",
            "--print-reply",
            "--dest=org.freedesktop.DBus",
            "/org/freedesktop/DBus",
            "org.freedesktop.DBus.NameHasOwner",
            "string:org.freedesktop.secrets",
        ]
    ):
        if time.monotonic() >= until:
            raise ValueError("M1_OWNER_KEYRING_NOT_READY")
        time.sleep(0.1)
    wrapping = secrets.token_bytes(32)
    seed = secrets.token_bytes(32)
    SECRET_MARKERS.extend([wrapping, seed, wrapping.hex().encode(), seed.hex().encode()])
    for application, value in (("kryvola-owner-v1", wrapping), ("kryvola-owner-approval-v1", seed)):
        run(
            [
                "secret-tool",
                "store",
                "--label=M1 disposable owner",
                "application",
                application,
                "slot",
                SLOT,
            ],
            value.hex().encode(),
        )
    PHASE = "CUSTODY_INIT"
    run([str(AGENT), "init", str(ROOT), sys.executable, SLOT])
    PHASE = "CUSTODY_CHECK"
    run([str(AGENT), "check", str(ROOT), sys.executable, SLOT])
    # Public native sealing interface; the restored opaque key never leaves this owner UID.
    context = hashing.blake3(b"kryvola/owner-custody/v1\0" + SLOT.encode()).digest()
    PHASE = "KEY_RESTORE"
    key = importlib.import_module("kryvola_owner").OwnerKey.restore(
        wrapping, context, (ROOT / (SLOT + ".key")).read_bytes()
    )
    PHASE = "SIGNING_PUBLIC"
    public = run(
        ["openssl", "pkey", "-inform", "DER", "-pubout", "-outform", "DER"],
        bytes.fromhex("302e020100300506032b657004220420") + seed,
    )
    trust = {
        "signer": "m1-owner",
        "key_id": "qualification",
        "key_epoch": "1",
        "public_key_hex": public[-32:].hex(),
    }
    return key, trust


def prepare(engine_digest):
    global PHASE
    key, trust = session()
    PHASE = "SDK_PREPARE"
    evaluation = key.evaluation_key()
    operation = fixture("control.json")["Operation"]
    operation["operation_id"] = "m1-inference"
    operation["workflow_epoch"] = "1"
    operation["deadline_unix_ms"] = str(int(time.time() * 1000) + 300000)
    context = fixture("canonical-corpus.json", "key-context")
    context.update(
        tenant_scope=operation["tenant_scope"],
        owner_identity=trust["signer"],
        native_codec_version="tfhe-rs-1.8.1",
        evaluation_key_blob_digest=sdk.commitment("blob", 1, evaluation),
    )
    parameters = "cda9e129d55cc6a17060d8913f6e0d554c5a990e62c967514db86bf57a524674"
    context["parameters"].update(
        parameter_set_digest=parameters,
        radix_bits="8",
        message_modulus="4",
        carry_modulus="4",
        scheme="TFHE",
    )
    reference = operation["key_context_ref"]
    reference.update({name: context[name] for name in ("key_context_id", "key_epoch")})
    reference["key_context_digest"] = sdk.commitment("key-context", 1, canonical(context))
    descriptor = fixture("profiles/model.json")
    program = files("kryvola_ml").joinpath("_fixtures/fhe-q1/program.txt").read_bytes()
    program_digest = hashing.blake3(program).hexdigest()
    descriptor["workload"].update(
        operators=["ADD", "MUL"],
        parameter_set_digest=parameters,
        program_digest=program_digest,
        engine_digest=engine_digest,
        model_digest=sdk.commitment("blob", 1, program),
    )
    descriptor["reference_program_digest"] = program_digest
    consent = fixture("fhe-q1-consent.json")
    agent = owner_sdk.OwnerAgent(AGENT, ROOT, SLOT)
    state = {}

    def approve(plan_bytes, approved):
        plan = json.loads(plan_bytes)
        approval = fixture("canonical-approval-receipt-v3.json", "approval")
        for name in (
            "tenant_scope",
            "logical_job_id",
            "operation_id",
            "workflow_epoch",
            "policy_digest",
        ):
            approval[name] = approved[name]
        for name in ("recipient", "output_stage", "disclosure_index"):
            approval[name] = approved["disclosure_identity"][name]
        for name in (
            "model_digest",
            "program_digest",
            "key_context_digest",
            "consent_digest",
            "evidence_policy_digest",
        ):
            approval[name] = plan[name]
        approval.update(
            purpose="COMPUTE",
            subject_kind="plan",
            session_epoch="0",
            plan_digest=approved["plan_ref"]["plan_digest"],
            subject_digest=approved["plan_ref"]["plan_digest"],
            valid_from_unix_ms=str(int(time.time() * 1000) - 1000),
            expires_unix_ms=approved["deadline_unix_ms"],
        )
        policy = {"approval": approval, "assurance": "CONFIDENTIALITY_ONLY", **trust}
        write("plan", plan_bytes)
        write("consent", consent)
        write("approval-policy", policy)
        signed = agent.approve(plan_bytes, approved)
        state.update(plan=plan, operation=approved, compute=json.loads(signed))
        approval["purpose"] = "RELEASE"
        write("approval-policy", policy)
        release = agent.approve(plan_bytes, approved)
        write("approval", release)
        state["release"] = json.loads(release)
        return signed

    class Owner:
        def evaluation_key(self):
            return evaluation

        def encrypt_pair(self, values):
            return key.encrypt_pair(values)

    prepared = sdk.prepare_submission(
        Owner(), approve, descriptor, operation, context, consent, values=bytes(VALUES)
    )
    write("key-context", context)
    emit(
        {
            "stage": "PREPARED",
            "trust": trust,
            "consent": consent,
            **state,
            "manifests": [json.loads(item.manifest) for item in prepared.artifacts],
            "reservations": [json.loads(item.reservation) for item in prepared.artifacts],
        }
    )
    return prepared, state, descriptor


def main():
    global PHASE, VALUES
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    if ctypes.CDLL(None).prctl(4, 0, 0, 0, 0) != 0:
        raise ValueError("M1_OWNER_PROCESS_PROTECTION")
    VALUES = tuple(secrets.choice((0, 1, 2, 7, 15, 63, 127, 128, 254, 255)) for _ in range(2))
    prepared, state, descriptor = prepare(sys.argv[1])
    if sys.argv[2:] == ["prepare"]:
        return
    for item in prepared.artifacts:
        SECRET_MARKERS.extend(
            [item.data[-64:], item.data[-64:].hex().encode(), base64.b64encode(item.data[:96])]
        )

    def credential(action, target):
        global PHASE
        PHASE = action
        emit({"stage": "GRANT", "action": action, "target": target})
        token = receive()["token"]
        return token

    spec = importlib.util.spec_from_file_location("m1_service", "/opt/m1/service.py")
    if spec is None or spec.loader is None:
        raise ValueError("M1_OWNER_TLS")
    service = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(service)
    client = client_sdk.Client(
        "runtime", 8443, service.tls("owner"), "spiffe://m1.test/runtime", credential
    )
    admitted = sdk.submit(client, prepared)
    emit({"stage": "ADMITTED", "response": admitted})
    # The operator supplies only committed public release documents after the real workflow.
    released = receive()
    for suffix in ("release", "release-signature", "open-policy"):
        write(suffix, released[suffix])
    svid = json.loads(
        run(
            [
                "/opt/m1/spire-agent",
                "api",
                "fetch",
                "x509",
                "-socketPath",
                "/run/workload/agent.sock",
                "-output",
                "json",
            ]
        )
    )
    import ssl

    identity = next(x for x in svid["svids"] if x["spiffe_id"] == "spiffe://m1.test/owner")
    for field, suffix, label in (
        ("x509_svid", "consumer-cert", "CERTIFICATE"),
        ("x509_svid_key", "consumer-key", "PRIVATE KEY"),
        ("bundle", "consumer-ca", "CERTIFICATE"),
    ):
        write(
            suffix,
            ssl.DER_cert_to_PEM_cert(base64.b64decode(identity[field]))
            .replace("CERTIFICATE", label)
            .encode(),
        )
        if label == "PRIVATE KEY":
            SECRET_MARKERS.extend(
                line
                for line in (ROOT / (SLOT + "." + suffix)).read_bytes().splitlines()
                if not line.startswith(b"-----")
            )
    client.tls = service.tls("owner")
    lifecycle = importlib.import_module("kryvola_ml.sdk.lifecycle").Lifecycle(
        client, state["operation"]
    )
    opener = owner_sdk.ResultOpener(
        AGENT,
        ROOT,
        Path(sys.executable),
        SLOT,
        lambda scope: credential("CONSUMER_READ", {"scope": scope, "part_index": None}),
    )
    output = lifecycle.open_result(released["scope"], opener)
    expected = (
        importlib.import_module("kryvola_ml.baseline").tiny_circuit(descriptor).evaluate(VALUES)
    )
    if output != bytes(expected):
        raise ValueError("M1_OWNER_REFERENCE_MISMATCH")
    reference = importlib.import_module("kryvola_ml.baseline.fixture").verify_fixture()
    for pair in (VALUES, tuple(output)):
        SECRET_MARKERS.extend([canonical(list(pair)), json.dumps(list(pair)).encode()])
    emit(
        {
            "stage": "OPENED",
            "assurance": "CONFIDENTIALITY_ONLY",
            "owner_reference_match": True,
            "frozen_reference_sha256": reference["manifest_sha256"],
        }
    )

    # Inspect actual service logs inside the owner domain: wrapping/signing keys
    # and the plaintext witness never become scanner inputs outside this UID.
    def clean(raw):
        if (
            any(marker in raw for marker in SECRET_MARKERS)
            or any(marker in raw.lower() for marker in (b"client_key", b"begin private key"))
            or re.search(rb"(?i)plaintext[\"']?\s*[:=]", raw)
        ):
            raise ValueError("M1_OWNER_LOG_SECRET")

    try:
        clean(SECRET_MARKERS[0])
    except ValueError:
        pass
    else:
        raise ValueError("M1_OWNER_LOG_NEGATIVE_CONTROL")
    tail = b""
    while True:
        command = receive()
        if command == {"scan_done": True}:
            break
        raw = base64.b64decode(command["logs_base64"], validate=True)
        if len(raw) > 12000:
            raise ValueError("M1_OWNER_CONTROL_BOUND")
        clean(tail + raw)
        tail = (tail + raw)[-128:]
        emit({"stage": "LOG_CHUNK_CLEAN"})
    emit({"stage": "AUDITED", "logs_clean": True, "negative_control": True})


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        code = str(error)
        if code not in {
            "SUBMISSION_REJECTED",
            "LIFECYCLE_REJECTED",
            "OUTPUT_NOT_RELEASED",
            "OWNER_UNAVAILABLE",
        }:
            code = type(error).__name__
        raise SystemExit("M1_OWNER_INFERENCE_FAILED:" + PHASE + ":" + code) from None
