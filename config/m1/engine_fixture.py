"""Non-executed M1 startup assignment: real native Engine RPC, no inference."""

import copy
import importlib
import json
import os
import socket
import subprocess
import sys
import time
from pathlib import Path
from types import ModuleType

# Installed only in the admitted M1 role images; the host retains frozen M0.
control: ModuleType = importlib.import_module("kryvola_fabric.control")

ROOT = Path("/run/execution")


def prepare():
    request = copy.deepcopy(json.loads(Path("/opt/m1/execute-fixture.json").read_bytes()))
    deadline = str(int(time.time() * 1000) + 900000)
    request["operation"]["deadline_unix_ms"] = request["execution"]["deadline_unix_ms"] = deadline
    request["program_digest"] = "52687303e4a13081f0f40c15bfa0fafbf35812fb96a3d30f99206ee534c010f5"
    request["parameter_set_digest"] = (
        "cda9e129d55cc6a17060d8913f6e0d554c5a990e62c967514db86bf57a524674"
    )
    request["required_operators"] = ["ADD", "MUL"]
    request["engine_digest"] = os.environ["M1_ENGINE_DIGEST"]
    second = copy.deepcopy(request["input_refs"][0])
    second["manifest_digest"] = "b" * 64
    request["input_refs"].append(second)
    ROOT.mkdir(exist_ok=True)
    ROOT.chmod(0o700)
    key = ROOT / "receipt.pk8"
    subprocess.run(
        ["openssl", "genpkey", "-algorithm", "ED25519", "-outform", "DER", "-out", str(key)],
        check=True,
        capture_output=True,
    )
    key.chmod(0o600)
    assignment = {
        "execute_protobuf_hex": control.encode_control("ExecuteRequest", request).hex(),
        "fabric_address": socket.gethostbyname("runtime") + ":8443",
        "fabric_id": "spiffe://m1.test/runtime",
        "worker_id": "spiffe://m1.test/worker",
        "workload_endpoint": "unix:///run/workload/agent.sock",
        "credentials": {"reads": [["0" * 64], ["0" * 64]], "output": "0" * 64, "receipt": "0" * 64},
        "receipt": {
            "signer": "spiffe://m1.test/worker",
            "key_id": "startup-only",
            "key_epoch": "1",
            "policy_epoch": "1",
            **{
                name: "a" * 64
                for name in (
                    "consent_digest",
                    "model_digest",
                    "capability_profile_digest",
                    "leakage_profile_digest",
                    "evidence_policy_digest",
                )
            },
        },
        "receipt_key": str(key),
        "evaluator": "/opt/kryvola/kryvola-cpu-evaluator",
        "supervisor": "/opt/kryvola/cpu_runner.py",
    }
    (ROOT / "assignment.json").write_text(json.dumps(assignment))
    (ROOT / "assignment.json").chmod(0o600)
    (ROOT / "status.json").write_text(
        json.dumps(
            {
                "schema_version": "1",
                "attempt": request["execution"]["attempt"],
                "execution_id": request["execution"]["execution_id"],
            }
        )
    )
    for path in [*ROOT.iterdir(), ROOT]:
        os.chown(path, 65532, 65532)


def probe():
    grpc = importlib.import_module("grpc")

    request = json.loads((ROOT / "status.json").read_bytes())
    # Tonic requires a valid HTTP/2 authority; a socket pathname is not a hostname.
    with grpc.insecure_channel(
        "unix:/run/execution/engine.sock",
        options=[("grpc.default_authority", "localhost")],
    ) as channel:
        call = channel.unary_unary("/kryvola.spec.v1.EngineService/GetExecutionStatus")
        response = control.decode_control(
            "GetExecutionStatusResponse",
            call(control.encode_control("GetExecutionStatusRequest", request), timeout=5),
        )
    if (
        response["execution"]["physical_state"] != "CREATED"
        or response["error_code"] != "NONE"
        or response.get("output_refs")
    ):
        raise ValueError("M1_ENGINE_STARTUP_STATE")
    print("M1_ENGINE_RPC_READY_NO_EXECUTION")


if __name__ == "__main__":
    {"prepare": prepare, "probe": probe}[sys.argv[1]]()
