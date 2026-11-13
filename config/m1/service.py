"""Local M1 startup adapters; no synthetic inference or owner-key transport."""

import asyncio
import base64
import http.client
import importlib
import importlib.util
import json
import os
import select
import ssl
import subprocess
import sys
import tempfile
from pathlib import Path

STATE = Path("/run/m1-state")
SECRETS = Path("/run/m1-secrets")


def ready(role):
    (STATE / "ready.json").write_text(json.dumps({"role": role, "ready": True}))


def tls(role):
    raw = subprocess.check_output(
        [
            "/opt/m1/spire-agent",
            "api",
            "fetch",
            "x509",
            "-socketPath",
            "/run/workload/agent.sock",
            "-output",
            "json",
        ],
        timeout=20,
    )
    identity = "spiffe://m1.test/" + role
    svid = next(x for x in json.loads(raw)["svids"] if x["spiffe_id"] == identity)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    with tempfile.TemporaryDirectory(prefix="m1-svid-") as tmp:
        root = Path(tmp)
        for field, name, label in (
            ("x509_svid", "cert", "CERTIFICATE"),
            ("x509_svid_key", "key", "PRIVATE KEY"),
            ("bundle", "ca", "CERTIFICATE"),
        ):
            data = ssl.DER_cert_to_PEM_cert(base64.b64decode(svid[field])).replace(
                "CERTIFICATE", label
            )
            (root / name).write_text(data)
            (root / name).chmod(0o600)
        context.load_verify_locations(root / "ca")
        context.load_cert_chain(root / "cert", root / "key")
    return context


async def proxy(port, host, destination):
    slots = asyncio.Semaphore(64)

    async def connection(reader, writer):
        if slots.locked():
            writer.close()
            return
        async with slots:
            other = None
            try:
                remote, other = await asyncio.wait_for(
                    asyncio.open_connection(host, destination), 5
                )

                async def copy(source, target):
                    while data := await asyncio.wait_for(source.read(65536), 30):
                        target.write(data)
                        await target.drain()

                jobs = [
                    asyncio.create_task(copy(reader, other)),
                    asyncio.create_task(copy(remote, writer)),
                ]
                _, pending = await asyncio.wait(jobs, return_when=asyncio.FIRST_COMPLETED)
                for job in pending:
                    job.cancel()
                await asyncio.gather(*jobs, return_exceptions=True)
            except OSError, TimeoutError:
                pass
            finally:
                writer.close()
                if other is not None:
                    other.close()

    return await asyncio.start_server(connection, "0.0.0.0" if port == 8443 else "127.0.0.1", port)


async def runtime():
    process = subprocess.Popen(
        [
            "/opt/fabric/bin/fabric-runtime",
            "--spiffe",
            "unix:///run/workload/agent.sock",
            "spiffe://m1.test/runtime",
            str(SECRETS / "policy.json"),
            "--registry",
            str(SECRETS / "database"),
            "--uploads",
            str(SECRETS / "s3.json"),
        ],
        stdout=subprocess.PIPE,
    )
    try:
        if process.stdout is None or not select.select([process.stdout], [], [], 45)[0]:
            raise ValueError("M1_RUNTIME_STARTUP")
        address, boot = process.stdout.readline(4096).decode().split()
        host, port = address.rsplit(":", 1)
        if host != "127.0.0.1":
            raise ValueError("M1_RUNTIME_LISTENER")
        (STATE / "boot.json").write_text(json.dumps({"boot_id": boot}))
        server = await proxy(8443, host, int(port))
        ready("runtime")
        async with server:
            while process.poll() is None:
                await asyncio.sleep(0.2)
        raise ValueError("M1_RUNTIME_EXITED")
    finally:
        process.terminate()
        process.wait(timeout=5)


def probe(role, host="127.0.0.1", context=None):
    connection = http.client.HTTPSConnection(host, 8443, context=context or tls(role), timeout=5)
    connection.connect()
    cert = connection.sock.getpeercert() if connection.sock is not None else None
    if cert is None:
        raise ValueError("M1_RUNTIME_IDENTITY")
    names = cert.get("subjectAltName", ())
    if [x for x in names if x[0] == "URI"] != [("URI", "spiffe://m1.test/runtime")]:
        raise ValueError("M1_RUNTIME_IDENTITY")
    connection.request("GET", "/healthz")
    response = connection.getresponse()
    if response.status != 200 or json.loads(response.read(4096)) != {"status": "ok"}:
        raise ValueError("M1_RUNTIME_HEALTH")
    connection.close()
    print("M1_RUNTIME_MTLS_READY")


async def maintain_workload(role, registry=None):
    while True:
        # Replace the complete trust store with each short-lived client SVID.
        context = await asyncio.to_thread(tls, role)
        if registry is not None:
            registry.tls = context
            await asyncio.to_thread(probe, role, "runtime", context)
        ready(role)
        await asyncio.sleep(10)


async def workflow():

    # Role libraries are installed in pinned role images, separate from M0's env.
    Client = importlib.import_module("temporalio.client").Client
    Worker = importlib.import_module("temporalio.worker").Worker
    module = importlib.import_module("kryvola_fabric.compute_activities")
    ComputeActivities, Registry = module.ComputeActivities, module.Registry
    CoordinatorRelease = importlib.import_module(
        "kryvola_fabric.compute_release"
    ).CoordinatorRelease
    module = importlib.import_module("kryvola_fabric.compute_workflow")
    ComputeWorkflow, DATA_CONVERTER = module.ComputeWorkflow, module.DATA_CONVERTER
    module = importlib.import_module("kryvola_fabric.ray_dispatch")
    RayDispatcher, local_candidates, local_jobs = (
        module.RayDispatcher,
        module.local_candidates,
        module.local_jobs,
    )

    if importlib.util.find_spec("kryvola_owner") is not None:
        raise ValueError("M1_WORKFLOW_OWNER_IMPORT")

    def credential(action, scope):
        # No fixture capability grants: absent operator-issued tokens fail closed.
        return json.loads((SECRETS / "tokens.json").read_bytes()).get(action, "")

    registry = Registry("runtime", 8443, tls("workflow"), "spiffe://m1.test/runtime", credential)
    dispatcher = RayDispatcher(local_jobs(), local_candidates(Path("/run/compute")))
    activities = ComputeActivities(registry, dispatcher)
    release = CoordinatorRelease(
        Path("/opt/fabric/bin/fabric-runtime"),
        SECRETS / "database-release",
        SECRETS / "release.json",
    )
    client = await Client.connect("temporal:7233", data_converter=DATA_CONVERTER)
    server = await proxy(8265, "ray", 8265)
    async with (
        server,
        Worker(
            client,
            task_queue=os.environ["M1_TASK_QUEUE"],
            workflows=[ComputeWorkflow],
            activities=[
                activities.prepare,
                activities.dispatch,
                activities.dispatch_ray,
                activities.select,
                release.commit,
            ],
        ),
    ):
        await maintain_workload("workflow", registry)


async def owner():
    kryvola_owner = importlib.import_module("kryvola_owner")
    Client = importlib.import_module("kryvola_ml.sdk.client").Client
    PreparedSubmission = importlib.import_module("kryvola_ml.sdk.submission").PreparedSubmission

    assert kryvola_owner.OwnerKey and Client and PreparedSubmission
    result = subprocess.run(
        ["/opt/owner/bin/kryvola-owner-agent", "--invalid"], capture_output=True
    )
    if result.returncode != 2 or os.stat("/owner").st_mode & 0o077:
        raise ValueError("M1_OWNER_BOUNDARY")
    await maintain_workload("owner")


if __name__ == "__main__":
    try:
        role = sys.argv[1]
        if role == "probe":
            probe(sys.argv[2])
        else:
            asyncio.run({"runtime": runtime, "workflow": workflow, "owner": owner}[role]())
    except Exception:
        raise SystemExit("M1_SERVICE_STARTUP_FAILED") from None
