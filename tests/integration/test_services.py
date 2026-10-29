"""Actual public fixture operations; invoked explicitly by integration.py up."""

import json
from concurrent.futures import ThreadPoolExecutor


def require(condition, code):
    if not condition:
        raise ValueError(code)


def s3(stack, operation, *args, endpoint="http://seaweed:8333", check=True):
    return stack.execute(
        "s3-client", "aws", "--endpoint-url", endpoint, "s3api", operation, *args, check=check
    )


def get(stack, key, expected, version=None, byte_range=None, endpoint="http://seaweed:8333"):
    args = ["--bucket", "fixture", "--key", key]
    if version is not None:
        args += ["--version-id", version]
    if byte_range:
        args += ["--range", byte_range]
    s3(stack, "get-object", *args, "/data/result.bin", endpoint=endpoint)
    require((stack.folder / "data/result.bin").read_bytes() == expected, "S3_READ_CONTENT")


def qualify(stack):
    stack.ready("postgres", "pg_isready", "-U", "temporal_fixture")
    require(
        stack.execute(
            "postgres", "psql", "-U", "temporal_fixture", "-d", "postgres", "-Atc", "SELECT 1"
        ).stdout.strip()
        == b"1",
        "POSTGRES_QUERY",
    )
    stack.ready(
        "temporal-cli", "temporal", "--address", "temporal:7233", "operator", "cluster", "health"
    )
    stack.execute(
        "temporal-cli",
        "temporal",
        "--address",
        "temporal:7233",
        "operator",
        "namespace",
        "create",
        "--namespace",
        "fixture",
    )
    stack.execute(
        "temporal-cli",
        "temporal",
        "--address",
        "temporal:7233",
        "operator",
        "namespace",
        "describe",
        "--namespace",
        "fixture",
    )
    script = (
        "import ray; ray.init(address='auto', namespace='fixture'); "
        "f=ray.remote(lambda: 7); assert ray.get(f.remote(), timeout=30)==7; "
        "ray.shutdown(); print('RAY_FIXTURE_OK')"
    )
    result = stack.ready("ray", "python", "-c", script)
    require(b"RAY_FIXTURE_OK" in result.stdout, "RAY_TASK")
    stack.ready("redpanda", "rpk", "cluster", "info", "-X", "brokers=localhost:9092")
    stack.execute("redpanda", "rpk", "topic", "create", "fixture", "-p", "1", "-r", "1")
    stack.execute("redpanda", "rpk", "topic", "produce", "fixture", payload=b"public-fixture\n")
    consume = ("rpk", "topic", "consume", "fixture", "-n", "1", "-o", "start", "-f", "%v")
    require(
        stack.execute("redpanda", *consume).stdout.strip() == b"public-fixture", "BROKER_RECORD"
    )
    stack.ready(
        "s3-client", "aws", "--endpoint-url", "http://seaweed:8333", "s3api", "list-buckets"
    )
    s3(stack, "create-bucket", "--bucket", "fixture")
    s3(
        stack,
        "put-bucket-versioning",
        "--bucket",
        "fixture",
        "--versioning-configuration",
        "Status=Enabled",
    )
    require(
        json.loads(s3(stack, "get-bucket-versioning", "--bucket", "fixture").stdout)["Status"]
        == "Enabled",
        "VERSIONING_DISABLED",
    )
    for name, data in (("first", b"abcdefgh"), ("second", b"ijklmnop")):
        (stack.folder / ("data/" + name + ".bin")).write_bytes(data)
    first = json.loads(
        s3(
            stack,
            "put-object",
            "--bucket",
            "fixture",
            "--key",
            "object",
            "--body",
            "/data/first.bin",
            "--if-none-match",
            "*",
        ).stdout
    )
    require(
        isinstance(first.get("VersionId"), str) and first["VersionId"] not in {"", "null"},
        "MISSING_VERSION_ID",
    )
    duplicate = s3(
        stack,
        "put-object",
        "--bucket",
        "fixture",
        "--key",
        "object",
        "--body",
        "/data/second.bin",
        "--if-none-match",
        "*",
        check=False,
    )
    require(
        duplicate.returncode != 0 and b"PreconditionFailed" in duplicate.stderr,
        "CONDITIONAL_CREATE_ACCEPTED",
    )
    second = json.loads(
        s3(
            stack,
            "put-object",
            "--bucket",
            "fixture",
            "--key",
            "object",
            "--body",
            "/data/second.bin",
            "--if-match",
            first["ETag"],
        ).stdout
    )
    require(second["VersionId"] != first["VersionId"], "VERSION_REUSED")
    stale = s3(
        stack,
        "put-object",
        "--bucket",
        "fixture",
        "--key",
        "object",
        "--body",
        "/data/first.bin",
        "--if-match",
        first["ETag"],
        check=False,
    )
    require(stale.returncode != 0 and b"PreconditionFailed" in stale.stderr, "STALE_WRITE_ACCEPTED")
    get(stack, "object", b"abcdefgh", version=first["VersionId"])
    get(stack, "object", b"ijklmnop", version=second["VersionId"])
    get(stack, "object", b"klm", version=second["VersionId"], byte_range="bytes=2-4")
    # Two clients competing to create the same absent key must not both win.
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [
            pool.submit(
                s3,
                stack,
                "put-object",
                "--bucket",
                "fixture",
                "--key",
                "race",
                "--body",
                body,
                "--if-none-match",
                "*",
                check=False,
            )
            for body in ("/data/first.bin", "/data/second.bin")
        ]
        outcomes = [f.result() for f in futures]
    require(sum(r.returncode == 0 for r in outcomes) == 1, "NONATOMIC_CREATE")
    require(
        all(
            r.returncode == 0
            or b"PreconditionFailed" in r.stderr
            or b"ConditionalRequestConflict" in r.stderr
            for r in outcomes
        ),
        "UNRELATED_RACE_FAILURE",
    )
    stack.execute(
        "toxiproxy",
        "/toxiproxy-cli",
        "create",
        "--listen",
        "0.0.0.0:8666",
        "--upstream",
        "seaweed:8333",
        "s3",
    )
    get(stack, "object", b"ijklmnop", endpoint="http://toxiproxy:8666")
    # Recreate the object gateway rather than preserving its writable layer.
    stack.compose("up", "--detach", "--force-recreate", "seaweed", timeout=90)
    stack.ready(
        "s3-client", "aws", "--endpoint-url", "http://seaweed:8333", "s3api", "list-buckets"
    )
    get(stack, "object", b"abcdefgh", version=first["VersionId"])
    get(stack, "object", b"ijklmnop", version=second["VersionId"])
    stack.compose("restart", "postgres", timeout=90)
    stack.ready("postgres", "pg_isready", "-U", "temporal_fixture")
    stack.compose("restart", "redpanda", "temporal", "ray", timeout=90)
    stack.ready("redpanda", "rpk", "cluster", "info", "-X", "brokers=localhost:9092")
    require(
        stack.execute("redpanda", *consume).stdout.strip() == b"public-fixture",
        "BROKER_RESTART_LOST_RECORD",
    )
    stack.ready(
        "temporal-cli",
        "temporal",
        "--address",
        "temporal:7233",
        "operator",
        "namespace",
        "describe",
        "--namespace",
        "fixture",
    )
    require(b"RAY_FIXTURE_OK" in stack.ready("ray", "python", "-c", script).stdout, "RAY_RESTART")
    stack.boundary()
    print("SERVICE_HEALTH_S3_VERSION_RANGE_CONDITIONS_RACE_RESTART_PASSED")
