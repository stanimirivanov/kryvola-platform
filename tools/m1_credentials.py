"""Fresh local-fixture credentials, never accepted as production authorization."""

import json
import secrets
import subprocess


def create(folder):
    folder.mkdir(mode=0o700)

    def write(name, value):
        path = folder / name
        path.write_text(value if isinstance(value, str) else json.dumps(value))
        # Parent is private; only explicit individual files are mounted into roles.
        path.chmod(0o444)

    passwords = {
        role: secrets.token_hex(24)
        for role in ("admin", "temporal", "runtime", "events", "release")
    }
    for role in ("admin", "temporal"):
        write("pg-" + role, passwords[role])
    sql = []
    for role in ("runtime", "events", "release"):
        sql.append(f"CREATE ROLE fabric_{role} LOGIN PASSWORD '{passwords[role]}';")
        write(
            "database" + ("" if role == "runtime" else "-" + role),
            f"postgresql://fabric_{role}:{passwords[role]}@postgres:5432/fabric",
        )
    sql += [
        f"CREATE ROLE m1_temporal LOGIN PASSWORD '{passwords['temporal']}';",
        "CREATE DATABASE fabric OWNER fabric_runtime;",
        "CREATE DATABASE temporal OWNER m1_temporal;",
        "CREATE DATABASE temporal_visibility OWNER m1_temporal;",
    ]
    write(
        "init-db.sh",
        '#!/bin/sh\nset -eu\nexport PGPASSWORD="$(cat /run/m1-secrets/pg-admin)"\n'
        + "psql -h postgres -U m1_admin -d postgres -v ON_ERROR_STOP=1 <<'SQL'\n"
        + "\n".join(sql)
        + "\nSQL\n",
    )
    access, secret = secrets.token_hex(16), secrets.token_hex(24)
    admin_access, admin_secret = secrets.token_hex(16), secrets.token_hex(24)
    write(
        "s3-server.json",
        {
            "identities": [
                {
                    "name": "runtime",
                    "credentials": [{"accessKey": access, "secretKey": secret}],
                    "actions": ["Read:m1-artifacts", "Write:m1-artifacts", "List:m1-artifacts"],
                },
                {
                    "name": "admin",
                    "credentials": [{"accessKey": admin_access, "secretKey": admin_secret}],
                    "actions": ["Admin", "Read", "Write", "List", "Tagging"],
                },
            ]
        },
    )
    write(
        "s3.json",
        {
            "endpoint": "http://storage:8333",
            "bucket": "m1-artifacts",
            "region": "us-east-1",
            "access_key_id": access,
            "secret_access_key": secret,
            "tenant_quota_bytes": 128 << 20,
            "allow_http": True,
        },
    )
    write(
        "aws",
        f"[default]\naws_access_key_id={admin_access}\naws_secret_access_key={admin_secret}\n",
    )
    write("tokens.json", {})
    write("policy.json", {"boot_id": "unstarted", "grants": []})
    write("release.json", {})  # No release authority is granted by service startup.

    def openssl(*args):
        subprocess.run(["openssl", *args], cwd=folder, check=True, capture_output=True, timeout=30)

    openssl(
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-days",
        "2",
        "-subj",
        "/CN=M1-fixture-only",
        "-keyout",
        "ca.key",
        "-out",
        "ca.crt",
    )
    for name in ("broker", "events", "admin"):
        openssl(
            "req",
            "-new",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-subj",
            "/CN=" + name,
            "-keyout",
            name + ".key",
            "-out",
            name + ".csr",
        )
        write(
            name + ".ext",
            "subjectAltName=DNS:" + name + "\nextendedKeyUsage=serverAuth,clientAuth\n",
        )
        openssl(
            "x509",
            "-req",
            "-in",
            name + ".csr",
            "-CA",
            "ca.crt",
            "-CAkey",
            "ca.key",
            "-CAcreateserial",
            "-days",
            "2",
            "-extfile",
            name + ".ext",
            "-out",
            name + ".crt",
        )
        (folder / (name + ".key")).chmod(0o444)
    (folder / "ca.crt").chmod(0o444)
    base = "/run/m1-secrets/"
    write(
        "kafka.json",
        {
            "bootstrap_servers": "broker:9092",
            "topic": "m1-events",
            "dead_letter_topic": "m1-dead-letter",
            "subscriber": "m1-local",
            "tls_ca_file": base + "ca.crt",
            "tls_certificate_file": base + "events.crt",
            "tls_key_file": base + "events.key",
        },
    )
    write(
        "broker.json",
        {
            "redpanda": {
                "data_directory": "/var/lib/redpanda/data",
                "node_id": 0,
                "rpc_server": {"address": "0.0.0.0", "port": 33145},
                "advertised_rpc_api": {"address": "broker", "port": 33145},
                "kafka_api": [{"name": "tls", "address": "0.0.0.0", "port": 9092}],
                "advertised_kafka_api": [{"name": "tls", "address": "broker", "port": 9092}],
                "kafka_api_tls": [
                    {
                        "name": "tls",
                        "enabled": True,
                        "cert_file": base + "broker.crt",
                        "key_file": base + "broker.key",
                        "truststore_file": base + "ca.crt",
                        "require_client_auth": True,
                    }
                ],
                "admin": [{"address": "127.0.0.1", "port": 9644}],
                "developer_mode": True,
            }
        },
    )
    return passwords["temporal"]
