"""Shared real-runtime campaign; adapters only supply owned transports and fixtures."""

import base64
import copy
import hashlib
import json
import secrets
import time
from zipfile import ZipFile

if __package__:
    from . import m1_assets
else:
    import m1_assets


class Campaign:
    def __init__(self, adapter):
        self.adapter = adapter
        self.tokens = []
        adapter.tokens = self.tokens
        self.boot = adapter.boot()
        with ZipFile(next((m1_assets.OUTPUT / "ml").glob("*.whl"))) as archive:
            self.operation = json.loads(archive.read("kryvola_ml/_wire/fixtures.json"))["Operation"]
            self.manifest = json.loads(
                archive.read("kryvola_ml/_spec/fixtures/canonical-modular-v2.json")
            )["objects"][0]["value"]
        self.cases = []

    def registry(self, operation, actions):
        token = secrets.token_hex(32)
        self.tokens.append(token.encode())
        policy = {
            "boot_id": self.boot,
            "grants": [],
            "registry_grants": [
                {
                    "spiffe_id": "spiffe://m1.test/workflow",
                    "token_sha256": hashlib.sha256(token.encode()).hexdigest(),
                    "scope": {
                        k: operation[k] for k in ("tenant_scope", "operation_id", "workflow_epoch")
                    },
                    "actions": actions,
                    "expires_unix_ms": int(time.time() * 1000) + 45000,
                }
            ],
        }
        self.adapter.publish(policy)
        return token

    def grant(self, case, purpose="COMPUTE_READ"):
        token = secrets.token_hex(32)
        self.tokens.append(token.encode())
        self.adapter.publish(
            {
                "boot_id": self.boot,
                "registry_grants": [],
                "grants": [
                    {
                        "spiffe_id": "spiffe://m1.test/worker",
                        "token_sha256": hashlib.sha256(token.encode()).hexdigest(),
                        "scope": {**case["scope"], "purpose": purpose},
                        "expires_unix_ms": int(time.time() * 1000) + 45000,
                    }
                ],
            }
        )
        return token

    def call(self, role, method, path, token, body=None, data=None):
        request = {
            "mode": "http",
            "host": self.adapter.runtime_host,
            "role": role,
            "method": method,
            "path": path,
            "token": token,
        }
        if data is not None:
            request["data"] = base64.b64encode(data).decode()
        else:
            request["body"] = body
        return self.adapter.probe(role, request)

    @staticmethod
    def expect(result, status):
        if result.get("status") != status:
            actual = result.get("status")
            if type(actual) is not int:
                raise ValueError("M1_ISOLATION_HTTP_CONTROL")
            raise ValueError(f"M1_ISOLATION_HTTP_CONTROL expected={status} actual={actual}")
        return result.get("body")

    def prepare(self):
        for label, tenant in (("own", "tenant-fixture"), ("foreign", "tenant-foreign")):
            operation = copy.deepcopy(self.operation)
            operation.update(
                tenant_scope=tenant,
                operation_id="m1-isolation-" + label,
                idempotency_key="m1-isolation-" + label,
                deadline_unix_ms=str(int(time.time() * 1000) + 600000),
            )
            for field in ("plan_ref", "key_context_ref", "disclosure_identity"):
                operation[field]["tenant_scope"] = tenant
            manifest = copy.deepcopy(self.manifest)
            manifest["tenant_scope"] = tenant
            canonical = self.adapter.canonical(manifest)
            digest = canonical["digest"]
            token = self.registry(
                operation, ["CREATE_OPERATION", "GET_OPERATION", "ENSURE_ATTEMPT"]
            )
            self.expect(
                self.call(
                    "workflow",
                    "POST",
                    "/v1/operations",
                    token,
                    {
                        "schema_version": "1",
                        "operation": operation,
                        "input_manifest_digests": [digest],
                    },
                ),
                200,
            )
            lease = self.expect(
                self.call(
                    "workflow",
                    "POST",
                    "/v1/attempts/ensure",
                    token,
                    {
                        "schema_version": "1",
                        "attempt": {
                            "schema_version": "1",
                            "tenant_scope": tenant,
                            "operation_id": operation["operation_id"],
                            "workflow_epoch": operation["workflow_epoch"],
                            "attempt_epoch": "1",
                        },
                    },
                ),
                200,
            )
            case = {
                "operation": operation,
                "scope": {
                    "schema_version": "1",
                    "attempt": lease["attempt"],
                    "manifest_digest": digest,
                },
                "manifest": base64.b64decode(canonical["raw"]),
            }
            upload = self.expect(
                self.call(
                    "worker",
                    "POST",
                    "/v1/uploads",
                    self.grant(case, "COMPUTE_WRITE"),
                    {"schema_version": "1", "tenant_scope": tenant, "byte_length": 4},
                ),
                201,
            )["upload_id"]
            self.expect(
                self.call(
                    "worker",
                    "PUT",
                    f"/v1/uploads/{upload}/parts/0",
                    self.grant(case, "COMPUTE_WRITE"),
                    data=bytes([0, 1, 2, 255]),
                ),
                204,
            )
            self.expect(
                self.call(
                    "worker",
                    "PUT",
                    f"/v1/uploads/{upload}/manifest",
                    self.grant(case, "COMPUTE_WRITE"),
                    data=case["manifest"],
                ),
                204,
            )
            self.expect(
                self.call(
                    "worker",
                    "POST",
                    f"/v1/uploads/{upload}/finalize",
                    self.grant(case, "COMPUTE_WRITE"),
                    {"schema_version": "1", "tenant_scope": tenant, "manifest_digest": digest},
                ),
                200,
            )
            self.cases.append(case)
        self.adapter.sql(
            "UPDATE fabric_attempts SET lease_expires_unix_ms="
            "floor(extract(epoch FROM clock_timestamp())*1000)+60000 "
            "WHERE operation_id IN ('m1-isolation-own','m1-isolation-foreign')"
        )

    def positive(self):
        for case in self.cases:
            operation = case["operation"]
            self.expect(
                self.call(
                    "workflow",
                    "GET",
                    "/v1/operations/" + operation["operation_id"],
                    self.registry(operation, ["GET_OPERATION"]),
                ),
                200,
            )
            result = self.call(
                "worker", "POST", "/v1/compute-inputs/parts/0", self.grant(case), case["scope"]
            )
            self.expect(result, 200)
            if result.get("digest") != hashlib.sha256(bytes([0, 1, 2, 255])).hexdigest():
                raise ValueError("M1_ISOLATION_ARTIFACT_CONTROL")

    def run(self):
        self.prepare()
        self.positive()
        snapshot = self.adapter.sql(
            "SELECT json_agg(row_to_json(o) ORDER BY operation_id)::text "
            "FROM fabric_operations o WHERE operation_id IN "
            "('m1-isolation-own','m1-isolation-foreign')"
        )
        own, foreign = self.cases
        denied = {}
        attacks = [
            ("foreign_tenant", "/v1/compute-inputs/parts/0", foreign["scope"]),
            (
                "privileged_mutation",
                "/v1/admin/operations/cancel",
                {
                    "schema_version": "1",
                    **{k: own["operation"][k] for k in ("tenant_scope", "operation_id")},
                    "idempotency_key": "isolation-denied",
                },
            ),
            ("release_grant", "/v1/executions/output-grants", {}),
        ]
        # Each grant is published immediately before its request, not precomputed:
        # replacing the policy must not make all negative credentials dead by setup.
        for name, path, body in attacks:
            token = self.grant(own)
            result = self.call("worker", "POST", path, token, body)
            self.expect(result, 403)
            if result.get("body") != {"schema_version": "1", "code": "FORBIDDEN"}:
                raise ValueError("M1_ISOLATION_DENIAL")
            denied[name] = "FORBIDDEN"
        operation = own["operation"]
        stolen = self.registry(operation, ["GET_OPERATION"])
        path = "/v1/operations/" + operation["operation_id"]
        result = self.call("worker", "GET", path, stolen)
        self.expect(result, 403)
        if result.get("body") != {"schema_version": "1", "code": "FORBIDDEN"}:
            raise ValueError("M1_ISOLATION_DENIAL")
        # The identical credential and target must work for its genuine identity.
        self.expect(self.call("workflow", "GET", path, stolen), 200)
        denied["stolen_coordinator"] = "FORBIDDEN"
        if (
            self.adapter.sql(
                "SELECT json_agg(row_to_json(o) ORDER BY operation_id)::text "
                "FROM fabric_operations o WHERE operation_id IN "
                "('m1-isolation-own','m1-isolation-foreign')"
            )
            != snapshot
        ):
            raise ValueError("M1_ISOLATION_MUTATION")
        self.positive()
        operation = foreign["operation"]
        cancel = {
            "schema_version": "1",
            **{k: operation[k] for k in ("tenant_scope", "operation_id")},
            "idempotency_key": "isolation-cancel",
        }
        self.expect(
            self.call(
                "workflow",
                "POST",
                "/v1/admin/operations/cancel",
                self.registry(operation, ["ADMIN_CANCEL"]),
                cancel,
            ),
            200,
        )
        return denied
