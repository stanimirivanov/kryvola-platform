"""M1 compromised-worker evidence: precise denials, live positives, no secret output."""

if __package__:
    from . import isolation
else:
    import isolation

POSITIVES = {
    "coordinator_before",
    "coordinator_after",
    "artifact_before",
    "artifact_after",
    "owner_canary",
    "denied_targets_before",
    "denied_targets_after",
    "privileged_route",
}
EXPECTED = {
    "foreign_tenant": "FORBIDDEN",
    "stolen_coordinator": "FORBIDDEN",
    "privileged_mutation": "FORBIDDEN",
    "release_grant": "FORBIDDEN",
    "metadata": "NETWORK_DENIED_HEALTHY_TARGET",
    "broker_admin": "NETWORK_DENIED_HEALTHY_TARGET",
    "database": "CREDENTIAL_REQUIRED",
    "owner_files": "NOT_MOUNTED",
}


def validate(value):
    if (
        set(value) != {"positive", "denied", "inventory"}
        or value["positive"] != dict.fromkeys(POSITIVES, True)
        or any(v is not True for v in value["positive"].values())
        or value["denied"] != EXPECTED
        or value["inventory"]
        != {
            "uid": 65532,
            "effective_capabilities": 0,
            "owner_library": False,
            "forbidden_files_absent": True,
        }
    ):
        raise ValueError("M1_ISOLATION_EVIDENCE")
    return value


def scan(raw, secrets):
    for secret in secrets:
        isolation.scan(raw, secret)
