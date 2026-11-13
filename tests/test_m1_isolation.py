"""Isolation evidence requires successful real controls and specific denials."""

import copy
import json
import unittest


class IsolationEvidenceTests(unittest.TestCase):
    def test_missing_controls_transport_errors_and_unexpected_denials_fail(self):
        from tools import m1_isolation as m

        value = {
            "positive": {name: True for name in m.POSITIVES},
            "denied": {name: m.EXPECTED[name] for name in m.EXPECTED},
            "inventory": {
                "uid": 65532,
                "effective_capabilities": 0,
                "owner_library": False,
                "forbidden_files_absent": True,
            },
        }
        m.validate(value)
        for mutate in (
            lambda d: d["positive"].pop("artifact_after"),
            lambda d: d["positive"].update(artifact_before=False),
            lambda d: d["positive"].update(artifact_before=1),
            lambda d: d["denied"].update(foreign_tenant="TIMEOUT"),
            lambda d: d["denied"].update(foreign_tenant="404"),
            lambda d: d["denied"].update(metadata="CONNECTION_REFUSED"),
            lambda d: d["inventory"].update(owner_library=True),
            lambda d: d["inventory"].update(uid=0),
            lambda d: d.update(untrusted_extra="private payload"),
        ):
            with self.subTest(mutate=mutate):
                wrong = copy.deepcopy(value)
                mutate(wrong)
                with self.assertRaisesRegex(ValueError, "M1_ISOLATION_EVIDENCE"):
                    m.validate(wrong)

    def test_secret_scanning_precedes_report_acceptance(self):
        from tools import m1_isolation as m

        secret = b"sensitive-fixture-nonce-123456"
        import base64

        for value in (secret, secret.hex().encode(), base64.b64encode(secret)):
            with self.assertRaisesRegex(ValueError, "PROHIBITED_ISOLATION_MATERIAL"):
                m.scan(json.dumps({"code": value.decode()}).encode(), [secret])
