"""Synthetic IAM/owner fixtures; never a production approval or target proof."""
import base64
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("descriptor_read", ROOT / "scripts/read-acquisition-permission-descriptors-20261025.py")
m = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(m)


def active():
    return {"policyRef": "ouf-lab-authorization:48", "contentHash": "sha256:"+"a"*64,
            "policy": {"capabilities": [
                {"capabilityId": m.CAPS[0], "operation": "READ", "requiredScope": m.CAPS[0], "allowedActors": ["HUMAN"]},
                {"capabilityId": m.CAPS[1], "operation": "READ", "requiredScope": m.CAPS[1], "allowedActors": ["SERVICE"]}],
                "grants": [{"subjectId": "PRIVATE_CANARY_NEVER_PRINT"}]}}


class Fake:
    deadline = 600

    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []
        self.counts = {"ownerGets": 0}
        self.now = 0

    def clock(self):
        return self.now

    def sleep(self, seconds):
        self.now += seconds

    def request(self, url, **kwargs):
        self.calls.append((url, kwargs))
        self.counts["ownerGets"] += 1
        reply = self.responses.pop(0)
        if isinstance(reply, Exception):
            raise reply
        return reply


class DescriptorReadTests(unittest.TestCase):
    def test_missing_and_nonhuman_are_distinct_without_printing_grants(self):
        value = active()
        fake = Fake([(200, value), (200, []), (200, value)])
        result = m.observe(fake, "synthetic-token")
        self.assertTrue(result["descriptors"][0]["activeHumanCompatible"])
        self.assertFalse(result["descriptors"][1]["activeHumanCompatible"])
        self.assertIsNone(result["descriptors"][2]["activeDescriptor"])
        self.assertNotIn("PRIVATE_CANARY", json.dumps(result))
        self.assertNotIn("synthetic-token", json.dumps(result))
        self.assertTrue(all(not kw.get("form") for _, kw in fake.calls))
        self.assertEqual(result["administrativeWrites"], 0)
        self.assertFalse(result["runtimeAuthorityIssued"])

    def test_active_drift_stops_without_replacing_policy(self):
        before = active()
        after = active()
        after["policyRef"] = "ouf-lab-authorization:49"
        fake = Fake([(200, before), (200, []), (200, after)])
        with self.assertRaisesRegex(m.Stop, "ACTIVE_CHANGED_RECONCILE"):
            m.observe(fake, "synthetic")
        self.assertEqual(len(fake.calls), 3)

    def test_duplicate_active_descriptor_stops_before_catalogue(self):
        value = active()
        value["policy"]["capabilities"] *= 2
        fake = Fake([(200, value)])
        with self.assertRaisesRegex(m.Stop, "DUPLICATE_ACTIVE_DESCRIPTOR"):
            m.observe(fake, "synthetic")
        self.assertEqual(len(fake.calls), 1)

    def test_duplicate_registration_stops(self):
        descriptor = active()["policy"]["capabilities"][0]
        row = {"capability_id": m.CAPS[0], "owner_ref": "ingestion", "descriptor": descriptor}
        fake = Fake([(200, active()), (200, [row, row])])
        with self.assertRaisesRegex(m.Stop, "DUPLICATE_REGISTERED_DESCRIPTOR"):
            m.observe(fake, "synthetic")

    def test_registered_is_not_active(self):
        descriptor = {"capabilityId": m.CAPS[2], "operation": "READ", "requiredScope": m.CAPS[2], "allowedActors": ["HUMAN"]}
        row = {"capability_id": m.CAPS[2], "owner_ref": "ingestion", "descriptor": {"type": "jsonb", "value": json.dumps(descriptor)}}
        fake = Fake([(200, active()), (200, [row]), (200, active())])
        result = m.observe(fake, "synthetic")
        item = result["descriptors"][2]
        self.assertEqual(item["registeredDescriptor"], descriptor)
        self.assertIsNone(item["activeDescriptor"])
        self.assertFalse(item["activeHumanCompatible"])

    def test_owner_denial_not_retried(self):
        fake = Fake([m.Stop("OWNER_HTTP_403")])
        with self.assertRaisesRegex(m.Stop, "OWNER_HTTP_403"):
            m.observe(fake, "synthetic")
        self.assertEqual(len(fake.calls), 1)

    def test_transport_rejects_writes_redirect_hosts_and_scope_edits(self):
        t = m.Transport()
        with patch.object(t.opener, "open") as opened:
            for url, kwargs in [
                (m.ADMIN+"/capabilities", {"form": {"x": "y"}}),
                (m.ADMIN+"/policies/active", {"form": {"x": "y"}, "token": "synthetic"}),
                ("https://other.invalid/", {}),
                (m.ADMIN+"/policies/arbitrary:publish", {"token": "synthetic"}),
                (m.ADMIN+"/capabilities?limit=200&offset=10000", {"token": "synthetic"})]:
                with self.assertRaises(m.Stop):
                    t.request(url, **kwargs)
            opened.assert_not_called()

    def test_finite_deadline_and_attempt_reservation(self):
        now = [0]
        t = m.Transport(clock=lambda: now[0])
        now[0] = 601
        with patch.object(t.opener, "open") as opened:
            with self.assertRaisesRegex(m.Stop, "FINITE_READ_EXPIRED"):
                t.request(m.ADMIN+"/policies/active", token="synthetic")
            opened.assert_not_called()
        now[0] = 0
        with patch.object(t.opener, "open", side_effect=OSError("PRIVATE_CANARY")) as opened:
            with self.assertRaisesRegex(m.Stop, "READ_TRANSPORT_STOP_NO_RETRY"):
                t.request(m.ADMIN+"/policies/active", token="synthetic")
            self.assertEqual(opened.call_count, 1)
            self.assertEqual(t.counts["ownerGets"], 1)

    def login_fixture(self, *, subject=m.SUBJECT, error=None):
        claims = {"iss": m.ISSUER, "sub": subject, "tenant_id": "ouf-lab", "ouf_actor_type": "HUMAN",
                  "exp": 2000, "scope": "openid authorization.policy.admin"}
        payload = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip("=")
        token = "synthetic."+payload+".signature"
        replies = [(200, {"issuer": m.ISSUER, "device_authorization_endpoint": m.ISSUER+"/protocol/openid-connect/auth/device",
                           "token_endpoint": m.ISSUER+"/protocol/openid-connect/token"}),
                   (200, {"verification_uri": m.ISSUER+"/device", "user_code": "SYNTH-TEST", "device_code": "synthetic-private-device", "expires_in": 600})]
        if error:
            replies.append((400, {"error": error}))
        else:
            replies += [(400, {"error": "authorization_pending"}), (400, {"error": "slow_down"}),
                        (200, {"access_token": token, "refresh_token": "PRIVATE_REFRESH_CANARY"})]
        return Fake(replies), token

    def test_finite_device_pending_slowdown_and_no_token_output(self):
        fake, token = self.login_fixture()
        output = []
        self.assertEqual(m.login(fake, sleep=fake.sleep, emit=output.append, wall=lambda: 1000), token)
        self.assertEqual(fake.now, 20)
        self.assertNotIn(token, " ".join(output))
        self.assertNotIn("synthetic-private-device", " ".join(output))
        self.assertNotIn("PRIVATE_REFRESH_CANARY", " ".join(output))

    def test_device_instructions_flush_even_when_stdout_is_a_log_pipe(self):
        fake, _ = self.login_fixture()
        with patch("builtins.print") as output:
            m.login(fake, sleep=fake.sleep, wall=lambda: 1000)
        self.assertEqual(output.call_count, 3)
        self.assertTrue(all(call.kwargs.get("flush") is True for call in output.call_args_list))

    def test_wrong_account_stops_before_owner_reads(self):
        fake, _ = self.login_fixture(subject="another-account")
        with self.assertRaisesRegex(m.Stop, "EXACT_OUF_ADMIN_CONTEXT_REQUIRED"):
            m.login(fake, sleep=fake.sleep, emit=lambda _: None, wall=lambda: 1000)
        self.assertFalse(any(url.startswith(m.ADMIN) for url, _ in fake.calls))

    def test_device_access_denied_not_retried(self):
        fake, _ = self.login_fixture(error="access_denied")
        with self.assertRaisesRegex(m.Stop, "DEVICE_LOGIN_STOP_NO_RETRY"):
            m.login(fake, sleep=fake.sleep, emit=lambda _: None)
        self.assertEqual(len(fake.calls), 3)

    def test_non_tty_refused_before_network(self):
        with patch.object(m.sys, "argv", ["reader"]), patch.object(m.sys.stdin, "isatty", return_value=False), patch.object(m, "Transport") as transport:
            with self.assertRaisesRegex(m.Stop, "INTERACTIVE_OPERATOR_TERMINAL_REQUIRED"):
                m.main()
            transport.assert_not_called()

    def test_claim_consumed_on_login_denial_and_cannot_be_reopened(self):
        with tempfile.TemporaryDirectory() as tmp:
            context = Path(tmp) / "fixed-claim"
            with patch.object(m.sys, "argv", ["reader"]), patch.object(m.sys.stdin, "isatty", return_value=True), patch.object(m.os, "geteuid", return_value=1000), patch.object(m, "Path", return_value=context), patch.object(m, "login", side_effect=m.Stop("DEVICE_LOGIN_STOP_NO_RETRY")) as login, contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaisesRegex(m.Stop, "DEVICE_LOGIN_STOP_NO_RETRY"):
                    m.main()
                retained = json.loads((context / "state.json").read_text())
                self.assertEqual(retained["state"], "STOP_RECONCILE")
                self.assertFalse(retained["budgetReset"])
                with self.assertRaisesRegex(m.Stop, "DIAGNOSTIC_SCOPE_EXISTS_RECONCILE_NO_REPLAY"):
                    m.main()
                self.assertEqual(login.call_count, 1)
                self.assertEqual(json.loads((context / "state.json").read_text()), retained)

    def test_request_attempt_retained_before_failed_dispatch(self):
        with tempfile.TemporaryDirectory() as tmp:
            context = Path(tmp) / "fixed-claim"

            def open_failed(request, **kwargs):
                retained = json.loads((context / "state.json").read_text())
                self.assertEqual(retained["counts"]["ownerGets"], 1)
                self.assertEqual(request.get_method(), "GET")
                raise OSError("PRIVATE_TRANSPORT_CANARY")

            with patch.object(m.sys, "argv", ["reader"]), patch.object(m.sys.stdin, "isatty", return_value=True), patch.object(m.os, "geteuid", return_value=1000), patch.object(m, "Path", return_value=context), patch.object(m, "login", return_value="PRIVATE_TOKEN_CANARY"), patch.object(m.urllib.request.OpenerDirector, "open", side_effect=open_failed), contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaisesRegex(m.Stop, "READ_TRANSPORT_STOP_NO_RETRY"):
                    m.main()
            retained = (context / "state.json").read_text()
            self.assertEqual(json.loads(retained)["counts"]["ownerGets"], 1)
            self.assertNotIn("PRIVATE", retained)


if __name__ == "__main__":
    unittest.main()
