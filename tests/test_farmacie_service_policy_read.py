"""Synthetic IAM/owner fixtures; never a production approval or target proof."""
import base64
import copy
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from datetime import datetime, timezone
import os
import types

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("service_policy_read", ROOT / "scripts/read-farmacie-service-policy-20261027.py")
m = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(m)


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


NOW = datetime(2026, 10, 27, tzinfo=timezone.utc).timestamp()


def grant(**changes):
    return {"grantId": m.NAMED_GRANT, "capabilityId": m.CAPABILITY, "tenantId": "ouf-lab",
            "servicePrincipalId": m.SERVICE, "subjectId": None, "organizationId": None,
            "validFrom": "2026-09-25T00:00:00Z", "validUntil": "2026-10-25T00:00:00Z", "constraints": None,
            **changes}


def active(rows=None):
    return {"policyRef": "ouf-lab-authorization:55", "contentHash": "sha256:" + "a" * 64,
            "policy": {"bundleId": "ouf-lab-authorization", "version": 55,
                       "capabilities": [{"capabilityId": m.CAPABILITY, "operation": "READ",
                                         "requiredScope": "ouf.internal.object-storage.read", "allowedActors": ["SERVICE"]}],
                       "grants": [grant()] if rows is None else rows}}


class ServiceProjection(unittest.TestCase):
    def observe(self, value):
        fake = Fake([(200, value)])
        result = m.observe(fake, "PRIVATE_BEARER_CANARY", wall=lambda: NOW)
        self.assertEqual(fake.calls, [(m.ADMIN + "/policies/active", {"token": "PRIVATE_BEARER_CANARY"})])
        return result

    def test_expired_service_grant_minimized_without_unrelated_policy_or_token(self):
        value = active([grant(), grant(grantId="unrelated", servicePrincipalId="PRIVATE_OTHER_SERVICE", constraints={"private": "PRIVATE_POLICY_CANARY"})])
        before = copy.deepcopy(value)
        result = self.observe(value)
        self.assertEqual(value, before)
        self.assertTrue(result["allMatchingWindowsExpired"])
        self.assertFalse(result["anyCurrentAllowGrantConfigured"])
        self.assertTrue(result["namedSourceGrantPresent"])
        self.assertTrue(result["namedSourceGrantMatchesTarget"])
        self.assertEqual(result["matchingServiceGrants"][0]["validUntil"], "2026-10-25T00:00:00Z")
        self.assertNotIn("PRIVATE_", json.dumps(result))
        self.assertFalse(result["effectivePermissionProven"])
        self.assertEqual(result["applicationPreviewCalls"], 0)

    def test_current_constrained_allow_is_not_effective_authority_and_deny_not_allow(self):
        result = self.observe(active([grant(validUntil="2036-10-25T00:00:00Z", constraints={"effect": "ALLOW", "resourceId": "PRIVATE_OBJECT_REFERENCE"})]))
        self.assertTrue(result["anyCurrentAllowGrantConfigured"])
        self.assertFalse(result["effectivePermissionProven"])
        self.assertNotIn("PRIVATE_OBJECT", json.dumps(result))
        result = self.observe(active([grant(validUntil="2036-10-25T00:00:00Z", constraints={"effect": "DENY"})]))
        self.assertFalse(result["anyCurrentAllowGrantConfigured"])

    def test_absent_or_changed_named_grant_is_reported_without_fabricating_expiry(self):
        result = self.observe(active([]))
        self.assertEqual(result["matchingServiceGrants"], [])
        self.assertFalse(result["allMatchingWindowsExpired"])
        self.assertFalse(result["namedSourceGrantPresent"])
        result = self.observe(active([grant(servicePrincipalId="other-service")]))
        self.assertTrue(result["namedSourceGrantPresent"])
        self.assertFalse(result["namedSourceGrantMatchesTarget"])

    def test_duplicate_grants_or_descriptors_cannot_be_silently_overwritten(self):
        for kind in ("grants", "capabilities"):
            value = active(); value["policy"][kind] *= 2
            with self.assertRaisesRegex(m.Stop, "UNIQUE_ACTIVE"):
                self.observe(value)

    def test_bad_policy_identity_dates_and_unbounded_target_sets_stop(self):
        values = []
        value = active(); value["policy"]["version"] = True; values.append(value)
        value = active(); value["policyRef"] = "other:55"; values.append(value)
        values += [active([grant(validUntil="2026-10-25")]), active([grant(validUntil="not-a-date")]),
                   active([grant(grantId="grant-" + str(i)) for i in range(65)])]
        for value in values:
            with self.assertRaises(m.Stop):
                self.observe(value)

    def test_missing_capability_is_observed_not_reconstructed(self):
        value = active(); value["policy"]["capabilities"] = []
        self.assertIsNone(self.observe(value)["capability"])


class TransportAndScope(unittest.TestCase):
    def test_only_one_owner_dispatch_including_failure(self):
        t = m.Transport()
        with patch.object(t.opener, "open", side_effect=OSError("PRIVATE_ERROR")) as opened:
            with self.assertRaisesRegex(m.Stop, "READ_TRANSPORT_STOP_NO_RETRY"):
                t.request(m.ADMIN + "/policies/active", token="synthetic")
            with self.assertRaisesRegex(m.Stop, "FINITE_REQUEST_LIMIT"):
                t.request(m.ADMIN + "/policies/active", token="synthetic")
            self.assertEqual(opened.call_count, 1)
            self.assertEqual(t.counts["ownerGets"], 1)

    def test_noninteractive_protected_main_stops_before_network(self):
        with patch.object(m.sys, "argv", ["reader"]), patch.object(m.sys.stdin, "isatty", return_value=False), \
             patch.object(m.sys, "flags", types.SimpleNamespace(isolated=1, no_site=1)), \
             patch.object(m.sys, "dont_write_bytecode", True), patch.object(m.os, "geteuid", return_value=0), \
             patch.object(m.os, "getegid", return_value=0), patch.object(m, "Transport") as transport:
            with self.assertRaisesRegex(m.Stop, "INTERACTIVE_OPERATOR_TERMINAL_REQUIRED"):
                m.main()
            transport.assert_not_called()

    def test_existing_scope_and_failed_login_cannot_reset_the_read(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); scope = root / "scope"
            real_path = Path
            code = root / "code"; code.mkdir()
            entry = code / "read.py"; entry.write_text("synthetic"); entry.chmod(0o400)
            mapper = lambda path: scope if str(path).startswith("/etc/ouf/deploy-snapshots/farmacie-service-policy") else real_path(path)
            with patch.object(m, "__file__", str(entry)), patch.object(m, "Path", side_effect=mapper), \
                 patch.object(m, "ancestry"), patch.object(m.sys, "argv", ["reader"]), \
                 patch.object(m.sys, "flags", types.SimpleNamespace(isolated=1, no_site=1)), \
                 patch.object(m.sys, "dont_write_bytecode", True), patch.object(m.sys.stdin, "isatty", return_value=True), \
                 patch.object(m.sys.stdout, "isatty", return_value=True), \
                 patch.object(m, "login", side_effect=m.Stop("DEVICE_LOGIN_STOP_NO_RETRY")) as login, \
                 contextlib.redirect_stdout(io.StringIO()):
                # Isolated root fixture only. Actual sudo custody is also qualified separately.
                if os.geteuid() != 0:
                    self.fail("root CI fixture required")
                with patch.object(m.sys.stdout, "isatty", return_value=True):
                    with self.assertRaises(m.Stop):
                        m.main()
                retained = (scope / "state.json").read_bytes()
                self.assertEqual(json.loads(retained)["state"], "STOP_RECONCILE")
                with self.assertRaises((m.Stop, FileExistsError)):
                    m.main()
                self.assertEqual(login.call_count, 1)
                self.assertEqual((scope / "state.json").read_bytes(), retained)
                self.assertEqual((scope / "state.json").stat().st_mode & 0o777, 0o600)


class ReusedTransportAndLogin(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main(verbosity=2)
