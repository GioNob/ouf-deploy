import copy
import hashlib
import json
import subprocess
import sys
import unittest
from unittest.mock import patch

from tools.iam_profile.plan import gate, plan, receipt
from tools.iam_profile.profile import (
    CONFIG, POOLS, Invalid, canonical, digest, fields, materialize, read_json, validate,
)
from tools.iam_profile.qualify import LiveProbe, qualify


FIXTURES = CONFIG.parents[1] / "tools/iam_profile/fixtures"


def setup():
    before = read_json(FIXTURES / "before.json")
    profile = materialize(read_json(CONFIG / "profile.template.json"),
                          read_json(FIXTURES / "parameters.json"))
    return profile, before


def measured(profile):
    pools = {key: {"occupiedDataSlots": pool["dataSlots"]["value"], "concurrentControlServed": 2}
             for key, pool in profile["pools"].items()}
    pools["Gateway"]["concurrentRenewalRelayRequests"] = 2
    sample = {"profileSha256": digest(profile), "pet": "55g",
              "sourceTraceSha256": digest(["fixture", pools]), "pools": pools}
    return {**sample, "traceSha256": digest(sample)}


def simulate(snapshot, rows, source):
    """Standalone consumer. Reject stale baseline/foreign mutation and verify source bytes."""
    state = dict(snapshot["managed"])
    for change in rows:
        path, action = change["path"], change["action"]
        if path.startswith("foreign/"):
            assert action == "foreign"
            continue
        assert change["beforeSha256"] == (digest(state[path]) if path in state else None)
        if action == "delete":
            assert change["afterSha256"] is None
            del state[path]
        elif action in ("update", "create"):
            assert digest(source[path]) == change["afterSha256"]
            state[path] = source[path]
        else:
            assert action == "unchanged" and change["beforeSha256"] == change["afterSha256"]
    return {**snapshot, "managed": state}


class FixtureIAM:
    """Independent permission store and mandate records, with an observable owner."""
    def __init__(self, profile, bindings):
        self.p = profile
        self.bindings = bindings
        self.now = 100
        self.targets = {
            role: {"mandateId": f"00000000-0000-4000-8000-00000000000{index}",
                   "human": "holder-" + role, "grantRef": "assignment-" + role, "generation": "1"}
            for index, role in enumerate(("A", "B"), 1)}
        self.permissions = {
            t["grantRef"]: {"issuer": profile["trust"]["issuer"], "tenant": "shared",
                            "workload": profile["clients"]["mcp"]["clientId"],
                            "workloadSubject": "credential-" + role, "mandateId": t["mandateId"],
                            "subject": t["human"], "policyRef": "fixture-policy"}
            for role, t in self.targets.items()}
        self.analysis_profile = {"assetId": "00000000-0000-4000-8000-000000000010",
                                 "profileId": "00000000-0000-4000-8000-000000000011",
                                 "profileVersion": 1, "schemaHash": "sha256:" + digest("columns"),
                                 "columnCount": 1}
        self.nonce = 0
        self.invalid_after = {}
        self.forwards = []

    def epoch(self):
        return self.now

    def sleep(self, delay):
        self.now += delay

    def introspect(self, role):
        if self.now >= self.invalid_after.get(role, float("inf")):
            return {"active": False}
        return {"active": True, "sub": "credential-" + role, "tenant_id": "shared",
                "client_id": self.p["clients"]["mcp"]["clientId"], "ouf_actor_type": "SERVICE",
                "iss": self.p["trust"]["issuer"], "aud": self.p["trust"]["gatewayAudience"],
                "scope": " ".join(self.p["clients"]["mcp"]["scopes"]), "exp": 1000}

    def decision(self, raw):
        """IAM side of the authority-check wire contract for the two PET actions."""
        request = json.loads(raw)
        hashed = hashlib.sha256(raw).hexdigest()
        permission = self.permissions.get(request["grantRef"])
        if (request["contract"] != "ouf.analysis.authority-check.v1"
                or request["action"] not in ("status", "dispatch") or not permission
                or any(request.get(k) != v for k, v in permission.items())):
            return {"requestHash": hashed, "allowed": False}
        return {"requestHash": hashed, "allowed": True, "policyRef": permission["policyRef"],
                "grantRef": request["grantRef"], "decisionRef": "fixture-decision",
                "validUntil": int(self.now) + 1, "grantExpiresAt": 1000,
                "allowedOperations": ["ouf.semantic.search.batch"], "roles": [],
                "acr": "fixture-acr", "client": self.p["clients"]["ths"]["clientId"]}

    def admitted(self, role, target, action):
        claims = self.introspect(role)
        if not claims["active"] or self.bindings["scopeByAction"][action] not in claims["scope"].split():
            return False
        mandate = self.targets[target]
        self.nonce += 1
        request = {"contract": "ouf.analysis.authority-check.v1", "nonce": str(self.nonce),
                   "action": action, "issuer": claims["iss"], "tenant": claims["tenant_id"],
                   "workload": claims["client_id"], "workloadSubject": claims["sub"],
                   "subject": mandate["human"], "actor": "SERVICE", "actorRef": claims["sub"],
                   "analysisId": digest(target), "profile": self.analysis_profile,
                   "manifestChecksum": digest("fixture-manifest"), "mandateId": mandate["mandateId"],
                   "grantRef": mandate["grantRef"], "policyRef": "fixture-policy"}
        if action == "dispatch":
            request.update(operation="ouf.semantic.search.batch", intentKey=digest("intent"),
                           argumentsHash=digest({}), resourceId=mandate["mandateId"])
        response = self.decision(canonical(request))
        return response["requestHash"] == digest(request) and response["allowed"]

    def status(self, role, target):
        if not self.admitted(role, target, "status"):
            return 404, {"code": "ANALYSIS_MANDATE_UNKNOWN"}
        mandate = self.targets[target]
        return 200, {"mandateId": mandate["mandateId"], "generation": mandate["generation"],
                     "state": "ACTIVE", "expiresAt": "2030-01-01T00:00:00Z",
                     "decisionRef": "fixture-decision"}

    @staticmethod
    def error_code(body):
        return body.get("code")

    def dispatch(self, role, target):
        if not self.admitted(role, target, "dispatch"):
            return False
        self.forwards.append(self.targets[target]["mandateId"])
        return True

    def verify_denied_forward(self, profile, identity):
        assert not self.dispatch("A", "B")
        assert self.forwards == []

    def revoke(self):
        del self.permissions[self.targets["A"]["grantRef"]]
        self.invalid_after["A"] = self.now + 1
        return self.now


class ProfileTests(unittest.TestCase):
    def setUp(self):
        self.p, self.s = setup()
        self.b = self.s["gatewayBindings"]

    def rejected(self, code):
        with self.assertRaisesRegex(Invalid, "^" + code + "$"):
            validate(self.p, self.b)

    def test_client_collision(self):
        self.p["clients"]["ths"]["clientId"] = self.p["clients"]["mcp"]["clientId"]
        self.rejected("CLIENTS_NOT_DISTINCT")

    def test_resource_server_is_a_separate_client(self):
        """55h: the assignment resource-server never reuses the MCP or THS client."""
        for role in ("mcp", "ths"):
            self.setUp()
            self.p["grant"]["resourceServer"]["clientId"] = self.p["clients"][role]["clientId"]
            self.rejected("CLIENTS_NOT_DISTINCT")
        self.setUp()
        self.p["grant"]["resourceServer"]["secretRef"] = "plain-secret"
        self.rejected("PROFILE_INVALID")

    def test_missing_and_extra_scopes_both_clients(self):
        for role in ("mcp", "ths"):
            for operation in ("missing", "extra", "duplicate", "substitution"):
                with self.subTest(role=role, case=operation):
                    self.p, _ = setup()
                    scopes = self.p["clients"][role]["scopes"]
                    if operation == "missing":
                        scopes.pop(0)
                    elif operation == "extra":
                        scopes.append("fixture.extra")
                    elif operation == "duplicate":
                        scopes.append(scopes[0])
                    else:
                        scopes[0] = "fixture.other"
                    self.rejected("SCOPES_INVALID")

    def test_wrong_audience(self):
        for role in self.p["clients"].values():
            role["audience"] = "other.invalid"
        self.p["trust"]["gatewayAudience"] = "other.invalid"
        self.rejected("AUDIENCE_MISMATCH")

    def test_https_and_embedded_credentials(self):
        for key in ("issuer", "jwks", "decisions", "gatewayOrigin", "introspection"):
            for bad in ("http://iam.invalid", "https://", "https://user@iam.invalid",
                        "https://iam.invalid?token=fixture", "https://iam.invalid:65536"):
                with self.subTest(field=key, value=bad):
                    self.p, _ = setup()
                    self.p["trust"][key] = bad
                    self.rejected("HTTPS_REQUIRED")

    def test_all_installation_limits_and_reserve(self):
        for key in self.p["capacity"]:
            self.p, _ = setup()
            self.p["capacity"][key] += 1
            self.rejected("PROFILE_INVALID")
        self.p, _ = setup()
        del self.p["capacity"]["ControlReservedSlots"]
        self.rejected("PROFILE_INVALID")

    def test_pool_reserve_and_parameter_maxima(self):
        for key in POOLS:
            self.p, _ = setup()
            self.p["pools"][key]["controlReservedSlots"] = 0
            self.rejected("PROFILE_INVALID")
        for key in self.p["iam"]:
            self.p, _ = setup()
            self.p["iam"][key]["maximum"] = 1
            self.rejected("LIMIT_INVALID")

    def test_closed_objects_and_raw_secret(self):
        self.p["clients"]["ths"]["secret"] = "disposable"
        self.rejected("PROFILE_INVALID")
        del self.p["clients"]["ths"]["secret"]
        self.p["clients"]["ths"]["secretRef"] = "disposable"
        self.rejected("PROFILE_INVALID")

    def test_foreign_conflict_and_snapshot_custody(self):
        self.s["foreign"][0]["idSha256"] = digest(["client", self.p["clients"]["ths"]["clientId"]])
        with self.assertRaisesRegex(Invalid, "FOREIGN_CLIENT"):
            plan(self.p, self.s)
        self.s["managed"]["clients.ths.secretRef"] = "disposable"
        with self.assertRaisesRegex(Invalid, "REFERENCE_REQUIRED"):
            plan(self.p, self.s)

    def test_IAM_55M_01_shared_client(self):
        """IAM-55M-01. Same client and tenant. Check both positive and negative forwarding."""
        iam = FixtureIAM(self.p, self.b)
        self.assertEqual(iam.introspect("A")["client_id"], iam.introspect("B")["client_id"])
        self.assertEqual(iam.status("A", "A")[0], 200)
        self.assertEqual(iam.status("A", "B")[0], 404)
        self.assertFalse(iam.dispatch("A", "B"))
        self.assertEqual(iam.forwards, [])
        self.assertTrue(iam.dispatch("B", "B"))

    def test_IAM_55M_02_revocation_by_deadline(self):
        """IAM-55M-02. Run the same qualification used by the live CLI with a virtual clock."""
        self.p["iam"]["introspectionsPerMinute"] = {"value": 120, "default": 120, "maximum": 120}
        for kind in ("existing-iam", "keycloak-ouf"):
            self.p["kind"] = kind
            iam = FixtureIAM(self.p, self.b)
            result = qualify(self.p, self.b, iam, begin_revocation=iam.revoke,
                             sleep=iam.sleep, clock=iam.epoch)
            self.assertEqual(result, {"IAM-55M-01": "PASS", "IAM-55M-02": "PASS"})
            self.assertFalse(iam.dispatch("A", "A"))
            iam = FixtureIAM(self.p, self.b)
            with self.assertRaisesRegex(ValueError, "PET_REVOCATION_TIMEOUT"):
                qualify(self.p, self.b, iam, begin_revocation=iam.epoch,
                        sleep=iam.sleep, clock=iam.epoch)

    def test_IAM_55M_03_gate(self):
        """IAM-55M-03. A receipt and every measured pool belong to the same projection."""
        self.assertEqual(gate(self.p, self.s, None), {"status": "HELD", "code": "RECEIPT_MISSING"})
        self.s["managed"] = dict(fields(self.p))
        self.s["controlProof"] = measured(self.p)
        signed_off = receipt(self.p, self.s)
        for key in ("issuer", "kind", "observedSha256", "profileSha256", "clients", "status"):
            corrupt = {**signed_off, key: None}
            self.assertEqual(gate(self.p, self.s, corrupt)["code"], "RECEIPT_MISMATCH")
        for pool in POOLS:
            sample = self.s["controlProof"]["pools"][pool]
            sample["concurrentControlServed"] = 1
            proof = self.s["controlProof"]
            proof["traceSha256"] = digest({k: v for k, v in proof.items() if k != "traceSha256"})
            self.assertEqual(gate(self.p, self.s, signed_off)["code"], "CONTROL_UNPROVEN")
            sample["concurrentControlServed"] = 2
        self.s["controlProof"]["pools"]["Gateway"]["concurrentRenewalRelayRequests"] = 1
        self.assertEqual(gate(self.p, self.s, signed_off)["code"], "CONTROL_UNPROVEN")
        self.s["controlProof"] = None
        self.assertEqual(gate(self.p, self.s, signed_off)["code"], "CONTROL_UNPROVEN")
        self.p["trust"]["issuer"] = "https://changed.invalid"
        self.assertEqual(gate(self.p, self.s, signed_off)["code"], "PROFILE_DRIFT")

    def test_IAM_55M_04_round_trip(self):
        """IAM-55M-04. Plan, guarded simulation, verified observation and exact inverse."""
        before = copy.deepcopy(self.s)
        first = plan(self.p, self.s)
        self.assertEqual(canonical(first), canonical(plan(self.p, self.s)))
        self.assertEqual(first["planSha256"], digest({k: v for k, v in first.items() if k != "planSha256"}))
        self.assertEqual({row["action"] for row in first["diff"]}, {"create", "unchanged", "update", "foreign"})
        after = simulate(self.s, first["diff"], dict(fields(self.p)))
        observed = {**after, "controlProof": measured(self.p)}
        verified = receipt(self.p, observed)
        self.assertEqual(gate(self.p, observed, verified)["status"], "VERIFIED")
        self.assertEqual(simulate(after, first["returnDiff"], before["managed"]), before)
        self.assertEqual(self.s, before)
        with self.assertRaises(AssertionError):
            simulate(after, first["diff"], dict(fields(self.p)))

    def test_cli_deterministic_and_missing_receipt(self):
        base = [sys.executable, "-B", "-m", "tools.iam_profile"]
        args = [str(CONFIG / "profile.template.json"), str(FIXTURES / "before.json"),
                "--parameters", str(FIXTURES / "parameters.json")]
        one = subprocess.check_output([*base, "plan", *args])
        self.assertEqual(one, subprocess.check_output([*base, "plan", *args]))
        held = subprocess.run([*base, "gate", *args], capture_output=True)
        self.assertEqual(held.returncode, 2)
        self.assertEqual(json.loads(held.stdout)["code"], "RECEIPT_MISSING")


    def test_public_effective_fixture_and_scope_order(self):
        snapshot = read_json(FIXTURES / "effective.json")
        signed_off = receipt(self.p, snapshot)
        self.assertEqual(gate(self.p, snapshot, signed_off)["status"], "VERIFIED")
        snapshot["managed"]["clients.mcp.scopes"].reverse()
        self.assertEqual(receipt(self.p, snapshot)["status"], "VERIFIED")
        snapshot["complete"] = False
        self.assertEqual(gate(self.p, snapshot, signed_off)["code"], "OBSERVATION_INCOMPLETE")

    def test_live_probe_wire_calls_and_retained_forward_count(self):
        config = read_json(FIXTURES / "probe.example.json")
        with patch("tools.iam_profile.qualify.ssl.create_default_context"), patch(
                "tools.iam_profile.qualify.Path.read_text", side_effect=["fixture-A", "fixture-B"]):
            probe = LiveProbe(self.p, config)
        with patch.object(probe, "post", return_value=(200, {"active": True})) as send:
            self.assertEqual(probe.introspect("A"), {"active": True})
            self.assertEqual(send.call_args.args, ("introspection", self.p["trust"]["introspection"],
                             {"Content-Type": "application/x-www-form-urlencoded"}, "token=fixture-A"))
            probe.status("A", "B")
            dest, url, headers, payload = send.call_args.args
            self.assertEqual(dest, "status")
            self.assertEqual(url, self.p["trust"]["gatewayOrigin"] + "/internal/analysis/v1/mandates/status")
            self.assertEqual(headers["Authorization"], "Bearer fixture-A")
            self.assertEqual(json.loads(payload), {"mandateId": config["targets"]["B"]["mandateId"],
                                                  "generation": "1"})
        trace = config["deniedForward"]
        claims = {"iss": self.p["trust"]["issuer"], "client_id": self.p["clients"]["mcp"]["clientId"],
                  "tenant_id": "tenant.invalid", "sub": "assignment-A.invalid"}
        probe.verify_denied_forward(self.p, claims)
        for field in ("ownerForwards", "credentialHuman", "targetGrantRef", "profileSha256"):
            with self.subTest(field=field), patch.dict(trace, {field: 1}):
                with self.assertRaisesRegex(Invalid, "PET_FORWARD_UNPROVEN"):
                    probe.verify_denied_forward(self.p, claims)

    def test_gate_requires_saturated_data_and_intact_evidence(self):
        self.s = read_json(FIXTURES / "effective.json")
        old = receipt(self.p, self.s)
        proof = self.s["controlProof"]
        proof["sourceTraceSha256"] = "0" * 64
        self.assertEqual(gate(self.p, self.s, old)["code"], "CONTROL_UNPROVEN")
        for pool in POOLS:
            proof = measured(self.p)
            proof["pools"][pool]["occupiedDataSlots"] -= 1
            proof["traceSha256"] = digest({k: v for k, v in proof.items() if k != "traceSha256"})
            self.s["controlProof"] = proof
            self.assertEqual(gate(self.p, self.s, old)["code"], "CONTROL_UNPROVEN")

    def test_plan_never_exports_observed_values(self):
        self.s["managed"]["clients.mcp.secretRef"] = "ref:fixture/previous"
        result = canonical(plan(self.p, self.s))
        self.assertNotIn(b"ref:fixture", result)
        self.assertNotIn(b"mcp.invalid", result)
        self.assertNotIn(b"fixture.status", result)
        self.s["managed"]["clients.mcp.secret"] = "synthetic-canary"
        with self.assertRaisesRegex(Invalid, "^OBSERVATION_INVALID$"):
            plan(self.p, self.s)
