import json
import re
import subprocess
import sys
import unittest

from tools.iam_profile.kcadm import kcadm_plan
from tools.iam_profile.plan import plan
from tools.iam_profile.profile import CONFIG, Invalid, digest, materialize, read_json, validate


FIXTURES = CONFIG.parents[1] / "tools/iam_profile/fixtures"
TEMPLATE = CONFIG / "profile.template.json"


class KeycloakTests(unittest.TestCase):
    def setUp(self):
        self.profile = materialize(read_json(TEMPLATE), read_json(FIXTURES / "parameters.json"))
        self.before = read_json(FIXTURES / "before.json")
        self.bindings = self.before["gatewayBindings"]

    def cli(self, action, snapshot="before.json"):
        return subprocess.check_output([
            sys.executable, "-B", "-m", "tools.iam_profile", action, str(TEMPLATE),
            str(FIXTURES / snapshot), "--parameters", str(FIXTURES / "parameters.json"),
        ])

    def test_IAM_58H_01_issuer(self):
        """IAM-58H-01. Issuer HTTPS e suffisso del realm."""
        for suffix in ("", "/realms/", "/issuer", "/realms/example/", "/realms/example/child"):
            with self.subTest(suffix=suffix), self.assertRaisesRegex(Invalid, "^KEYCLOAK_ISSUER_INVALID$"):
                self.profile["trust"]["issuer"] = "https://iam.invalid" + suffix
                validate(self.profile, self.bindings)
        self.profile["trust"]["issuer"] = "https://iam.invalid/prefix/realms/example"
        validate(self.profile, self.bindings)

    def test_IAM_58H_02_endpoint_paths(self):
        """IAM-58H-02. Path distinti anche tra host differenti."""
        self.profile["trust"]["introspection"] = "https://iam.invalid/check"
        with self.assertRaisesRegex(Invalid, "^ENDPOINTS_NOT_DISTINCT$"):
            validate(self.profile, self.bindings)

    def test_IAM_58H_03_rates_and_existing_iam(self):
        """IAM-58H-03. Soglie operative e compatibilita del tipo existing-iam."""
        for name, floor in (("decisionsPerMinute", 5), ("introspectionsPerMinute", 2)):
            rate = self.profile["iam"][name]
            for key in ("value", "default"):
                rate[key] = floor - 1
                with self.subTest(name=name, key=key), self.assertRaisesRegex(
                        Invalid, "^IAM_RATE_BELOW_OPERATION$"):
                    validate(self.profile, self.bindings)
                rate[key] = floor
            validate(self.profile, self.bindings)
        self.profile["kind"] = self.before["kind"] = "existing-iam"
        self.profile["trust"].update(issuer="https://iam.invalid/issuer",
                                     introspection=self.profile["trust"]["decisions"])
        self.profile["iam"]["decisionsPerMinute"]["value"] = 1
        validate(self.profile, self.bindings)
        with self.assertRaisesRegex(Invalid, "^KEYCLOAK_PROFILE_REQUIRED$"):
            kcadm_plan(self.profile, self.before)

    def test_IAM_58H_04_example(self):
        """IAM-58H-04. Validazione, plan e ricevuta delle fixture pubbliche."""
        self.assertEqual(json.loads(self.cli("validate")), {"status": "VALID"})
        self.assertEqual(json.loads(self.cli("plan")), plan(self.profile, self.before))
        # Two issues and the three status calls for A/A, B/B and A/B.
        self.assertGreaterEqual(self.profile["iam"]["decisionsPerMinute"]["value"], 2 * 5 + 3 * 3)
        self.assertEqual(json.loads(self.cli("receipt", "effective.json"))["status"], "VERIFIED")

    def test_IAM_58H_05_review_sheet(self):
        """IAM-58H-05. Diff, ritorno, GET e determinismo della stampa."""
        raw = self.cli("kcadm-plan")
        self.assertEqual(raw, self.cli("kcadm-plan"))
        sheet = raw.decode()
        self.assertLessEqual(max(map(len, sheet.splitlines())), 100)
        for value in ("ref:fixture", ".invalid", "foreign/", "clients.mcp.clientId"):
            self.assertNotIn(value, sheet)
        projected = plan(self.profile, self.before)
        self.assertIn(projected["planSha256"], sheet)
        headings = re.findall(r"^# ([\w.]+) \| ANDATA (\w+) \| RITORNO (\w+)$", sheet, re.M)
        self.assertEqual(headings, [(a["path"], a["action"], b["action"])
                                    for a, b in zip(projected["diff"], projected["returnDiff"])
                                    if a["action"] in ("create", "update")])
        functions = re.findall(r"^(andata|ritorno)_(\d+)\(\) \{\n(.*?)^\}", sheet, re.M | re.S)
        self.assertGreater(len(functions), 2)
        for i, (direction, number, body) in enumerate(functions):
            self.assertEqual((direction, int(number)), (("andata", "ritorno")[i % 2], i // 2 + 1))
            commands = re.findall(r"kcadm\.sh (\w+)", body)
            self.assertIn(commands[0], ("update", "create", "delete"))
            self.assertEqual(commands[1:], ["get"])
        self.assertEqual(len(functions) % 2, 0)
        self.assertIn("-s authorizationServicesEnabled=true -s serviceAccountsEnabled=true", sheet)
        for number in range(0, len(functions), 2):
            apply, undo = functions[number][2], functions[number + 1][2]
            op = re.search(r"kcadm\.sh (\w+)", apply)[1]
            self.assertIn("kcadm.sh " + {"create": "delete", "update": "delete"}[op], undo)
            if op == "create":
                created = re.search(r"(\w+)=\$\(kcadm", apply)[1]
                self.assertIn(created, undo)
        for role, client in self.profile["clients"].items():
            for mapper in client["mappers"]:
                self.assertIn(f"clients.{role}.mappers.{mapper} | ANDATA create | RITORNO delete"
                              "\n# DA VERIFICARE:", sheet)
        self.assertIn("grant.resourceType | ANDATA create | RITORNO delete\n# DA VERIFICARE:", sheet)
        self.assertNotIn("kcadm.sh", self.cli("kcadm-plan", "effective.json").decode())

    def test_IAM_58H_06_scope_delta_and_native_identity(self):
        """IAM-58H-06. Delta di appartenenza, rinomina e oggetti estranei."""
        observed = self.before["managed"]
        observed["clients.mcp.scopes"] = ["untrusted\n$(canary)" + "x" * 2000]
        observed["grant.resourceServer.clientId"] = "previous.invalid"
        observed["clients.ths.clientId"] = "previous-ths.invalid"
        sheet = kcadm_plan(self.profile, self.before)
        self.assertLessEqual(max(map(len, sheet.splitlines())), 100)
        self.assertNotIn("canary", sheet)
        self.assertNotIn("previous.invalid", sheet)
        for role in self.profile["clients"].values():
            for scope in role["scopes"]:
                self.assertIn("=" + scope + "\n", sheet)
        section = sheet.split("# BEFORE.managed clients.mcp.scopes[0]\n")[-1].split("\n\n")[0]
        self.assertRegex(section, r"(?s)andata_\d+\(\).*?kcadm.sh delete.*?ritorno_\d+\(\).*?kcadm.sh update -n")
        self.assertNotIn("delete client-scopes/", section)
        self.assertIn('clientId="${OLD_RS_CLIENT:?}"', sheet)
        self.assertIn('clientId="${OLD_THS_CLIENT:?}"', sheet)
        self.assertNotIn("authorizationServicesEnabled=true", sheet)
        self.before["foreign"][0]["idSha256"] = digest(["client", self.profile["grant"]["resourceServer"]["clientId"]])
        with self.assertRaisesRegex(Invalid, "^FOREIGN_CLIENT$"):
            kcadm_plan(self.profile, self.before)
