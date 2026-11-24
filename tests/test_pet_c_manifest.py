"""PETC-58B-01 · contratto di ingresso e piano 55n-01…08."""

import json
import unittest
from copy import deepcopy
from hashlib import sha256

from tools.pet_c.manifest import CONFIG, ERROR_CODES, Refusal, parse, validate
from tools.pet_c.scenarios import CATALOG, plan


def fixture(site="B"):
    data = json.loads((CONFIG / "manifest.template.json").read_text(encoding="utf-8"))
    candidates = {}
    for k in data["candidates"]:
        raw = sha256(k.encode()).hexdigest()
        candidates[k] = raw if k.endswith("Sha256") else "sha256:" + raw
    data.update(site=site, runId="00000000-0000-4000-8000-000000000001",
                createdAt="2030-01-01T00:00:00Z", expiresAt="2030-01-01T08:00:00Z",
                candidates=candidates, scenarios=[k for k, v in CATALOG.items() if site in v.sedi])
    data["cleanup"] = dict(tenants=["pet-uno", "pet-due"], sources=["pet-test"],
                           idPrefix="pet-test", objectsManifest="objects.json")
    data["provider"]["baseUrl"] = "http://localhost"
    if site == "A":
        data["provider"] = dict(mode="real-probe", search=1, fetch=3)
    data["thresholds"].update(iamIntrospectionQuota=200, iamDecisionQuota=300)
    return data


class ManifestTest(unittest.TestCase):
    def test_valid_and_plan(self):
        """PETC-58B-01 · 55n-01…08. Ogni piano contiene solo la sede scelta."""
        for site in "BA":
            data = fixture(site)
            original = deepcopy(data)
            validate(data)
            self.assertEqual(data, original)
            listing = plan(data)
            for sid, row in CATALOG.items():
                self.assertEqual(sid in listing, site in row.sedi)
            for marker in ("1.", "Prerequisiti", "Arresto", "Ritorno"):
                self.assertIn(marker, listing)

    def test_rejections(self):
        """PETC-58B-02 · 55n-06/08. Vincoli D-091, finestra, scope e D-058."""
        for site, section, key, value, code in (
            ("B", "capacity", "ActivePlans", True, "CAPACITY_NOT_D091"),
            ("B", "capacity", "windowSeconds", 61, "CAPACITY_NOT_D091"),
            ("A", "provider", "search", 2, "REAL_PROBE_OVER_CAP"),
            ("A", "provider", "fetch", 4, "REAL_PROBE_OVER_CAP"),
            ("A", None, "scenarios", ["55n-01"], "SITE_MISMATCH"),
            ("B", None, "scenarios", ["55n-08"], "SITE_MISMATCH"),
            ("B", "provider", "baseUrl", "http://example.invalid", "UNSAFE_URL"),
            ("B", "provider", "baseUrl", "https://" + ".".join(["192","0","2","1"]), "UNSAFE_URL"),
            ("B", "provider", "baseUrl", "http://user@localhost", "UNSAFE_URL"),
            ("B", "provider", "baseUrl", "http://localhost?key=x", "UNSAFE_URL"),
            ("B", "provider", "token", "fixture", "INVALID_MANIFEST"),
            ("B", "load", "subjects", 101, "INVALID_MANIFEST"),
            ("A", None, "expiresAt", "2030-01-01T08:00:01Z", "WINDOW_TOO_LONG"),
            ("A", None, "candidates", {}, "CANDIDATES_REQUIRED"),
            ("B", "cleanup", "objectsManifest", "../objects.json", "INVALID_MANIFEST"),
        ):
            with self.subTest(key=key, code=code):
                data = fixture(site)
                (data if section is None else data[section])[key] = value
                with self.assertRaises(Refusal) as raised:
                    validate(data)
                self.assertEqual(str(raised.exception), code)
                self.assertIn(code, ERROR_CODES)

    def test_mix_template_and_strict_json(self):
        """PETC-58B-03 · 55n-06. Parametri obbligatori, JSON e mix esatti."""
        data = fixture()
        data["load"]["mix"]["wait"] = 0
        with self.assertRaisesRegex(Refusal, "INVALID_MIX"):
            validate(data)
        data = fixture()
        del data["thresholds"]["minP99"]
        with self.assertRaisesRegex(Refusal, "INVALID_MANIFEST"):
            validate(data)
        for raw in ('{"site":"A","site":"B"}', '{"x":NaN}'):
            with self.assertRaisesRegex(Refusal, "INVALID_JSON"):
                parse(raw)
