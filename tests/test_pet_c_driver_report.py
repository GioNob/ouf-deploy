"""PETC-58B-11…14 · driver R-043 e rapporto sulle sedi 55n-01…08."""

import asyncio
import subprocess
import sys
import tempfile
import unittest
from collections import Counter
from dataclasses import asdict
from pathlib import Path

from test_pet_c_manifest import fixture
from test_pet_c_measures import rows_for
from tools.pet_c.load import FakeTransport, execute, schedule
from tools.pet_c.manifest import Refusal, canonical, digest, parse
from tools.pet_c.report import markdown, report
from tools.pet_c.scenarios import CATALOG


def bundle(data, sid, events):
    return b"".join(canonical(dict(e, manifestSha256=digest(canonical(data)))) + b"\n"
                    for e in rows_for(data, sid, events))


class DriverReportTest(unittest.TestCase):
    def test_calendar(self):
        """PETC-58B-11 · 55n-06. Stesso calendario al byte, mix e distribuzione R-043."""
        data = fixture()
        first, = schedule(data)
        second, = schedule(data)
        self.assertEqual(canonical([asdict(a) for a in first]), canonical([asdict(a) for a in second]))
        self.assertEqual(len(set(a.workflow for a in first)), 3000)
        self.assertEqual(len(set(a.subject for a in first)), 100)
        self.assertEqual(len(set(a.tenant for a in first)), 2)
        counts = Counter(a.operation for a in first)
        self.assertEqual(counts, {k: round(3000*v) for k, v in data["load"]["mix"].items()})
        data["runId"] = data["runId"][:-1] + "2"
        self.assertNotEqual(schedule(data)[0][0].subject, first[0].subject)

    def test_transport(self):
        """PETC-58B-12 · 55n-06. Workflow concorrenti e registrazione per ogni azione."""
        data = fixture()
        data["load"]["workflows"] = 12
        events = []
        asyncio.run(execute(schedule(data, 2), FakeTransport(), events.append))
        self.assertEqual(len(events), 48)
        self.assertTrue(all(e["kind"] == "actionStart" for e in events[:12]))
        for e in events:
            self.assertRegex(e["subject"], "^[a-f0-9]{64}$")
            if e["kind"] == "actionEnd":
                self.assertEqual((e["outcome"], e["code"]), ("ok", 200))
                self.assertGreaterEqual(e["duration"], 0)

    def test_open_report_and_receipts(self):
        """PETC-58B-13 · 55n-01…08. Una misura mancante trattiene l'attivazione."""
        b, a = fixture(), fixture("A")
        sid = "55n-02"
        oracle = list(CATALOG[sid].oracoli)
        events = [dict(kind="proof", name=k, passed=True, receipt=digest(k.encode())) for k in oracle]
        raw = bundle(b, sid, events)
        doc = report([(b, raw), (a, b"")])
        rows = {(r["site"], r["id"]): r for r in doc["rows"]}
        self.assertEqual(len(rows), 10)
        self.assertEqual(rows["B", sid]["status"], "PASS")
        self.assertEqual(rows["B", sid]["traceSha256"], digest(raw))
        self.assertEqual(rows["A", "55n-08"]["status"], "APERTA")
        self.assertIn("Attivazione trattenuta", markdown(doc))
        self.assertEqual(report([(b, bundle(b, sid, events[:-1]))])["rows"][1]["status"], "APERTA")
        b["load"]["seed"] += 1
        with self.assertRaisesRegex(Refusal, "TRACE_MANIFEST_MISMATCH"):
            report([(b, raw)])

    def test_cli(self):
        """PETC-58B-14 · 55n-06. Interfaccia CLI, JSON canonico e rifiuto applicativo."""
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "manifest.json"
            trace = path.with_suffix(".jsonl")
            data = fixture()
            data["load"]["workflows"] = 6
            path.write_bytes(canonical(data))
            def cli(*args):
                return subprocess.run([sys.executable, "-B", "-m", "tools.pet_c", *args],
                                      capture_output=True, check=False)
            for command in ("validate", "plan"):
                self.assertEqual(cli(command, path).returncode, 0)
            for command in ("load", "measure", "report"):
                p = cli(command, path, trace)
                self.assertEqual(p.returncode, 0, p.stderr)
            self.assertEqual(canonical(parse(p.stdout)), p.stdout.rstrip(b"\n"))
            self.assertEqual(cli("load", path, trace).returncode, 2)
            data["capacity"]["count"] = 21
            path.write_bytes(canonical(data))
            p = cli("validate", path)
            self.assertEqual((p.returncode, p.stderr.strip()), (2, b"CAPACITY_NOT_D091"))

    def test_probe_receipt_counts_retries_across_scenarios(self):
        """PETC-58B-15 · 55n-08. Il tetto reale copre anche invii di altri scenari."""
        a = fixture("A")
        sid = "55n-08"
        proofs = [dict(kind="proof", name=k, passed=True, receipt=digest(k.encode()))
                  for k in CATALOG[sid].oracoli]
        raw = bundle(a, sid, proofs)
        self.assertEqual(report([(a, raw)])["rows"][-1]["status"], "APERTA")
        raw += bundle(a, sid, [dict(kind="probeSend", route="search"),
                               *[dict(kind="probeSend", route="fetch") for _ in range(3)]])
        self.assertEqual(report([(a, raw)])["rows"][-1]["status"], "PASS")
        raw += bundle(a, "55n-06", [dict(kind="probeSend", route="fetch")])
        self.assertEqual(report([(a, raw)])["rows"][-1]["status"], "FAIL")
