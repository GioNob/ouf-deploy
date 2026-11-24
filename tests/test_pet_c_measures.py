"""PETC-58B-07…10 · contratti numerici di 55n-06 e 55n-07."""

import unittest

from test_pet_c_manifest import fixture
from tools.pet_c.measures import measure, nearest_rank, peak60
from tools.pet_c.scenarios import CELLS


def rows_for(data, sid, events):
    return [dict(e, scenario=sid, runId=data["runId"], site=data["site"]) for e in events]


def metrics(sid, events, site="B"):
    data = fixture(site)
    return measure(data, rows_for(data, sid, events))[sid]


class MeasuresTest(unittest.TestCase):
    def test_provider_lock_and_requeue(self):
        """PETC-58B-07 · 55n-06. Tempi fra sorgenti, lock e prima attesa FIFO."""
        events = [dict(kind="observation", t=0, end=120)]
        for route, start, end in (("search", 0, 1), ("fetch", .5, 1), ("search", 1, 2)):
            events.append(dict(kind="send", route=route, t=start, end=end))
        for i in range(20):
            for kind, t in (("queue", 0), ("slotTimeout", 1), ("queue", 2), ("acquire", i+3)):
                events.append(dict(kind=kind, t=t, intent=str(i)))
        events.extend(dict(kind="lock", request=0, acquired=.125, commit=.15625) for _ in range(100))
        m = metrics("55n-06", events)
        self.assertEqual(m["searchPerMinute"]["value"], 60 * 2 / 120)
        self.assertEqual(m["fetchPerMinute"]["value"], .5)
        self.assertEqual(m["inFlight"], dict(value=2, samples=3, verdict="FAIL"))
        self.assertEqual(m["slotP95Seconds"]["value"], 21)
        self.assertEqual(m["slotP95Seconds"]["timeouts"], 20)
        self.assertEqual(m["lockWaitP99Ms"]["value"], 125)
        self.assertEqual(m["lockHeldP99Ms"]["value"], 31.25)
        self.assertEqual(peak60([0, 59, 60, 119]), 2)

    def test_sparse_missing_and_physical_peaks(self):
        """PETC-58B-08 · 55n-06. La media non nasconde il burst o gli arrivi incompleti."""
        events = [dict(kind="observation", t=0, end=180)]
        events += [dict(kind="arrival", t=i, seq=i, route="search") for i in range(21)]
        m = metrics("55n-06", events)
        self.assertEqual(m["searchPerMinute"]["value"], 7)
        self.assertEqual(m["searchPeak60"]["verdict"], "FAIL")
        self.assertEqual(m["inFlight"]["verdict"], "INSUFFICIENT_SAMPLES")
        self.assertEqual(m["slotP95Seconds"]["verdict"], "INSUFFICIENT_SAMPLES")

    def test_iam_control_and_scrape(self):
        """PETC-58B-09 · 55n-06. Rapporti per decisione, picchi e percentili del controllo."""
        events = [dict(kind="iamDone", decision="d")]
        events += [dict(kind="iamCall", call=k, decision="d", t=i)
                   for k, count in (("introspection", 2), ("decision", 3)) for i in range(count)]
        events += [dict(kind="iamCall", call="decision", t=59)]
        for op in ("status", "revoke", "reconcile"):
            for scrape in (False, True):
                events += [dict(kind="control", operation=op, scrape=scrape, saturated=True,
                                ms=100 + 8*scrape if i < 99 else 3000, outcome="ok") for i in range(100)]
        events += [dict(kind="scrape", seconds=1.5) for _ in range(100)]
        m = metrics("55n-06", events)
        for key, value in (("iamCapacityPerMinute", min(200/2, 300/3)),
                           ("decisionPeak60", 4), ("callsPerDecision", 3),
                           ("introspectionsPerDecision", 2), ("controlP99Ms", 108),
                           ("scrapeIncreaseFraction", .08), ("scrapeP99Seconds", 1.5)):
            self.assertAlmostEqual(m[key]["value"], value)
            self.assertEqual(m[key]["verdict"], "PASS")
        events[-101]["outcome"] = "timeout"
        self.assertEqual(metrics("55n-06", events)["controlTimeouts"]["verdict"], "FAIL")

    def test_multiple_sources(self):
        """PETC-58B-16 · 55n-06. Stessa sequenza su due repliche, quorum sulle misure."""
        events = [dict(kind="observation", t=0, end=60)]
        for source, route, start in ((1, "search", 1), (2, "fetch", 2)):
            entry = dict(kind="arrival", seq=1, source=source, route=route, t=start)
            events.extend((entry, dict(entry, kind="arrivalEnd", end=3)))
        m = metrics("55n-06", events)
        self.assertEqual(m["inFlight"], dict(value=2, samples=2, verdict="FAIL"))
        self.assertEqual(m["fetchPerMinute"]["value"], 1)
        self.assertEqual(m["controlP99Ms"]["verdict"], "INSUFFICIENT_SAMPLES")

    def test_e2e_cells_and_unique(self):
        """PETC-58B-10 · 55n-07. Code incluse, celle distinte, minimi 20/100, casi incompleti."""
        events = [dict(kind="e2e", sample=str(i), columns=1000, residuals=50, cache="cold",
                       queue="queued", t=10, end=10+i, outcome="summary") for i in range(1, 21)]
        key = "e2e.1000.cold.queued.50"
        self.assertEqual(metrics("55n-07", events[:-1])[key]["verdict"], "INSUFFICIENT_SAMPLES")
        events += [dict(events[0], sample="unici", residuals=1000, spent=3000, outcome="budget")]
        m = metrics("55n-07", events)
        self.assertEqual(m[key], dict(value=19, samples=20, verdict="PASS", incomplete=0))
        self.assertEqual(m["unique1000"]["value"][0]["spent"], 3000)
        self.assertEqual(sum(m[k]["verdict"] == "PASS" for k in CELLS), 1)
        events[0]["outcome"] = "incomplete"
        self.assertNotEqual(metrics("55n-07", events)[key]["verdict"], "PASS")
        self.assertEqual(nearest_rank(list(range(1, 101)), 99), 99)
