"""PETC-58B-04 · simulatore di loopback per 55n-04 e 55n-06."""

import http.client
import json
import threading
import unittest
from contextlib import contextmanager

from test_pet_c_manifest import fixture
from tools.pet_c.simulator import Provider, server


@contextmanager
def running(fault=None):
    data = fixture()
    config = data["provider"]
    config["latencyMs"] = {"search": 0, "fetch": 0}
    if fault:
        config["outages"] = [dict(startSeconds=0, durationSeconds=60, route="both",
                                  effect=fault, delayMs=5, retryAfterSeconds=7)]
    records = []
    provider = Provider(config, dict(count=1, windowSeconds=60), records.append)
    with server("localhost", 0, provider) as service:
        worker = threading.Thread(target=service.serve_forever, kwargs={"poll_interval": .01})
        worker.start()
        try:
            yield service.server_address[1], records
        finally:
            service.shutdown()
            worker.join()


def fetch(port, path):
    conn = http.client.HTTPConnection("localhost", port, timeout=2)
    try:
        conn.request("GET", path, headers={"X-Private": "omesso"})
        response = conn.getresponse()
        return response.status, response.getheader("Retry-After"), json.loads(response.read())
    finally:
        conn.close()


class ProviderTest(unittest.TestCase):
    def test_quota_and_sanitized_ledger(self):
        """PETC-58B-04 · 55n-06. Due rotte indipendenti e ogni arrivo fisico."""
        path = "/search?fixture=omesso"
        with running() as (port, rows):
            status, _, payload = fetch(port, path)
            self.assertEqual(status, 200)
            code, retry, _ = fetch(port, path)
            self.assertEqual(code, 429)
            self.assertTrue(1 <= int(retry) <= 60)
            self.assertEqual(fetch(port, payload["results"][0]["href"])[0], 200)
        self.assertEqual([r["code"] for r in rows if r["kind"] == "arrivalEnd"], [200, 429, 200])
        self.assertEqual(len(rows), 6)
        for r in rows:
            self.assertIn("utc", r)
            self.assertGreaterEqual(r["inFlight"], 1)
        for forbidden in ("omesso", "fixture=", "X-Private", "/search", "localhost"):
            self.assertNotIn(forbidden, json.dumps(rows))
        with running() as (port, _):
            self.assertEqual(fetch(port, path)[2], payload)

    def test_faults(self):
        """PETC-58B-05 · 55n-04. Outage, chiusura, 429 upstream e risposta tardiva."""
        for fault, expected in (("503", 503), ("upstream429", 429), ("late", 200),
                                ("close", 0), ("timeout", 0)):
            with self.subTest(fault=fault), running(fault) as (port, rows):
                if expected:
                    status, retry, _ = fetch(port, "/fetch/resource")
                    self.assertEqual(status, expected)
                    if status in (429, 503):
                        self.assertEqual(retry, "7")
                else:
                    with self.assertRaises(http.client.RemoteDisconnected):
                        fetch(port, "/fetch/resource")
            self.assertEqual(rows[-1]["outcome"], fault)

    def test_fixed_window_boundary(self):
        """PETC-58B-06 · 55n-06. Reset esatto del contatore e concorrenza osservata."""
        now = [0.]
        p = Provider(fixture()["provider"], dict(count=1, windowSeconds=60),
                     lambda _: None, clock=lambda: now[0])
        first = p.begin("search", "GET")
        now[0] = 59.5
        second = p.begin("search", "GET")
        self.assertEqual((second[1], second[-1], second[0]["inFlight"]), (429, 1, 2))
        now[0] = 60
        self.assertEqual(p.begin("search", "GET")[1], 200)
        p.finish(first[0], 200, "ok")
