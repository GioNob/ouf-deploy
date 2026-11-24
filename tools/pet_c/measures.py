"""Misure sulle tracce normalizzate PET C, tempi monotoni in secondi."""

import math
import re
from collections import Counter, defaultdict
from itertools import groupby

from .manifest import Refusal, numeric
from .scenarios import CATALOG, requirements


def require(ok):
    if not ok:
        raise Refusal("INVALID_TRACE")


def number(row, key):
    v = row.get(key)
    require(numeric(v) and v >= 0)
    return v


def delta(row, first, last):
    result = number(row, last) - number(row, first)
    require(result >= 0)
    return result


def nearest_rank(samples, percentile):
    if not samples:
        return None
    return sorted(samples)[math.ceil(percentile * len(samples) / 100) - 1]


def result(value=None, n=0, passed=True, minimum=1):
    verdict = "INSUFFICIENT_SAMPLES" if n < minimum or value is None else (
        "PASS" if passed else "FAIL")
    return dict(value=value, samples=n, verdict=verdict)


def percentile(values, p, limit, minimum):
    value = nearest_rank(values, p)
    return result(value, len(values), value is not None and value <= limit, minimum)


def peak60(times):
    ordered = sorted(times)
    left = peak = 0
    for right, t in enumerate(ordered):
        while t - ordered[left] >= 60:
            left += 1
        peak = max(peak, right - left + 1)
    return peak


def max_overlap(intervals):
    """Intervalli semiaperti: a parità di tempo l'uscita precede l'ingresso."""
    edges = []
    for start, end in intervals:
        require(end >= start)
        if end > start:
            edges.extend(((start, 1), (end, -1)))
    active = peak = 0
    for _, change in sorted(edges):
        active += change
        peak = max(active, peak)
    return peak


def slot_waits(rows):
    queued = {}
    acquired = set()
    waits = []
    for e in sorted(rows, key=lambda e: number(e, "t")):
        intent = e["intent"]
        require(isinstance(intent, str) and intent and intent not in acquired)
        if e["kind"] == "queue":
            queued.setdefault(intent, e["t"])
        else:
            require(intent in queued)
            if e["kind"] == "acquire":
                waits.append(e["t"] - queued.pop(intent))
                acquired.add(intent)
    return waits, len(queued)


def _provider(groups, limits):
    rows = list(groups["send"])
    ledger = [e for e in groups["arrival"] if e["route"] in ("search", "fetch")]
    arrivals = {(e.get("source"), e["seq"]): e for e in ledger}
    require(len(arrivals) == len(ledger))
    completed = set()
    for e in groups["arrivalEnd"]:
        if e["route"] not in ("search", "fetch"):
            continue
        seq = e.get("source"), e["seq"]
        require(seq in arrivals and seq not in completed and arrivals[seq]["t"] == e["t"]
                and arrivals[seq]["route"] == e["route"] and not groups["send"])
        completed.add(seq)
        rows.append(e)
    output = {}
    if not groups["observation"]:
        return output
    require(len(groups["observation"]) == 1)
    window = groups["observation"][0]
    seconds = delta(window, "t", "end")
    require(seconds > 0)
    intervals = []
    by_route = defaultdict(list)
    require(not (groups["send"] and arrivals))
    for e in rows:
        require(e["route"] in ("search", "fetch"))
        delta(e, "t", "end")
        require(window["t"] <= e["t"] <= e["end"] <= window["end"])
        intervals.append((e["t"], e["end"]))
        by_route[e["route"]].append(e["t"])
    for seq in arrivals.keys() - completed:
        start = number(arrivals[seq], "t")
        require(window["t"] <= start <= window["end"])
        by_route[arrivals[seq]["route"]].append(start)
    for route in ("search", "fetch"):
        times = by_route[route]
        output[route + "PerMinute"] = result(60 * len(times) / seconds, len(times))
        peak = peak60(times)
        output[route + "Peak60"] = result(peak, len(times), peak <= min(20, limits["routePeakMax"]))
    if arrivals.keys() == completed:
        peak = max_overlap(intervals)
        output["inFlight"] = result(peak, len(intervals), peak <= min(1, limits["inFlightMax"]))
    return output


def _iam(groups, limits):
    output = {}
    done = [e["decision"] for e in groups["iamDone"]]
    require(len(set(done)) == len(done))
    calls = groups["iamCall"]
    require(all(e["call"] in ("introspection", "decision") for e in calls))
    quotas = (limits["iamIntrospectionQuota"], limits["iamDecisionQuota"])
    for i, (kind, ratio, peak_name, expected) in enumerate((
            ("introspection", "introspectionsPerDecision", "introspectionPeak60", "iamIntrospections"),
            ("decision", "callsPerDecision", "decisionPeak60", "iamDecisions"))):
        events = [e for e in calls if e["call"] == kind]
        counts = Counter(e.get("decision") for e in events)
        values = [counts[d] for d in done]
        output[ratio] = result(sum(values)/len(done) if done else None, len(done),
                               all(v == limits[expected] for v in values))
        peak = peak60([number(e, "t") for e in events])
        output[peak_name] = result(peak, len(events), peak <= quotas[i] * limits["iamQuotaFraction"])
    output["iamCapacityPerMinute"] = result(min(quotas[0]/2, quotas[1]/3), len(done))
    return output


def _control(groups, limits):
    output = {}
    controls = groups["control"]
    parts = defaultdict(list)
    timeouts = 0
    for e in controls:
        require(e["operation"] in ("status", "revoke", "reconcile") and type(e["scrape"]) is bool
                and e["outcome"] in ("ok", "timeout", "error") and e["saturated"] is True)
        parts[e["operation"], e["scrape"]].append(number(e, "ms"))
        timeouts += e["outcome"] == "timeout"
    output["controlTimeouts"] = result(timeouts, len(controls), timeouts <= limits["controlTimeoutsMax"])
    p99 = {}
    for op in ("status", "revoke", "reconcile"):
        for scrape in (False, True):
            data = parts[op, scrape]
            p99[op, scrape] = percentile(data, 99, limits["controlP99Ms"], limits["minP99"])
    enough = all(v["verdict"] != "INSUFFICIENT_SAMPLES" for v in p99.values())
    observed = [v["value"] for v in p99.values() if v["value"] is not None]
    good = all(e["outcome"] == "ok" for e in controls)
    overall = result(max(observed, default=None), len(controls),
                     good and all(v["verdict"] == "PASS" for v in p99.values()))
    if not enough:
        overall["verdict"] = "INSUFFICIENT_SAMPLES"
    overall["perOperation"] = {f"{op}.scrape{int(scrape)}": v for (op, scrape), v in p99.items()}
    output["controlP99Ms"] = overall
    increases = []
    if enough:
        for op in ("status", "revoke", "reconcile"):
            base = p99[op, False]["value"]
            if base > 0:
                increases.append(p99[op, True]["value"] / base - 1)
    maximum = max(increases) if len(increases) == 3 else None
    output["scrapeIncreaseFraction"] = result(maximum, len(controls),
                                              maximum is not None and maximum <= limits["scrapeIncreaseFraction"] + 1e-12)
    output["scrapeP99Seconds"] = percentile([number(e, "seconds") for e in groups["scrape"]],
                                            99, limits["scrapeP99Seconds"], limits["minP99"])
    return output


def _capacity(groups, limits):
    output = _provider(groups, limits)
    waits, pending = slot_waits(groups["queue"] + groups["slotTimeout"] + groups["acquire"])
    slot = percentile(waits, 95, limits["slotP95Seconds"], limits["minP95"])
    if pending and slot["verdict"] == "PASS":
        slot["verdict"] = "INSUFFICIENT_SAMPLES"
    slot.update(pending=pending, timeouts=len(groups["slotTimeout"]),
                p99Seconds=nearest_rank(waits, 99) if len(waits) >= limits["minP99"] else None)
    output["slotP95Seconds"] = slot
    for name, first, last in (("lockWaitP99Ms", "request", "acquired"),
                              ("lockHeldP99Ms", "acquired", "commit")):
        durations = [1000 * delta(e, first, last) for e in groups["lock"]]
        output[name] = percentile(durations, 99, limits[name], limits["minP99"])
    output.update(_iam(groups, limits))
    output.update(_control(groups, limits))
    return output


def _performance(rows, limits, site):
    output = {}
    cells = defaultdict(list)
    unique = []
    seen = set()
    for e in rows:
        require(isinstance(e["sample"], str) and e["sample"] not in seen)
        seen.add(e["sample"])
        cols = e["columns"]
        residual = e["residuals"]
        require(cols in (18, 1000) and type(residual) is int and 0 <= residual <= cols
                and e["cache"] in ("warm", "cold") and e["queue"] in ("free", "queued")
                and e["outcome"] in ("summary", "timeout", "incomplete", "budget"))
        seconds = delta(e, "t", "end")
        if site == "A":
            cells["functionalSample"].append((seconds, e["outcome"]))
        elif residual == 1000:
            unique.append(dict(seconds=seconds, spent=number(e, "spent"), outcome=e["outcome"]))
        else:
            require(residual <= 80)
            band = 50 if residual <= 50 else 80
            key = f"e2e.{cols}.{e['cache']}.{e['queue']}.{band}"
            cells[key].append((seconds, e["outcome"]))
    for key, samples in cells.items():
        times = [s for s, outcome in samples if outcome == "summary"]
        if key == "functionalSample":
            measure = result(max(times, default=None), len(times))
        else:
            limit = limits["e2e50Seconds" if key.endswith(".50") else "e2e80Seconds"]
            measure = percentile(times, 95, limit, limits["minP95"])
        measure["incomplete"] = len(samples) - len(times)
        if measure["incomplete"] and measure["verdict"] != "INSUFFICIENT_SAMPLES":
            measure["verdict"] = "FAIL"
        output[key] = measure
    if unique:
        output["unique1000"] = result(unique, len(unique),
                                      all(e["outcome"] in ("summary", "budget") for e in unique))
    return output


def measure(manifest, rows):
    """Accetta solo eventi legati a questo run/sede e agli scenari prenotati."""
    grouped = defaultdict(lambda: defaultdict(list))
    capacity = {"arrival", "arrivalEnd", "send", "observation", "queue", "slotTimeout", "acquire",
                "lock", "iamDone", "iamCall", "control", "scrape", "actionStart", "actionEnd"}
    probes = Counter()
    for e in rows:
        require(isinstance(e, dict) and e.get("runId") == manifest["runId"]
                and e.get("site") == manifest["site"] and e.get("scenario") in manifest["scenarios"])
        sid, kind = e["scenario"], e["kind"]
        require(kind in ("proof", "arrival", "arrivalEnd") or (sid == "55n-06" and kind in capacity)
                or (sid == "55n-07" and kind == "e2e")
                or (manifest["site"] == "A" and kind == "probeSend"))
        if kind == "probeSend":
            require(e["route"] in ("search", "fetch") and manifest["provider"]["mode"] == "real-probe")
            probes[e["route"]] += 1
        grouped[sid][kind].append(e)
    output = {}
    for sid in manifest["scenarios"]:
        groups = grouped[sid]
        measures = {k: result() for k in requirements(sid, manifest["site"])}
        for key, items in groupby(sorted(groups["proof"], key=lambda e: e["name"]), lambda e: e["name"]):
            proofs = list(items)
            require(key in CATALOG[sid].oracoli and all(type(e["passed"]) is bool and
                    re.fullmatch("[a-f0-9]{64}", e["receipt"]) for e in proofs))
            measures[key] = result([e["receipt"] for e in proofs], len(proofs), all(e["passed"] for e in proofs))
        if sid == "55n-06":
            measures.update(_capacity(groups, manifest["thresholds"]))
            population = manifest["load"]
            if (population["subjects"] < 100 or population["workflows"] < 3000
                    or not all(population["mix"].values())):
                if measures["r043"]["verdict"] == "PASS":
                    measures["r043"]["verdict"] = "INSUFFICIENT_SAMPLES"
        elif sid == "55n-07":
            measures.update(_performance(groups["e2e"], manifest["thresholds"], manifest["site"]))
        elif sid == "55n-08" and measures["probe"]["verdict"] == "PASS":
            cfg = manifest["provider"]
            if not probes or cfg["mode"] != "real-probe":
                measures["probe"] = result()
            elif probes["search"] != 1 or any(probes[k] > cfg[k] for k in ("search", "fetch")):
                measures["probe"]["verdict"] = "FAIL"
        output[sid] = measures
    return output
