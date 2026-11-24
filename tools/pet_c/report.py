"""Rapporto D-082 per tutti gli obblighi di sede delle righe 55n-01…08."""

from .manifest import SCHEMA, Refusal, canonical, digest, parse, validate
from .measures import measure, result
from .scenarios import CATALOG, requirements


def read_traces(raw, manifest):
    fingerprint = digest(canonical(manifest))
    events = []
    for line in raw.splitlines():
        if line.strip():
            event = parse(line)
            if not isinstance(event, dict) or event.get("manifestSha256") != fingerprint:
                raise Refusal("TRACE_MANIFEST_MISMATCH")
            events.append(event)
    return events


def report(bundles):
    """Un fascicolo JSONL in byte per manifesto. Stessi candidati fra le due sedi."""
    matrix = {}
    candidates = {}
    expected = SCHEMA["properties"]["candidates"]["properties"].keys()
    for manifest, raw in bundles:
        validate(manifest)
        current = manifest["candidates"]
        if any(candidates[k] != current[k] for k in candidates.keys() & current.keys()):
            raise Refusal("CANDIDATE_MISMATCH")
        candidates.update(current)
        site = manifest["site"]
        measurements = measure(manifest, read_traces(raw, manifest))
        for sid, values in measurements.items():
            if (sid, site) in matrix:
                raise Refusal("DUPLICATE_SCENARIO")
            verdicts = {m["verdict"] for m in values.values()}
            if current.keys() != expected or "INSUFFICIENT_SAMPLES" in verdicts:
                status = "APERTA"
            elif "FAIL" in verdicts:
                status = "FAIL"
            else:
                status = "PASS"
            matrix[sid, site] = dict(site=site, id=sid, date=manifest["createdAt"],
                                     runId=manifest["runId"], candidates=current,
                                     manifestSha256=digest(canonical(manifest)),
                                     traceSha256=digest(raw), status=status, measures=values)
    rows = []
    for sid, scenario in CATALOG.items():
        for site in scenario.sedi:
            rows.append(matrix.get((sid, site), dict(
                site=site, id=sid, date=None, runId=None, candidates={}, manifestSha256=None,
                traceSha256=None, status="APERTA",
                measures={key: result() for key in requirements(sid, site)})))
    return dict(schema="ouf.pet-c-report.v1", rows=rows, activation=(
        "In attesa di approvazione HUMAN" if all(r["status"] == "PASS" for r in rows)
        else "Attivazione trattenuta"))


def markdown(document):
    lines = ["# Rapporto D-082 · PET C della T2", "", document["activation"] + "."]
    for row in document["rows"]:
        lines += ["", f"## {row['id']} · sede {row['site']} · {row['status']}", "",
                  CATALOG[row["id"]].titolo, "",
                  f"- Data del run · {row['date'] or 'assente'}",
                  f"- Run · {row['runId'] or 'assente'}",
                  f"- SHA-256 del manifesto · {row['manifestSha256'] or 'assente'}",
                  f"- SHA-256 del fascicolo · {row['traceSha256'] or 'assente'}"]
        for key, value in sorted(row["candidates"].items()):
            lines.append(f"- {key} · {value}")
        lines += ["", "| Misura | Campioni | Valore | Esito | Dettaglio |", "|---|---:|---|---|---|"]
        for key, metric in sorted(row["measures"].items()):
            value = canonical(metric["value"]).decode() if metric["value"] is not None else "—"
            extra = {k: v for k, v in metric.items() if k not in ("value", "samples", "verdict")}
            detail = canonical(extra).decode() if extra else "—"
            lines.append(f"| {key} | {metric['samples']} | {value} | {metric['verdict']} | {detail} |")
    return "\n".join(lines) + "\n"
