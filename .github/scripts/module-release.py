"""Unprivileged client for the four governed module releases."""
import json
import os
from pathlib import Path
import re
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from release_review import approval


MIGRATION_FIELDS = ("version", "script", "type", "checksum", "success")
RETENTION_ADMIN = "mcp-retention-admin-019"


def retention_facts(review):
    lines = []
    for key in ("imageDigest", "databaseRef", "sqlSha256", "ownerAclSha256"):
        pattern = r"sha256:[0-9a-f]{64}" if key == "imageDigest" else r"[0-9a-f]{64}"
        value = review.get(key) if isinstance(review, dict) else None
        if not isinstance(value, str) or not re.fullmatch(pattern, value):
            raise SystemExit("Revisione retention 019 mancante o non valida")
        lines.append(f"{key} = {value}")
    return lines


def public_fields(source, fields):
    return {key: source[key] for key in fields if key in source}


def image_facts(result):
    labels = (("candidateImageId", "Immagine candidata"),
              ("predecessorImageId", "Immagine in esercizio da sostituire"))
    if not any(key in result for key, _ in labels):
        return ["ID immagine candidata e predecessore: non esposti dall’esecutore"]
    lines = []
    for key, label in labels:
        value = result.get(key)
        if not isinstance(value, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", value):
            raise SystemExit(f"Risposta esecutore non valida ({key})")
        lines.append(f"{label}: {value}")
    return lines


def module_review(summary, module, phase, result, next_phase, plan_migrations):
    status = result["status"]
    candidate = public_fields(result.get("candidateReview", {}),
                              ("candidateCmdSha256", "predecessorCmdSha256", "removedArgs", "envOperations"))
    if "envOperations" in candidate:
        candidate["envOperations"] = public_fields(candidate["envOperations"], ("SPRING_FLYWAY_ENABLED",))
    database = public_fields(result.get("databaseReview", {}),
                             ("migrations", "pending", "migrationsSha256", "databaseSha256", "schemaSha256",
                              "targetSchemaSha256", "before", "after"))
    for key in ("migrations", "pending"):
        if key in database:
            database[key] = [public_fields(row, MIGRATION_FIELDS) for row in database[key]]
    images = image_facts(result) if phase in ("plan", "apply") else []
    facts = [f"Modulo {module} · stato {status}", *images, *(result.get("approvalLines", ()) if phase == "plan" else ())]
    if next_phase == RETENTION_ADMIN:
        facts.append("Installazione o verifica delle due funzioni di retention 019, del proprietario e dei permessi.")
        facts.extend(retention_facts(result["retentionReview"]))
    for key, label in (("predecessorCmdSha256", "SHA-256 comando predecessore"),
                       ("candidateCmdSha256", "SHA-256 comando candidato")):
        if key in candidate:
            facts.append(f"{label}: {candidate[key]}")
    if "removedArgs" in candidate:
        facts.append("Argomenti rimossi: " + (", ".join(candidate["removedArgs"]) or "nessuno"))
    if "envOperations" in candidate:
        ops = candidate["envOperations"]
        facts.append("Operazioni ambiente: " + (f"SPRING_FLYWAY_ENABLED={ops['SPRING_FLYWAY_ENABLED']}"
                                                if "SPRING_FLYWAY_ENABLED" in ops else "nessuna"))
    for key, label in (("migrationsSha256", "SHA-256 elenco migrazioni"), ("databaseSha256", "SHA-256 database"),
                       ("schemaSha256", "SHA-256 schema"), ("targetSchemaSha256", "SHA-256 schema atteso"),
                       ("before", "SHA-256 storia iniziale"), ("after", "SHA-256 storia attesa")):
        if key in database:
            facts.append(f"{label}: {database[key]}")
    rows = database.get("pending", database.get("migrations", plan_migrations))
    if rows is not None:
        facts.append(f"Migrazioni nuove: {len(rows)}")
        for row in rows:
            facts.append(" · ".join(f"{k}={v}" for k, v in row.items()))
    elif next_phase == "migrate":
        facts.append("Elenco delle migrazioni non esposto dall’esecutore")
    if next_phase:
        approval(summary, next_phase, result["digest"], facts)
    print(module, status, file=summary)
    if not next_phase:
        for line in images:
            print(f"- {line}", file=summary)
    for review in (candidate, database):
        if review:
            print("```json", json.dumps(review, indent=2), "```", sep="\n", file=summary)
    if next_phase:
        print(f"Job `{next_phase} {result['digest']}`", file=summary)
        print("Approvare il job (nessun commento richiesto)", file=summary)


def main():
    e = os.environ
    req = dict(run=e["GITHUB_RUN_ID"], attempt=e["GITHUB_RUN_ATTEMPT"], commit=e["GITHUB_SHA"],
               operation="module-release", module=e["MODULE"], phase=e["PHASE"], digest=e["DIGEST"])
    wire = json.dumps({"request": req, "token": e.pop("REVIEW_TOKEN")}).encode()
    out = subprocess.run(["/usr/bin/sudo", "-n", "--", "/usr/local/sbin/ouf-a2"],
                         input=wire, stdout=subprocess.PIPE)
    if out.returncode:
        raise SystemExit(out.returncode)
    result = json.loads(out.stdout)
    stamp = result["digest"]
    if not re.fullmatch("[0-9a-f]{64}", stamp):
        raise SystemExit("Risposta esecutore non valida")
    status = result["status"]
    following = {"plan": {"PLANNED": "apply"}, "apply": {"GATED": "migrate", "READY": None},
                 "migrate": {"READY": None}, "rollback": {"ROLLED_BACK": None}}
    next_phase = following[req["phase"]][status]
    if req["module"] == "mcp" and req["phase"] in ("apply", "migrate") and status == "READY" and "retentionReview" in result:
        next_phase = RETENTION_ADMIN
    previous = json.loads(e.get("PLAN_MIGRATIONS") or "null")
    with open(e["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as f:
        module_review(f, e["MODULE"], req["phase"], result, next_phase, previous)
    with open(e["GITHUB_OUTPUT"], "a") as f:
        print("digest=" + stamp, "status=" + status, sep=chr(10), file=f)
        if req["phase"] == "plan":
            rows = result.get("databaseReview", {}).get("migrations")
            if rows is not None:
                public = [{k: row[k] for k in ("version", "checksum")} for row in rows]
                print("migrations=" + json.dumps(public), file=f)


if __name__ == "__main__":
    main()
