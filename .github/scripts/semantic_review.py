"""Public cutover facts shared by plan, apply, migrate and sign."""
import json
import runpy
from pathlib import Path

approval = runpy.run_path(str(Path(__file__).with_name("release_review.py")))["approval"]
IMAGE = {"imageId": "Immagine Semantic", "zipSha256": "SHA-256 ZIP",
         "inventorySha256": "SHA-256 inventario Flyway", "migrationMode": "Modalità di migrazione",
         "migrationCount": "Migrazioni nuove", "migrationsSha256": "SHA-256 elenco migrazioni"}
QUEUE_FIELDS = ("ref", "state", "recoveryState", "attempts", "claimGeneration", "leaseUntil",
                "nextAttemptAt", "budgetStartedAt", "budgetDeadline")


def cutover(summary, request, result, next_phase, previous):
    context = {key: result.get(key, previous.get(key)) for key in IMAGE if key in result or key in previous}
    details = []
    if result.get("returnAfterIssue") == "available":
        details.append(f"Ritorno al CID predecessore dopo la firma con emissione {result['returnSequence']}")
    details.extend(f"{label}: {result[key]}" for key, label in IMAGE.items() if key in result)
    for row in result.get("pending", []):
        details.append(f"{row['script']} · CRC32 Flyway {row['checksum']}")
    if "ingress" in result:
        details.append(f"Ingresso {result['ingress']} · readiness {result['readiness']} · worker {result['worker']}")
    if "queueCount" in result:
        details.append(f"Job in coda: {result['queueCount']} · SHA-256 {result['queueDigest']}")
        for row in result["queue"]:
            details.append(json.dumps({k: row[k] for k in QUEUE_FIELDS if k in row}, sort_keys=True))
    if next_phase:
        facts = [f"Cutover Semantic · direzione {request['direction']} · coda {request['queue']}"]
        facts.extend(f"{label}: {context[key]}" for key, label in IMAGE.items() if key in context and key not in result)
        approval(summary, next_phase, result["digest"], facts + details)
    for line in details:
        print(line, file=summary)
    if next_phase:
        print(f"Job `{next_phase} {result['digest']}`", file=summary)
        print("Approvare il job (nessun commento richiesto)", file=summary)
    elif "proof" in result:
        print("Prova chatbot", result["proof"], file=summary)
    return context
