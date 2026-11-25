"""MCP plan and retention client for the protected manual release workflow."""
import json
import os
from pathlib import Path
import re
import runpy
import subprocess


BATCH_FACT = ("Un solo batch di retention con il ruolo di manutenzione: cancella al massimo "
              "OUF_ANALYSIS_RETENTION_BATCH righe per tabella (letture, snapshot, tentativi) "
              "delle analisi concluse oltre i TTL del candidato.")


def main():
    common = runpy.run_path(str(Path(__file__).resolve().parents[1] / ".github/scripts/module-release.py"))
    env = os.environ
    phase = env["PHASE"]
    req = dict(run=env["GITHUB_RUN_ID"], attempt=env["GITHUB_RUN_ATTEMPT"], commit=env["GITHUB_SHA"],
               operation="module-release", module="mcp", phase=phase, digest=env["DIGEST"])
    wire = json.dumps({"request": req, "token": env.pop("REVIEW_TOKEN")}).encode()
    response = subprocess.run(["/usr/bin/sudo", "-n", "--", "/usr/local/sbin/ouf-a2"],
                              input=wire, stdout=subprocess.PIPE, check=True)
    result = json.loads(response.stdout)
    stamp = result["digest"]
    if not re.fullmatch("[0-9a-f]{64}", stamp) or result["status"] != {
            "plan": "PLANNED", "mcp-retention-admin-019": "VERIFIED", "analysis-retention-once": "SUCCEEDED"}[phase]:
        raise SystemExit("Risposta esecutore non valida")
    review = result.get("retentionReview")
    rows = result.get("databaseReview", {}).get("migrations")
    facts = []
    if phase != "plan" or review is not None or any(row["version"] >= 19 for row in rows or []):
        facts = common["retention_facts"](review)
    if phase != "plan" and (stamp != req["digest"] or review.get("status") != "VERIFIED"
                            or review.get("planSha256") != stamp):
        raise SystemExit("Ricevuta retention 019 incoerente")
    with open(env["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as summary:
        if phase == "plan":
            common["module_review"](summary, "mcp", phase, result, "apply", None)
        if phase == "mcp-retention-admin-019":
            common["approval"](summary, "analysis-retention-once", stamp, [BATCH_FACT, *facts])
        elif facts:
            print("mcp-retention-admin-019", *facts, sep="\n\n", file=summary)
    with open(env["GITHUB_OUTPUT"], "a") as output:
        print("digest=" + stamp, "status=" + result["status"], sep="\n", file=output)
        if phase == "plan":
            print("retention=" + ("true" if review else "false"), file=output)
            if rows is not None:
                print("migrations=" + json.dumps([{k: row[k] for k in ("version", "checksum")} for row in rows]),
                      file=output)


if __name__ == "__main__":
    main()
