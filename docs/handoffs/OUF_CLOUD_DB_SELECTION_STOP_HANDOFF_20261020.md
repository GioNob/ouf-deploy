# OUF CLOUD — retained DB selection STOP, files-only reconciliation

Technical8/8; functional4/6. Owner7 and projection7 remain complete/consumed.
Preserve `/home/oufadmin/ouf-ingestion-db-read.vXzy92vP/read.log` and all retained
contexts/claims. Do not replay the stopped DB preflight, completed five-app reader,
Owner7, projection7, installation or readback. Last observed HUMAN278/288 with
expired access token and window1792450664; no new observation or runtime authority.
No automatic login, refresh, renewal, reset or automation; no subagents.

## Target evidence and exact limit

Operator receipt is retained in
`evidence/ingestion-db-selection-stop-target-20261020.json` without inventing
unreported counters. `RETAINED_DATABASE_SELECTION` and
`EXACT_ORIGINAL_DATABASE_PLAN_REQUIRED` precede `collect()` in source81462f2.
No target SQL or Engine call was reached by that code. Target admission remains
unproven. The failed guard combines original schema, Engine equality with Owner7,
and original databasePlan equality with cohortPlan.databasePlanHash. This receipt
does not distinguish these predicates.

## Reproduced producer inconsistency, not yet target diagnosis

The unchanged `scripts/source-revision-postboot-policy.py` at delivery6570c3d,
function `project()`, deep-copies the historical original and explicitly replaces
Engine and databasePlan.postgresRuntimeBinding after governed host recovery. It
does not rewrite the historical cohortPlan.databasePlanHash. The new regression
test invokes that actual producer and reproduces a DB hash mismatch after a PG
generation change. This exposes a coverage gap in the earlier22-test qualification;
those tests did not establish this retained provenance predicate on the VPS.
It does not prove which of the three predicates failed on the VPS. Do not edit
retained documents, accept a self-chosen DB or discard the hash requirement.

## Next exact action: metadata only

`scripts/launch-ingestion-db-selection-reconcile-20261020.sh` delivers
`scripts/reconcile-ingestion-db-selection-20261020.py` by immutable Git blob and
SHA256 before isolated sudo Python. Reader SHA256:
`9b6f99173b041de44de93ca0845d788ca92a7818e98ab1a8ec8512f66521bc5f`.
Reader blob:`6619184c829e499c52339bd03013692472e1c8eb`.

It verifies the completed Owner7 plan/result, publication package/review/decision,
consumed publication claim, bound case and exact originalBinding bytes. It exposes
only fixed booleans for all three predicates plus fixed Engine comparison fields.
No paths, roles, database names, unknown hashes, credential values or document
payload are printed. All8selected files are read again with exact hashes and
metadata.40s finite deadline. No retained code imports or execution; zero Engine,
SQL, OAuth, owner/Gateway requests, subprocesses, credential journal/bearer reads,
runtime writes, lifecycle operations, authority or replay. The delivery creates
only a new operator diagnostic directory and retains read.log on EXIT.

`complete:true` means metadata reconciliation completed, even if a predicate is
false. It never means admission. Obtain the exact redacted receipt before selecting
a corrected provenance path. The next DB reader must separately authenticate the
governed postboot successor when applicable; a new hash is not runtime permission.

## Qualification and normative consultation

8local tests PASS: separate predicate diagnostics; actual postboot producer
regression; authenticated case drift; double read/metadata drift; forbidden runtime
operations; immutable checksum before sudo; portable existing gh; preserved log and
STOP exit code. GitHub CI qualification is recorded separately when complete.
The original DB query/executor and their qualification are unchanged; no new native
DB or rollout qualification is claimed from these files-only tests.

Original attached Matrix1.7 §1 and Ingestion PET1.3 §§83–83.1 were reconsulted.
Service owners retain enforcement; normal application startup must not migrate.
No automatic DDL, grants or configuration repair is introduced. DB admission,
qualified Ingestion/Gateway rollout, governed native profile and functional5–6
remain open, with separate current HUMAN/THS gates.
