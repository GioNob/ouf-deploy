> SUPERSEDED NEXT ACTION: target DB preflight is COMPLETE; do not replay the reader.
> Continue with [startup/image qualification and private bootstrap draft](OUF_CLOUD_DB_COMPLETE_STARTUP_IMAGE_QUALIFIED_HANDOFF_20261020.md).

# OUF CLOUD — retained selection reconciled; postboot-bound DB reader ready

Technical8/8; functional4/6. Owner7/projection7 remain complete and consumed.
No subagents, automations, completed installation/readback/owner/publication replay,
automatic OAuth/login/refresh, budget reset or window renewal. Preserve contexts,
claims and all logs after any STOP. Last observed HUMAN278/288, token and
window1792450664 expired; it is not current runtime authorization.

## New target receipt

Operator-supplied `ouf.ingestion-db-selection-reconcile.v1` is COMPLETE:
schema and Engine match the completed Owner7 plan; only
`originalDatabasePlanMatchesCohortHash` is false. All selected document bytes
and metadata were rechecked. Zero Engine, SQL, OAuth, journals/bearer reads,
writes, effects or authority. Exact receipt:
`evidence/ingestion-db-selection-reconciled-target-20261020.json`.
No log path was supplied for that receipt; do not invent one.
Do not replay that completed files-only reader or the stopped v1 DB preflight.

The target evidence identifies the failed predicate. The retained postboot
producer `scripts/source-revision-postboot-policy.py:project` replaces Engine
and PostgreSQL generations in the original prepared inputs but preserves the old
cohortPlan.databasePlanHash. The previous new DB reader incorrectly treated that
historical hash as a hash of the entire postboot databasePlan. No retained file
has been changed to make the test pass.

## Exact authenticated successor, no permissive fallback

New reader:`scripts/read-ingestion-db-postboot-preflight-20261020.py`.
It requires the entire original document hash
`b3988d964a3c60b06b17952863f4fc62fc9a8f1626ced82bfb864721eb7b740a`,
retained postboot private inputs hash
`1ab309f747d2e0c70b3a284258ea0f2100d51bc149ef9c2ae2b55b73f3871c62`,
and completed preparation receipt hash
`3eb2fd4fff1048accdb954322faa58979bb490250c8535c1dd8512253e603587`.
These are existing release pins from the completed source-revision readback and
MCP transport preparation, not freshly computed target acceptance hashes.

Canonical pair is under
`/etc/ouf/deploy-snapshots/source-revision-postboot-prepared-kfy691gh`;
receipt is
`/etc/ouf/deploy-snapshots/source-revision-human-recovery-inmfuoj2/postboot-preparation-result.json`.
The completed publication case still authenticates its exact originalBinding
bytes; they must equal the pinned whole postboot original. The receipt binds the
canonical pair. Private inputs and original must match in Engine and the complete
databasePlan, with explicit retained generation-rebind proof and no authority reuse.
Owner7 plan/current Engine, exact4DB modules, ingestion role/database/OID, exact18
SQL history and candidate resources remain independently checked.

No arbitrary path/hash/DB/role/SQL arguments, legacy fallback or retained code
execution is introduced. The historical cohort hash remains unchanged in the
pinned document. All selection is repeated after the read; any drift stops.

## Qualified immutable delivery

Source:`9625c35eee701f75eecb367ae0378da3aa2c894f`.
[CI39379643028](https://github.com/GioNob/ouf-deploy/actions/runs/39379643028),
job118485558537: **32PASS/zero skips** (24unit/delivery +8actualPG17/native
Docker/Flyway),18native SQL checksum matches. Actual postboot producer generates
the selection fixture. Tampered full original, recomputed historical hash,
private-input/receipt drift, independently pinned but inconsistent pairs and
historical authority reuse all fail closed. Immutable delivery checksum,
portable existing gh, retained log and STOP exit status pass.

Reader SHA256:`82ccde1ccd0b889480eefd1bae7eaee749bfe9592244e796eebafc26d643f849`.
Reader Git blob:`034c3146c88e28bea42d42f92b20c0cf7ae08d42`.
Launcher:`scripts/launch-ingestion-db-postboot-preflight-20261020.sh`.
Launcher SHA256:`74c166f91ec17082f4cf404cfdbcdf1b2e1b36ebfcee73b1063030c29c377add`.
Launcher Git blob:`867f6f17854b773079ecce7ea0f52e108c61bf67`.
Evidence:`evidence/ingestion-db-postboot-preflight-qualification-20261020.json`.

## Only next operator action

Execute the new immutable launcher once, then supply its redacted JSON and log
path. CLOUD has no VPS executor. This is a new finite diagnostic after provenance
reconciliation; the stopped v1 never reached Engine or SQL. No consumed runtime
effect is replayed.

SQL and native effect adapter are unchanged and requalified:4EngineGETs (PG and
Ingestion twice), one fixed psql session in the selected existing PG container,
existing application role, isolated environment, explicit READ ONLY transaction,
bounded statements/output/time and ROLLBACK.90s outer diagnostic,15s native psql,
20s child bound. No migrations, schema/data/grant changes, container lifecycle,
candidate JVM start, owner/Gateway API or credential files. Existing18migration
history, exact catalog, effective role privileges, pressure/work/leases and
connection headroom are checked. CI DDL exists only in disposable test fixtures.

`complete:true` is completed observation, not release acceptance. Even a green
`databaseReadPrerequisitesProven` leaves `databaseAdmissionProven:false`,
`runtimeStartupMigrationPolicyProven:false` and `runtimeAuthorityIssued:false`.
New result schema:`ouf.ingestion-db-read-preflight.v2`; after final selection
recheck it reports `retainedPostbootDatabasePairBound:true`.

## Remaining gates and original normative sources

Reconsulted attached Matrix1.7 §1 and Ingestion PET1.3 §§83–83.1. Ingestion normal
startup must not migrate; candidate application.yml enables Flyway unless
effectively overridden. The runtime override/readiness/zero-startup-migration
behavior, precise Ingestion/Gateway rollout executor, current HUMAN/THS authority,
governed native profile and functional5–6 remain unproven. No service starts from
this diagnostic. Functional5 reuses the same CSV;6 requires both acquisitions'
provenance/ACK,13Teatri identity/20property preservation and8Cinema preservation.
