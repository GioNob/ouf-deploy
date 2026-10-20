> SUPERSEDED NEXT ACTION: the target DB reader stopped at retained selection.
> Do not replay it. Continue with [DB selection STOP reconciliation](OUF_CLOUD_DB_SELECTION_STOP_HANDOFF_20261020.md).
> Earlier qualification below does not prove the failed target provenance predicate.

# OUF CLOUD — checkpoint complete, finite native DB preflight ready

Technical8/8, functional4/6. No subagents, automations, completed action replay or
new runtime authority. Continue diagnosis/resolution. Keep all private contexts,
claims and logs after STOP. Owner7/projection7 remain completed/consumed.

## Proven operator target checkpoint

Exact supplied JSON is retained in
`evidence/ingestion-rollout-checkpoint-five-apps-complete-target-20261020.json`.
Observed1792472533 =20October2026 07:02:13 Europe/Rome. Log:
`/home/oufadmin/ouf-rollout-five-apps.wbwPYkt9/read.log`.

All5 runtime generations match retained pins twice: onboarding,mcp,udp,ingestion,
gateway. Active projection7 bytes and integer nanosecond metadata unchanged;
244source hashes verified and consumed claims retained. HUMAN actually278/288,
10remaining, matching published token, boot/wall consistent. Both bearer and
window1792450664 are expired. Local READY is not current provider authorization
or runtime authority. No OAuth, owner/Gateway/DB calls, writes, lifecycle,
login/refresh/renewal/reset or completed owner/publication replay occurred.

The diagnostic is COMPLETE. Do not repeat the old readers, installation/readback,
Owner7, projection7 or legacy preparers/runtime mains as the next action. This
receipt does not re-query backend owner ACTIVE/full payload/ETag or live82 routes.

## New finite native DB reader

- Source:`81462f2298576cf7c84f92fca02e82bacaf614a9`.
- Native CI:[39375241448](https://github.com/GioNob/ouf-deploy/actions/runs/39375241448), job118471805928,22PASS/zero skips.
- Scope:14unit tests plus8actualPostgreSQL17/Docker/nativeFlyway tests.
- Reader:`scripts/read-ingestion-db-preflight-20261020.py`.
- SHA256:`814c0da470aa9c2a15b82b6d900f608bb7a5d6b8c4e3503eb7c65acfd5028c47`.
- Immutable reader blob:`b9a7ac830b14d971f8fff43cedc8c40dcdb5742c`.
- Delivery:`scripts/launch-ingestion-db-read-preflight-20261020.sh`.
- Candidate SQL manifest:`releases/ingestion-db-read-manifest-20261020.json`.

Target DB preflight has NOT run. CLOUD has no SSH executor. Only next operator
action is the new immutable DB-read delivery once, then return its redacted JSON.
This is an operator-executed native infrastructure diagnostic using the retained
OS/DB binding; no UI/MCP SQL tool or caller-supplied query is introduced.

Selection is read-only: completed Owner7 execution plan SHA256
`e5f69f89aa40b8c9b963134d38a6aecaf864499346f9e366539c1eb1aefa0938`,
completed publication source/claim/case, exact originalBinding path+hash, original
prepared cohort databasePlanHash and its4 module bindings. The ingestion module
selects database,user,schema,OID and PostgreSQL runtime generation. The original
MCP migration admin binding may be null and is never used. Candidate metadata is
bound to private inputsHash7b5d811ba31ab5899f969759eb5140c586785b1a17bdfe9287b6666ba788b314
and exact source663faa03288f9ad7775382b9757e44eaba4f51ca/image51a514d8… SQL resources.
No old source, preparer, main, authority or credential journal is executed/opened.

Current PG and Ingestion are each inspected twice through exact EngineAPI1.44.
PG pin uses original raw mount order; ingestion uses its retained mount-set pin.
JDBC database/runtime role and the explicit network peer are checked from current
configuration against retained binding. The adapter is for this retained Docker
installation. It is not a portable multi-host transport qualification.

One ephemeral psql process runs inside the existing selected PG container via
the hash-bound root Docker executable. It uses the retained native Unix-socket
adapter, existing application role, clean environment, -X/-w, /dev/null pgpass
and service files, default_transaction_read_only, fixed literal query, explicit
REPEATABLE READ READ ONLY, local5s statement/1s lock/5s idle limits and ROLLBACK.
No password/token is forwarded. No arbitrary SQL/host/role arguments are accepted.
No container is created/started/restarted; no application function is invoked.

Bounds:4Engine GETs,one SQL batch/session,no retries,90s total; inner psql15s,
outer native process20s,capped stdout512KiB/stderr64KiB. Waits hold no file locks.
Child pipes are drained concurrently and the client process group is killed on
timeout; inner timeout bounds the retained-container process too. Errors expose
constant reason and SQLSTATE only. The root Docker CLI context must contain no
config.json; native tests prove its entries/metadata remain unchanged.

## What the preflight proves and does not prove

It checks exact18SQL Flyway history including a legitimate optional SCHEMA row,
native Flyway checksums, runtime catalog, effective role privileges/broad role
flags, stored pressure policy, bounded work/lease/outbox counts and control
headroom. Reference catalog SHA256:
`0ae9e4f3fda6fd7f4432c1816139a53eba471077730badf2beb61712585ed209`.
Catalog contains OID/owner/data-independent column/default, constraint, index,
trigger, function, sequence-definition and policy metadata; mutable sequence
values and all raw rows are excluded. Unknown catalog fingerprints stay private.

The conservative read profile requires PG17/UTF8, ordinary scoped runtime role,
the complete minimum privilege matrix for33 runtime tables,2sequences and
functions, NORMAL stored pressure below soft backlog, at least5observed server
connection headroom/2database headroom when limited, no prepared transactions,
lock waiters, unobservable peers, advisory locks, runnable runs, eligible schedules
or live leases. These are observational prerequisites for a new bounded plan;
the reader does not alter the stored policy, concurrency, grants or work.

`complete:true` means the read/rechecks completed. Inspect every gate flag.
`databaseReadPrerequisitesProven` may be false; no repair/retry is automatic.
Even if true, `databaseAdmissionProven:false`,
`runtimeStartupMigrationPolicyProven:false` and `runtimeAuthorityIssued:false`
remain explicit. This snapshot is not a durable admission lease or fresh HUMAN
consent. Startup, current owner/live route map, staged image/key custody,
availability/drain/readiness and executor crash/reconciliation remain separate.

All DDL/migrate/schema tampering/role changes in the tests are disposable CI
fixture effects. The exact candidate18 SQL and Boot4.0.8-managed Flyway are used
to migrate/validate that fixture and compare every native checksum. The full
native read path is real, while the application container sleeps: the candidate
JVM was not started and no VPS/production DB was contacted by CI. Evidence is
separate from target execution and end-to-end acceptance.

## Startup migration policy — still open before rollout

Original PET Ingestion1.3 §83.1 requires ordinary app startup not to migrate;
release-governed migration/compatibility precedes rollout. Candidate base
application.yml has Flyway schemas/create-schemas and no enabled:false override.
An effective overriding profile has NOT been proven. The current report's
directFlywayEnvironmentExplicitFalse is an observation of one ENV only, not a
proof of effective Spring configuration or candidate startup behavior.

Before any new candidate start, qualify the precise validated bootstrap with
migrate disabled, native schema compatibility/readiness and restart/ambiguous
result behavior. Do not infer zero startup Flyway work from unchanged18resource
hashes or identical history, and do not silently widen the old5ENV draft delta.
Any new startup-setting delta must be explicit in the qualified governed plan.
No manual DDL/repair, old ALLOW_CONNECTIONS migration adapter or grant changes
are authorized by this read or the completed owner/publication scopes.

## Normative consultation and remaining sequence

Actual attached originals consulted for this gate: Matrix1.7 §1; Blueprint0.3 §9;
Ingestion1.3 §§40,55–56,60,83.1; Onboarding/THS1.6 §2 P01/P02/P03. Branch AGENTS
and resiliencev3 remain normative; archive323 checksums were previously verified,
which is integrity evidence only. This is bounded diagnostic qualification,
not full PET/coherence or release acceptance.

After target DB evidence: resolve actual red gates without manual repair/replay;
qualify exact2-runtime/2-route executor and bootstrap, preservation of80 other
routes, Gateway-wide availability impact, key custody and finite readiness.
Only then present a concrete native HUMAN/THS plan with fresh two-role authority.
HUMAN278/288 is retained but expired; no automatic login/window/budget expansion.
Re-query current owner ACTIVE/full payload/ETag and82-route map under appropriate
fresh authority before runtime effects. Preserve all old claims and histories.

Then publish governed native client profile with its consent and fresh client
readback; verify actual ouf-admin ingestion status/history. Functional5 repeats
the same CSV to prove canonical reuse;6 proves both acquisitions and preserved
8Cinema/13Teatri/lineage. Source activation/run remains separate HUMAN/THS action.
No source, job, metadata profile, key, grant, rollout or release acceptance has
been performed by preparing this reader.
