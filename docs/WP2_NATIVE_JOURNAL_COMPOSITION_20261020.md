# WP2 — native journal composition, old-runtime guards and readiness

Technical8/8, functional4/6. G1 PASS; G2 OPEN. No target operations/authority.

## CAS integration correction

Native current-gate checks durably increment their counters, and native effect
readback may persist first-generation resource identity. Runner previously held
the journal version from before those calls. It now reloads after every native
guard/apply/observation and verifies that only native counters/new resource
metadata changed. A native port cannot advance nextStage, rewrite applied
evidence, alter an existing claim/resource, extend deadlines, modify Runner read
budget or decrease retained native counters. The reload keeps the exact
current CAS version rather than retrying a stale write.

Before any dependency probe, Runner now checks retained retry deadlines and
read exhaustion. Claimed effects pause immediately for reconciliation. A new
effect cannot dispatch when its observation budget is exhausted. Local signed
CAS regression:8tests PASS.

## Stage-aware predecessor and unchanged applications

The profile has exactly2replaced and3unchanged distinct applications, bound by
their complete original runtime hashes/restart counts. Every old Config,
HostConfig, mount, process and name stays exact except the specific owned
attempted/APPLIED stages. Each network requires its own detach claim. Stopped
Docker1.44 allocation fields may retain their original observed value or become
empty; foreign MAC/IP/aliases/ports remain forbidden. The stopped legacy
Config.MacAddress echo may disappear but never becomes a new machine address.
7pure model tests PASS; real Docker delta compatibility remains a G2 obligation.

## Ingestion readiness

An explicit per-Ente program/loopback endpoint profile feeds a sealed child
through the new Ingestion first-process namespaceFD. The API path is the fixed
Spring readiness contract. It reuses the existing bounded classifier and
provider Retry-After floor. One persisted attempt precedes each child; no
background retry, credential, SQL or runtime mutation occurs. A restored policy
must match exactly, without fallback to restart-disabled after APPLIED restore.

3local profile/closed-child tests PASS.5Linux cases run actual setns and HTTP
with real role signatures/CAS but synthetic Engine/image observations; their CI
status is recorded after completion. This alone is not full NativePorts or G2.

Normative originals consulted: IngestionPET1.3 §146/146.1 (application validates,
production migrate disabled, checksum/compatibility failures block rollout);
Blueprint0.3 §§9–10 and current AGENTS budget/fencing/installation rules.
The already completed SQL/preflight/Owner7/projection7 work is not replayed.
