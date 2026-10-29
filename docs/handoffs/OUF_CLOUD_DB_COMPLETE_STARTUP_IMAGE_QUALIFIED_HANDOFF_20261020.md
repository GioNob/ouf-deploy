# OUF CLOUD — target DB read complete; guarded startup/image qualified; private bootstrap DRAFT next

Technical8/8, functional4/6. No subagents or automations. Owner7 and publication7
are complete/consumed. Preserve every context, claim and log after STOP; reconcile,
never replay. Do not repeat completed DB reader, installation/readback, Owner7,
publication7, old input preparation, five-app checkpoint or metadata reconciliation.
Last observed HUMAN278/288,10remaining, token/window1792450664 expired. No HUMAN
journal, bearer, login, refresh, budget or window was touched this sprint.

## New target DB receipt is complete

Exact operator receipt is in evidence/ingestion-db-read-complete-target-20261020.json.
Observed1792477298 (20October2026 08:21:38 Europe/Rome), log path not supplied.
Exact postboot selection, retained file recheck and runtime generation stability:
PASS. Native READ ONLY PG17/UTF8,18successful SQL/checksums plus SCHEMA marker,
qualified catalog0ae9e4f3…,33runtime tables, no privilege gaps or broad role flags/
memberships, NORMAL pressure, no eligible/runnable/live-lease/outbox work and
61observed connection headroom.4EngineGETs/one SQL session; zero mutations, OAuth,
owner/Gateway requests, credentials, lifecycle or new authority.

This receipt proves databaseReadPrerequisitesProven, not runtime admission.
schemaCreatePrivilegePresent:true is observed capability, never permission to
migrate. Current container directFlywayEnvironmentExplicitFalse:false and startup
migration policy remain unproven. Do not fix that by changing a live container.

## Concrete source fixes and exact candidate

The old candidate663faa0 readiness only read MAX(installed_rank); it could report
UP for missing/failed/future/checksum-incompatible migrations. New owner source
`0fe0de60c6d980fe97610acf195d4bfd46d3777f` is on
`GioNob/ouf-ingestion-runtime:fix/validate-only-startup-readiness-20261020`,
parent663faa03288f9ad7775382b9757e44eaba4f51ca. Only2Java files changed:
- IngestionReadinessHealthIndicator now checks exact18release migration versions,
  scripts/types/success/checksums and optional SCHEMA marker in a bounded explicit
  read-only repeatable-read transaction, PG17/UTF8, rollback and safe DOWN reasons.
- IngestionValidateOnlyStartup fences bean creation before migration initialization
  when mode VALIDATE_ONLY is selected; missing/true effective spring.flyway.enabled
  fails with ING_STARTUP_MIGRATE_FORBIDDEN.

Legacy Flyway defaults are unchanged outside this qualified profile. The new pure
tools/ingestion_startup_profile/contract.py preserves other configuration and adds
SPRING_FLYWAY_ENABLED=false plus command arguments
--spring.flyway.enabled=false and
--ouf.ingestion.startup.schema-mode=VALIDATE_ONLY.
It rejects conflicting policy arguments/environment, duplicate keys, nonstandard
entrypoints and ambiguous command separators. This is not a deployed bootstrap.

Source/context qualification [39380669962](https://github.com/GioNob/ouf-deploy/actions/runs/39380669962),
job118488827804, deploy source2690a4e755d266e7076aacda52fc1c81b14d016f:
**17PASS/zero skips**. Actual Spring+PG17/nativeFlyway18; no Flyway beans with
the profile; CLI false wins over environment/JSON/JVM true; guard stops before
creating a schema in an empty DB; read-only readiness rejects drift/missing/
failed/future history; positive startup preserves catalog/history.

Scanned package [39380965920](https://github.com/GioNob/ouf-deploy/actions/runs/39380965920),
job118489741793, source0f0f846386bf659afde9dfe0b1a904b21e30ea25:
image `sha256:5dfdf2239fa9eb3ae2ff8510521322cf91718bc787eee179db8e65c515a30e8b`.
PASS_HIGH_CRITICAL_UNKNOWN_INCLUDING_UNFIXED; source-locked export and checksums.
Artifact12245228551, name ingestion-validate-only-candidate-39380965920,
ZIP352127312bytes, SHA256
02974a024e66d2f3adb9933f654954868598f6dfcec8899bf76daced9a1aeb02.
No self-hosted staging/import/target service access. Package is not runtime
authority and does not claim future build byte reproducibility.

Exact-image qualification [39381522188](https://github.com/GioNob/ouf-deploy/actions/runs/39381522188),
job118491478673, source93578ee5ffcf8d5049727c418d5b122df4e89e51:
**10PASS/zero skips**, actual scanned image loaded only in disposable CI.
HTTP readiness UP on exact18,503/DOWN on checksum drift and UP after fixture-only
reversal; no catalog/history change on positive startup. Image with migrate=true
exits before creating an empty schema.18native checksum matches. No image was
imported or container started on the VPS. Full rollout executor remains unqualified.

## Only next operator action: private bootstrap draft

New source `51ef47177ad1c4ec558a69d38ffdc9d1bf005fbd`.
scripts/launch-ingestion-startup-bootstrap-draft-20261020.sh delivers standalone
scripts/prepare-ingestion-startup-bootstrap-draft-20261020.py.
[CI39382298148](https://github.com/GioNob/ouf-deploy/actions/runs/39382298148),
job118493925347: **8PASS/zero skips**, including actual root-private
exclusive write/readback/no-clobber and immutable launcher/STOP log preservation.
Source SHA256 fdd0e8144e3799579ff277a4560c933e48835e8f0133467d0a1e30f791f7113e,
source blob8a317dd8c60db8e0b22724e805663b1d09fdc9f1.
Launcher SHA256232b0df047859512f8c550b4845625d56c1313e6f01134805a5e4cbb23de2ed6,
blob259970aee816232276984d7e132efd60d1d8ed50.

CLOUD has no executor for the private target context. Execute this new launcher
once as oufadmin, then return JSON and log path.90s maximum.
It reads only hash-bound completed Owner7 plan/result and retained original draft,
uses4closed EngineGETs for current Ingestion/Gateway, compiles the actual Cmd
profile/collision checks and binds the already-published dedicated owner reference.
It verifies exactly2receipt-function changes and80other preserved routes from
the sealed draft; it does NOT read the live route map or owner ACTIVE.
It rechecks both generations and retained inputs before writing new private
root700/0600DRAFT plan, preparation result and exclusive preparation claim.
Old contexts/claims remain unchanged. An existing logical draft claim blocks
automatic replay; retain the new context even on STOP.

No SQL, credential/key/bearer/HUMAN journal reads, new login, OAuth, owner/Gateway
API, image import, service stop/start, live route write, source/job/grant/metadata
change or authority. Private draft serialization retains the existing bounded8MiB document profile.
New source/image remains only proposed. Secrets are carried
as references without opening the key. The plan does NOT constitute a complete
container creation frame or executable rollout review yet. Its6explicit unproven
gates remain mandatory: archive custody/complete creation frame, signed runtime
executor qualification, current HUMAN/separate review, fresh Owner7 payload/strong
ETag, live82routes and fresh DB admission immediately before effects.

## Next development after target draft receipt

Use the exact new draft binding/actual startup command to finish source-locked
candidate custody and complete Ingestion/Gateway create frames, image unchanged
for Gateway, stable network/mount/identity/labels, bounded readiness,2new receipt
functions and80unchanged routes. Qualify the signed/fenced finite executor with
crash/revocation/ambiguity reconciliation before issuing any native action.
Do not reuse the stale663faa0candidate binding or replay Owner7/projection7.
Native HUMAN/THS gates remain separate; no automatic token/window/budget renewal.

Then governed native client profile and functional5–6: same CSV reuse; both
acquisitions' provenance/ACK,13Teatri identities/20properties and8Cinema preserved.
None of that is proved by CI, a private DRAFT, readiness or the target DB snapshot.

Original attached normative sources actually consulted: Matrix1.7 §1;
Blueprint0.3 §9; Ingestion PET1.3 §§83–83.1 and146–146.1.
Library baseline integrity remains323/323 history, not normative compliance proof.
