# Descrizioni PR precedenti alla qualifica client OCI33

## ouf-deploy PR54

Qualify exact MinIO–OCI33 migration, crash reconciliation and post-write return

La migrazione era qualificata soltanto fra due SeaweedFS di laboratorio. Questa PR aggiunge il rehearsal **MinIO esatto → SeaweedFS OCI33 esatta → MinIO indipendente vuoto**, riusando senza modifiche inventario, compilatore e core copy-new. Prova inoltre il ritorno dopo aggiunta, sostituzione del corpo, modifica dei metadati e cancellazione, con originali sorgente intatti.

Qualifica nativa: [run42068964202](https://github.com/GioNob/ouf-deploy/actions/runs/42068964202), commit `4555f7dc2be2e44aa25277a22a35d7e2597c80ea`, **12 esiti PASS inclusi subtest; tutti i52 workflow del candidato SUCCESS**. 120oggetti sintetici/203743byte,10senza hash annunciato,360riletture condizionali finali; tre crash e503 dopo PUT riconciliati senza secondo PUT. Il Retry-After usa clock virtuale. Tre container senza egress/porte pubblicate e tre stop puliti; scan moduli/eseguibili zero rilievi.

Archivio13435386238 verificato localmente:369047byte,27membri/26checksum/137sorgenti Git esatti. I tre tentativi falliti sono conservati: ownership del runner, cache del reporter Go e diniego InvalidTag del MinIO legacy. Il diniego viene ora verificato senza alterazione dell'originale; il caso positivo conserva tag supportati/gzip/metadati. Nessun controllo indebolito né modifica al vecchio test SeaweedFS. Il gate sicurezza MinIO resta HELD; il mirror non autentica il publisher originale.

Checkpoint documentale `466209aaf58c1c1d936bde382089a253b90e6a2c`: 46/51 workflow SUCCESS; 5 ancora in corso, nessun PASS anticipato. Questi controlli sono distinti dai52 workflow del candidato qualificato.
- [Dossier](https://github.com/GioNob/ouf-deploy/blob/466209aaf58c1c1d936bde382089a253b90e6a2c/docs/OUF_STORAGE_MINIO33_REHEARSAL_20261105.md)
- [Ricevuta e fallimenti conservati](https://github.com/GioNob/ouf-deploy/blob/466209aaf58c1c1d936bde382089a253b90e6a2c/evidence/storage-minio33-rehearsal-qualified-20261105.json)
- [Handoff corrente](https://github.com/GioNob/ouf-deploy/blob/466209aaf58c1c1d936bde382089a253b90e6a2c/docs/handoffs/OUF_STORAGE_CLOSURE_HANDOFF_20261105.md)
- [Descrizioni precedenti e scope storico della PR](https://github.com/GioNob/ouf-deploy/blob/466209aaf58c1c1d936bde382089a253b90e6a2c/docs/handoffs/OUF_PR54_STORAGE_HISTORY_BEFORE_MINIO33_REHEARSAL_20261105.md)

**MiniPET invariato:18,3/46=39,78%,0/8gate,0/21AT,0/120oggetti reali.** Mancano raccolta corrente G0, riconciliazione riferimenti DB/oggetti, profilo rappresentativo, dossier G1 e ammissione/passaggio/osservazione. AT14 non è chiuso per dopo-checkpoint/versioni; AT17 richiede anche assenza di divergenza DB. Custodia Actions fino3febbraio2027, non durevole.

Prossima coppia delimitata: completare una consegna unica concreta per G0 (corpi/ACL/writer/DB/capacità/finestra) e ricomporre le prove già disponibili sulla coorte finale G2–G4. Valutare prima fermo completo; niente nuovo filone recovery/HTTP-HUMAN senza dipendenza dimostrata. Draft/open; nessun merge/deploy/grant/riapertura/reset, source-lock e piano storico congelato invariati.

## ouf-source-onboarding PR54

Bind PostgreSQL recovery to authenticated HUMAN commands and finite restricted connections

Storage replacement remains the priority. Source HEAD stays at d5155899b09dda298494b68cefa7e1f281167652 (8/8 CI SUCCESS); the116 native/API/HUMAN tests and12 SDK tests remain component evidence, not MiniPET acceptance. Deploy now qualifies the exact MinIO→OCI33 migration, crash/503 reconciliation and empty-store return after acknowledged object mutations:12 native passes and52/52 candidate workflows SUCCESS. The [current handoff](https://github.com/GioNob/ouf-deploy/blob/466209aaf58c1c1d936bde382089a253b90e6a2c/docs/handoffs/OUF_STORAGE_CLOSURE_HANDOFF_20261105.md) and [qualification](https://github.com/GioNob/ouf-deploy/blob/466209aaf58c1c1d936bde382089a253b90e6a2c/evidence/storage-minio33-rehearsal-qualified-20261105.json) delimit the next pair to current G0 collection and final-cohort evidence reconciliation. HTTP/HUMAN wiring is conditional on the selected migration procedure. No new source commit, endpoint, bean, operational grant or deploy; MiniPET remains18.3/46,0gates,0AT,0real objects copied.

---

Recovery of an uncertain PostgreSQL owner transaction now has an explicit authenticated HUMAN request adapter and a separate bounded resolver connection profile. The adapter derives actor and policy decision from the existing OUF IAM token/bridge and shared evaluator, and binds approval to the exact command, lease digest/generation, reason and revoked-next proof. Earlier upload, policy delivery, durable authority, real COMMIT outcome resolution and rollback protections remain; their descriptions and evidence are preserved in history.

Approval requires POST and the server bearer write proof, configured issuer/audience/installation/tenant, HUMAN identity, scope and current policy/assurance. It lasts at most 30 seconds within bearer expiry and five-minute authentication freshness. No raw bearer or reusable approval authority is persisted. Each attempt requires fresh authentication; completed receipt replay remains historical readback.

A policy swap after SQL preflight denies the command and retains the owner latch. Only the final file mutation seals the exact current SDK snapshot using a nonwaiting local publication fence. Refresh then returns POLICY_PUBLICATION_CONTENDED/installed=false until close; no SQL/network wait occurs under that fence. This serializes the local JVM and does not prove distributed revocation, remote ACTIVE freshness or IdP session revocation. Approved/Prepared must always close; expiry denies further use but does not unlock a possibly active mutation automatically.

The dedicated resolver pool has one connection, 1s acquisition, 0.5s validation, driver connect/login/socket limits of 2/3/2s and bounded SQL/cancel waits. It accepts a single literal IPv4 binding and explicit TLS mode; tests use disposable loopback without TLS. It never replaces the exact Spring-bound owner connection or provisions SQL grants.

**No controller, bean, operational grant or admission is installed.** The new capability `installation.storage.authority.reconcile` is not registered/granted. Five tests exercise real RSA/Nimbus validation plus OUF converter/bridge directly, not a deployed HTTP route, remote IdP, UI confirmation or MCP/Gateway end-to-end flow. Other SDK consumers retain their pinned source.

Qualification at `d5155899b09dda298494b68cefa7e1f281167652`:

- [Native 42049204934](https://github.com/GioNob/ouf-source-onboarding/actions/runs/42049204934): **103 native + 8 API/storage + 5 HUMAN = 116 PASS**, zero failures/errors/skips; **12 SDK tests PASS** separately. Six new native cases cover authenticated receipt binding, policy revocation after preflight, restricted-role rollback, SQL privilege revocation/commit, pool exhaustion and an actual TCP peer accepting without replying.
- Pool exhaustion returned in **1,001ms**, silent TCP peer in **1,003ms** (qualification bound 4s). Restricted role has no superuser/admin/pg_monitor membership or application-table grants; owner SELECT/UPDATE, policy reads and CREATE SCHEMA deny.
- Stock PG17 exposes pg_control_system via PUBLIC. The fixture temporarily removes that inherited access, tests the single direct EXECUTE grant and its revocation, then restores the original PUBLIC ACL. Other PUBLIC defaults remain: this is a minimal additional-grant profile on a hardened fixture, not a complete production privilege audit.
- Local native archive verification: **191 members, 190 checksums, 301 exact Git blobs**, including SDK manifest; 32 provider receipts, 17 child JVM logs and eight complete PostgreSQL outcome receipts. No repeated native execution locally.
- [Physical 42049204791](https://github.com/GioNob/ouf-source-onboarding/actions/runs/42049204791): producer/readback SUCCESS; **39 members, 38 checksums, 304 source bindings, 1,695 backup files, 15 semantic corruptions rejected**. Existing sequential physical driver does not integrate this HUMAN adapter/resolver; readback is not a second native restore. Physical ZIP not reverified locally.
- **Source CI 8/8 SUCCESS**; general suite 473 reported − 103 native skips = **370 executed PASS**; blocking image scan and container boot successful. All 14 changed files reread at final commit. Prior deploy checkpoint `7e04721`: **50/50 SUCCESS**; new documentation checks are separate.

Initial candidate `a0f9510` had two native assertions fail because direct REVOKE left PUBLIC access intact; physical producer passed but readback rejected the newly included SDK source set. Final commit corrects fixture ACL handling, exact verifier set and contract; production implementation is unchanged between candidates. Failed evidence and causes remain in the qualification receipt.

Scope is same-host/local POSIX/ext4, PG17 and component IAM. Operational HTTP/MCP/Gateway integration, exact HUMAN confirmation, policy distribution/revocation, capability registration/grants, custody/admission, TLS and governed restart/restore rebind remain open. No merge, deployment, target operation, runtime grant, automatic re-admission or MinIO/source-lock change. MiniPET **18.3/46 = 39.78%, 0/8 gates, 0/21 AT, 0/120 real objects**.

[Dossier](https://github.com/GioNob/ouf-deploy/blob/41431adaac06a85d9deeb31da70c156b3f955141/docs/OUF_STORAGE_HUMAN_APPROVAL_20261105.md), [qualification receipt](https://github.com/GioNob/ouf-deploy/blob/41431adaac06a85d9deeb31da70c156b3f955141/evidence/storage-human-approval-qualified-20261105.json), [archive verifier](https://github.com/GioNob/ouf-deploy/blob/41431adaac06a85d9deeb31da70c156b3f955141/scripts/readback-human-approval-native-20261105.py), [handoff](https://github.com/GioNob/ouf-deploy/blob/41431adaac06a85d9deeb31da70c156b3f955141/docs/handoffs/OUF_STORAGE_ONBOARDING_RECOVERY_HANDOFF_20261105.md), [prior PR descriptions and handoff](https://github.com/GioNob/ouf-deploy/blob/41431adaac06a85d9deeb31da70c156b3f955141/docs/handoffs/OUF_PR54_STORAGE_HISTORY_BEFORE_HUMAN_APPROVAL_20261105.md).

Historical next-pair proposal superseded by the closure review linked above. Preserve the technical gap; execute it only when the selected storage migration procedure requires this resolver path.

