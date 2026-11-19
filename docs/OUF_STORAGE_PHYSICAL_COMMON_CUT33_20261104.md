## Checkpoint storage 2026-11-04 — PITR fisico e common-cut33 PASS

- Producer `7444df039a8b4990d1518a343f4f57a698db0b74`, [run41914041465](https://github.com/GioNob/ouf-deploy/actions/runs/41914041465), attempt1 completed/success. Job nativo126868857170 e readback indipendente126870953332 SUCCESS: **35test Linux PASS**, caso positivo coordinato e caso WAL mancante PASS. Stessa OCI33/binario; le prove storiche di compattazione189test/14scenari restano integre e non sono state rieseguite.
- Basebackup fisico prima degli intenti; WAL post-base necessario, target `ouf_joint33_frozen_epoch2`, LSN`0/4008E28`, timeline1/segment`000000010000000000000004`. Sorgenti ferme prima del recupero. Stesso system ID fisico7704428212093439541 su directory indipendenti. Ledger FROZEN epoch2/version2 e sei eventi identici; ACK preservato e intento ambiguo riconciliato senza nuovo PUT. Canary non-domain dopo il target escluso; **zero ACK di oggetti deliberatamente esclusi**.
- pg_isready ha richiesto2sonde readonly prima di SQL; processo avviato distinto da SQL disponibile. Clone promosso, quindi reserve(epoch2) e finish(epoch1) tornano FENCED per il fence persistente, non per hot-standby readonly. Solo dopo identità/target/WAL/ledger/fence verificati è iniziato il ripristino S3. Due oggetti/77byte e metadati GET/HEAD/LIST identici, sei AccessDenied nativi.
- Negativo nativo prima del positivo: WAL richiesto rimosso dalla sola copia di prova; PostgreSQL termina per target non raggiunto e **zero processi S3 ripristinati avviati**. Originali invariati; positivo da altra directory con archivio completo.12stati container puliti,2arresti PostgreSQL puliti e1processo di recupero negativo terminato.
- Readback originale su secondo runner e locale con risultati identici: **214membri/213checksum/30sorgenti esatti**. Verificati tutti i payload dei tre tar: basebackup1282file/46885503byte, WAL5file/67109203byte, cold-copy104file/22305byte; totale1391file/114017011byte. Sono verifiche byte-per-byte del pacchetto, non un secondo restore nativo.
- Originale artifact13362874826,6018250byte SHA256`33b5a7124d3990dce5c0049ff0a33653fec2d6fb29f07edb767a9680b8a441e3`; copia indipendente13364970618,5988845byte SHA256`95af435a5c65c803a25f701311fd325f0e46fcca8c14ed552e45a97fb6ceb552`. Custodia Actions fino2027-02-02; nessuna nuova custodia Git dei ZIP dichiarata. Receipt `evidence/storage-physical-cut33-hosted-readback-20261104.json`.
- Primo run41913004716 resta FAILED con originali13364540297/13363806513 e diagnosi/SQL/log `evidence/storage-physical-cut33-first-failure-20261104.json`: pg_ctl0 precedeva disponibilità SQL. Correzione limitata a sonde finite60tentativi/20s e3test aggiunti. Tutta la precedente descrizione PR è conservata integralmente in `docs/handoffs/OUF_PR54_STORAGE_HISTORY_BEFORE_PHYSICAL_CUT_20261104.md`.
- MiniPET **18,3/46=39,78%**,0/8gate,0/21AT,0/120oggetti reali, MinIO invariati. Qualifica del punto quiescente della fixture; niente target/merge/deploy/admission/replay/reset/grant, RPO/RTO rappresentativi o power-loss. Isolamento laterale già provato altrove non trasferito automaticamente a questo laboratorio. Prossimo passo singolo: restore su runner nuovo usando soltanto i backup esportati e l'immagine fissata, senza directory di lavoro del producer. Il readback attuale non esegue tale secondo restore. Gli stati PENDING sottostanti sono storici.

## Checkpoint storage 2026-11-04 — correzione disponibilità SQL nel recupero fisico

- Native41913004716 su57a3de3f:32test PASS, caso nativo WAL mancante bloccato prima di S3, poi FAILED `FIXTURE_SQL_RETURN_CODE`. pg_ctl start aveva restituito0 mentre PostgreSQL rifiutava SQL durante il replay (`Hot standby mode is disabled`); cleanup completo. Readback negativo preserva l'originale, senza qualifica parziale.
- Originale13364540297,5996122byte SHA2566c2c8fc856678b1cacae625da61d52f059d41a44592d6e085da50f16ebfe49ff; copia13363806513.171membri/170checksum verificati localmente. Diagnosi, SQL/log e metadati completi in evidence/storage-physical-cut33-first-failure-20261104.json.
- Aggiunta attesa di sole sonde pg_isready: massimo60tentativi/20s, probe2s; solo exit0 consente i controlli ledger, exit1/2 transitori, configurazione invalida bloccata.15test locali PASS (3nuovi positivi/negativi),35test Linux attesi. Nessuna deroga su punto nominato, WAL, identità, ACK, fence o payload.
- Nuova esecuzione solo dopo questa correzione; qualifica PITR coordinata ancora PENDING. Precedenti prove, MiniPET39,78%,0gate/AT/oggetti reali e MinIO preservati.

# Generation33 — physical PostgreSQL / SeaweedFS common recovery cut

Status: implementation and local boundary tests complete; native qualification PENDING.

The existing logical common-cut33 and standalone physical PITR are already qualified.
This step integrates them: a physical PostgreSQL17.11 basebackup is taken before
the two fixture intents; the WAL archive must reproduce the FROZEN ledger at one
named restore point while the matching SeaweedFS master/filer/volume/S3 roots
are stopped and copied. This is a new proof, not transferred credit.

The sole public S3 identity is replaced with Read/List after a complete stop.
Pending publication blocks freeze; readback reconciles the ambiguous effect
without another PUT. Both source systems stop before restoration. The basebackup,
required WAL, cold-copy inventory, read-only config, ledger and named target
are bound in one manifest.

A separate physical clone must recover the same system identifier, exact ACK/event
history and FROZEN epoch/version. A non-domain canary changed after the named point
must be excluded; no post-target object or object acknowledgement is introduced
or deliberately lost. hot_standby=off prevents SQL readiness before reaching the
target; recovery_target_action=promote allows testing the persisted SQL fence after
promotion rather than mistaking standby read-only mode for writer fencing.
PostgreSQL17 semantics: https://www.postgresql.org/docs/17/runtime-config-wal.html#RUNTIME-CONFIG-WAL-RECOVERY-TARGET

Before the positive restore, a fresh basebackup copy is started with the required
post-base WAL segment missing. Native recovery must terminate with the configured
target not reached; zero restored S3 processes may start. The original backup and
archive are retained untouched. Positive recovery then uses a different directory
and the complete archive. Only exact restored ledger/cluster/target/WAL validation
releases the isolated S3 restore. New PUT, overwrite and DELETE remain denied;
GET/HEAD bodies, MIME/hash/generation metadata and complete LIST must match.

Original physical basebackup, WAL and cold-storage payloads are packaged and
retained, along with SQL, start/stop logs, manifests and failed observations.
A separate runner reads the original ZIP, every internal checksum, all30 source
bindings, every packaged backup byte, actual WAL reads, native negative logs and
S3/ledger evidence. It does not execute a second physical restore.

Local:12 new boundary tests PASS. Python AST and two-job workflow YAML PASS.
Linux CI requires32tests (12new+11common-cut+9WAL boundaries), native positive
joint recovery and native missing-WAL rejection, then original-artifact readback.
No local PostgreSQL/Docker execution is claimed on Windows.

Scope remains two public synthetic objects/77bytes, one stopped/replaced identity,
private-socket PostgreSQL, a quiesced recovery point and unchanged OCI33/binario.
Target-wide fencing, online snapshot, continuous workload, host power loss,
representative RPO/RTO, durable Git image/ZIP custody and target admission stay OPEN.
MiniPET18.3/46=39.78%,0/8gates,0/21AT,0/120real objects, MinIO unchanged.
No target operation, deployment, merge, replay, reset or production grant.

Historical marker-only qualification: checkpoint74f28277,189tests/14scenarios,
native41886227100/readback41886345188; all earlier proofs and negative attempts
remain unchanged. See the existing common-cut and marker-only dossiers.
