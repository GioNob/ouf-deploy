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
