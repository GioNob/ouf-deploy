# Ripresa storage — consegna/revoca Authorization, 5 novembre 2026

Continuare per due passi alla volta, senza subagenti. Verificare branch e CI prima di modificare; non ripetere prove concluse senza modifiche o motivo documentato.

- Deploy:PR54 draft,branch `feat/m2-discovery-complete-profile-20261029`; leggere l'HEAD che contiene questo handoff. Precedente18810180ca0e6db6dcf866b5fdc5ca49916abb82 con50/50CI SUCCESS.
- Onboarding:PR54 draft,branch `feat/storage-upload-intent-20261105`,fonte `f909fbfbc3f060f2cb83238cb94c8d7b710f77dc`.
- [Dossier](../OUF_STORAGE_AUTHORIZATION_DELIVERY_20261105.md),[ricevuta](../../evidence/storage-authorization-delivery-qualified-20261105.json).57scenari nativi+8API/storage PASS;common-cut/readback SUCCESS,38membri/37checksum/270sorgenti/1695file backup,9negativi.
- `StorageRecoveryAuthorization` usa il registry Authorization reale già presente nel repository. Capability candidata `installation.storage.recovery`,HUMAN,scope omonimo,risorsa installation-storage-recovery server-side. Nessuna registrazione/grant automatica;HUMAN fresco e deadline massimo15minuti. V40 crea tabelle vuote e proiezioneversione0.
- Preparazione idempotente per chiave/hash;consegna con versione attesa e audit atomico;risposta persa riconciliata sullo stesso ID/versione. Sostituzione/revoca terminale,nessun rinnovo implicito di decisioni o budget. Gate reale rivalida policy/decisione dopo GET;lock condiviso741093 confligge con attivazione policy esclusiva e lockproiezione con revoca esplicita.
- `PolicyStorageRecoveryGate` e servizio sono interni,nonbean/nonendpoint. Integrazione qualificata SOLO nello stesso PostgreSQL. Custodia separata test-only;nessun servizio di revoca remota distribuita o sessione Gateway/THS installato.
- Il common-cut conserva le nuove tabelle V40 nello stato vuoto/senza autorità. NON è ancora il restore di una storia V40 popolata. Restano validi runtime/installazione/postmaster e precedente prova di decisione corrente esterna revocata;un bundle Authorization vecchio ripristinato NON è automaticamente corrente.

Prossima coppia:1) integrare decisioni/consegne/audit V40 popolati nel common-cut;2) qualificare ripristino con revoca dopo il taglio e blocco della riattestazione su policy/proiezioni obsolete,usando autorità corrente indipendente dal backup. Nessun grant target. Riesaminare il fence di generazione e il confine Authorization/THS/Gateway prima di collegare il percorso operativo.

MinIO/source-lock,MiniPET18,3/46=39,78%,0/8gate,0/21AT,0/120oggetti reali invariati. Nessun merge/deploy/target/admission/replay/reset/grant. Produzione,custodia completa,audit dinieghi,revoca distribuita,rollback logico,UDP/Ingestion,rollout misto,riapertura,RPO/RTO OPEN. Prove precedenti preservate;nessun terzo readback locale degli ZIP.
