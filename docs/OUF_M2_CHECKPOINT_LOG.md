# Log dei checkpoint M2

Il log è append-only e in ordine cronologico. Aggiungere una voce datata in fondo. Se serve correggere una voce, aggiungere un riferimento a quella precedente. Per decidere la prossima azione, leggere [STATE.md](STATE.md).

Le voci fino al 2 novembre sono una sintesi dei checkpoint preesistenti. Il [documento originale integrale](https://github.com/GioNob/ouf-deploy/blob/b8d5b67c1c4d2e42b4eaed1a2c2678806e92624b/docs/OUF_M2_MINIPET_v1_0_20261026.md) conserva il testo esatto, i riferimenti e le istruzioni storiche.

## 26 ottobre 2026 — Baseline e audit

L’audit mappava 63 file, 24 criteri di accettazione e 8 criteri UX. M1 era acquisito per il caso Teatri. Il piano iniziale proponeva di riprendere il job Farmacie allora in errore e comporre i componenti esistenti. La stima da 34 a 58 ore era stata ritirata dopo l’inventario.

- [Audit](OUF_M2_CODE_EVIDENCE_GAP_AUDIT_20261026.md)
- [Tabella di stato del 26 ottobre](https://github.com/GioNob/ouf-deploy/blob/b8d5b67c1c4d2e42b4eaed1a2c2678806e92624b/docs/OUF_M2_MINIPET_v1_0_20261026.md#2-baseline-fonti-e-stato-certo)
- [Primo tratto operativo originario](https://github.com/GioNob/ouf-deploy/blob/b8d5b67c1c4d2e42b4eaed1a2c2678806e92624b/docs/OUF_M2_MINIPET_v1_0_20261026.md#14-primo-tratto-operativo)

## 30 ottobre 2026 — Teatri e Farmacie

Teatri aveva completato M1/G4 a passi singoli. Farmacie conservava lo stesso profilo riuscito, con 61 righe e 10 colonne. Il codice ministeriale era stato confermato come stringa e le 10 colonne come OPEN. M2 restava aperto.

- [Handoff del 30 ottobre](handoffs/OUF_M2_SINGLE_MCP_NATIVE_20261030.md)

## 1 novembre 2026 — Custodia e provenienza delle immagini

1. Catturate 13 immagini, per 2.774.726.144 byte. La verifica privata dei byte era pronta. [Handoff](handoffs/OUF_M2_IMAGE_BYTE_VERIFICATION_20261101.md)
2. La prima verifica si è fermata. La correzione dei metadati opzionali è stata qualificata. [Riconciliazione OCI](handoffs/OUF_M2_IMAGE_BYTE_RECONCILIATION_20261101.md)
3. La seconda verifica si è fermata. È stata preparata la diagnosi della struttura delle immagini. [Diagnosi](handoffs/OUF_M2_IMAGE_GRAPH_DIAGNOSTIC_20261101.md)
4. Collegati 13 ruoli, 10 configurazioni pubbliche e 4 manifesti. Tre origini restavano da confrontare. Il dodicesimo scope era consumato. [Ricevuta](../evidence/m2-runtime-origin-join-target-20261101.json)
5. Collegata la provenienza di Semantic. La scansione osservò 3 HIGH, 56 MEDIUM e 38 LOW. Il gate restava sospeso. [Provenienza e scansione](handoffs/OUF_M2_RUNTIME_PROVENANCE_RECONCILIATION_20261101.md)
6. Il candidato Semantic corretto passò senza HIGH, CRITICAL o UNKNOWN. Restava da sostituire l’immagine installata. [Correzione](handoffs/OUF_M2_SEMANTIC_HIGH_REMEDIATION_20261101.md)
7. Verificato il nuovo candidato Gateway. La scansione dell’immagine MinIO recuperata rilevò 9 CRITICAL, 127 HIGH e 8 UNKNOWN. Serviva una scelta sullo storage. [Decisione storage](handoffs/OUF_M2_STORAGE_SECURITY_DECISION_20261101.md)

## 2 novembre 2026 — Filone MinIO → SeaweedFS

Aperto un MiniPET dedicato alla sostituzione S3. Il piano partiva con 8 gate e 21 criteri di accettazione aperti. M2 conservava il proprio criterio di completamento. [MiniPET SeaweedFS](OUF_MINIO_SEAWEEDFS_MINIPET_v1_0_20261102.md)

## 7 novembre 2026 — Ripartenza e blocco del selettore

1. Il VPS ha avviato lo stack originale su MinIO e SeaweedFS OCI33 sulla rete privata. Il rinnovo dei token host ha ripristinato cinque servizi e cinque timer.
2. MCP è uscito dopo la prima ripartenza. Il successivo avvio mirato ha restituito HTTP 204 su `/health/ready`.
3. La capability di upload ha restituito un handoff. Il browser ha ricevuto HTTP 403 `ONB_CAPABILITY_DENIED` per `ouf.managed-source.file.upload` prima della selezione del file. La policy `ouf-lab-authorization:59` mostra un grant diretto scaduto e un ruolo configurato con la capability per `ouf-admin`. Il permesso effettivo della sessione THS resta da accertare.

- [Procedura di avvio sul VPS](OUF_RUNTIME_RESTART_20261107.md)

## 7 novembre 2026 — Verifica della sessione THS

Il selettore ha restituito lo stesso 403 in InPrivate. Il redirect OIDC effettivo del client THS include lo scope `ouf.managed-source.file.upload`. La lettura della policy `ouf-lab-authorization:59` ha trovato un ruolo con questa capability per `ouf-admin` e nessun grant di upload per `giovanni-chatgpt`. Rimane da identificare il soggetto della sessione browser e verificare il permesso effettivo.
