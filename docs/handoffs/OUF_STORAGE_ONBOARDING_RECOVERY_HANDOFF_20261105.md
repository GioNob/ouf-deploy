# Ripresa storage Onboarding — 5 novembre 2026

Continuare per due passi alla volta, senza subagenti. Prima controllare i branch e i run; non rilanciare prove già concluse senza una modifica o un motivo documentato.

- Deploy:PR54,branch `feat/m2-discovery-complete-profile-20261029`; checkpoint antecedente99594c878a3130a353531841e91c53c38741dbd0 con50/50CI verde. Leggere l'HEAD effettivo del commit che contiene questo handoff.
- Onboarding:PR54,branch `feat/storage-upload-intent-20261105`,fonte qualificata bf6bcf926727b5ea738155ac70a71b73f1b21f68.
- [Dossier completo](../OUF_STORAGE_ONBOARDING_COMMON_CUT_20261105.md) e [ricevuta](../../evidence/onboarding-common-cut-qualified-20261105.json):24scenari owner+8test API/storage PASS;common cut fisico e readback separato PASS,1671file dei backup verificati. Conservati entrambi i fallimenti e il successo precedente.
- Il componente interno ManagedFileStorageRecovery implementa drain/reconcile/freeze; nessun endpoint/scheduler o riapertura è ammesso da questa modifica. La fixture prova l'arresto storage, la restrizione Read/List e il ripristino FROZEN; non qualifica la gestione operativa di tutti i writer.

Prossima coppia delimitata:1) riesaminare i contratti operativi owner già esistenti e collegare il protocollo a una prova autorizzata di quiescenza;2) qualificarne revoca, concorrenza, scadenza e blocco della riapertura senza nuova autorità. Non inventare una nuova HUMAN authority o eseguire azioni sul target dalla sola delega di sviluppo. UDP/Ingestion e rollout misto restano da integrare.

MinIO,source-lock,18,3/46=39,78%,0/8gate,0/21AT e0/120oggetti reali invariati. Nessun deployment,merge,nuova acquisizione,replay,reset o grant effettuato. Il readback dello ZIP è stato eseguito sul secondo runner; nessun terzo download locale dichiarato.
