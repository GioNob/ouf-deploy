# Ripresa storage Onboarding — autorità e quiescenza, 5 novembre 2026

Continuare per due passi alla volta, senza subagenti. Prima controllare branch e CI; non ripetere prove concluse senza una modifica o un motivo documentato.

- Deploy: PR54 draft, branch `feat/m2-discovery-complete-profile-20261029`. Leggere l'HEAD che contiene questo handoff; precedente fd5e774c48b00c410ba203bf407b9373640a3bb2 con50/50CI SUCCESS.
- Onboarding: PR54 draft, branch `feat/storage-upload-intent-20261105`, fonte qualificata `5d9ba774b0d8b38c2acab36e1736803a1158059d`.
- [Dossier](../OUF_STORAGE_ONBOARDING_AUTHORITY_GATE_20261105.md), [ricevuta](../../evidence/onboarding-authority-gate-qualified-20261105.json).35scenari nativi+8API/storage PASS;common-cut fisico/readback PASS,265sorgenti/1680file backup;CI sorgente8/8SUCCESS.
- Il protocollo interno richiede `StorageRecoveryGate`; senza adattatore è negato. Autorità/azione/scope/epoch/scadenza e quiescenza controllati prima e dopo GET, stesso binding, audit atomico, limiti12s/2s/5s e controllo scadenza dopo audit. Non esiste un adattatore di autorità produttivo: quello PostgreSQL è test-only. Nessun permesso per-file è diventato un grant storage globale.
- Il ripristino preserva le tabelle sintetiche di autorità/audit ma NON dimostra validità produttiva dei grant ripristinati. Il futuro binding deve usare autorità corrente e prova di quiescenza su tutti i writer, non fidarsi del solo backup.

Prossima coppia delimitata:1) definire il binding di piattaforma e separare l'autorità corrente dal backup recuperato, partendo dai contratti Authorization/THS/Gateway e di installazione;2) qualificare che restart/restore non resuscitino decisioni revocate o prove di quiescenza obsolete. Nessuna nuova HUMAN authority implicita né operazione target dalla sola delega di sviluppo. UDP/Ingestion,rollout misto,riapertura e RPO/RTO restano aperti.

MinIO,source-lock,MiniPET18,3/46=39,78%,0/8gate,0/21AT,0/120oggetti reali invariati. Nessun merge/deploy/target/admission/replay/reset/grant. La prova precedente bf6bcf9 e la prima di questa coppia050a5a2a restano conservate; readback dello ZIP sul secondo runner, nessun terzo download locale dichiarato.
