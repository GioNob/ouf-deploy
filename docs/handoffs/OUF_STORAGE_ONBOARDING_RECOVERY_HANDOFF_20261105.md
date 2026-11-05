# Ripresa storage Onboarding — restart, restore e autorità corrente, 5 novembre 2026

Continuare per due passi alla volta, senza subagenti. Controllare branch e CI prima di modificare; nessuna ripetizione di prove già concluse senza una modifica o un motivo documentato.

- Deploy:PR54 draft,branch `feat/m2-discovery-complete-profile-20261029`; leggere l'HEAD che contiene questo handoff. Precedente8f210c07fd1673eec20a49cf73911dede9540047 con50/50CI SUCCESS.
- Onboarding:PR54 draft,branch `feat/storage-upload-intent-20261105`,fonte `c1d0dd22eebbd27565ccbc86a225ea4a69c8a1f9`.
- [Dossier](../OUF_STORAGE_ONBOARDING_RUNTIME_BINDING_20261105.md),[ricevuta](../../evidence/onboarding-runtime-binding-qualified-20261105.json).42scenari nativi+8API/storage PASS;recupero fisico e readback indipendente PASS,38membri/37checksum/266sorgenti/1680file backup,9negativi.
- `StorageRecoveryRuntime` crea una sessione nuova fuori dal DB e osserva l'avvio PostgreSQL. L'owner controlla installazione,sessione,incarnazione DB e binding separato della quiescenza. Niente sessioni ripristinate,reset budget o riapertura.
- La fixture revoca una decisione esterna dopo il cut e ripristina volutamente la proiezione locale non revocata:nuova JVM bloccata,attestazione corrente revocata/assente respinta. Una JVM rimasta viva attraverso la distruzione e il restore DB è bloccata dal cambio postmaster. Owner/audit restano identici al cut. Fonte corrente modellata da file test-only fuori dai backup,non da un servizio Authorization produttivo.
- Restano invariati i controlli del gate precedente:128letture/24h,transazioni12s/lock2s/SQL5s,esatto binding pre/post GET,audit atomico e controllo scadenza finale. Il nuovo runtime non rinnova decisioni o prove di custodia.

Prossima coppia delimitata:1) predisporre il contratto applicativo di recovery storage nell'owner Authorization/piattaforma,senza assegnare grant runtime;2) qualificare consegna/revoca della decisione fra autorità e proiezione owner,con esiti ambigui e generazioni obsolete. Riesaminare prima PET/Matrix e stato dei repository coinvolti. Non riciclare i permessi HUMAN di profiling o configurazione d'installazione come autorità storage globale.

Binding produttivo,revoca distribuita concorrente,custodia completa dei writer,audit dei dinieghi,fence per rollback logico a postmaster invariato,UDP/Ingestion,rollout misto,riapertura e RPO/RTO rimangono OPEN. MinIO/source-lock,MiniPET18,3/46=39,78%,0/8gate,0/21AT,0/120oggetti reali invariati. Nessun merge/deploy/target/admission/replay/reset/grant. Prove precedenti preservate;nessun terzo readback locale degli ZIP.
