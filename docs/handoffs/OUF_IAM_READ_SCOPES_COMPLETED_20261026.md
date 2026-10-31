# OUF — IAM READ completato, nuova autenticazione HUMAN necessaria — 26 ottobre 2026

## Stato verificato

Owner ha autorizzato esplicitamente le due creazioni persistenti realm ouf/Type None e l'assegnazione dei sei READ come Default al solo ouf-chatgpt, preservando le 33 assegnazioni. Questo consenso specifico risolve il precedente rifiuto automatico senza aggirarne il controllo. Console autenticata IAM oufadmin, nessun nuovo login o lettura di segreti.

Create e rilette:
- lineage.object.read: 6c7af46b-e96b-40a1-954c-527993ea2fe9
- lineage.property.read: 7523a2c6-088f-4478-9965-ed95412234eb

Entrambe Type None, OpenID Connect, Include in token scope On. Nessun Realm Default. Tre definizioni precedenti e ingestion.run.read riusati.
Client ouf-chatgpt UUID3e64ac3a-eeaa-47bd-94ec-b78040b39e71: lettura UI finale 2026-10-26T12:59:25Z dimostra 39 assegnazioni, tutte le 33 righe baseline identiche, più:
- ingestion.run.read — Default
- ingestion.contract.read — Default
- ingestion.lineage.read — Default
- urban.object.read — Default
- lineage.object.read — Default
- lineage.property.read — Default

Nessun altro client, mapper, ruolo, audience, PKCE o impostazione security modificato. Nessuna acquisizione invocata in questa continuazione. Screenshot acquisito ma non sincronizzato nel workspace dopo cinque secondi: non inventare allegato/link.

[Evidence](../../evidence/iam-read-client-scopes-completed-20261026.json).
[Handoff precedente integrale](OUF_IAM_READ_SCOPES_PARTIAL_REVIEW_20261026.md), inclusi baseline33 e riferimenti storici.
[Policy51 e diagnosi integrale](OUF_POLICY51_SCOPE_MISSING_HANDOFF_20261026.md).

## Prossimo passo

Serve una normale NUOVA autenticazione OAuth della connessione OUF - MCP Server con account applicativo ouf-admin. Il login della console IAM oufadmin non rinnova il contesto del connettore. Nessun token corrente introspezionato; non dichiarare scope effettivi risolti o riprovare acquisizioni solo per la modifica IAM.
User deve effettuare la riconnessione nel normale flusso ChatGPT del connettore, senza password/codici/token in chat. Non usare credenziali Keycloak admin per la connessione applicativa.

Policy51 PUBLISHED, proposta c1908145-5aa5-4dc4-a2fb-e8bf7ba5daf5/rev1; hash sha256:449d5629097730226841ca73a43c0d8cfa8068be5fcdbabc85e9b749f996ecea. Grant finestra12:14:26→14:14:26Z (13:14:26→15:14:26CET Europe/Rome26ottobre). Se scaduta, niente rinnovo/proposta automatica.
Dopo prova nuovo contesto HUMAN e finestra valida: UNA READ Ingestion source teatri-csv-6609b245/run bb2e2af4-9c0a-49ea-8ad9-a947987c1472/limit100. Solo eventuali cursor owner, <=1MiB/12s. Primo nuovo DENY STOP senza retry.
Seconda run esistente a3208f2f-ebfd-415d-bddc-79ab05dea78f; nessuna terza acquisizione.
Link link_6aafef96b4148191b767e9af7b756a07; subject b93d8cf6-cd14-4ee6-91d7-84cd76c4f500.

Precedente UN READ policy51: SCOPE_MISSING/MCP_PRE_ADMISSION/evaluated51/retryablefalse, nessun retry/UDP/seconda run. Configurazione IAM ora corretta non prova emissione token né ALLOW owner.
MCP9a già installato VPS positivo, tutti vecchi scope capture/prep/APPLY/recovery/reader consumati e non rilanciabili. Registry invariato. E2E/G4/F5/F6 OPEN, tecnico8/8 funzionale4/6, Supervisor dopo E2E; nessun merge/release acceptance/reset/attivazione/reinstall/restart Registry.
