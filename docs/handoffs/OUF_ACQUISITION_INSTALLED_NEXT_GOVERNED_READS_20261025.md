# Installazione VPS conclusa; prossime letture governate — 25 ottobre 2026

## Prova effettiva server

L'owner ha restituito `ACQUISITION_READ_PATH_INSTALLED_E2E_NOT_ACCEPTED`, complete=true, Exit0/DeliveryExit0. Non è CI. Il risultato pubblico integrale e i percorsi dei log sono in [evidence target](../../evidence/acquisition-detached-mcp-residual-installed-target-20261025.json). Nessun timestamp server è stato fornito.

Review: c77171d86ab5af4c81926fb9a0c3402f4f2c79f6dd7e946fc280a1354d1808de.
Authority:6147d3a683cebcd66a6c076dc8f5970777d3c824b7d697b95aa0b4e34f5047ee.
Runtime389719d67ba4686a5d8082628a8bf6795cb2e744, delivery222a9a52fd2c18e95279a67acaebeb7af6579457, manifest4633a0f61b564aa4a50abba6ae41467a4648a3dbdb34d9f4d41b01672aea5d70. La sequenza mostra i16progress residui e il risultato finale completo; il journal server non è stato riletto indipendentemente dall'agente. L'Exit0 del codice pinned segue verifica dell'attestazione finale.

- 2READ propri riavviati e pronti,1manager MCP, vecchioMCP trattenuto fermo.
- 82rotte preservate e2aggiunte; originalScopeUnchanged/originalWorkersUnchanged/componentReadinessProven true.
- Registry worker non toccato, nessun nuovo import (3precedenti conservati), grantfonte/attivazione/SQLrepair/OAuthrepair.
- Bootstrap OAuth normaleMCP può essere avvenuto; numero non osservato, nessun reset attribuito al repair.
-applicationE2EProven=false/releaseAcceptance=false: installazione e readiness non chiudono G4/F5/F6.

Finali cumulativi: EngineGET306, Enginewrites22, imageLoad3, ownerConfigurationRead83, quarantineStop2, readinessGET8, adminGET9/PUT2, serviceCredentialFileRead3.
13stageAPPLIED retained; stesso journalHash1fb1159ada9d78123d1a90985e8c6ba23a18648bd3b3f621406c43dc9f57817d.
Nessun contatore azzerato.

Scope `detached-mcp-recovery-v1` CONSUMATO sotto:
`/etc/ouf/deploy-snapshots/acquisition-read-apply-5fa62e4f6869a6f40fb512878dcf65dcb6ffaf941be487e4189826f418046591/terminal-continuation-v1`.
NON rilanciare wrapper/controller/lettori precedenti o cambiare child. Nessun altro comando VPS è ora necessario o consegnato.

Log: `/home/oufadmin/ouf-detached-mcp-recovery.s0Si2E4i/operator.log`.
Delivery: `/home/oufadmin/ouf-detached-recovery-delivery.hr6CzART/bootstrap.log`.
Precedenti pin e qualificazione: [handoff della recovery](OUF_ACQUISITION_DETACHED_MCP_RESIDUAL_RECOVERY_20261025.md), ora STORICO per la sua istruzione di prima esecuzione.

## Letture applicative riuscite DOPO installazione

Connessione usata esclusivamente ouf-admin, link_id link_6aafef96b4148191b767e9af7b756a07. Non cambiare account per aggirare un diniego.

1. `authorization.permissions.read`, SOLO view=ROLES oltre al routing link_id:2ruoli,34permission nel ruolo admin,2assegnazioni; nessuna modifica. Baseline canonica SHA2567081ee0bbfef156d35d7d79d221a641b1dc91bd1bc540e81bdfeb902eee0b37d.
2. GRANTS dello stesso subject, limit100:82grants/nextAfter null, policyRefouf-lab-authorization:48; baselineSHA256f01ccbc9bef0591629c05deee7764c2feb1a8a17610fd261db30a4567860acac. La policy48 è ancora la versione ACTIVE letta; è il vecchio grant temporaneo Teatri a essere scaduto. Non è autorità per le sei nuove READ.
3. `urban.object.search` distinto per Cinema e Teatri, pageSize20, via permission admin già esistente:8Cinema e13Teatri, partial=false/nextCursor=null. Stessi ID/status/revisioni/chiavi proprietà della baseline evidence/csv-post-native-activation-objects-20261025.json. Cinema revision1; Teatri revision2,11–19proprietà/oggetto e unione20IRI, invariati. Valori non nella baseline: uguaglianza byte dei valori NON provata. Nessun binding di queste search a run/ACK/provenance.
4. `source.onboarding.revision.read` sulla sola versioneACTIVEc9fec43c-19b3-4ffb-9111-781bc347c5b0 della fonte teatri-csv-6609b245: hashsha256:b13c5fe234168bdb8b315087917bccfe428ceaa8e136ed1c0f56f5bf43deed3d/lock4/CONFIRMED/humanApprovalRequiredfalse, publicationdffa2a5e-740b-4e3d-95a0-14c841940b72 attiva/compatibilitytrue. Cumulativi4/generazione6 e sessione storica conservati; phaseACTIVE. I flag di budget storico scaduto/esaurito NON richiedono nuova attivazione o grant. Nessuna lista propertyRules/rules nella risposta: causa della sparsità proprietà non provata.

Dettagli minimizzati: [serving](../../evidence/acquisition-post-install-authorized-serving-20261025.json) e [fonte](../../evidence/acquisition-post-install-source-active-20261025.json). Niente valori delle proprietà pubblicati. Nessuna query SQL diretta, nessuna nuova acquisizione, nessun replay/attivazione/revision.prepare.

## Blocco corrente: esposizione dei due nuovi tool nella connessione della chat

Nel manifest del MCP pinnedbd60ccd092b51557b280e533c8db6b3f98842f9e sono presenti e toolEligible:
- `ouf.ingestion.acquisition.read`
- `urban.acquisition.read`

In questa connessione i due tool NON compaiono tra quelli disponibili e i rispettivi metodi non sono esposti. ROLES, GRANTS, serving e readsource invece funzionano. Questo dimostra il limite della connessione corrente; non è un diniego owner delle due READ, che non sono state invocate, né una nuova prova live di tools/list. Non affermare una specifica causa cache/refresh come già provata sul wire.

Consultata la procedura plugin-management e cercata l'integrazione: nessun controllo di aggiornamento del catalogo custom OUF è esposto agli strumenti della sessione. Non installare plugin generici alternativi, cambiare permessi globali/account o aggirare le capability con SQL/HTTP owner/raw endpoint. Non riavviare o reinstallare MCP/Registry per il catalogo del client.

NEXT necessario: aggiornare/rendere disponibili nella connessione OUF della chat questi due tool. Dopo un aggiornamento, ricontrollare la loro presenza senza chiamare ancora letture protette. Se restano assenti, distinguere catalogo client e discovery server prima di proporre diagnosi o effetti.

Per evitare la scadenza anticipata già avvenuta in passato, NESSUNA proposal HUMAN a15min è stata creata ora e nessun nuovo grant è pubblicato. Nessun link di approvazione attuale da usare. Non riproporre o confermare le vecchie proposal scadute.

## Piano concreto di permission, pronto OFFLINE

[Piano minimizzato](../../releases/acquisition-evidence-governed-read-plan-20261025.json), stato OFFLINE_PREPARED_NOT_SUBMITTED. Non è un payload API direttamente invocabile: validità e snapshot completo vengono risolti su letture fresche al momento della proposta. Il tempo non è stato consumato da una proposal pendente.

Sei permission distinte:
- INGESTION: ingestion.run.read, ingestion.contract.read, ingestion.lineage.read.
- UDP: urban.object.read, lineage.object.read, lineage.property.read.

Le sole run sono bb2e2af4-9c0a-49ea-8ad9-a947987c1472 e a3208f2f-ebfd-415d-bddc-79ab05dea78f. Due ruoli temporanei nominali, uno per run, ciascuno con le6READ:12grant compilati,6capability distinte. Durata proposta2ore dal momento della futura proposta; HUMAN decide sulla finestra concreta. Nessun budget di acquisizione, nessuna operazione WRITE/RETRY/ACTIVATE.

Issuer copiato dalla ROLES live; tenantouf-lab, subjectouf-adminb93d8cf6-cd14-4ee6-91d7-84cd76c4f500. Ogni permission vincola moduleINGESTION/UDP, sourceRefesatta, jobRefesatto della run, detailLevelTENANT_OPERATIONAL e sole labelOPEN/ANONYMOUS. resourceType/resourceId restano null perché il readerUDP verifica sia contesti operational/run che object/property: i vincoli sourceRef/jobRef sono sempre forniti dall'owner, non dal chiamante.

Motivo dei due ruoli: SDK pinned e RoleCatalogue supportano uguaglianza esatta su attributi stringa, non array/OR inventati; la stessa capability non può essere duplicata dentro un ruolo. Preservare contenuto esatto e semantica di tutti e2ruoli/34permissionadmin/2assegnazioni originari. I nuovi ruoli portano4ruoli/4assegnazioni senza modificare admin; PermissionProposalService mantiene i grant diretti estranei al catalogo, inclusi gli storici. Tra i sei ID, la lettura GRANTS mostra solo un grant storico ingestion.run.read valido fino2036, privo delle altre cinque permission: non basta all'intero contesto owner e va conservato. La pagina è CONFIGURED_GRANTS_NOT_EFFECTIVE_PERMISSIONS; non inferire ALLOW dai soli grant configurati. Struttura/preservazione sono state verificate nei sorgenti, non ancora pubblicate.

Quando i tool saranno disponibili:
1. Rileggere ROLES e GRANTS con lo stesso account, costruire il catalogo COMPLETO preservando qualsiasi entry corrente. Se il baseline è cambiato, non sovrascrivere con lo snapshot vecchio.
2. Risolvere validFrom/validUntil concreti di2ore e inviare UNA authorization.permissions.propose/REPLACE_ROLES. Non creare6proposal indipendenti e non inviare il piano offline con campi template.
3. Conservare proposalId/revision/hash/expiry/approvalPath e leggere la receipt; la conferma/pubblicazione avviene SOLO nella THS autenticata HUMAN, mai come agente.
4. Dopo conferma owner, leggere authorization.proposal.read dello stessoID e verificare PUBLISHED/finalPolicyRef. ROLES deve preservare gli originali e aggiungere soltanto i due ruoli/assegnazioni temporanei; nessun diniego va aggirato o ritentato automaticamente.
5. Leggere una pagina bounded di ciascuna delle due nuove capability per ciascuna run, con sourceId/runId/limit e cursore SOLO dell'owner. Trattare partial/REDACTED/truncated come limite, mai come accettazione. Confrontare run→snapshot/publication/CSV/bundle, durable ACK/watermark e intake/materialization/provenance,13ID/20proprietà con gli8Cinema preservati ai limiti già documentati.
6. Nessuna terza acquisizione. Supervisor soltanto dopo sufficiente prova E2E. Nessun merge o release acceptance.

Fonti primarie consultate: MCPbd60ccd docs/ACQUISITION_EVIDENCE_READ_20261025.md, internal/kernel/acquisition_read.go, internal/manifest/capabilities.json, internal/authorization/constraints.go; Ingestion3ab998f AcquisitionEvidenceService; UDPb6a9f36 AcquisitionEvidenceService e vendorAuthorizationPolicy; OnboardingOufRoleCatalogue/PermissionProposalService per struttura e preservazione del catalogo. Non modificati repository prodotto o servizi.

Stato: tecnico8/8, funzionale4/6, sourceACTIVE/G3PASSED riconfermata; E2E/G4/F5/F6 OPEN. Prove502/403/GEToriginale200 conservate. Nessun nuovo runtime command, install/restart Registry o reset di contatori. L'agente non ha avviato procedure di login/refresh o letto credenziali; l'autenticazione ordinaria del connettore non è stata misurata. Nessuna nuova autorità dedotta dal messaggio dell'owner.
