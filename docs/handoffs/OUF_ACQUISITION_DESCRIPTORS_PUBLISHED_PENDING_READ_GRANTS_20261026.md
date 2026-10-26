# Descrittori pubblicati sul VPS; proposta HUMAN per leggere due acquisizioni — 26 ottobre 2026

## Stato autorevole acquisito

[Receipt target](../../evidence/acquisition-existing-descriptors-published-target-20261026.json).
VPS EXISTING_ACQUISITION_DESCRIPTORS_PUBLISHED_GRANTS_UNCHANGED, complete=true, Exit0/DeliveryExit0.
Il messaggio contiene due copie IDENTICHE dello stesso risultato/delivery: registrare UNA esecuzione, non duePUBLISH o due budget.
Reviewe16e816b6ab0c78c7645b22cb72aec357e2730ca133c68f32c0db538be6cbf07 acquisita HUMAN, tty72byte+Invio/rejectedLines0.
Draftcb75ddb0-bd19-48fb-847f-1c47aff3207a revision1; policyouf-lab-authorization:49/hashb4bed35f9fe591aa828a50f8d2fc7c7d8aeb054b88c320f0a66b9c51f2d50a8e.
Cinque descrittori READ/HUMAN ora ACTIVE: ingestion.contract.read, ingestion.lineage.read, urban.object.read, lineage.object.read, lineage.property.read.
106grant preservati/hash25113670d8962ca87ade9f0ef2828ae64d1fa55f81a05800ebbb94178214e201.
Cumulativi7writes/27ownerGET/2preview/1554476bytes;1previewretained+1nuova,1PUBLISH,0REGISTER/CREATE/nuovigrant/SQL/Engine/Registrytouch.
StorieIAM complete e1SQLstorica conservate nella receipt, nessun reset o nuovoSQLrepair.
Il risultato NON prova E2E/scopesOAuth/grantREAD/runtimeAuthority o accettazione release.

Scope /etc/ouf/deploy-snapshots/acquisition-existing-draft-publish-cb75ddb0-v1/tty-publication-continuation-v1/editable-review-continuation-v1 CONSUMATO. Runtime3d8408ac6154d667ab64042561f5d3d14b9f7a84 e delivery059ea7fc60b19916bf484bd7bfc483407840540b NON rilanciabili.
Tutti i vecchi scope restano consumati; nessun cambiochild/reset/rollback.
OperatorLog/etc/ouf/deploy-snapshots/acquisition-existing-draft-publish-cb75ddb0-v1/tty-publication-continuation-v1/editable-review-continuation-v1/operator.log; delivery/home/oufadmin/ouf-descriptor-editable-continuation-delivery.kLzve29S/bootstrap.log.
Nessun nuovo comando VPS necessario o consegnato.
[Handoff precedente](OUF_ACQUISITION_DESCRIPTOR_EDITABLE_CONTINUATION_20261026.md) e riferimenti ora storici per il comando. Leggere comunque prove e regole terminale/MAC se pertinenti.

## Riconferma MCP e catalogo conservato

Connessione SOLOouf-admin/link6aafef... come autorizzato. Due ROLES fresche (seconda immediatamente prima della proposta) identiche:
2ruoli,34permissionadmin,2assegnazioni/issuerhttps://auth.ouf-lab.it/realms/ouf; digestcanonico7081ee0bbfef156d35d7d79d221a641b1dc91bd1bc540e81bdfeb902eee0b37d, identico baseline precedente.
Una GRANTSsubjectlimit100 osserva policy49/hashb4bed...,82grant/nextAfter null. Snapshot digest1da47eb597b35e096648ed61495175d1b4a28cdb15c33540183e87ae8a7883ca. È CONFIGURED_GRANTS_NOT_EFFECTIVE_PERMISSIONS.
Fra seiREAD è presente soltanto storicoingestion.run.read fino2036, da conservare; gli altri5grant mancanti. Vecchio grant temporaneoTeatri scaduto, mai riusarlo.
Catalogo tool espone entrambiouf.ingestion.acquisition.read eurban.acquisition.read; nessuna READ di acquisizione invocata in questo segmento.
Permessi toolChatGPT non equivalgono a OAuthscope: plugin-management get_app_permissions esclude esplicitamenteOAuth/adminscopes, quindi NON usato per dedurli.
Nessuna capability disponibile espone introspezione scope live; nessun token/credenziale letto, reauth o bypass. mcpOAuthScopesVerified=false, da provare con chiamata governata SOLO dopo nuova pubblicazioneHUMAN. Non confondere esposizionetool o letturaGRANTS con ALLOW effettivo.
MCPpinnedbd60ccd docs/ACQUISITION_EVIDENCE_READ_20261025.md e internal/kernel/acquisition_read.go riletti: admissionpreflight richiede ingestion.lineage.read/lineage.object.read per resourceoperational/runesatto/module/source/job/OPEN/TENANT_OPERATIONAL; owner verifica tutte le permission contributive. Owner403 mai vuoto/ritentato.

## Proposta attuale: UNA, PENDING, conferma soltanto THS

[Proiezione minimizzata](../../evidence/acquisition-governed-read-grants-proposal-20261026.json).
operationREPLACE_ROLES con catalogo COMPLETO preserva entrambi i ruoli e34permissionadmin e2assegnazioni ESATTI. Aggiunge soltanto:
- teatri-e2e-read-bb2e2af4-20261026 con6READ sulla runbb2e2af4-9c0a-49ea-8ad9-a947987c1472;
- teatri-e2e-read-a3208f2f-20261026 con6READ sulla runa3208f2f-ebfd-415d-bddc-79ab05dea78f;
- due assegnazioni nominali per subjectouf-adminb93d8cf6-cd14-4ee6-91d7-84cd76c4f500, nessun ruoloesterno.
SeiREAD: ingestion.run.read/ingestion.contract.read/ingestion.lineage.read/urban.object.read/lineage.object.read/lineage.property.read.
Ogni permission ha sourceRefteatri-csv-6609b245/jobRefesatto/moduleINGESTIONoUDP/detailLevelTENANT_OPERATIONAL, solelabelOPEN/ANONYMOUS, nessun wildcard/arrayOR. resourceType/resourceIdnull per consentire ownercontextoperational/object/property sotto gli stessi vincoli esatti.
ValiditàUTC2026-10-26T06:24:50Z→2026-10-26T08:24:50Z; Europe/Rome **07:24:50→09:24:50 CET**. Durata2ore concreta, nessun'estensione automatica.
NessungrantWRITE/RETRY/attivazione/acquisizione/budgetfonte o ampliamentoadmin. Grantdiretti estranei preservati dall'owner.
Hashcanonico args75e55007c3b6bb44bdb913c841d510bbc5bb09be189a7f2596e3fc93d26a153a NON è ownerreviewHash.

proposalId **64655de1-bf1e-4acd-aada-d2f27154539a**, revision0, statePENDING, finalPolicyRefnull.
Scadenza2026-10-26T06:39:58.060790Z = **07:39:58.060790+01:00 Europe/Rome**. Il26ottobre Roma èUTC+1; una prima conversione inchaterrata è stata corretta subito.
approvalPathowner:
https://api.ouf-lab.it/trusted-human/authorization/?proposal=64655de1-bf1e-4acd-aada-d2f27154539a
Una invocazionepropose riuscita euna proposal.read dello STESSOID confermaPENDING. Nessun approvazioneHUMAN/finalPolicyRef ricevuto ora.
Login e verifica review conouf-admin direttamente nellaTHS; conferma SOLO lì. Agente NON conferma/pubblica e non simula consenso, nemmeno via browser con accountutente.
Non sostituire questa proposta con altra o riproporre vecchie rifiutate/scadute. Se scade/rifiutata/ambigua, conserva ricevuta e stato, nessun replayautomatico.

## NEXT dopo decisioneHUMAN

Leggereauthorization.proposal.read dello STESSOID64655de1...; solo PUBLISHED/finalPolicyRef effettivo consente verificare ROLES eGRANTS correnti, originali identici+2ruoli/2assegnazioni,12grantcompilati e sole6READ,validità e vincoli.
Non presumere nextpolicy50prima dell'owner. Nessun polling aggressivo o creazionepropostanuova.
Poi quattro chiamate bounded ai due tool (limit<=100/risposta<=1MiB/12s), semprelinkouf-admin/sourceIdteatri-csv-6609b245 e ciascuna runESISTENTE. Tool schema può omettere link_id ma il routing lo richiede: includerlo come sopra, non cambiareaccount.
Sequenza: Ingestionrun1,UDPrun1,Ingestionrun2,UDPrun2. Usare cursor esclusivamenteowner se necessario, non inventarlo. Un403/permanentdenial non si ritenta automaticamente o aggira; conserva classificazione e riconcilia policy/scopes come prova distinta.
Correlare contratti/CSV/sourcepublication/durableACK/watermark eUDPintake/materialization/propertyprovenance/13identità/11–19property/unione20. Gli8Cinema preservati nei limiti giàdocumentati; assenza baselinevalori non prova uguaglianzabyte. REDACTED/truncated/partial non accettanoE2E.
Nessuna terzaacquisizione, nuovaattivazione, sourcebudget o reset, Registryworkerrestart/reinstall. E2E/G4/F5/F6 OPEN, tecnico8/8funzionale4/6; Supervisor solo dopoE2E. Nessunmerge/releaseacceptance.

Fontinormative e storia: handoff precedente integrale e sue referenze, pianooffline20261025 ora materializzato SOLO per questa nuova proposta con snapshotfresco/tempi concreti; mai invocare i template vecchi. BaselinePEToriginale hash e63df... e Matrix/Authorization/THS restano vincolanti. ProductTHS/ApprovalChallenge non dichiarato conforme dalla sola approvazioneterminale di repair.
