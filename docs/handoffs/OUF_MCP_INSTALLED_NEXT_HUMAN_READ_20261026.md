# OUF — MCP diagnostico installato sul VPS; E2E attende nuovo mandato READ — 26 ottobre 2026

## Risultato VPS realmente ricevuto

**MCP_DIAGNOSTIC_UPDATE_INSTALLED_E2E_NOT_ACCEPTED**, complete=true,
componentReadinessProven=true, Exit0/DeliveryExit0.
[Receipt completa](../../evidence/mcp-diagnostic-update-installed-target-20261026.json).
Sorgente MCP **9a374dd07745f059de3ad39757c68f02db6d29c3** (draft ouf-mcp-server#79),
nativeimage **sha256:9a1af5be94ff3dda4084b829e824482c5cf863525375c6f104a3fe89517e781e**.
Questa è prova SERVER dichiarata dall’operatore, distinta dalla qualificaCI e dal solo preparatore.
L’assistente non ha letto i log privati del VPS e non ne richiede copia integrale.

Review approvata nel terminale con riga esatta+Invio come riportato:
**53baa1e1be6b600da78f5f4915a21e19e6e553b0f610bc66080fd6bf3a4af86e**.
Autorità runtime per quell’esecuzione:
**e2d940ff16896bae706efe9acdf3cf1b5cabc79aa36c0c6260b91294ec564be6**.
NativeBindingHashf5a014435647efb7aa059abb1ee84a60c347641399b2eef012c88c2a83d27550;
runtimeBindingHash05f8dab7097dd4a42d010b609d88b9be634d26b302222c67169a68377dd853d1.
frozenPland1baf924e456bd5d2ce5a9bd3b8cb6f12ea80016feb76cde3c1556eec497a142,
preparedNativePlanff06ec1afc5da65dc6b6c64edb9ab9ec87926f4a9de7aec355b69b96c4cd8653.

Contatori:116EngineGET/8Enginewrite/1imageLoad/12ownerConfigurationReads/2readinessGET,
0quarantineStop/0serviceCredentialFileRead/0adminGET/0adminPUT.
Le12ownerReads includono le2originali;9file/120945byte del reader restano storia separata consumata.
Tre operazioni firma con chiavi installate esistenti; nessuna nuova chiave.
Un solo nuovoMCPmanager, vecchioMCP trattenuto fermo; sei originali+READ invariati,
RegistryWorkerTouched=false.0GatewayRequests/SQLbyrepair/migrazioni/grant/attivazioni/acquisizioni.
BootstrapOAuth/catalogomanifest del normale MCP MAY_HAVE_OCCURRED, numero richieste non osservato;
non confondere con OAuthrequestsByRepair=0.
mountSourceContentIdentityProven=false: non affermare identità contenuti montati o fullOCI.
applicationE2EProven=false/releaseAcceptance=false; nessun 502/403 chiuso dalla sola readiness.

Directory delivery /home/oufadmin/ouf-mcp-host-policy-apply-delivery.EGCAfPOS,
logruntime /usr/local/lib/ouf-mcp-diagnostic-update-b8bae202a3222f01/operator.log,
deliverylog /home/oufadmin/ouf-mcp-host-policy-apply-delivery.EGCAfPOS/bootstrap.log.
Scope **/etc/ouf/deploy-snapshots/mcp-diagnostic-update-ff06ec1afc5da65d-v1/retained-host-policy-continuation-v1 CONSUMATO**.
Codeb9697462f293d7481c9fd7cdd84c549b70214eda/delivery11178c1ff09dd6eff18c909473a72bddd9635369.
NON rilanciare, cancellare claim o cambiarechild; nessun rollback/oldrestart.
Leggere integralmente [handoff esecuzione ormai STORICA](OUF_MCP_ZERO_MEMORY_CONTINUATION_20261026.md)
e tutti suoi riferimenti (STOP Memory0/reader/inputcapture/preparazione/installazioni/pubblicazioni/PET).
Tutti vecchi scope/delivery/recovery/reader/policyproposal restano consumati. Nessun nuovo comandoVPS.

## Letture governate dopo installazione — account ouf-admin

[Prova minimizzata](../../evidence/acquisition-post-mcp-auth-context-20261026.json).
Accountlink_6aafef96b4148191b767e9af7b756a07,subjectb93d8cf6-cd14-4ee6-91d7-84cd76c4f500,tenantouf-lab.
authorization.permissions.read:
- ROLES:4ruoli/4assegnazioni; due ruoli READ esatti delle run e loro vecchie assegnazioni ancora presenti;
- GRANTSsubject/limit200:94configuredgrant,nextAfternull,policy **ouf-lab-authorization:50**,
  hashsha256:067cb58da4e6f0278b5a81f4858646bb50222bb48e9cf63d3141621e9cfaf05f;
- i12grant6READ×2run finiscono tutti a **2026-10-26T08:24:50Z =09:24:50Europe/Rome(CET)**: SCADUTI.
  Historicalingestion.run.read di lungo termine non sostituisce i5altri contributi mancanti.
Sono CONFIGURED_GRANTS_NOT_EFFECTIVE_PERMISSIONS; nessuna provaALLOWeffettivo/cachebundlelocale/scopesOAuth.

Toolmetadata della sessione incompleta: permissions.read omette link_id, ma router lo richiede.
Prima chiamata senza link_id respinta dal client; seconda ROLES con filtri subjectId/limit respinta
dallo schema oneOf PRIMA della capability valida. Il sorgente pinned9a internal/manifest/capabilities.json
vieta subjectId/limit/after/policyRef su ROLES eCAPABILITIES; usare solo view+link_id per questi.
Correzione dei parametri non è retry di un diniego autorizzativo. SuccessoROLES effettivo soltanto dopo contratto corretto.
GRANTS richiede selettore nominale, usa subjectId+limit200+viewGRANTS+link_id.

Una prima e SOLA viewCAPABILITIES (schema nuovo supportato dal sorgente9a) restituisce
toolisError/INVALID_ARGUMENT con oggetto problema Status400 e campi Code/Title/Detail vuoti.
Nessun retry; origine400 non determinata, non attribuirla arbitrariamente a owner/Gateway/cache.
Non dimostra assenza dei descrittori pubblicati49/50 e non rende inutilizzabili ROLES/GRANTS.
Non aggirare conSQL/auditprivato/token/filemounted o altri account.
L’attuale metadata catalogo non include CAPABILITIES: distinguere metadata client da manifest effettivamente distribuito.

**ZERO chiamate acquisition dopo l’APPLY. ZERO nuove proposal/grant/rinnovi.**
Le due vecchie negazioni Ingestion/UDP sulla runbb2... restano permanenti e non ritentate,
la runa320... non letta da quei tentativi. Nuovo motivoDENY/versione effettiva del guard non ancora osservati:
non chiamare risolta la causa vecchia o inferireSCOPE_MISSING daCI.
Non richiedere all’owner una lista scope non esposta. Nessun token/secret/logcompleto.

## Passo successivo concreto, soggetto a nuovo mandato HUMAN

L’owner ha vietato rinnovi/proposte automatici. Non creare una nuova proposta solo perché l’installazione è riuscita.
È preparato SOLO [un piano di review non inviato](../../evidence/acquisition-read-next-human-review-plan-20261026.json):
4ruoli e4assegnazioni attuali preservati, incluse le2scadute senza modificarne date o contatori;
aggiunta proposta di2nuove assegnazioni nominali aouf-admin sugli STESSI2ruoli/runesatte,
durata massima2ore, tempi assoluti freschi solo dopo nuovo mandato esplicito.
6READ perrun: ingestion.run.read/ingestion.contract.read/ingestion.lineage.read/
urban.object.read/lineage.object.read/lineage.property.read.
Vincoli invariati sourceRefteatri-csv-6609b245/jobRefesatto/moduleINGESTIONoUDP,
TENANT_OPERATIONAL/labelsANONYMOUS-OPEN, nessunwildcard/allargamentoadmin.
Nessuna proposal creata, nessun grant emesso. Il piano non ha authority e non è una reviewTHS giàaperta.

Dopo nuovo mandato per la proposta: rileggere ROLES/GRANTSfreschi, preservare catalogointero e vecchiassegnazioni,
preparare UNA nuova proposta nominale e lasciare pubblicazione alla decisione HUMAN nella THS.
Mai agente che conferma/APPROVO/approva nellaTHS. Se ambiguo leggereSTESSOID, mai riproporre.
Non sostituire date vecchie o resetbudget. Fonte/scheduler/acquisizioni intatti.
Solo dopo PUBLISHED e provegrants/vincoli/validità correnti, nuovo contesto finito per4lettureiniziali
(2tool×2run) e paginazioneownerbounded entro nuovo mandato; primoDENYstop, nessun retry.
Non invocare acquisition solo per ottenere diagnostica sottogrant scaduti.

Due run ESISTENTI:
bb2e2af4-9c0a-49ea-8ad9-a947987c1472 e a3208f2f-ebfd-415d-bddc-79ab05dea78f,
sourceIdteatri-csv-6609b245,accountouf-admin.
Tool ouf.ingestion.acquisition.read e urban.acquisition.read, limit100,soli cursorowner,<=1MiB12s.
ACKdurabile/watermark/intake/materializzazione/provenienzaproprietà sono fatti distinti;
correlare contrattipinned/sourcepublication/13Teatri/11–19properties/union20IRI e8Cinema preservati entro baseline reali.
HTTP200GETRegistryoriginale giàprovato; non inventare nuove502/403 o baseline byteequality.
E2E/G4/F5/F6 OPEN,tecnico8/8funzionale4/6; Supervisor SOLOdopoE2E.
Nessunaterzaacquisizione/attivazione/reset/Registryrestart/reinstall/merge/releaseacceptance.
