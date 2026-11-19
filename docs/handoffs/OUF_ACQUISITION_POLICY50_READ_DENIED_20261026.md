# SUPERATO nel NEXT — diagnosi codice qualificata, nuova cattura READ pronta

Le due negazioni e policy50 sotto restano prove storiche valide, senza retry. La richiesta all'owner di cercare una listaOAuth non esposta è superata. NEXT: [diagnostica MCP e sola cattura corrente](OUF_MCP_DENIAL_DIAGNOSTICS_AND_READONLY_CAPTURE_20261026.md), nessun APPLY o rilancio precedente.

# Policy50 pubblicata HUMAN; prime letture governate negate — 26 ottobre 2026

## Risultati, nell'ordine delle autorità

[Pubblicazione descrittori VPS](../../evidence/acquisition-existing-descriptors-published-target-20261026.json) resta positiva: policy49/106grantpreservati/Exit0/DeliveryExit0, scopeeditableCONSUMATO. Non rilanciare alcun comando VPS precedente.

L'owner ha confermato nella THS la proposta64655de1-bf1e-4acd-aada-d2f27154539a.
authorization.proposal.read STESSOID ora conferma revision1/statePUBLISHED/finalPolicyRefouf-lab-authorization:50.
Policy50/hashsha256:067cb58da4e6f0278b5a81f4858646bb50222bb48e9cf63d3141621e9cfaf05f.
[Receipt delle verifiche e tentativi](../../evidence/acquisition-read-policy50-denied-target-20261026.json).
La [receiptPENDING precedente](../../evidence/acquisition-governed-read-grants-proposal-20261026.json) è STORICA, non nuova review da approvare. Proposta consumata/pubblicata: non riproporla né usare vecchio link per ulteriori decisioni.

ROLES correnti:4ruoli/4assegnazioni, originali2ruoli/34permissionadmin/2assegnazioni preservati ESATTAMENTE.
GRANTSsubjectouf-admin:94/nextAfter null, tutti82precedenti preservati e12nuovi grant verificati, una coppia per ciascuna6READ×2runesatte, nessunaltrograntnuovo rilevato nella pagina completa subject.
Nessuna inferenza sull'ALLOWeffettivo dai soli configuredgrants.
Validità2026-10-26T06:24:50Z→08:24:50Z = **07:24:50→09:24:50CET Europe/Rome(+01)**.
Grantlimitati a tenantouf-lab/sourceRefteatri-csv-6609b245/jobRefesatto/moduleINGESTIONoUDP/TENANT_OPERATIONAL/solelabelANONYMOUS-OPEN, nessun wildcard/ampliamentoadmin.
SeiID ingestion.run.read,ingestion.contract.read,ingestion.lineage.read,urban.object.read,lineage.object.read,lineage.property.read.
Nessunreset/rinnovoautomatico/nuovaacquisizione/attivazione/budgetfonte. Solo grantHUMAN approvati, nonagentapproval.

## Due letture distinte, una sola invocazione ciascuna, nessun retry

Account SOLOouf-admin/link_6aafef96b4148191b767e9af7b756a07.
Fonte teatri-csv-6609b245, runbb2e2af4-9c0a-49ea-8ad9-a947987c1472,limit100.
1. ouf.ingestion.acquisition.read: isErrortrue, content{"code":"authorization denied","retryable":false}, connectorerror_codeINVALID_ARGUMENT.
2. urban.acquisition.read: identico errore nonritentabile.

Sono due tool/owner distinti, non due tentativi dello stesso tool. Entrambi permanenti: NON ripeterli automaticamente.
La prima Ingestion a policy50 avviene DOPO nuovi grantHUMANeffettivamentePUBLISHED, non replay cieco del precedente diniego a policy48. Nessun'altra richiesta di lettura acquisizioni dopo i due dinieghi.
Runa3208f2f-ebfd-415d-bddc-79ab05dea78f NON invocata in questo segmento.
Nessun record di acquisizione ricevuto, nessun ACK/watermark/intake/materializzazione/provenance provati da queste risposte.
Nessun HTTPstatus owner esposto: non chiamarli403owner o nuova prova502/403, non inferire invio all'owner o consumo dei suoi contatori.
InvocazioniMCP osservabili=2, conteggiwireinterni non osservati. Nessun Engine/SQL/credenzialefile/token letto.

## Diagnosi di codice, distinta dalle prove live

MCP DEPLOYEDpinnedbd60ccd092b51557b280e533c8db6b3f98842f9e primari riletti:
- internal/kernel/acquisition_read.go: preflight scelto ingestion.lineage.read/lineage.object.read con contestooperational/run/module/source/job/OPEN/TENANT_OPERATIONAL, owner verifica tuttepermission contributive;
- internal/kernel/kernel.go: service.Call restituisce errorstring senza decisioncode/classificazione, quindi questo errore non distingue il guard;
- internal/orchestration/service.go: ErrUnauthorized("authorization denied") per delega assente o rifiutoAuthlocale prima diAdmission/dispatch. Il ramo specialepublicStatus non riguarda acquisition;
- internal/authorization/cache.go: actor/capabilitydeclared/requiredscope/grantconstraints su cachelocale, non GET sincrona di ACTIVE per ogni richiesta;
- cmd/ouf-mcp/main.go: refreshbackground(default30s/maxstaleness300s), valori CONFIGURATIlive e bundlecaricato NON osservati qui;
- docs/INSTALLAZIONE_KEYCLOAK_CHATGPT.md: assegnazione scopeIAM, scope richiesti dalclient egrantOUF sono distinti; dopo modifiche scope serve autenticazionenuova normale. Runbooksettembre è STORICO, non prova configurazioneclient corrente o token esistente;
- docs/OPERATIONAL_AUDIT_CAPTURE.md: private audit/security evidence NON autorizzata a essere esposta da genericoperationalREAD. Non leggereSQL/rawlog come bypass del diniego.

**SCOPE_MISSING è un'ipotesi, NON causa live provata.** Altre possibilità restano bundlelocale nonattuale o guarddelegazione. Non affermare che i grant siano errati, allargarli, aspettareuntempo e ritentare, né riavviare/reset cache/Registry per aggirare.
Un successo ROLES/GRANTS passa su percorsoowneramministrativo, non dimostra quale bundle/scopes abbia valutato il preflight acquisitionMCP.
Nessuna capability esposta offre introspezionescope/decisioncode correnti. PluginManagementget_app_permissions escludeOAuth/adminscopes: non usarlo come prova o per modificare queste impostazioni.
Token/refreshbearer rimangono privati e non vanno richiesti o copiati.

## NEXT concreto senza replay

Occorre acquisire un dato di connessione corrente: **elenco dei soli nomi degli ambiti OAuth configurati/richiesti nel connettore OUF - MCPServer per ouf-admin**, non token/password/secret.
Confrontare almeno ingestion.run.read/ingestion.contract.read/ingestion.lineage.read/urban.object.read/lineage.object.read/lineage.property.read.
Questo dato non è direttamente esposto agli strumenti della sessione: va letto dalla configurazione della connessione, senza cambiare account o client.
Se lo scope manca, preparare la minima correzione specifica nel bindingIAM/client/consensoHUMAN preservando tutto il resto; non inventare liveclientconfig o assegnare scopeadmin per aggirare.
Una eventuale normale riconnessioneHUMAN deve essere esplicita e documentata con nuovo contesto/scopes, NON reset di budget o replayautomatico del diniego.
Se tutti i6scope sono già configurati, distinguere configurazione da token effettivo e leggere evidenza governata owner del guard/cache prima di proporre effetti; nessun audit/SQL/rawlogbypass.
Solo dopo provato cambiamento del contesto autorizzativo considerare una nuova lettura bounded specifica; preservare entrambe le negazioni attuali e non definirle transitorie.

Una volta ottenute letture positive correlare2run/contratti/CSV/publication/ACK/watermark/UDPintake/materialization/propertyprovenance/13identità/11–19property/unione20, preservare8Cinema nei limiti giàdocumentati. Non creare terzaacquisizione.
E2E/G4/F5/F6 OPEN, tecnico8/8funzionale4/6; Supervisor solo dopoE2E. Nessun merge/releaseacceptance/Registryrestart/reinstall/attivazione/reset.

Leggere prima [handoffpolicy49/proposta ora pubblicata](OUF_ACQUISITION_DESCRIPTORS_PUBLISHED_PENDING_READ_GRANTS_20261026.md) e riferimentiintegrali ai precedenti, inclusi baselinePEToriginali. Nessun comandoVPS nuovo consegnato a questo checkpoint.
