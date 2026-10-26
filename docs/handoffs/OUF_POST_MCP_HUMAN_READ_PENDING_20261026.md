> AGGIORNAMENTO: proposta c1908145 ora PUBLISHED/rev1/policy51. Primo READIngestion ha restituito SCOPE_MISSING/MCP_PRE_ADMISSION/versione51, nessun retry. Leggere integralmente [il nuovo handoff](OUF_POLICY51_SCOPE_MISSING_HANDOFF_20261026.md). Linkreview sotto consumato, NON riproporre.

# OUF — nuova proposta HUMAN READ PENDING dopo installazione MCP — 26 ottobre 2026

## Punto esatto e approvazione ancora da ricevere

L’operatore ha risposto **autorizzo** al piano di nuova finestra READ di due ore sulle due run esistenti.
Questo autorizza la preparazione della proposta; NON è una decisione THS o concessione di permessi.

Creata UNA sola proposal con accountouf-admin/link_6aafef96b4148191b767e9af7b756a07:
**c1908145-5aa5-4dc4-a2fb-e8bf7ba5daf5**, revision0, **PENDING**, finalPolicyRef=null.
authorization.proposal.read dello STESSOID conferma PENDING/rev0.
[Receipt e preservazione](../../evidence/acquisition-post-mcp-human-read-proposal-20261026.json).
THSreale owner:
**https://api.ouf-lab.it/trusted-human/authorization/?proposal=c1908145-5aa5-4dc4-a2fb-e8bf7ba5daf5**.
Scadenza review **2026-10-26T12:29:32.817993Z =13:29:32Europe/Rome(CET)**.
FinestraREAD proposta **2026-10-26T12:14:26Z→14:14:26Z =13:14:26→15:14:26Europe/Rome(CET)**.
Se review scaduta/rifiutata/ambigua: conservare questoID/prove, nessuna nuova proposta o estensione automatica.

Decisione e pubblicazione SOLO HUMAN diretto nellaTHS conouf-admin; agente NON conferma né naviga per approvare.
Una fraseautorizzo nella chat non sostituisce questa approvazione governata.
Nessuna reviewTHS approvata ricevuta, nessun grant nuovo o lettura acquisizioni eseguiti in questo segmento.

## Contesto fresco e contenuto ESATTO della proposta

Prima della mutazione: authorization.permissions.read ROLES(view+link_id) e
GRANTS(viewGRANTS/subjectIdb93d8cf6-cd14-4ee6-91d7-84cd76c4f500/limit200/link_id).
Policy50/hashsha256:067cb58da4e6f0278b5a81f4858646bb50222bb48e9cf63d3141621e9cfaf05f,
94configuredgrant/nextAfternull,4ruoli/4assegnazioni, come piano approvato.
Sono configuredgrants, NON effectivepermissions/bundlelocale/scopesOAuth.
Nessuna ripetizione diCAPABILITIES400 o delle vecchie acquisitionREAD negate.

REPLACE_ROLES preserva INTEGRALMENTE i4ruoli e le4assegnazioni precedenti,
incluse le2READ scadute con dateoriginali inalterate. Nessun ruolo/permission admin aggiunto o rimosso.
Aggiunge soltanto2NUOVE assegnazioni nominali, non modifica le vecchie scadenze:
- teatri-e2e-read-bb2e2af4-20261026-post-mcp-9a374dd0
  sul ruolo teatri-e2e-read-bb2e2af4-20261026;
- teatri-e2e-read-a3208f2f-20261026-post-mcp-9a374dd0
  sul ruolo teatri-e2e-read-a3208f2f-20261026.
Subjectouf-admin b93d8cf6-cd14-4ee6-91d7-84cd76c4f500,externalRoleRefnull,tenantouf-lab.
Durata esatta7200s, non reset/rinnovo di vecchi scope o dei budgetfonte.

Ogni ruolo conserva6READ:
ingestion.run.read/ingestion.contract.read/ingestion.lineage.read,
urban.object.read/lineage.object.read/lineage.property.read.
Vincoli sourceRefteatri-csv-6609b245/jobRefesatto/moduloINGESTIONoUDP,
detailLevelTENANT_OPERATIONAL e allowedDetailLevels[TENANT_OPERATIONAL],
allowedDataLabels[ANONYMOUS,OPEN], resourceType/idnull per owner object/property checks,
nessun wildcard, nientepermission sufonti/attivazioni/esecuzioni/acquisizioni.
Il motivo esplicito della proposta dichiara0acquisizioni/attivazioni/migrazioni/reset/budgetsourcechange.

Hash canonici: baselineCatalogue a8949e89cd30f81950eaa55d0ceb1113fb4ee041e8551f27d54f735a5432f4ad;
proposedCatalogue270fbdf04ee7d16ecad14d0414fa6e0f665e35e19546474321cd05df0925db67;
rolesimmutati57916160d6e17461d12757a719531c5234ad95f357aa490287c1af784984f435;
4assignoriginalid4b8615c9349f9a4cfc867e70b08ca0334d481e366544896c2858ce39e21565f.
Payload completo delle nuoveassegnazioni/2ruoli nell’evidence; il confronto è stato eseguito prima dell’UNICA mutazione.

## NEXT dopo decisione HUMAN

1. Leggere authorization.proposal.read STESSOIDc1908145..., senza ricreare proposta.
2. Solo se PUBLISHED/finalPolicyRef valorizzato: ROLES eGRANTSsubject freschi, verificare preservazione dei4ruoli/
   4vecchieassegnazioni e nuove2/validità/vincoli. Nessuna inferenza ALLOW dai configuredgrants.
   Se pubblicazione ha effetti differenti o grant mancanti: STOP/prove, nonautocompensare.
3. Quattro prime letture bounded,2tool×2run esistenti, soltanto entro nuovo mandato e finestra effettiva:
   ouf.ingestion.acquisition.read e urban.acquisition.read, sourceIdteatri-csv-6609b245,
   runbb2e2af4-9c0a-49ea-8ad9-a947987c1472 e a3208f2f-ebfd-415d-bddc-79ab05dea78f,
   accountouf-admin/link_6aafef96b4148191b767e9af7b756a07,limit100.
   Solo cursorowner per pagine successive, <=1MiB/12s; primoDENYstop e nessun retry.
   MCP9a ora può proiettare motivo/versione del guard, ma non è ancora stato osservato un nuovo esitoREAD.
4. Correlare contratti/publication/ACKdurabile/watermark/intake/materializzazione/provenienzaproprietà,
   13Teatri/11–19properties/union20IRI/8Cinema preservati nei limiti delle baseline documentate.
   Nessuna terzaacquisizione; non confondere ACK/intake/materializzazione.
5. Solo dopoE2E completo passareSupervisor. E2E/G4/F5/F6 ancora OPEN,tecnico8/8funzionale4/6.

Toolmetadata imperfetta: permissions.read/propose omettono link_id nella firmaunion,
ma router richiede esplicitamente accountlink; passarlo sempre.
ROLES eCAPABILITIES vietano subjectId/limit/after/policyRef; solo view+link_id.
CAPABILITIES ha giàdato400 nel segmento precedente: nonritentarlo come introspezione/tokenbypass.
Per propose usare operationREPLACE_ROLES+reason+roleCatalogue completo+link_id;
nessuna confirmation tool o authorityruntime usata per pubblicaregrants.

## Installazione positiva da NON ripetere

[Handoff precedente INTEGRALE](OUF_MCP_INSTALLED_NEXT_HUMAN_READ_20261026.md)
e tutti suoi riferimenti restano vincolanti.
MCPsource9a374dd07745f059de3ad39757c68f02db6d29c3/nativeID9a1af5 installati:
MCP_DIAGNOSTIC_UPDATE_INSTALLED_E2E_NOT_ACCEPTED/complete/readiness/Exit0/DeliveryExit0.
Review53baa1e1be6b600da78f5f4915a21e19e6e553b0f610bc66080fd6bf3a4af86e,
authoritye2d940ff16896bae706efe9acdf3cf1b5cabc79aa36c0c6260b91294ec564be6;
116GET/8write/1import/12ownerConfig(incl2originali)/2health,3firme,1MCPmanager,
vecchio fermo trattenuto,6componentiinvariati/Registryfalse,0Gateway/SQL/migrazioni/grant/attivazioni/acquisizioni.
Contenuti filemontati non attestati, normaleOAuth MAY/countnotobserved, E2E/releasefalse.
Tutti scope/capture/prep/APPLY/recovery/reader/proposte vecchie consumati; NONrilanciare/comandinuoviVPS.
Policy50READvecchie scadute09:24:50CET non sono la nuova reviewPENDING e non autorizzano letture.
Nessunmerge/releaseacceptance/Registryrestart/reinstall/nuovaattivazione/reset/bypassautorizzazioni.
