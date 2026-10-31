> Aggiornamento successivo: diagnostica owner qualificata in CI, non installata; nuovo passo di sola cattura metadati. Leggere OUF_M1_REDACTION_DIAGNOSTICS_READY_20261026.md. Questa evidenza live rimane valida e non va ripetuta.

# OUF — dopo riconnessione: owner raggiunti, dettagli REDACTED — 26 ottobre 2026

## Punto esatto

Owner conferma OUF - MCP Server riconnesso con ouf-admin dopo correzione IAM (39scope=33precedenti+6READDefault).
Ora 2026-10-26T13:05:12Z, prima di scadenza51 14:14:26Z/15:14:26CET.
Eseguite DUE chiamate distinte sulla SOLA run bb2e2af4-9c0a-49ea-8ad9-a947987c1472, source teatri-csv-6609b245, limit100, link_6aafef96b4148191b767e9af7b756a07, accountouf-admin.
Entrambe isError=false e schema owner, authorizationDecisionRef51.
[Receipt complete](../../evidence/acquisition-post-oauth-owner-redaction-20261026.json).

Ingestion:
- runSUCCEEDED, bundle2/checksum7cebf0..., publication dffa2a5e-740b-4e3d-95a0-14c841940b72, managed hash08b206..., snapshot_matches_run=true/read_only_snapshot=true;
- attempts13/failed0/lineage13/handoffs13/unresolvedQuarantine0;
- partitiondefaultSUCCEEDED, watermark presente e appartenente alla run, sequenza13, ACKpresente, watermarkmatchesCandidate/notBeforeAck/completeAckPrefix TUTTItrue;
- items0, partialtrue, authorizationREDACTED, nextLineageIdnull, partitionTruncatedfalse.
UDP: items0, partialtrue, authorizationREDACTED, nextHandoffIdnull, ingestionAckProvenfalse.

Il vecchio SCOPE_MISSING MCP_PRE_ADMISSION è superato PER QUESTE CHIAMATE. Dal codice pinned, entrambe le requireOPEN iniziali/finali controllano tutte3capabilityowner; non solo preflightMCP. Questo è successo applicativo dei guardbase, non introspezioneJWT né autorizzazione di tutti dati. Nessun nuovo502/403owner ricevuto.
GRANTSletto una volta restituisce51/hash449d..., configurednotEffective; i nuovi READ hanno labelallowlistOPEN+ANONYMOUS e run/source/module/detail vincolati. Nessuna modifica/grantnuovo.

## Diagnosi source-level precisa, limiti live

Ingestion pinned3ab998feb55ba0681d30635cdac35fac0f78e5db:
src/main/java/it/comune/trieste/ouf/ingestion/AcquisitionEvidenceService.java.
REDACTED viene impostato SOLO da labelsVisible=false sui handoff memorizzati.
Cause ammesse dal codice: label list assente/vuota/struttura o labelId non valido/label sconosciuta, oppure decide dei treREAD per label nonALLOW/TENANT_OPERATIONAL.
Non c'è un erroreMCP scopes ancora osservato: requireOPEN con stesse3capability/resourceattrs passa e rimane solo il controllo delle label effettive.
PublishedExecutionMapper trasforma le dataAccessPolicies pubblicate in labelId, CanonicalRecordPipeline conserva le label nelhandoff; ciò non prova quali label abbia lo snapshot VPS esatto.
FixtureCI usaOPEN; non attesta le label delle runreali.
Non dichiarare RESTRICTED certo: vecchi grantmaterializationRESTRICTED riguardano storia distinta e non provano questa classificazione.

UDP pinnedb6a9f36a4f98ae8a2aab3bd055e5703bd84a8fb7:
src/main/java/it/comune/trieste/ouf/udp/AcquisitionEvidenceService.java.
REDACTED può essere tenantRAW/object mancante o divergente, labelrow, guardobject o property. items0 NONprova assenzaintake/materializzazione né suaquarantena.
Nessunactual label/denialReason/tenantrowprivato esposto dai tool attuali.
Niente raw SQL/token/log/API alternativi per aggirare redazione.

## Arresto e prossimo passo governato

ZERO retry/cursor, ZEROsecondarun, nessuna prova ottenuta per runa3208f2f-ebfd-415d-bddc-79ab05dea78f in questa continuazione.
Dopo la redazione uniforme non chiamare la seconda run per trovare un percorso meno protetto.
Non chiedere un'altra riconnessione, non aggiungere scope olabelgrant alla cieca.
Serve diagnosi owner MINIMIZZATA che distingua metadata label nonvalido e diniego perlabel per Ingestion, poi tenant/label/object/property perUDP senza rilasciare righe/valori nascosti.
I tool correnti non espongono questa distinzione. Eventuale nuova diagnostica richiede codice owner qualificato e piano runtime concreto con reviewHUMAN; non distribuire patch, invocare vecchieAPPLY o leggereDBprivati sulla base di questo handoff. Solo dopo causa provata preparare la correzione strettamente necessaria; eventuale allargamento READ richiede nuovo mandatoHUMAN specifico.
Policy51 scade15:14:26CET26ottobre; nessuna estensione/proposta automatica. Conservare run/budget/scope originali.

Bindingrun/pub/filehash e ACKprefix/watermark della prima run ora positivi, ma itemlineage/contracts/properties/13ID/materializzazione/provenienza/20IRI/8Cinema restano nonchiudibili.
E2E/G4/F5/F6 OPEN,Supervisor DOPO E2E. Nessuna terzaacquisizione/attivazione/reset/Registryrestart/reinstall/merge/releaseacceptance.
Tutti scopeVPS capture/prep/APPLY/recovery/reader precedenti consumati, nessun nuovo comandoVPS.
Leggere [handoffIAMcompletato](OUF_IAM_READ_SCOPES_COMPLETED_20261026.md) e [storia51](OUF_POLICY51_SCOPE_MISSING_HANDOFF_20261026.md) integralmente con riferimenti.
