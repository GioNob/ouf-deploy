# OUF — IAM browser: tre definizioni READ create, completamento bloccato da revisione automatica — 26 ottobre 2026

## Punto esatto

L’owner ha autorizzato il fallbackbrowser per verificare e correggere gli scopeREAD.
La console https://auth.ouf-lab.it/admin/ richiedeva autenticazione nel realm master.
Prima BrowserAuth: sito Invalid username or password; owner ha spiegato di aver inserito l’account applicativoouf-admin
e ha chiesto esplicitamente di ripetere con credenzialiKeycloak.
Seconda BrowserAuth sicura: accesso riuscito, console mostra utenteIAM **oufadmin**.
Nessuna credenziale/token/secret vista, letta, pubblicata o richiesta inchat; nessun cambio password/account.

[Prova minimizzata](../../evidence/iam-read-scope-definitions-partial-20261026.json).
Browsercloud tab1, binding persistente mcp__cua_repl variabiletab, realmouf, sessione autenticata.
Ultima pagina verificata:
https://auth.ouf-lab.it/admin/master/console/#/ouf/client-scopes/ac96ddab-a6b9-44a7-ae44-853edf64ef03/settings
= **urban.object.read**, salvataggio disabilitato/nessuna modifica pendente.
Tab markHandoff impostato; nessuna richiesta takeover attiva.
All’inizio di una ripresa computeruse leggere cua.rewriteDocumentation come prescrive il tool e riusare il binding se valido.
Non rifare login, estrarre cookie/bearer o automatizzare credenziali con API inferiori.

## Dati LIVE verificati senza segreti

Client **ouf-chatgpt**, UUID **3e64ac3a-eeaa-47bd-94ec-b78040b39e71**,
realmouf, OpenIDConnect/enabled/PKCEonS256, redirectesattoChatGPT
https://chatgpt.com/connector_platform_oauth_redirect.
La sua paginaSessions mostra accountouf-admin (subjectb93d...), comprese sessioni offline con accesso26ottobre.
Non sono stati esportati IP, identificativi sessione o token nelle prove.
Questo prova il client configurato perChatGPT e le sessioni nominali; NON è introspezione del clientID del token
specifico della connessione link_6aafef96b4148191b767e9af7b756a07.
Prima dell’assegnazione il client ha **33scope** incl.dedicated; elenco completo+tipo nell’evidence.
Tutti6READnecessari assenti dalle assegnazioni:
ingestion.run.read/ingestion.contract.read/ingestion.lineage.read/
urban.object.read/lineage.object.read/lineage.property.read.

Popup AddclientScope non ha mutato nulla e mostrava29scope nonassegnati, senza pagine residue.
Solo ingestion.run.read esisteva tra i6, non assegnato al client.
Realm ClientScopes conferma ingestion.run.read UUID023b8792-3762-43e3-8f4f-e85bdad9d1f4,
TypeNone/IncludeInTokenScopeOn/IncludeInOpenIDProviderMetadataOn; non modificato.
Lealtre5definizioni mancavano dal completoinsieme assegnati+disponibili.

## Effetti già avvenuti, NON ripetere

Create e rilette positivamente TRE definizioni persistenti nel realmouf:
- ingestion.contract.read — c3dfdd8a-f088-4639-beb4-0867076e3905
- ingestion.lineage.read — fd654927-b341-416e-9c9d-4ccdf8f65092
- urban.object.read — ac96ddab-a6b9-44a7-ae44-853edf64ef03

Tutte protocolopenid-connect, **TypeNone** (nessuna assegnazioneRealmDefault),
IncludeInTokenScopeOn, IncludeInOpenIDProviderMetadataOn, DisplayOnConsentOn,
descrizione OUF governed READ scope +nomeesatto.
Nessun mapper/rolecreato, nessun altroclient modificato, nessun secret/clientcredential letto.
**ZERO assegnazioni scope al client** ancora inviate.
Non cancellare/ricreare queste definizioni; recuperare i rispettivi ID e verificarle prima di aggiungerealtro.

Il batch successivo che avrebbe creato lineage.object.read e lineage.property.read è stato
**RIFIUTATO dalla revisione automatica**:
“La creazione di due nuovi client scope è una modifica IAM persistente; l’autorizzazione copre la correzione
degli scope del client, ma non specifica chiaramente la creazione di definizioni realm-wide invece
della sola assegnazione al client.”
Nessun aggiramento o ripetizione del batch. Ispezione successiva mostra ancora urban.object.read,
createdReadScopes=3; nessun effetto del batch rifiutato osservato.

## Revisione concreta da autorizzare prima di riprendere

Serve autorizzazione esplicita alla CREAZIONE di definizioni persistenti nel realmouf,
distinta dalla sola assegnazione al client.
Proposta esatta:
1. creare solo **lineage.object.read** e **lineage.property.read**, protocolopenid-connect,
   TypeNone, IncludeInTokenScopeOn, metadataOn; nessunaRealmDefault o privilegioadmin;
2. assegnare come **Default al SOLO clientouf-chatgpt** i6READelencati sopra,
   riusando i4scope giàesistenti (ingestion.run.read +3appena creati);
3. preservare tutte33assegnazioni originali/ruoli/mappers/audience/PKCE/security, senza toccare
   workloadouf-mcp-server o deviceclientouf-human-admin;
4. verificare nelclient esattamente39scope=33precedentiimmutati+6READDefault e flagdiinclusione;
5. normale nuovaautenticazioneHUMAN della connessioneouf-admin, senza bearer/tokeninchat;
6. solo dopo evidenza contesto cambiato e grant51 ancora validi, UNA nuovaREADbounded.
   PrimoDENYstop, nessunretry né estensioneautomatica dei grant.

Questo piano NON è ancora completato. La precedente autorizzazione generica non è stata considerata
sufficiente dalla revisione automatica; non cambiaremezzo/APIpereseguire le stesse creazioni bloccate.
Il browser resta aperto al medesimo stato per continuare dopo consenso esplicito.

È stata acquisita una schermata senza segreti della paginaurban.object.read.
La sincronizzazione del file col workspace non era disponibile dopo5secondi:
non mostrare linkinesistenti o sostenere che lo screenshot sia allegato.

## Contesto applicativo e vincoli immutati

Leggere integralmente [handoffpolicy51SCOPEMISSING](OUF_POLICY51_SCOPE_MISSING_HANDOFF_20261026.md)
e tutti riferimentiprecedenti (proposta51HUMAN/installazioneMCP/Memory0/PET/baseline).
Policy51PUBLISHED/rev1/proposalc1908145-5aa5-4dc4-a2fb-e8bf7ba5daf5,
hashsha256:449d5629097730226841ca73a43c0d8cfa8068be5fcdbabc85e9b749f996ecea.
4ruoli/6assign/106grant,94precedentipreservati+12READconrunesatte,
finestra **13:14:26→15:14:26Europe/Rome26ottobreCET (12:14:26→14:14:26Z)**.
Nessun rinnovo o propostanuova automatici se scade durante IAM.

UNA lettura Ingestion runbb2... sotto51 ha negato:
authorizationPhaseMCP_PRE_ADMISSION/reasonCodeSCOPE_MISSING/evaluatedPolicyVersion51/retryablefalse.
Nessun retry, UDPread osecondarun; ZERO acquisitionREAD dopo questa negazione durantebrowser.
Non confondere definizioniIAM/assegnazioniclient, OAuthscopeemessi, grantOUF ed evidenzeE2E.
Tutto qui è correzioneIAM; NONnuova installazioneMCP/Registry/restart/sorgenteacquisizione.

Solo DUErun esistenti bb2e2af4-9c0a-49ea-8ad9-a947987c1472 e a3208f2f-ebfd-415d-bddc-79ab05dea78f,
sourceIdteatri-csv-6609b245/accountouf-admin,limit100/solicursorowner/<=1MiB12s.
MCPsource9a realmenteinstallato complete/readiness/Exit0/DeliveryExit0, vecchio MCP fermo trattenuto,
6componenti invariati/Registryfalse; scopeAPPLY/prep/capture/recovery/readerconsumati NONrilanciabili.
E2E/G4/F5/F6 OPEN,SupervisorDOPOE2E,tecnico8/8funzionale4/6.
Nienteterzaacquisizione/attivazione/reset/Registryrestart/reinstall/merge/releaseacceptance.
