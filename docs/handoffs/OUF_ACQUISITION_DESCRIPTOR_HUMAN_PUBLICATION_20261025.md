# Cinque descrittori mancanti: pubblicazione amministrativa HUMAN — 25 ottobre2026

## Risultato VPS acquisito, scope consumati

[Evidenza target](../../evidence/acquisition-descriptor-read-observed-target-20261025.json): DESCRIPTORS_OBSERVED_NO_AUTHORITY/complete=true/Exit0/ContinuationExit0. Policyouf-lab-authorization:48/hash6209fe7a832a4b92fcd543304a5480edb85f6f66dfe8476245075509e2c7f46b; fullresponsehash5de0b80b176ab6cbcb4b0e933d7408558731610c50521c466736d7464578ef70.153497byte/1IAMGET/5IAMPOST/3ownerGET; zero scrittureamministrative/Engine/filecredenziale/attivazioni/acquisizioni. Accountouf-admin selezionato/verificato dal codice pinned e ownerAPI.

ingestion.run.read è già registrato, ACTIVE, READ/requiredScopeugualeID/HUMAN. Mancano da ENTRAMBI i cataloghi:
- ingestion.contract.read — owneringestion
- ingestion.lineage.read — owneringestion
- urban.object.read — ownerudp
- lineage.object.read — ownerudp
- lineage.property.read — ownerudp

Log /home/oufadmin/ouf-acquisition-descriptor-read-delivery.XdyYVHv1/permission-mode-v1/operator.log e bootstrap.log. Il primo JSON della riparazionepermessi non è stato incollato: completamento inferito dal flusso pinned/ContinuationExit0, non rilettura indipendente della journalroot. Diagnostico e permission-mode-v1 sono CONSUMATI. NON ripetere [precedente continuazione](OUF_ACQUISITION_DESCRIPTOR_PUBLIC_MODE_STOP_20261025.md) o lettore, riaprire claim, copiare/cancellare directory o riusare sessioni/token esauriti.

ROLES riletta DOPO il risultato con accountouf-admin:2ruoli/admin34permission/2assegnazioni invariati. Registro sorgente sempreACTIVE e vecchi risultati installazione/502/403/GET200 conservati. Nessuna nuova authority/grant/accettazione.

## Azione successiva concreta

Nuovo controller 3f0b407d01a34967e03e02ecc5bf441963704e7c, SHA2561cbb40dd80d9e258d55de530096fb139f7ae193df1a62c912ea24509f43ca284; wrapper4ccff5b125e8fc9cb4ae2785807bb9677ba2bdc8, SHA256810fac40f995797c50d9b6122d65b052070f9e1069bfacffd322db7b028fabbc. [Qualifica](../../evidence/acquisition-descriptor-publication-qualified-20261025.json).

Usa l'API amministrativa HUMAN ESISTENTE, non nuovi tool di conferma o header di autorità simulati. Login device ordinario del SOLOouf-admin/clientouf-human-admin e bearer in memoria, verificato dall'owner su ciascuna richiesta. Riusa soltanto la funzione login del codice PUBBLICO già installato d2e8098/hash062b..., dopo verifica rootowner/mode0444/ancestry/hash; NON esegue il vecchio main né legge vecchi scope/token/journal. Nessun filecredenziale, chiavefirma, Engine, SQL, IAMadmin o login dal cloud.

Preflight READ fresco ACTIVE+registrazioni+ACTIVE, vincolato esattamente a48/hash6209 e fullsnapshot5de. Qualsiasi drift di ACTIVE STOP prima delle mutazioni. Eventuali registrazioni già presenti sono ammesse SOLO se identiche nel contenuto/owner, non riscritte; conflitti STOP. Piena policy/grant nella reviewprivata0600, mai in output pubblico. Candidate49 aggiunge ESCLUSIVAMENTE i5descrittori READ, requiredScopeugualeID, allowedActorsHUMAN; mantiene tutte le capability e TUTTI i grant preesistenti esattamente al livello JSON, compresi DENY/scaduti/altri tenant. Nessun cambio a ruoli/assegnazioni/superadmin.

La reviewconcreta mostra5ID/owner/scope/attore, numero grant preservati, baseline/finestra/limiti e hash. Il file review.json è privato ed è controllato per hash/custodia anche prima dei dispatch dopo approvazione. L'operatore approva nel VERO terminale con la riga APPROVO+hash mostrata DAL CONTROLLER, su riga isolata. Nessun hash statico da approvare in chat e nessuna conferma dell'agente. Nessun POST mutante prima dell'approvazione esatta.

Dopo approvazione:
1. Al massimo5registrazioni, riservateCLAIMED/fsync PRIMA di ogni POST e APPLIED solo dopo readback. Nessun tentativo di aggiornare registrazioni esistenti.
2. Nuovo draft49 con tutte le grant/capability vecchie immutate, ETagrevision e readback completo dell'owner.
3. Due previewowner: esattamente5addedCapabilities,0removed,0grantChanges, stesso ownerDraftHash e stessa baseACTIVE. La preview è authoritative=false come da contratto; non è una simulazione IAM o prova di ALLOW.
4. Un solo publish con ETag, poi ACTIVE49 verificata su intere capability/grants. publishedAt dell'owner può differire dal draft; hashfinale osservato senza fingere uguaglianza conpreviewhash. Risultato distingue dichiarazioni, grant e scope.

POST massimi7 (5registrazioni+1draft+1publish), più2previewPOST;160GETowner,5MiB/risposta/32MiB cumulativi. Totale1800s dal nuovo login; review+esecuzione massimo900s e SEMPRE ulteriormente limitate dall'exp token meno15s, senza refresh/rinnovo automatico. IAM1metadataGET/max121POST come funzione login già qualificata. GET esplicitamente transitori(408/429/502/503/504 o timeout/connection) hanno profilo finito8tentativi/stage, backoff5/15/60/300/900s+jitter0–20%, Retry-After rispettato e contatori/reservations persistenti, mai lock condivisi durante pause. Nessun retry di POST o errore permanente/ignoto; risposta mutante persa/ambigua rimane CLAIMED e impone riconciliazione. Nessun rollback automatico o grant/budget/attivazione fonte.

Nuovo scope FISSO /home/oufadmin/ouf-acquisition-descriptor-publication-20261025, esclusivo0700, review/state/result0600, fsyncfile/dir/parent. È una nuova azione HUMAN amministrativa approvabile, non reset/ripresa del diagnostico o di scopefonte consumati. STOP/rifiuto/scadenza/crash consuma il nuovo scope; niente rilancio, nuova directory o rimozione delle prove per aggirare il blocco.

## Qualifica prima della consegna

19testprotocollo locali/CI PASS,0skip, owner/IAM/decisioni di approvazione SINTETICI, parserPTY REALE: grantsinclusiDENY/scaduti/altritenant preservati, APIbody/ETag/preview/hash/comparazionecompleta, registrazioni già identiche adottate, conferma esatta vsfraseaggiunta e noTTY, nessun POSTsenzaapprovazione, derivaACTIVE/reviewmemory/disco, perdita di risposta registrazione/pubblicazione, CLAIMED/no replay,403nonritentato,503GETconbudgetpersistente e scadenza, endpoint fuori scope negati. Push40224066964/job121261613335 ePR40224071597/job121261626270, logdiretti letti.

ConsegnaREALE downloadcodicepinned/checksum/rootcopy e checksumNONroot; umaskroot077 REALE con fchmodFD0444 esplicito e rootdir0555. Wrapper nonTTY si ferma PRIMA di dipendenza/login/scopeprivato: nessun owner/IAM request. Push40224228906/jobs121262089953+121262089966 ePR40224232648/jobs121262100817+121262100630 PASS/logdiretti letti. Nessuna simulazione di approvazione PRODUCTION, nessun nuovo effetto target daCI. CI non prova l'esito dell'API live.

## Comando: PRIMA esecuzione della nuova azione, review nel terminale

Come oufadmin nel terminale VPS interattivo, UNA volta:

```bash
(
  set -Eeuo pipefail
  umask 077
  ouf_publication_bootstrap=$(mktemp -d "$HOME/ouf-descriptor-publication-bootstrap.XXXXXXXX")
  curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --max-redirs 3 --connect-timeout 15 --max-time 60 \
    "https://raw.githubusercontent.com/GioNob/ouf-deploy/4ccff5b125e8fc9cb4ae2785807bb9677ba2bdc8/releases/publish-acquisition-read-descriptors-20261025.sh" \
    -o "$ouf_publication_bootstrap/run.sh"
  printf '%s  %s\n' '810fac40f995797c50d9b6122d65b052070f9e1069bfacffd322db7b028fabbc' "$ouf_publication_bootstrap/run.sh" | sha256sum -c -
  bash "$ouf_publication_bootstrap/run.sh"
)
```

Sudo custodisce soltanto codice PUBBLICO root0444/dir0555 con checksum e fchmodesplicito. Esecuzione Python-I-S-B comeoperatore. Prima appariranno indirizzo/codice IAM: inserirli SOLO nel browser conouf-admin. Poi il terminale mostrerà il percorso della reviewprivata, le5aggiunte e la riga APPROVO con hash esatto. Per approvare, copiare SOLO QUELLA RIGA, senza parole aggiunte. Non incollare token/codiceIAM o review.json in chat.

Atteso SOLO dopo esecuzione positiva: ACQUISITION_READ_DESCRIPTORS_PUBLISHED_GRANTS_UNCHANGED/complete=true/policy49/Exit0/DeliveryExit0, grantpreservati e newReadGrantsGranted0. Riportare JSONfinale, Exit/DeliveryExit e percorsi dei log. STOP/scadenza/rifiuto/connessionepersamutante: conserva scope/journal/review/log e NON rilanciare. La pubblicazione target è ANCORA NON ESEGUITA/RICEVUTA a questo checkpoint.

## Passo seguente e limiti E2E

La pubblicazione dei descrittori NON concede i sei permessi di lettura e NON crea scope OAuth. Scope richiesti dal percorso MCP restano una verifica governata distinta, mcpOAuthScopesVerified=false nel risultato. Non abbassare requiredScope a mcp.connect o sostituire account per superare il gate. Nessuna modifica IAM è inclusa in questa review.

Dopo risultato targetpubblicazione: verificarepolicy49 e rileggereROLES per preservazione; risolvere/verificare governatamente scopeOAuth necessari, poi UNA nuova propostaTHS temporanea per le2run esistenti bb2e2af4-9c0a-49ea-8ad9-a947987c1472 e a3208f2f-ebfd-415d-bddc-79ab05dea78f. HUMANTHS/PUBLISHED prima delle4READ. Proposta precedente AUTH_ROLE_CAPABILITY_INVALID senza receipt e prima IngestionREADnegata retryablefalse non vanno ripetute alla cieca.

Poi correlare contratto/CSV/snapshot/publication/ACK/watermark/13ID/20proprietà/provenance, preservando i limiti delle8Cinema e la sparsità11–19proprietà/Teatro non ancora spiegata. Nessuna terza acquisizione, resetbudget, attivazione, reinstall/restartRegistry, merge o releaseacceptance. E2E/G4/F5/F6OPEN, tecnico8/8funzionale4/6; Supervisor dopoE2E.

Fonti owner consultate integralmente nei tratti pertinenti: Onboarding tree84828f74ac586bae09a78f0fb197b75b1a3d98d1, AuthorizationAdminApi/Service, AuthorizationReviewApi/Service, TrustedWriteProof, PolicyBundle/SDK e r4a_authorization_lifecycle; MCPbd60ccd cache.evaluate/acquisition_read: requiredScope è gateautonomo e richiede grant e attore corretti. Le APIHUMAN verificano il bearer direttamente; nessun token viene inoltrato tramiteMCP.
