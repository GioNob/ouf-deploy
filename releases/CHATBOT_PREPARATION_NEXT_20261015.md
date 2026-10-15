# CSV/chatbot — handoff corrente, 15 ottobre 2026

## Readback OSError completato: credenziale pubblicata, grant0

L'operatore ha fornito l'intero output del reader87f2d8e:54 record, END complete=true, unavailableChecks vuoto. Archiviato integralmente in `evidence/chatbot-pregrant-oserror-readback-20261015.json` (allegato SHA25668ae2671e29b07ae1e2f3e56836e86f63e8bc0f6f88ccfe4297c747392c15557). Il processo4a65b9 è spento/not-found/PID0. Stato PAUSED_REQUIRES_RECONCILIATION/OSError. Nessun errno o traceback è conservato nei10 record systemd.

**Non eseguire wrapper o sorgenti di installazione, compreso07a2c4.** La correzione TLS è qualificata ma la continuazione post-credenziale NON è implementata. Il precedente recupero richiedeva credenziale/sessione assenti e non può essere riutilizzato. La prossima azione è solo il probe pubblico sotto.

Evidenze target nuove:
- Credenziale: NEW_CREDENTIAL_CUSTODIED_NOT_RUNTIME_ACCEPTED/version1, iamMutationAttemptConsumed=true, credentialPublished=true. Hash record **a9fa6304781bff2c9a795d16520881401a49124db869de87338f8978251436ae**. La directory credenziale contiene1 elemento, il reader non ne ha letto il contenuto.
- Sessione: NEW_FINITE_SESSION/version0/attemptSlotsConsumed0. Hash **2879325cd95434413f29dc4058d945e16d0bbc71eaf29d44176c705b5ca6ce0c**. Receipt firstGrant assente; output token vuoto; quattro record worker assenti. Il contratto riserva il tentativo prima della POST di grant: questa sessione non è arrivata alla richiesta.
- Continuazione: intent6bdf577601a0b4275b52c2758e7bb5493024682cdea12f1f46a62e8ee75d6dc7; completed assente. Receipt output c5d6d3bc78d65c18127058b8e236246f5cfde87d93ddc5aac5d7f8f6471880a7; retirement3b054f15c49ff43e9de9a6fb5aa642dad8ad23757130af2a9cdd236cb83538d5, QUIESCENCE_OBSERVED. Record originari95749 intatti.
- Stage corrente: intent a654074cc01bf4c702041591907614e1ca22a6ee34ff37b6b0e4abadf084dc53, manifest **0ff3cf4f630709a74c089b4aa75359aa27d62176a9c0975d8f9db90a831b99bf**,10file tutti corrispondenti, zero staging parziali.
- authorization journal80db4295967f18a733adff0c3b5273d1af9af0789bcddbe7b76ac4849907b465/version1; containers/databases/gateway/gatewayRuntime assenti nel nuovo context. APISIX completato resta nel predecessor95749, non è stato reinstallato nel context4a65b9.
- Spazio corrente:352277303296byte disponibili,32668398inode liberi nel filesystem target; /tmp8369836032byte disponibili. Mount scrivibili. Non c'è evidenza corrente di esaurimento; non attribuire OSError a disco/RAM. Footprint capsule108397015040byte,20intake+4signed. Nessuna pulizia effettuata o autorizzata da questo checkpoint.

## Difetto reale riprodotto e corretto, causa VPS ancora da confermare

Il client `iam_admission._Socket.makefile` avvolgeva direttamente SSLSocket in un RawIOBase senza il riferimento nativo creato da socket.makefile. http.client chiude la connessione dopo gli header di una risposta non persistente; il successivo read del body usava quindi il socket già chiuso. Riprodotto prima della correzione con vero TLS loopback/HTTP1.0: **OSError errno9 EBADF,1 discovery GET,0 grant**. Il punto corrisponde alla fascia osservata: prima sessione aperta, prima consume_attempt_slot. Il VPS non ha conservato l'errno, quindi questa è una causa candidata, non ancora una root cause dimostrata sul target.

Correzione sorgente **07a2c46203ea36b0af141cbe3f32f01475d90158**, tree18747c3e1390b617fd5f129c6420679dd0c6e9ca, PR31 draft/unmerged. Il Raw conserva il file nativo SSLSocket.makefile(rb,buffering=0) e lo rilascia alla chiusura del body. Restano deadline complessiva, massimo body, peer/IP, hostname/CA e redirect vietati. Nessuna modifica ai microservizi applicativi, immagini, ruoli o pacchetto. Capsula696912f1db597573baabd5915132e35d4df4872c2c1fb5ea1e67e216768dd7b8/112file; launcherb7fdc162d2a143569bad7ed15aa98d3ddee3b16bcdb21b17126efe433430448d.

Tutti gli8workflow push/PR PASS. Consegnacoordinata38719053215:263test/34suite/zero skip; online IAM38719053168:236test/31suite/zero skip. Installazione completa38719053131 PASS, incluso flusso reale con Connection:close e nuovo caso di errore discovery che conserva credenziale e sessione0. Localmente10testTLS e3closure completi PASS; nuovi casi HTTP1.0/Connection:close, body frammentati, deadline, socket chiusi. Vedi `evidence/chatbot-iam-http-close-qualification-20261015.json`.

## Passo richiesto all'operatore: solo due GET pubbliche

Reader `scripts/read-chatbot-iam-close-20261015.py`, SHA256 **ecd9849a4fd89657c267d2e1b0af7406c37fe19e84a385ad52bb63cb41f2c148**. Verificato localmente con serverTLS reale: il percorso precedente riproduce EBADF, quello con riferimento nativo passa; esattamente2GETdiscovery, nessun token o valore privato stampato. Il lettore rilegge review/authority/bundle del context eff1... e hash credential/session sopra, conferma processo fermo, stat del solo client-secret (nessuna lettura), scadenza della sessione e assenza del primo grant. Poi confronta due GET allo stesso issuer/IP/TLS trust già revisionati: vecchio comportamento e stream corretto. Massimo10secondi ciascuno, nessuna risoluzione DNS/proxy/redirect, nessuna POST, introspezione, credenziale, grant, scrittura o rinnovo di autorità. Riporta HTTPversion/will-close/errno ed esito identità del body senza stampare body o indirizzi.

La prossima risposta deve essere l'output di questo probe; non un nuovo tentativo di installazione. La chat può consegnarlo in memoria con verifica hash prima di sudo, come il reader precedente. Nessun login Keycloak/device/HUMAN necessario per il probe. CSV end-to-end ancora non dimostrato.

## Recupero post-credenziale da implementare dopo il probe

Serve una nuova review esplicita e un nuovo percorso stretto per la sola storia4a65b9 osservata, dopo finestra precedente scaduta/processo spento. Conservare credenziale già pubblicata, vecchia sessione0/scadenze, intent/receipt, source stage95749 e4a65b9, contatori e claim. Non rifare mask/stop, mkdir, image load, APISIX o rotazione. Il codice attuale NON lo fa e non deve essere lanciato sperando che riprenda.

La sessione di300secondi non può essere estesa o sovrascritta: una nuova decisione HUMAN può aprire un budget distinto per lo stesso logical operation/incident, con predecessore hashato e cumulative grant0→massimo1. Record e lock della prima claim restano stabili; un nuovo job/source ID non concede altri grant. Concorrenza/revoca, credenziale mutata, vecchio counter consumato, nuove history di worker/DB/applicazioni o drift nativo devono negare prima degli effetti. L'adozione del secret può leggerlo solo nell'owner corrente autorizzato, per confrontarlo con il record completato; il probe non lo legge. Prima della nuova review, verificare nativamente immagini/APISIX, entrambe le generazioni di source stage e public discovery corretta.

Attenzione al codice `previous_authorization_actions`: oggi visita95749 e chiama observe_pregrant che richiede credential/session assenti; questo ora fallirebbe anche prima di arrivare al context4a65b9. Occorre una prova post-credenziale completa preliminare, legata alla review4a65b9 che già incorpora il proof95749, per distinguere lo storico originario dalla continuazione successiva. Non aggiungere un generico allow_existing_history.

L'osservabilità va completata nel nuovo recupero: l'eccezione corrente conserva solo il tipo; registrare in modo sicuro fase/errno e posizioni del sorgente verificato, senza messaggi/argomenti o secret. Non ripetere una mutazione solo per ottenere un traceback.

## Binding e storia conservati

Il reader è fissato a:
- source **4a65b9326c15d9758ecba1793965617a2a92e43e**;
- context `/etc/ouf/deploy-snapshots/chatbot-file-cohort-signed-eff1b6915816bcfc409b16e1d24b9eb342b1c38e3d6ae80e362ac893c5480d0b`;
- unit `ouf-file-cohort-eff1b6915816bcfc409b16e1d24b9eb3.service`;
- authority **2c35198422227b7db0894ca37ee4d70947ae56fcce813f8d0d1ab9a81c9b5733**;
- plan **0a74c41f04068e11e6fefbb24430fa14a7fcdeaa0c087c76795039141fc6f5df**;
- scadenza1792061873.

Rilegge review/authority/bundle esatti, unità, ricevute originarie e della continuazione, staging corrente ed eventuale parziale, transazione credenziale/sessione/primo grant/worker, metadati delle directory e journal delle fasi successive. Legge il journal di systemd ma stampa solo eventuali errno e posizioni del traceback appartenenti ai sorgenti verificati; non stampa messaggi, codice o argomenti. Rileva spazio/inode/mount e footprint aggregato delle capsule; queste letture correnti non sono da sole prova della causa storica. Non legge file client-secret/token, non esegue sorgenti conservati, non crea lock/journal, non interroga IAM né rinnova autorità. Conserva errori di singoli controlli e prosegue.

Evidenza dell'output operatore: `evidence/chatbot-pregrant-continuation-oserror-20261015.json`. Il nuovo readback non è ancora stato ricevuto. **CSV/chatbot end-to-end resta non dimostrato.** Sorgenti applicativi e pacchetto restano congelati; nessuna modifica target è stata eseguita dall'agent in questa diagnosi.

## Qualificazione e storia precedenti

La revisione4a65b9 aveva superato tutti i9 workflow: consegna262 test/34 suite/zero skip, online IAM234 test/31 suite/zero skip, installazione completa, retirement e HUMAN. Il wrapper resta evidenza della consegna, non un comando da rilanciare dopo il nuovo arresto. PR31 draft/unmerged, source branch `codex/retained-inspection-channel-20261015`, base PR29 `codex/chatbot-mcp-migration-role-20261014` a fdc990136592f0353c2824f4de632a052910a2a0.

## Stato precedente95749 verificato prima della continuazione

- Tutte e cinque le immagini hanno journal VERIFIED e prove native di identità, configurazione e RootFS corrispondenti. Semantic è stato riutilizzato senza load (0 nuovi tentativi); UDP/onboarding/ingestion/MCP hanno ciascuno 1 load consumato.
- APISIX ha tutti gli otto passaggi APPLIED e versione journal19. La generazione attuale è running, non paused e coincide esattamente con il binding finale del journal. Il container precedente è conservato.
- Dieci file del token owner sono stati predisposti: manifest e hash dei file corrispondono alla revisione. La directory token-output esiste, è vuota, root:10001/0750; il root delle credenziali è vuoto, root:root/0700. Il root recovery contiene il solo token-output.
- Prenotazione installazione presente; completamento assente. Prenotazione comando ritiro presente/version0/consumata; nessun replay autorizzato.
- Transazione credenziale, first-gap-session, first-grant e quattro record del worker assenti. Journal applicativi containers/databases/gateway assenti. Nessuna migrazione o sostituzione dei cinque container applicativi è stata raggiunta da questa esecuzione.

Il timer `ouf-policy-token@semantic.timer` è LoadState=masked, UnitFileState=masked, ActiveState=failed, SubState=failed, Result=resources, Job vuoto. Il servizio `ouf-policy-token@semantic.service` è masked/inactive/dead/MainPID0/Job vuoto. Il predicato precedente pretendeva inactive anche per il timer e ha respinto questa condizione terminale. Result=resources **non dimostra** esaurimento RAM/disco; la causa storica specifica del timer resta ignota.

## Binding dell'ultima esecuzione

- Context: `/etc/ouf/deploy-snapshots/chatbot-file-cohort-signed-3f1e74ca1de7962018be8e1d6dd023f685ea208a70aa5e2e2078f92961d7fd4c`.
- Unit: `ouf-file-cohort-3f1e74ca1de7962018be8e1d6dd023f6.service`.
- Review: **6ff5430760e93ab51a26313a18198f094ded12760954fb8a4fcf53db5b3274a0**.
- Authority: **83d70a33518b7bf7c1ca2904d715623294bb8132d5db1373381ab7ea001f2072**.
- Plan: **c2fad152330f9bfa82615fc910e1a213770736e9d4d0408ed0dfdf61dd8242e8**.
- Scadenza finestra: 1792056838, 2026-10-15T09:33:58Z /11:33:58 CEST. Il controllo predecessori richiede scadenza naturale e processo fermo; non rinnova né revoca automaticamente la vecchia autorità.
- Unit osservata not-found/inactive/dead/MainPID0: transient unit raccolta. Result=success non significa riuscita della consegna.

Hash dei record immutabili:
installation ff7de4da5b1503e109891b7f00aaf2a7df2709e2aac89e0e6e61a8c4e442fca2;
retirement 38c670782408fd6843350f549eaeffe1b59adae7b923b907d4ccdad373424b7c;
output 0d176ef0fa749df76cbd636a944e1b420b33201b65741c652c9ad5c376fa01ce;
source intent 47f8ecd2d5cd70564cd9062fe093634f93083691e79a94abcb6697659a4428d7;
source intake e6f5140a6c63048b8ccd5f6c5d0b758ced5da9ef6d7c05f16180bf8f309cea94;
gateway runtime d9a7427d73867801fda31acbba4b1df3d7dafd4e99d35cd1cdbb2b5d7816448a.

## Correzione candidata e verifiche

Candidato4a65b9: stesso contratto di quiescenza nei due percorsi (retirement e worker standalone): entrambi permanentemente masked, nessun Job, servizio inactive/dead/PID0; al timer è consentito inactive/dead oppure failed/failed. Nessun reset-failed. Il worker resta indipendente dai moduli installer.

Il recupero è integrato nel modulo legacy già presente nei runtime chiusi. Richiede esattamente il predecessore95749a8, review/authority e record sopra, custodia/inode, dieci file precedenti intatti, assenza di rotazione/grant/worker/applicazioni e prova nativa di immagini/APISIX. La nuova revisione include tutto il proof nella scope owner corrente. Output e ritiro vengono osservati con nuove ricevute separate (massimo0 mkdir/mask/stop), conservando contatori/timestamp originali. Una sola prenotazione di continuazione stabile, autorità HUMAN e firme correnti; nessun riuso della start claim. Il nuovo codice owner viene predisposto come generazione distinta, conservando la precedente.

Le verifiche precedenti nel candidato71264d8 hanno passato i13 nuovi casi, inclusi sei con custodia root:10001, vere firme Ed25519 e TLS/grant/pubblicazione, oltre alla regressione owner. Hanno però individuato un'importazione incompatibile nel worker standalone e un errore nella fixture systemd: rifiutare inizialmente un timer con target già masked non produce lo stato failed. Il candidato22e856 ha riorganizzato il recupero senza ampliare i runtime e corretto la fixture del timer; conservava però l'ulteriore import incompatibile individuato e corretto in4a65b9. Questi risultati restano storici: la qualificazione corrente4a65b9 è documentata sotto.

Il candidato22e856 è stato fermato dalla CI: quattro workflow hanno fallito allo stesso import di producer dal modulo legacy, prima dei test di recupero. Nessuna esecuzione VPS. Il candidato4a65b9 elimina questa dipendenza dalla componente standalone, mantiene la lettura privata con FD/ancestry/no-follow e aggiunge una regressione che vieta il package worker durante l'import isolato.

Verifiche locali4a65b9: retirement9PASS, import runtime completo3PASS, recupero7PASS e6 skip per group10001 non disponibile nel sandbox. Le tre closure migration/installer/worker standalone compilano con32/39/24 moduli, senza ampliare allowlist o set dei moduli. I sei casi nativi restano obbligatori in CI. CI hosted4a65b9 completata: tutti i9 workflow push/PR PASS. PR consegna38715383127:262 test/34 suite/zero skip, incl13 casi recupero e timer systemd reale. PR online IAM38715383165:234 test/31 suite/zero skip, incluso Keycloak reale disposable. Installazione completa38715383033, retirement38715383112 e HUMAN verifier38715383372 PASS. Push corrispondenti38715377019/38715377065/38715377030/38715377158 PASS. Vedi evidence/chatbot-pregrant-recovery-qualification-20261015.json.

Capsula qualificata: **f9715d9728e78554305df567415bd949f8c3a89d00010204f6c549a1932a3728**,112 file.
Launcher qualificato: **4b6f30144055af38978f04d6eef16ddab134a890b0dcee460261ec28de5ca3dd**.
Wrapper qualificato e pubblicato: releases/chatbot-file-cohort-pregrant-recovery-execute-vps-20261015.sh, SHA2564e85a8e48f134a8c6d53ecaafd8b25942ff8cad9a38731a4dcd52be12caf6bf9. Verifica sintassi Bash PASS. Il wrapper è stato consegnato ed eseguito al commit4a65b9326c15d9758ecba1793965617a2a92e43e; dopo l'arresto OSError non va rilanciato. Il programma mostrerà una NUOVA review: approvare soltanto l'hash corrente, mai6ff o altri precedenti. Include gli effetti applicativi ancora da eseguire: cinque container, backup/migrazioni e primo grant/worker finito. APISIX e immagini completati vengono verificati e riutilizzati. Non rilanciare automaticamente dopo un nuovo PAUSED/BLOCKED: leggere stato e record prima di qualsiasi ulteriore azione. Dopo COHORT_READY_FOR_ACTUAL_CHATBOT_CSV_ACCEPTANCE proseguire subito con la prova MCP nella stessa finestra.

## Pacchetto applicativo congelato

Producer8bff54a52a0ce15daccaf2aee932004f106dd178; run38584614991 attempt2; artifact11907557440.
ZIP SHA256 **144699ab7756c8312d49783967cfbb64acc02a617015ad89f5adf51e25a10300**.
Esiste già in `$HOME/ouf-chatbot-file-delivery-126e49f3830667934bf8f8d7/cohort/cohort.zip`: riutilizzarlo verificandolo, nessun rebuild delle applicazioni.
Client gh: `$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh`, fallback command -v gh; preservare auth e non stampare token.

Pin moduli: semantic eccef11a97367f20e278db40b9ed6f45dd980c37; UDP b49c0d6f50c574c11684361ce4e8040e9cbddee2; onboarding **GioNob/ouf-source-onboarding** 84828f74ac586bae09a78f0fb197b75b1a3d98d1; ingestion c48ee4b1873a474e81c6e1be70d393854021e2c1; MCP f249b3dcc58c2a96742092d90fa09fd90b705bd0; Gateway bf179e96200deb84942ad32507edef52a4284cd0.
MCP conserva migrazioni1–9 e aggiunge10–12. Non merge globale del target overlay.

Il difetto precedente immagini era config digest vs native manifest digest in Docker/containerd. Corretto e provato nel VPS: semantic configuration29e32c1487b5ba29d6d29ec04f7daa3baeb1e30f392a46c838eef01493d60489, nativeb61bc39c1593c28404a8258962008c024d13689d7e9b132e6a85619580003ca3. Manifest/config/layer/RootFS e campi di esecuzione rimangono stretti; nessuna adozione sulla sola label. Payload applicativi invariati; nuovo envelope derivato conserva provenance e non pretende una nuova firma publisher. `image_import.validate_record` è la stessa validazione owner estratta per readback puro senza lock/scritture.

Precedente qualifica95749a8: run38704843732 e38704849033 (234 test/30 suite/zero skip), matrix38704843739 con tutte le5 immagini originali su classic/containerd, frame completo e owner firmato. CI Docker28.0.4; VPS29.8.1: non dichiarare equivalenza di versione. Referenze complete nella versione storica di questo documento al commit077c12021546c2c9d5b62b283d46ce3d6c3ec075.

## Storia e regole di recupero

Primo contesto auth-only b96d2afabbd3275beadb0bbb525608278d5f098af1e14de1f5e4333bff9b488d, source6959b1dbaeb30ca3a838c7d6243a55e9cfc5118a, finestra scaduta e processo fermo. I ruoli sono stati poi confermati: rileggere stato attuale senza ricreare una proposta invariata. Il vecchio link adf95413-92b0-460b-a112-2fd80bd208ac è scaduto e non va riaperto.

Secondo contesto dd03d434361deb62e1caeaf7958a71c39c095f065e776312779d59dd6a7f4a77, sourceb64645982655f58a2907bf1425dd86fd6ab0ed9f, authority48c75739575b7d618484ed78184834d2d1961da97fa2870d80d14ce26fe978f4. Semantic caricato, vecchio check config-ID fallito; gli altri4 mai tentati. Record IN_FLIGHT1 conservato e riconciliato tramite native manifest nel terzo tentativo.

I tre contesti vanno mantenuti. Nuova authority finita non azzera incidenti o tentativi, non riavvia claim, non estende TTL zero, non equivale ad accettazione. Nessun rollback DB automatico. Una sola invocazione systemd finita (Restart=no, massimo1h), primo grant<=300s e worker distinto<=128 tentativi/3600s. La storia legacy resta UNKNOWN. Seguire AGENTS.md e docs/OUF_RESILIENCE_POLICY.md v3.

## Accettazione finale ancora da dimostrare via MCP

Dopo `COHORT_READY_FOR_ACTUAL_CHATBOT_CSV_ACCEPTANCE` mantenere viva la stessa invocazione e continuare qui via MCP. L'MCP governa il CSV, non Docker/systemd/DB admin.
Account corretto **ouf-admin**, link_id **link_6aafef96b4148191b767e9af7b756a07**, owner profile b93d8cf6-cd14-4ee6-91d7-84cd76c4f500. Non usare giovanni-chatgpt/link6aaff0a687... . Nuovi tool potrebbero richiedere refresh del catalogo dopo l'upgrade: i ruoli pubblicati da soli non provano che il client li esponga.

Teatri: asset6609b245-86ed-4315-8ce0-73f2a8555bf3, profile7984c39c-7396-4248-ab0a-f2efc390b49c v1, 13 righe/20 colonne, UTF8/semicolon/header1, storico content SHA08b20658b2b4eadf34d25cd93eead2945096b353ae33b797cf3c41df5319c9e9.
Proposta pronta in releases/TEATRI_SEMANTIC_REUSE_REVIEW_20261014.md, teatri-reuse-semantic-proposal-20261014.json e teatri-reuse-20261014.ttl. ProposalHashbe74308e098aa3a65396f3df739dd8f2837e9f8e27b6e49deb0e49d04506cb1a; RDFSHA6e4668ea42cf1c75b822e17a8ca9cb71fb2c4d8f500eed628282fa6039a6dbaa.
Classe https://schema.org/PerformingArtsTheater, ontology https://api.ouf-lab.it/semantic/teatri#TeatriOntology. Nessuna proposta/DRAFT attualmente registrata o pubblicata è provata.

Sequenza: rilettura asset/profile/identity attuali → proposta semantica e vera approvazione HUMAN/pubblicazione → riferimenti owner realmente risolti → DRAFT onboarding e approvazione HUMAN → ACK ingestion distinto da COMMIT provato → lineage UDP e ricerca chatbot fresca → seconda sorgente governata, stesso contenuto, MATCH/NOOP e riuso. Preservare8 Cinema ACTIVE revision1 e loro IRI. 13 Teatri/21 totali soltanto se commit/unicità provati. Classificazione RESTRICTED e NATIVE_KEY nome_teatro normalization://managed-file/native-key-v1 richiedono decisioni reali. Nessun CSV sintetico o riferimento pubblicato inventato.

`ACTUAL_CSV_OWNER_ACCEPTANCE_OBSERVED` non basta: leggere ownerAcceptance.phase. Richiesti **TWO_SOURCE_COMMIT_AND_REUSE_PROVEN** e ricerca chatbot fresca. L'installazione non dimostra l'end-to-end.

## Modalità di collaborazione

Utente soprattutto da smartphone, molto provato dal numero di accessi/approvazioni. Aggiornamenti chiari almeno ogni60s; nessuna promessa di arrivo imminente o conteggio ostacoli non supportato. Procedere autonomamente fino a intervento necessario. Già autorizzati analisi, test, branch/PR draft ed evidence GitHub; niente merge/force o messaggi a terzi. Nessun SSH attivo: non inventarlo né chiedere chiavi/password in chat. Le password restano nei prompt locali. Prima delle nuove richieste di login completare tutti i preflight e le qualifiche possibili.

Consenso di sviluppo in chat distinto dall'esatta approvazione runtime nel terminale: mai auto-pipe APPROVO, riusare hash vecchi o usare un vecchio mandato per codice nuovo. Se il terminale mobile sparisce, fare readback prima di decidere. Non chiedere di rilanciare come diagnosi automatica.

Questa branch evidence non è una source applicativa/deployment qualificata: eseguire solo wrapper che pinna source e hash verificati. Il VPS è un test project, ma questa circostanza non autorizza a perdere dati o storia. Inventario completo originale resta sul VPS /home/oufadmin/ouf-vps-inventory-v2.sRYFvsMe/inventory-full.json; sono archiviati soltanto i report selezionati, non dichiarare un inventario integrale salvato.
