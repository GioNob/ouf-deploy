# Continuazione residua con riga terminale visibile e modificabile — 26 ottobre 2026

## Ultimo risultato VPS, non CI

[Receipt minimizzata](../../evidence/acquisition-descriptor-tty-input-stop-target-20261026.json).
La consegna ed628178ee6e450b3c62a47b8e193130fa882879/runtime d816b283a706e753d629e35e41c14cabdbbd247c è stata eseguita: STOP_RECONCILE / EXACT_TERMINAL_REVIEW_LENGTH_EXCEEDED, complete=false, publicationClaimed=false, Exit=2, DeliveryExit=2.
Review 9dce80014009683896a26ffa7520a0d93d1cbd2212cd1eca37558c86f27eb020 NON acquisita. Contatori finali6 administrativeWrites /17 ownerGets /1 previewPosts /950031 bytes.
Scope /etc/ouf/deploy-snapshots/acquisition-existing-draft-publish-cb75ddb0-v1/tty-publication-continuation-v1 CONSUMATO.
OperatorLog in quello scope; delivery /home/oufadmin/ouf-descriptor-tty-continuation-delivery.H62VDbv4/bootstrap.log.
Nessuna claim PUBLISH o seconda preview nel risultato di quel controller. Non dedurre stato corrente da queste sole prove.
NON rilanciare vecchio wrapper/controller, riusare hash/login/token, modificare child per aggirare STOP o resettare contatori.

Il log mostra attesa input, poi ricezione, attesa Invio e superamento lunghezza. Non è FINITE_HUMAN_WINDOW_EXPIRED.
Il vecchio reader disabilitava echo e canonical editing, interrompendo tutto al byte73 prima di Invio. Il transcript non contiene i byte ricevuti: non attribuire all'operatore la causa né affermare un incolla duplicato come fatto live.
Il nuovo test conserva la riproduzione sintetica del vecchio errore e la correzione recuperabile.
L'owner è sul cellulare: un solo terminale, niente secondo terminale obbligatorio, niente diagnostica lunga mentre resta occupato.

## Correzione e perimetro residuo

Nuovo reader tools/human_terminal_line_review.py, SHA256 3e698faea1e933b9ce04ad7ed204ed44b60863ad8fac620385c37a10179bfbf5:
- riga CANONICA e VISIBILE sul terminale reale, normale Backspace, Ctrl+U svuota la riga;
- nessuna decisione sulla riga parziale o al superamento dei72caratteri; Invio consegna la riga completa;
- riga non valida: messaggio esplicito, nessuna approvazione, reinserimento possibile nella STESSA review entro la STESSA scadenza;
- solo APPROVO più hash esatto e Invio acquisisce consenso; mai inferito da echo/incolla/scadenza;
- nessuna estensione deadline, nuovo login/review/hash o counter reset durante correzione; nessuna API owner durante attesa/correzione;
- solo stati/conteggi/rejectedLines privati, nessuna registrazione dei caratteri immessi; echo nativo non passa dal logger Python;
- guard foreground controllingTTY prima IAM/scope e al reader; termios ripristinato anche su errore/scadenza; stdout sudo diretto, nessuna pipe interattiva;
- EOF/cancellazione/scadenza/errori infrastrutturali restano STOP. Correzione input non riapre uno scope STOP.

Questo è un NUOVO esecutore residuo qualificato, vincolato alla catena delle prove consumate; non replay del vecchio controller.
Runtime **3d8408ac6154d667ab64042561f5d3d14b9f7a84**,
scripts/continue-existing-descriptor-publication-editable-20261026.py,
SHA256 **5ad8bd38a51ba13aee3501c6dffe3629583c0eeb3fe20fdedac04f62f8d4884d**.
Reader incorporato byte-identico/hash-checkato, nessun import da cartelle utente.
Delivery **059ea7fc60b19916bf484bd7bfc483407840540b**,
releases/continue-existing-descriptor-publication-editable-20261026.sh,
SHA256 **8578584cb6b8ca33bafde94229406f8c1ab8da203c768053bcd688d72dcfce6a**.
Codice root0400/dir0700 sotto /usr/local/lib/ouf-existing-descriptor-editable-continuation-5ad8bd38a51ba13a/continue.py; fchmodFD prima fsync, checksum eseguito ROOT.
Nuovo child FISSO /etc/ouf/deploy-snapshots/acquisition-existing-draft-publish-cb75ddb0-v1/tty-publication-continuation-v1/editable-review-continuation-v1.
Log privato root600 nello stesso child: operator.log. Bootstraplog privato nella nuova delivery dell'operatore.

Prefisso letto e vincolato prima del login:
1. review originale5a31.../cinqueREGISTER APPLIED/CREATE CLAIMED e candidato106grant;
2. lookup owner esistente UUIDcb75ddb0-bd19-48fb-847f-1c47aff3207a/rev0/DRAFT/ETag0/digest8f69...;
3. primo publisher scaduto review6ff5.../STOP/no approval/effects vuoti,6/13/1/744072 e receipt prima preview già consumata;
4. ultimo TTY STOP/state/result/review9dce... esatti,6/17/1/950031, nessuna approval/effects, sole4GET preflight COMPLETE/attempt1, stesso candidato/UUID/rev0/preview.
Fileoriginali e receipt immutati; storieIAM originali/lookup/primoSTOP/ultimoTTY preservate. Nessuna chiave privata o credenziale dafile, SQL/Engine/lifecycle o vecchioentrypoint.

Cumulativi iniziali **6writes/17GET/1preview/950031bytes**.
La prima preview è già consumata e NON viene ripetuta: rilettura della receipt privata owner.
Nuovo normale device login ouf-admin, account/sub/tenant/HUMAN esatti, token soloRAM senza refresh/file.
Helperpubblico root0444/hash062b... già installato importa solo definizioni; mai vecchi main o scope.
Prepare SOLO GET correnti ACTIVE48/catalogo/draft/ACTIVE: candidata49 deve contenere esclusivamente5descrittori aggiunti e tutti106grant invariati.
Review NUOVA privata con nonce/hashcodice/reader/login/scadenzaEuropeRome/UUIDrev0/candidato/catalogo/preview/contatori/limiti/prefissi. Vecchia9dce non approva questa review.
Dopo APPROVAZIONE ACQUISITA: GET governate, UNA preview RESIDUA identica alla retained (cumulativa2/2), ultimo ACTIVE/draft/ETag0, UNA claim PUBLISH con counter6→7 fsync PRIMA invio.
Raw status/ETag/body mutante PRIVATI conservati PRIMA parsing/guard, ancheHTTPError. Risposta persa/ambigua resta CLAIMED, nessun retry automatico.
Solo owner PUBLISHEDrevision1/ETag1 e ACTIVE49/catalogo/106grant invariati rendono APPLIED.
Nessuna REGISTER/CREATE/PUT/DELETE, grant nuovo, mutazione ruoli/assegnazioni/IAM/fonte/acquisizione/Registry.

Massimi invariati **7writes/160GET/2preview/32MiB**,900sreviewexec/1800stotale/IAM600s e tokenexp−15s possono ridurre finestra, mai estenderla.
SIGALRM reale e deadline monotonic limitano I/O. Solo GET transitori hanno retry finite8/stage e jitter/RetryAfter entro stessa scadenza; POST/permanenti/unknown non ritentati.
Due vecchie invocazioni diagnosticheMCPGRANTS separate con conteggiwire ignoti rimangono nella storia, non azzerate né attribuite al nativo.

## Qualificazione

[Prova e limiti](../../evidence/acquisition-descriptor-editable-continuation-qualified-20261026.json).
Commit finale test/delivery059ea7fc60b19916bf484bd7bfc483407840540b; runtime pinned3d8408ac invariato.
- Push40278392372/jobs121426008789(!use_pty),121426009037(use_pty);
  PR40278398191/jobs121426026426(!use_pty),121426026711(use_pty).
  PERjob12testPTY +25casi trasporto sudo reale PASS,0skip, logdiretti letti.
  Tre casi conservano vecchio sudo+tee;11core e11approve/logger reale. LF/CR/CRLF/frammentato/noEnter/wrong/noinput/duplicatoCtrlU/rigaerrata+correzione/backspace/riga1000byteCtrlU. Nuovo riproduttore vecchioerrorelunghezza incluso nei12test.
- Push40278392359/jobs121426009103(protocol+root),121426008892(owner);
  PR40278398186/jobs121426026739(protocol+root),121426026425(owner).
 8protocol +6custodiaROOT +3ownerJava21/PG17 PASS,0skip, logdiretti letti.
- Correzione input nella stessa review dimostra hash/counters/deadline invariati, zeroAPI intermedie.
  UltimoSTOP/result/review/claims/counters alterati rifiutati. Originali compresoTTYprefix immutati.
- Copia protetta ROOT sotto umask077/file400/dir700/hash/execisolata/nonrootdenial reali. Wrapperinterattivo senza pipeline verificato.
  Bootstrapcurl non esercitato contro produzione; copier provato direttamente.
- Owner DEPLOYED GioNob/ouf-source-onboarding1b1222ceaa5af85a25c20857e7c8c1b548b12dc1+SDK/controller/HTTPserialization/ETag0→1/transazioni PG17 reali.
  Prima preview seedata come prefisso consumato, una nuova preview e unaPUBLISH,0register/create.
  Successo, rifiuto/scadenza senzaPUBLISH e commit con risposta persa/no replay;106grant inclusoaltrotenant.
- IAM/principal/account/policy/storia/decisioniTTY inCI sintetici; externalAuthorizationRuntimeSynchronizer mocked.
  NON provaVPS, JWT/Gatewayproduction, refresh consumerMCP, E2E/THS/ApprovalChallenge o releaseacceptance.
  Vecchie fixture/script/readers e precedenti difetti rimangono conservati.

Riferimenti precedenti: [TTYconsumato](OUF_ACQUISITION_DESCRIPTOR_TTY_CONTINUATION_20261026.md) e sue prove/handoff integrali; lookup e prima pubblicazione nelle sue referenze.
Matrix1.7§1/4/7, AuthorizationPET1.5§16–18/36.6–36.7, THSPET1.6§27.1–27.3 già consultati daglioriginali allegati hashe63df... restano vincolanti. Reviewterminale di repair sotto mandatoowner non chiude conformitàproductTHS.

## Prima esecuzione di questa consegna — una volta, oufadmin

Nessun risultato VPS di questa nuova continuazione ricevuto.
Eseguire direttamente senza pipe esterne. LoginIAM nelbrowser conouf-admin: codice device SOLO browser.
Alla NUOVA review incollare SOLO la nuova riga APPROVO e premereInvio. Input ora VISIBILE.
Se incolla male: Backspace oCtrlU primaInvio; oppure Invio sulla riga errata e reinserire quando compare il messaggio. Non rilanciare il comando.
Non usare hash9dce/6ff/5a31, né approvazione inchat. APPROVAZIONE ACQUISITA conferma effettiva ricezione+verifica+fsync.

```bash
(
  set -Eeuo pipefail
  umask 077
  ouf_line_bootstrap=$(mktemp -d "$HOME/ouf-descriptor-line-bootstrap.XXXXXXXX")
  curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --max-redirs 3 --connect-timeout 15 --max-time 60 \
    "https://raw.githubusercontent.com/GioNob/ouf-deploy/059ea7fc60b19916bf484bd7bfc483407840540b/releases/continue-existing-descriptor-publication-editable-20261026.sh" \
    -o "$ouf_line_bootstrap/run.sh"
  printf '%s  %s\n' '8578584cb6b8ca33bafde94229406f8c1ab8da203c768053bcd688d72dcfce6a' "$ouf_line_bootstrap/run.sh" | sha256sum -c -
  chmod 0400 "$ouf_line_bootstrap/run.sh"
  /usr/bin/bash "$ouf_line_bootstrap/run.sh"
)
```

Restituire SOLO JSONfinale, Exit, DeliveryExit, percorsilog. Non condividere codice device/token/fullreview/state o operator.log.
Atteso EXISTING_ACQUISITION_DESCRIPTORS_PUBLISHED_GRANTS_UNCHANGED/complete=true/Exit0/DeliveryExit0,7writes/2preview/retainedPreviews1/newPreviews1/106grantpreservati/ACTIVE49.
Qualsiasi STOP/CLAIMED/scadenza consuma anche il nuovochild: conserva tutte le prove, niente rilancio/cambiopath/rollback automatico.

## Dopo pubblicazione provata

Solo risultato VPS positivo permette passare a scopeMCP/ROLES/GRANTS freschi e nuova proposta HUMAN/THS ristretta alle DUErun esistenti teatri-csv-6609b245:
bb2e2af4-9c0a-49ea-8ad9-a947987c1472 e a3208f2f-ebfd-415d-bddc-79ab05dea78f.
Pubblicare descrittori NON concede grantREAD/OAuthscope. Policy48 grantTeatri storico scaduto, mai riusarlo o riproporre proposalrifiutate/scadute.
Poi quattro READgovernate Ingestion+UDP e correlazione contratti/CSV/publication/ACK/watermark/13identità/propertyprovenance/11–19property/unione20, preservando8Cinema. Valoriassenti da baseline non provanouguaglianzabyte.
Tecnico8/8funzionale4/6; E2E/G4/F5/F6 OPEN; Supervisor dopoE2E. Niente terza acquisizione/attivazione/reset/Registryrestart/reinstall/merge/releaseacceptance.
