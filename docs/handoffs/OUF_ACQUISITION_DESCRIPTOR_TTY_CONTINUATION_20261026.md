# SUPERATO — comando CONSUMATO, NON eseguire

VPS 26ottobre2026: STOP_RECONCILE/EXACT_TERMINAL_REVIEW_LENGTH_EXCEEDED, Exit2/DeliveryExit2, publicationClaimed=false,6writes/17GET/1preview/950031bytes. Review9dce... non acquisita. Scope tty-publication-continuation-v1 CONSUMATO. Receipt: ../../evidence/acquisition-descriptor-tty-input-stop-target-20261026.json. Correzione in sviluppo/qualifica; nessun nuovo comando consegnato. Il testo seguente è STORICO e il suo comando non va rilanciato.

# Pubblicazione residua con TTY in foreground — 26 ottobre2026

## Prova target e responsabilità

Il journal target mostra STOP_RECONCILE/FINITE_HUMAN_WINDOW_EXPIRED, humanReviewApproved=false, pendingReads[], publishStatenull. Contatori6administrativeWrites/13ownerGets/1previewPosts/744072bytes, uguali al momento della review.
[Proiezione ricevuta](../../evidence/acquisition-existing-descriptor-publication-review-expired-target-20261026.json).
Non è stata acquisita l'approvazione e questo controller non ha claimed/inviato PUBLISH. Il solo echo della riga non provava ricezione. Exit/DeliveryExit non forniti; non inventarli o una cancellazioneCtrl+C.
L'operatore è sul cellulare: niente secondo terminale obbligatorio, script diagnostici lunghi mentre il primo resta occupato o responsabilità attribuita al suoInvio senza prova.

Scope /etc/ouf/deploy-snapshots/acquisition-existing-draft-publish-cb75ddb0-v1 e review6ff5fa76c217888e174d760b84a0ce8ad6e6242955546bd9ddcca050e7851ff7 CONSUMATI. Vecchio [wrapper24f2abbd](OUF_ACQUISITION_EXISTING_DESCRIPTOR_RESIDUAL_PUBLICATION_20261025.md) NON rilanciabile; nessun register/create/lookupSQL/login/token/reviewreplay o reset.
Il [lookup precedente](OUF_ACQUISITION_EXISTING_DESCRIPTOR_DRAFT_LOOKUP_20261025.md) aveva confermato UUIDcb75ddb0-bd19-48fb-847f-1c47aff3207a/rev0/DRAFT/base48/ETag0 e candidato027f626dce41cac0dc2d1dd9338bd2aeb20bc474a438e6e26a68d4214271b46b/106grant. Lo stato attuale va riletto dall'owner prima di proseguire.
Due invocazioni MCP GRANTSouf-admin dopo la review osservavano ACTIVE48/hash6209...; sono diagnostiche separate dai contatori nativi, conteggi wire/byte non osservati. Non trasformare invocazioni semanticamente riuscite in un totaleHTTP inventato. NessunaACTIVE49dimostrata.

## Difetto consegna riprodotto; correzione

La mia qualifica precedente passava veriPTY isolati ma non l'intera composizione sudo+pipeline. Riproduzione nuova: con sudo use_pty e invio della riga esatta COMPLETA+Invio, il vecchio comando interattivo in pipe atee scade con FINITE_HUMAN_WINDOW_EXPIRED. stdinIsTTY=true ma stdinForeground=false/controlForeground=false. L'input può apparire in echo senza essere disponibile al controller. Log della riproduzione conservati; non attribuire quel risultato al cellulare.
Questo riproduce la divergenza osservata, ma il valore effettivo sudoers/termios del VPS durante lo STOP non è stato letto: non dichiararlo retroattivamente provato.

Aprire /dev/tty da solo NON bastava conservando la stessa pipe in background: il nuovo guard lo rifiutava subito inCI. La composizione corretta:
- esecuzione sudo INTERATTIVA diretta, con stdout ancora sul terminale; nessun |tee attorno al controller;
- log del controller duplicato INTERNAMENTE, root600 nel suo contesto root700, senza registrare inputsegreti; log delle sole fasi di copia può ancora usaretee;
- foregroundTTY verificato PRIMA di IAM e creazione dello scope, poi reader del controlling terminal /dev/tty;
- input in modalità carattere senza echo, bytecount/Enterstate privati e messaggi immediati. Solo riga esatta+Invio autorizza; incolla senzaInvio non autorizza e riceve heartbeat massimo10s;
- LF/CR/CRLF/pasteframmentato gestiti, soli terminatori vuoti normalizzati, mai suffissi/testoextra o hashvecchio. Backspace ammesso. TTYflags sempre ripristinati su successo/errore/scadenza;
- ACK esplicito APPROVAZIONE ACQUISITA dopo verifica review/fsync, progresso delle letture e attese bounded dopo approvazione.

NESSUNA modifica sudoers sul VPS o disattivazione della sua use_pty. Le varianti sudoers sono solo fixture effimereCI.

## Nuova continuazione governata; stessi limiti

Runtime **d816b283a706e753d629e35e41c14cabdbbd247c**, scripts/continue-existing-descriptor-publication-tty-20261026.py, SHA256 **174bdaefedf693e133a918c6f246e2c9e427b768c651764289379f87f5fbe0a0**.
Il readerTTY qualificato è incorporato byte-identico/hash-checkato nel singolo codice protetto, nessun import da cartelleutente.
Delivery **ed628178ee6e450b3c62a47b8e193130fa882879**, releases/continue-existing-descriptor-publication-tty-20261026.sh, SHA256 **c44408931660941fdbd7d303b1152ebf61f223903a3896e54012b63e94be94dd**.
Codice root0400/dir0700 sotto /usr/local/lib/ouf-existing-descriptor-tty-continuation-174bdaefedf693e1/continue.py, fchmodFD prima fsync/checksumROOT. Nuovo childFISSO sotto lo scope consumato: /etc/ouf/deploy-snapshots/acquisition-existing-draft-publish-cb75ddb0-v1/tty-publication-continuation-v1. Nuova intentoresidua e review, non riapertura del vecchio scope.

Legge soltanto proveoriginali5a31+lookup8f69... e state/review/initial-preview-response dello STOP6ff5... root600. Richiede STOP, reasonesatto, humanReviewApprovednontrue, effectsVUOTI, contatori6/13/1/744072, reviewhash6ffesatto, candidato027f.../UUID/rev0 e previewownerequivalente. Non riscrive né esegue vecchi file/processi. StorieIAM originali, lookup e primo publisher scaduto conservate. La receiptlookup resta trasporto/prova storica, mai autorità riusata.

Contatori nativi iniziali **6writes/13GET/1preview/744072bytes** incorporati senza azzeramenti.
**La prima preview è già consumata e NON viene ripetuta.** È riletta dalla receiptprivata; la nuova prepare compie SOLE GET ACTIVE/catalog/draft/ACTIVE e confronti completi.
Nuovo normale device loginouf-admin, bearer soloRAM/scopesopenid authorization.policy.admin, stesso helperloginroot0444/hash062b... senza oldmain/refresh/tokenfile.
Nuova review privata con nonce/UUID0/candidato106grant/hashcatalogo/previewretained/contatori/limiti/scadenza effettiva Europe/Rome/hashcodice. Solo nuova rigaAPPROVO HASHFRESCO daTTYreale. La vecchia6ff non approva questa nuova review.

Dopo APPROVAZIONE ACQUISITA: nuove GET governate, UNA sola previewRESIDUA identica alla retained (cumulativo2/2), ultimoACTIVE/draft/ETag0, unico PUBLISH claim+counter6→7 fsync PRIMA dispatch. Trasporto ha SOLOGET/catalog/exactUUID/preview/publish, nessuna rottaREGISTER/CREATE/PUT/DELETE/SQL/Engine. Owner verifica correnteHUMAN/tenant/base/revision nella sua transazione. Tutti106grant, ruoli e assegnazioni preservati, nessun grantREADnuovo.

Status/ETag/body mutante PRIVATI salvati PRIMA parsing/guard, ancheHTTPError. Risposta ambigua/persa restaCLAIMED e non si ritenta. Solo ACKPUBLISHED/revision1/ETag1 più ACTIVE49/capability+106grant immutati rendeAPPLIED.
Massimi originari **7writes/160GET/2preview/32MiB**, nessun nuovo budget fonte oreset.900sreviewexec/1800stotale/IAM600s/tokenexp−15s, SIGALRM reale e scadenza monotonic limitanoI/O. SoloGETtransitori retry8massimi/stage con5/15/60/300/900+jitter<=20%/RetryAfter entro scadenza; permanenti/unknown/POST no retry.

Logruntime NUOVO root600:
 /etc/ouf/deploy-snapshots/acquisition-existing-draft-publish-cb75ddb0-v1/tty-publication-continuation-v1/operator.log.
Il logbootstrap rimane privato nella delivery dell'operatore. Non aggiungere pipe esterne al comando.

## Qualifica reale e limiti

[Qualifica](../../evidence/acquisition-descriptor-tty-continuation-qualified-20261026.json).
- Continuazione finale push40245135499/job121324991821(protocol+custody)/121324991979(owner), PR40245139357/job121325002894/121325002718:7protocollo+5custodiaROOT+3ownerJava21/PostgreSQL17 ciascuno,0skip, logdirettiletti. Il runtime/header/codice consegnato rimane identico al pinned d816b283; fc2051... aggiunge solo asserzioni immutabilità originali/pipeline.
- TTY completa PR40244833347: use_pty121324091729 e!use_pty121324091591,8unitPTY+17casitrasporto perbackend (3reproducerlegacy,7core,7continuazione) PASS/0skip/logdirettiletti. La stessa riproduzione è conservata anche push40244418730/job121322862088 ePR40244422632/job121322873581.
- Sudo e utenteoperatore/root/PTY/pipeline/foreground/logger/terminatori/restauro sono REALI. Il vecchio fallimento conInvio resta atteso come reproducer; non è chiamato successo della vecchia consegna.
- Owner deployed1b1222ceaa5af85a25c20857e7c8c1b548b12dc1+SDK/migrazioni/controllers/serialization/ETag0→1/transazioni PG17 REALI, Pythonclient viaHTTPbridgeCI. Prima preview giàseedata come prefissoconsumato; una sola ulteriorepreview e una solaPUBLISH, zeroREGISTER/CREATE. Successo/rifiuto/commitrispostapersa/no replay e106grant con storiaaltrotenant.
- PrincipalIAM, account, policies/storia e decisioniTTY inCI sono SINTETICI; externalRuntimeSynchronizer mocked. Non sono risultatiVPS o prova diIAM/JWKS/Gatewaylive/cacheMCPrefresh/E2E. Nessuna approvazioneproduction simulata.
- Root077/fileoperatore600/root600/hash/mode/symlink/counter/reviewprefix/replaynegati/copiaprotetta400/esecuzioneisolata/nonrootdenial reali. Tutti i file dello STOP, review eprimaPreviewimmutati; wrapperinterattivo senza pipe staticamente verificato.

Matrix1.7§1/4/7, AuthorizationPET1.5§16–18/36.6–36.7 eTHSPET1.6§27.1–27.3 già consultati dall'originale allegato hashe63df...; invariati. Terminalerepairreview sotto mandatoowner non chiudeTHS/ApprovalChallenge o releaseacceptance.

## Comando unico anche da cellulare: oufadmin, una volta

La vecchia procedura è STOP/consumata. Questo è il nuovo esecutore residuo con gli stessi contatori e budget.
Eseguire direttamente nel terminale: sudo copia/esecuzione; loginIAM conouf-admin nelbrowser; codice device SOLO browser. Alla nuova review incollare SOLOla rigaAPPROVO conhashmostrato e premereInvio↵. L'input è nascosto: compariranno Input ricevuto e APPROVAZIONE ACQUISITA, oppure attesa esplicita diInvio.

```bash
(
  set -Eeuo pipefail
  umask 077
  ouf_tty_bootstrap=$(mktemp -d "$HOME/ouf-descriptor-tty-bootstrap.XXXXXXXX")
  curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --max-redirs 3 --connect-timeout 15 --max-time 60 \
    "https://raw.githubusercontent.com/GioNob/ouf-deploy/ed628178ee6e450b3c62a47b8e193130fa882879/releases/continue-existing-descriptor-publication-tty-20261026.sh" \
    -o "$ouf_tty_bootstrap/run.sh"
  printf '%s  %s\n' 'c44408931660941fdbd7d303b1152ebf61f223903a3896e54012b63e94be94dd' "$ouf_tty_bootstrap/run.sh" | sha256sum -c -
  chmod 0400 "$ouf_tty_bootstrap/run.sh"
  /usr/bin/bash "$ouf_tty_bootstrap/run.sh"
)
```

Atteso EXISTING_ACQUISITION_DESCRIPTORS_PUBLISHED_GRANTS_UNCHANGED/complete/Exit0/DeliveryExit0; cumulativi7writes/2preview, retainedPreviews1/newPreviews1,106grantpreservati/ACTIVE49. Restituire SOLOJSONfinale/Exit/DeliveryExit/percorsilog. Non condividere devicecode, token, fullreview/state o operator.log.
SeSTOP/CLAIMED/scadenza: conserva prove e NON rilanciare o cambiarechild; nessun rollback automatico.

## Dopo risultatoVPS

Solo dopo PUBBLICAZIONE provata: MCPscopes/ROLES/GRANTS fresche, nuova proposta HUMAN/THS ristretta alle due run già esistenti teatri-csv-6609b245:
bb2e2af4-9c0a-49ea-8ad9-a947987c1472 e a3208f2f-ebfd-415d-bddc-79ab05dea78f. Mai replay proposalrifiutata/scaduta. Poi4READIngestion+UDP e correlazione contratto/CSV/publication/ACK/watermark/13identità/propertyprovenance/11–19property/unione20, preservando8Cinema.
Tecnico8/8funzionale4/6, E2E/G4/F5/F6OPEN, Supervisor dopoE2E. Nessuna terzaacquisizione/attivazione/reset/Registryrestart/reinstall/merge/releaseacceptance.
