# Recupero residuo dopo STOP MAC — 25 ottobre 2026

## Stato server autorevole

Ultimo risultato VPS: `RETAINED_OLD_MCP_GUARD_DIFFERENCE_OBSERVED`, complete=true/Exit0/DeliveryExit0,129 letture metadata e zero nuove chiamate Engine/admin/credenziali/chiavi/SQL/OAuth. Receipt integrale: [evidence target](../../evidence/acquisition-old-mcp-guard-observed-target-20261025.json). Sono provati nelle evidenze trattenute13stageAPPLIED, negativaAPPLIED con entrambi i READ propri quarantinati, vecchioMCP fermo/senzaendpoint/nome preservato. Nessuna claim RENAME, nuovoMCP o routePUT. Stato runtime corrente non osservato. Il solo delta Config è la scomparsa del campo legacy MacAddress coerente con l'endpoint: non null/vuoto né altri campi.

Tutti gli scope precedenti, compresa la diagnostica retained, sono CONSUMATI. Nessun risultato di questo nuovo recupero è ancora ricevuto; non descrivere CI come installazione VPS. [Handoff precedente e lezione permanente](OUF_ACQUISITION_MAC_LESSON_AND_RETAINED_STATE_20261025.md), AGENTS.md e i suoi riferimenti restano obbligatori. Non riavviare/ricollegare il vecchio MCP.

Root originale:
`/etc/ouf/deploy-snapshots/acquisition-read-apply-5fa62e4f6869a6f40fb512878dcf65dcb6ffaf941be487e4189826f418046591`.
Continuazione consumata: `terminal-continuation-v1`.
Nuovo child esclusivo al suo interno: `detached-mcp-recovery-v1`.
Review concreta nuova: `<nuovo child>/review.json`; nessuna approvazione in chat.

Binding retained: review7fcbce1f43fd99b4add8db9913b3dc2fe215836f16eecd8e8191f9e344e54aa9; authority496dda9a7057f67c4ffb10e6ae4606d101479c905cad6a731907eaf4010d56a4; journal1fb1159ada9d78123d1a90985e8c6ba23a18648bd3b3f621406c43dc9f57817d; privateEvidencee6b8642e1c04f510eabdddc6d038a87c9575e65be060928bf9981bd631eb4af2. Receipt canonico ricostruito dal testo owner7db79ea88e7f4ecf72dec889a8753afb40a53890573615bcebbf0b2fbc67e0f9: il controller deve verificarlo sul file server prima di usarlo; l'agente non ha letto quel file direttamente. Log target precedenti restano quelli elencati nell'handoff collegato.

## Operazione residua proposta alla review

Il nuovo controller legge le sole prove retained vincolate, verifica prefix/negativa e sorgenti senza eseguire i vecchi entrypoint. Adotta esclusivamente i due CID READ originariamente creati, verificati e quarantinati. Copia la storia nel nuovo child e sorveglia che file, contatori ed entry del vecchio scope non cambino. Le immagini devono essere già importate con identità native esatta: nessun nuovo import o READ CREATE.

Prima dell'approvazione: nessuna ulteriore lettura del file credenziale admin o delle chiavi private, nessuna API admin, nessun effetto. Solo Engine GET e owner configuration read entro i massimi PRECEDENTI, con tentativi registrati nel nuovo child. Vengono verificati di nuovo vecchioMCP fermo/detached, stesso Config meno il solo campo legacy provato, immagine/mount/StartedAt/HostConfig esatti; quattro owner originali attivi con binding e process pin invariati; due READ fermi con stessoCID/config/StartedAt; immagini già presenti e medesimo profilo Engine; nomi, custodia e risorse. Tutti questi controlli precedono la review e si ripetono dopo la decisione.

Soltanto dopo APPROVO esatto da vero TTY, firme dell'installazione e watchdog pronto: claim della terza lettura del medesimo file admin esistente, verifica fresca delle82rotte, riavvio dei due READ propri con generazioni/readiness nuove, rename del vecchio MCP già fermo/detached, CREATE/START del solo nuovoMCP, readiness, due routePUT esatte, verifica84rotte, ripristino delle restart policy dei soli candidati e health finale con attestazione firmata.16stage residui;13stage storici restano immutati. Nessun vecchio STOP/DETACH/restart o acquisizione ripetuto.

La review propone questi massimi CUMULATIVI; non sono ancora concessi dal semplice sviluppo del codice:

| Contatore | Già consumato | Massimo precedente | Proposto |
|---|---:|---:|---:|
| Engine GET |128|500|500|
| Engine writes |14|22|28|
| image load |3|3|3|
| owner configuration read |42|64|96|
| readiness GET |2|128|128|
| admin GET |2|32|32|
| admin PUT |0|2|2|
| file credenziale servizio |2|2|3|
| quarantine stop |2|3|5|

Motivo:8writes positivi residui portano14→22;6writes ulteriori sono riserva negativa per updateRestart/stop dei soli tre candidati propri, anche se il positivo fallisce alla fine. Una ulteriore lettura admin è necessaria per verificare e aggiungere le rotte: vecchie letture non azzerate né ripetute sotto il vecchio mandato. Nuovi guard e preflight richiedono ownerConfig oltre64 (profilo massimo96). La negativa può contare al massimo tre candidati nel nuovo scope, conservando le due quarantine già consumate. Gli altri massimi non cambiano. Nessun budget fonte, grant IAM, source activation o terza acquisizione.

900secondi di nuova autorità,180secondi per startup candidato e al massimo30secondi aggiuntivi di sola negativa; nessun rollback. Watchdog effimero vincolato a controller/processo/journal. La prima snapshot valida precede il READY. Il monitor legge sotto la transazione breve e nonblocking del journal; per la sola lock contention ha una pausa con jitter bounded a2secondi e64tentativi. Il profilo è esposto nella negativeCleanup firmata e nel prompt. Errori di custodia non sono ritentati; nessun lock attraversa sleep, firme, Engine I/O o cleanup. Custodia0600/linkcount1 invariata; nessuna accettazione di record unlinked.

MCP sostitutivo può eseguire il normale bootstrap OAuth e aggiornare il proprio catalogo sotto il mandato già descritto, senza migrazioni DB impartite dalla riparazione. READ restano senza Flyway/esecuzione, mount e rootfs RO. Registry worker intatto. Il normale bootstrap non concede grant applicativi, E2E o release acceptance.

## Consegna immutabile e qualificazione

Sorgente runtime: 389719d67ba4686a5d8082628a8bf6795cb2e744.
Delivery pinned:222a9a52fd2c18e95279a67acaebeb7af6579457.
Wrapper: `releases/recover-acquisition-detached-mcp-20261025.sh`.
Wrapper SHA256: aa9774d615dcba08ab53bdd81670dc7a0ce9114ac4b8a27489a88a903733a8f7.
19 sorgenti, manifestSHA256 4633a0f61b564aa4a50abba6ae41467a4648a3dbdb34d9f4d41b01672aea5d70.
Copia root esclusiva: `/etc/ouf/deploy-snapshots/acquisition-detached-recovery-code-4633a0f61b564aa4`, directory0700 e file0400, nofollow/frame/hash ed fsync; esegue `recovery.py` con python isolato/no-site/no-bytecode. Il bootstrap verifica i byte del base prima di eseguirne le definizioni; manifest chiuso e closure completa restano controllati.

Qualificazione finale dello stesso commit runtime389719d67ba4686a5d8082628a8bf6795cb2e744:
- Push [40214692413](https://github.com/GioNob/ouf-deploy/actions/runs/40214692413): job121233182208,21protocollo+7residuo PASS; job121233182056 containerd e121233182221 classic,2originali+2continuazione+3recupero PASS ciascuno.
- PR [40214696600](https://github.com/GioNob/ouf-deploy/actions/runs/40214696600): job121233194486,21+7 PASS; job121233194263 containerd e121233194581 classic,2+2+3 PASS ciascuno.
- MAC obbligatorio [40214696667](https://github.com/GioNob/ouf-deploy/actions/runs/40214696667):6test puri e2lifecycle reali con Configlegacy iniziale presente/assente dopo detach su OGNI backend; job121233194567 classic e121233194758 containerd PASS. MAC endpoint preservata, vecchioCID/image/mounts/StartedAt esatti e vecchio fermo.
- Wrapper finale push [40214798521](https://github.com/GioNob/ouf-deploy/actions/runs/40214798521)/job121233491269 e PR [40214803137](https://github.com/GioNob/ouf-deploy/actions/runs/40214803137)/job121233505619 PASS: veri19download pinned/checksum/copia root protetta/entrypoint isolato; scope originale assente nel runner, STOP/Exit2 ATTESO prima di autorità/effetti. Non è esecuzione production. Bootstrap esterno tramite gh qualificato staticamente con bash-n, non autenticazione VPS in CI.
- Docker29.8.1 esatto, archivio SHA256 d8db66739d2e28d4933786d73e918d9be643a67fbd835db1bf740d650a259e70; API1.44, classic/containerd.19/19 sorgenti locali confrontati con blob Git immutabili del commit, SHA256/AST/manifest e wrapper bash-n verificati.
- Log diretti dei10job citati letti, zero skip. Nei test residui il prefix13APPLIED e la quarantena precedente sono prodotti da vere transizioni Engine; il vecchio guard è riprodotto con un trigger CI sul confronto Config reale. Positivo: stessi due READ CID, nuove generazioni/readiness,16stage residui,22writes e3fileadmin cumulativi,84rotte, history immutata e attestazione. Negativo: TTY rifiutato senza ulteriore fileadmin/effetti; controller SIGKILL e tre soli candidati propri quarantinati,5quarantine cumulativi, vecchioMCP fermo e altri owner invariati.
- Dati, owner, chiavi e decisioni dei test Engine sono SINTETICI; il parser APPROVO è provato separatamente con vero PTY/hash errato/suffisso rifiutati. Nessuna approvazione production simulata, nessun accesso runtime VPS o equivalenza CI/E2E.

Nuova lezione sul watchdog: il candidato precedente9e3406e5 aveva una PR verde ma il push classic121227656016 mostrava RECOVERY_FILE_CUSTODY_REQUIRED nel monitor lock-free. Non è stato consegnato al VPS. La nuova transazione evita che il publisher cooperante scolleghi il record durante la lettura: test con processi separati verifica che il publisher trovi lock occupato e prosegua solo dopo il rilascio; stress200pubblicazioni verifica contatori/ordini, ammettendo soltanto l'esaurimento esplicito dei retry per lock contention entro una finestra globale di test, mai metadata invalidi. Il primo fixture stress trattava anche questa contention bounded come errore: run40213810732/job121230509710 conservato. Un successivo job121231335106 ha riportato WATCHDOG_INTERNAL_STATE_UNPROVEN nel monitor: il tipo dell'eccezione interna non è stato trattenuto. L'esaurimento degli8tentativi per lock occupato è riprodotto separatamente nel test, ma non va retroprovato come unica causa di quel job. Il candidato con sola transazione849176ba è quindi superato dal profilo corrente: snapshot iniziale prima del READY e pausa read-only2s/64tentativi con jitter, mai retry di custodia. Il nuovo test verifica anche l'esaurimento finito di questa pausa.

Errori CI precedenti conservati: fixture unitario iniziale con forma modulo errata; job classic121226466046 interrotto per watchdog;121226864755 e121227656016 negativi senza checkpoint atteso, ultimo con diagnostic custodia. Non retroprovare il reasonCode del primo dal solo errore LIVE_BOUND.9e3406e5/e4c46f9 e849176ba/792dd600 sono superati per la consegna. L'ulteriore fallimento generale PROTECTED_METADATA_ANCESTRY_REQUIRED già documentato è distinto: nessuna dichiarazione di CI globale tutta verde.

Normativa originale allegata nuovamente consultata: Matrix1.7 §§1/7, Blueprint0.3 §§4/9/10, MCP1.4 §33, Authorization1.5 §36. Nessuna attestazione di conformità integrale o acceptance dal solo esito dei test.

## Prima esecuzione sul VPS

Usare il comando seguente UNA volta nel terminale VPS. Usa il client GitHub esistente (portable poi PATH), senza login/token in chat, verifica il wrapper prima di sudo e conserva i log bootstrap/operator. La password eventualmente chiesta da sudo è quella del sistema, non l'approvazione della review.

```bash
(
  set -euo pipefail
  umask 077
  ouf_gh="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
  if [ ! -x "$ouf_gh" ]; then ouf_gh=$(command -v gh || true); fi
  if [ -z "$ouf_gh" ] || [ ! -x "$ouf_gh" ]; then
    printf '%s\n' 'STOP: client GitHub esistente non disponibile.'
    exit 2
  fi
  ouf_delivery_dir=$(mktemp -d "$HOME/ouf-detached-recovery-delivery.XXXXXXXX")
  ouf_delivery_log="$ouf_delivery_dir/bootstrap.log"
  set +e
  (
    set -euo pipefail
    "$ouf_gh" api --header 'Accept: application/vnd.github.raw+json' \
      '/repos/GioNob/ouf-deploy/contents/releases/recover-acquisition-detached-mcp-20261025.sh?ref=222a9a52fd2c18e95279a67acaebeb7af6579457' \
      > "$ouf_delivery_dir/run.sh"
    printf '%s  %s\n' 'aa9774d615dcba08ab53bdd81670dc7a0ce9114ac4b8a27489a88a903733a8f7' "$ouf_delivery_dir/run.sh" | sha256sum --check -
    bash "$ouf_delivery_dir/run.sh"
  ) 2>&1 | tee "$ouf_delivery_log"
  ouf_delivery_rc=${PIPESTATUS[0]}
  set -e
  printf 'DeliveryExit=%s\nDeliveryDirectory=%s\nDeliveryLog=%s\n' "$ouf_delivery_rc" "$ouf_delivery_dir" "$ouf_delivery_log"
  exit "$ouf_delivery_rc"
)
```

Quando il programma mostra il file review e il nuovo SHA256, leggere la revisione. Per approvare, digitare ESCLUSIVAMENTE la riga APPROVO più hash che il programma stampa da sola. Non aggiungere spiegazioni o punteggiatura; non utilizzare hash delle review precedenti e non approvare da questa chat. Il parser rifiuta hash errato o suffisso.

Risultato positivo atteso:
`ACQUISITION_READ_PATH_INSTALLED_E2E_NOT_ACCEPTED`, complete=true, Exit0/DeliveryExit0,16stage residui, retainedAppliedStages13, restartedOwnQuarantinedReads2 e attestazione firmata. Restituire JSON pubblico finale e percorsi dei log. Le readiness sono prove di installazione, non evidence E2E.

Su qualsiasi STOP/CLAIMED/errore: conservare root, review, journal, candidati e log; NON rilanciare wrapper, cambiare child o ripetere stage. Effetti ambigui restano CLAIMED e richiedono riconciliazione. Non ripristinare il vecchio MCP. Anche una review rifiutata consuma il nuovo child. Nessuna procedura vecchia va ripetuta per compensare.

## Dopo il risultato VPS positivo

Solo allora: ouf-admin ROLES con link_id e viewROLES per verificare2ruoli/34permission/2assegnazioni; preparare le sei READ ristrette via HUMAN con nuova decisione valida, dato che policy48 è scaduta. Leggere le sole due acquisizioni SUCCEEDED esistenti bb2e2af4-9c0a-49ea-8ad9-a947987c1472 e a3208f2f-ebfd-415d-bddc-79ab05dea78f. Nessuna terza acquisizione, attivazione o reset.

Restano da chiudere run→bundle/CSV, ACK/watermark durevoli,13ID stabili/20proprietà/provenance e8Cinema preservati. Prove storiche502/403/GEToriginale200 conservate; tecnico8/8 e funzionale4/6, E2E/G4/F5/F6 OPEN. Supervisor dopo E2E. PR50 resta draft, nessun merge o release acceptance.
