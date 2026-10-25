# OUF — review APPLY rifiutata per istruzione ambigua

## Stato corrente

Il primo APPLY è stato eseguito UNA VOLTA sul VPS. Il wrapper e il manifest root hanno superato i checksum. È stata prodotta la review privata con hash `4cdc8631745c00589e89c4763b34f57451032be714d168447df998dbbd1da328`. Il prompt scriveva «Scrivi APPROVO <hash> per la sola revisione esatta.» sulla stessa riga. L’operatore ha copiato l’intera frase; il parser esatto ha rifiutato il suffisso. È un difetto UX/consegna dell’assistente, non un errore da attribuire all’operatore.

Risultato VPS riportato: STOP_RECONCILE / EXACT_ACQUISITION_REVIEW_NOT_APPROVED / complete=false, Exit2/DeliveryExit2. Raw receipt: `evidence/acquisition-read-unapproved-review-stop-target-20261025.json`. Nessun timestamp di invocazione VPS fornito. Nessun JSON issued o risultato finale ricevuto.

Il reasonCode esatto nel codice pinned colloca questo STOP in terminal_decision, PRIMA di issue, firme, initialize, watchdog, import e mutazioni. Il flag generico runtimeEffectsMayBePartial=true rimane nella ricevuta raw; non prova effetti né autorizza a presumere marker assenti senza ispezione. La verifica offline delle prove conservate è il prossimo passo, non un altro APPLY.

Scope APPLY CONSUMATO:
`/etc/ouf/deploy-snapshots/acquisition-read-apply-5fa62e4f6869a6f40fb512878dcf65dcb6ffaf941be487e4189826f418046591`.
Non rilanciare il wrapper 84346ce, non cancellare/riaprire/rinominare scope, non modificare i 16 sorgenti root installati. Review e tutti i claim/preflight restano intatti.

Log operatore: `/home/oufadmin/ouf-acquisition-native-apply.bg9Pmstk/operator.log`.
Delivery: `/home/oufadmin/ouf-acquisition-apply-delivery.Tqy5Vf6a/bootstrap.log`.

## Prossimo passo qualificato: sola riconciliazione offline

Sorgente `scripts/read-acquisition-unapproved-review-20261025.py` al commit `02eb3f45e0d91e5960c46b7bea0de6a5f11e1d4c`, SHA256 `7f5aca8e3fd2827b21c1d871e5a29749f52825f18cac4918ae921e0178408619`.
Wrapper `releases/read-acquisition-unapproved-review-20261025.sh`: scarica UN sorgente pinned, checksum prima/dopo copia root0400 in directory esclusiva0700, FD no-follow/fstat/hash e fsync, poi Python -I -S -B. Log/Exit conservati. Nessun vecchio entrypoint importato o eseguito; nessuna nuova approvazione runtime richiesta dal lettore.

Il lettore apre solo manifest/16 sorgenti GIÀ installati, native-inputs e file retained della preparazione/review. Non apre file admin, trust policy live o chiavi. Non legge /proc e non usa Engine, APISIX, SQL, OAuth, namespace o account alternativo. Limiti30s/96letture metadata/32MiB. Crea solo il figlio esclusivo `unapproved-review-reconciliation-v1` sotto la root logica originale, con claim e risultato immutabili. Gli altri file parent non vengono riscritti.

Verifica hash esatto review/manifest/input, closure, assenza di qualunque entry post-review (authority/journal/result/quarantine), sequenza completa e conteggi claim, due controlli finali di stabilità. Il profilo pre-review atteso dal codice è9EngineGET/1adminGET/5ownerConfig/1fileadmin, zero mutazioni/import/readiness/PUT/quarantena. Sono conteggi DA VERIFICARE sul VPS, non una nuova osservazione. I precedenti12EngineGET/8metadata/2publicAuthority e planner1GETadmin/1fileadmin restano separati e conservati.

Atteso: `UNAPPROVED_ACQUISITION_REVIEW_RECONCILED_NO_AUTHORITY`, complete=true/Exit0. Pubblica soltanto hash, contatori e booleani; nessuna review/configurazione/Env/credenziale. currentRuntimeStateObserved=false e continuationAuthorized=false: il lettore non prova lo stato corrente dei container e non autorizza effetti. Ogni STOP conserva child/claim/log e vieta rilancio.

CI sorgente02eb3f4, filesystem root reale e input storici SINTETICI: push40203542674/job121199574568 e PR40203545825/job121199583966,13PASS/0skip entrambi; log diretti letti. Anche13PASS locali con radice fixture spostata nello scratch (unica variazione di harness locale, nessun guard modificato). Non prova il bootstrap scaricamento/sudo del wrapper completo: wrapper bash-n/static review separati.

Wrapper SHA256 `8457f27548719d7c8a945e5ff2bdd24ebedc3d48d0294f22a95f91d053e606cb`; bash-n PASS/static review, sorgente pubblicato byte-identico verificato prima della consegna. Qualifica strutturata: `evidence/acquisition-unapproved-review-reader-qualified-20261025.json`.

## Prompt corretto e continuazione successiva

Il sorgente protocol.py ora mostra istruzione e spiegazione su righe separate; l’unica riga che inizia per APPROVO contiene SOLO verbo e hash. Il parser non è stato allentato: suffissi, punteggiatura e hash sbagliato restano negati. Test PTY reale verifica le righe del prompt, rifiuto dell’esatta frase ambigua precedente e successo del solo comando. Protocollo CI push40203542573/job121199574567 e PR40203545823/job121199583509:10PASS/0skip ciascuno, log diretti letti. In locale la suite protocollo è bloccata dall’assenza di /proc/sys/kernel/random/boot_id: non è dichiarata PASS locale. Le nuove modifiche non sostituiscono i vecchi16 file installati né qualificano da sole un nuovo APPLY.

Regressione nativa aggiuntiva02eb: push40203542573 classic/containerd2PASS ciascuno; PR40203545823 containerd2PASS, classic/job121199583738 FALLITO in CREATE_MCP/candidate_guard per LIVE_BOUND_NEGATIVE_WATCHDOG_REQUIRED. Anche in quel job il test SIGKILL/quarantena è PASS. Log diretto letto, causa dell’uscita watchdog NON stabilita; nessun rerun per ottenere verde e nessuna guardia allentata. Non chiamare l’intera nuova coorte APPLY qualificata: questo blocca una futura continuazione mutante, non il lettore offline che non importa né usa quei moduli.

Dopo la ricevuta offline, progettare SOLO la continuazione del medesimo incidente, con contatori precedenti incorporati. Il limite serviceCredentialFileReads=1 del vecchio preflight è già consumato secondo il codice: non rileggere la chiave né ricreare Context azzerando counts. Qualsiasi ulteriore lettura indispensabile e relativi limiti cumulativi devono essere dichiarati in un nuovo mandato concreto, qualificato e approvato nel terminale PRIMA della lettura; non ricavare autorità dalla vecchia review rifiutata. Nessuna continuazione mutante è attualmente consegnata o autorizzata dal lettore.

E2E/G4/F5/F6 restano OPEN, tecnico8/8/funzionale4/6; prove502/403 osservate conservate; Supervisor dopo E2E. Nessuna terza acquisizione, nuova attivazione, grant fonte, reset budget, Registry restart/reinstall, merge o release acceptance. Solo dopo APPLY provato: ouf-admin, ROLES senza parametri extra, sei READ ristrette con decisione HUMAN valida (policy48 scaduta), poi le DUE acquisizioni già esistenti.
