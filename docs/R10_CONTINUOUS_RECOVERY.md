# R10: recupero continuo, qualificazione e applicazione target

> **Stato corrente, 11 ottobre 2026:** il piano nativo V11 è bloccato da `CURRENT_R12_PRIVATE_WORKER_UNPROVEN`, prima di ogni scrittura protetta. La lettura diretta del runner alle 20:48 UTC conferma R12 attivo, PID2446150, zero riavvii; non dimostra readiness o lease valide. La prossima operazione è la [diagnosi root di sola lettura](../releases/R12_READINESS_DIAGNOSIS_20261011.md), senza apply, restart o reset del budget. CSV Teatri end-to-end resta aperto.


Il vecchio R10 rimane consumato. Il suo fallimento dopo 250 rinnovi è storico;
il recupero operativo dei due flussi è confermato dalla ricevuta R12 riportata sotto.

## Current target state — R12 operational recovery confirmed, 11 October 2026

The operator supplied a successful VPS activation receipt: `TWO_FLOW_RESILIENT_LEASE_ACTIVE_AND_RENEWED`, worker `ACTIVE / RENEWED`, two renewals, one approved address per flow and exit 0. [Target receipt](../evidence/resilient-r12-active-target-20261011.json). This supersedes historical pending/failed observations below: the R10 lease incident has recovered through R12 at the activation observation, using the existing two flows and configuration.

The source-bound entrypoint requires the actual NET_ADMIN-only production guard to pass before consuming the R12 claim and verifies native lease readiness before reporting success. The successful receipt is operator-reported evidence of that path, not a direct assistant SSH read. The logical incident remains `34b9533ea3d8931bb9971ef7fa3b2ad9f423d5504350faa63421869f79817a73`; one recovery attempt and two renewals are reported. Consumed R10/R11 claims are preserved; cumulative recovery history is retained by the qualified transition. **Do not rerun R10, R11 or R12 applies.**

Service: `ouf-semantic-provider-lease-resilient-r12.service`. Target evidence: `/etc/ouf/deploy-snapshots/semantic-resilient-lease-recovery-r12-y048hyms`. No container lifecycle operations, private-key reads, signatures or provider calls by the worker are reported. Automatic restart and boot enablement remain disabled.

This observation establishes lease readiness at activation. It does not prove continuing availability, application health, application cutover, a fresh CSV end-to-end, release acceptance or whole-platform industrialization. Outage/pause/recovery, exhaustion and revocation are qualified in isolated CI; they have not been deliberately exercised on this target after activation. Future failures remain subject to the bounded resilience policy, with fresh evidence and authority required for restoration.

## Collegamento sviluppato

continuous_supervisor.py collega recupero durevole e rinnovo continuo. Il processo
rimane osservabile in RETRY_WAIT, PAUSED_EXHAUSTED, BLOCKED e RECONCILE_REQUIRED.
Un rinnovo sano conserva la lease precedente durante le nuove letture DNS; un
fallimento transitorio revoca e verifica i set prima delle pause incrementali.
DNS e pause sono fuori dai lock del journal e della lease. Solo la pubblicazione
ACL/readback usa il lock comune. TTL zero non viene accettato o esteso.

Il budget di recupero è unico per questa nuova sessione di servizio: 128 tentativi,
24 ore cumulative di recupero, non rinnovabile dal worker. I rinnovi sani non consumano
tentativi di recupero e non azzerano tentativi, deadline, contesto o incidente.
lease_recovery_budget.py conserva separatamente gli intervalli sani verificati:
non scambia un giorno di servizio sano per esaurimento del budget di un guasto.
Gli orari iniziali e i tentativi restano immutati; pause e tentativi di recupero
si sommano anche se intervallati da periodi sani. La vera scadenza dell'autorità
rimane indipendente e prevale sempre. L'esaurimento mantiene il processo vivo e
i flussi revocati.
Un eventuale nuovo budget richiede una nuova sessione governata, non un reset.
Il componente non concede nuova autorità o riavvio automatico.
L'autorità reale può imporre limiti ancora più brevi.

deadline_backend.py lega tutti i comandi nft di un tentativo alla stessa deadline.
Le query DNS sono limitate dalla deadline del tentativo e dal profilo DNS.
La revoca mantiene un budget separato per poter restringere anche dopo scadenza.
Il lock invocation.lock, distinto dai lock brevi, esclude processi concorrenti.
Un checkpoint ACTIVE ereditato da un'altra invocazione richiede riconciliazione.
Esiti ambigui, revoca, drift o errori ignoti non provocano retry.

## Prove e limiti

La workflow continuous-resilient-worker qualifica unit test, regressioni R10 e
un processo systemd con DNS UDP, nft inet/bridge, journal e lock reali.
La fixture esercita sano → indisponibilità di quattro ore virtuali → recupero
→ rinnovo sano → esaurimento → revoca durante parcheggio → stop.
Il tempo è accelerato soltanto con set vuoti verificati. Autorità, metadati di
generazione e scope sono sintetici; nessuna azione sul VPS è eseguita.
Gli esiti CI vanno registrati prima di dichiarare qualificato il candidato.

## Percorso storico di qualificazione e chiusura sul VPS

1. Completata la lettura protetta operatore del 11 ottobre 15:07 CEST: custodia
   R10/claim/journal, complete OCI, owner e peer/generazioni acquisiti. Non è
   autorità di apply. Il vecchio preflight rimane sospeso.
2. Nuovo entrypoint source-bound con autorità finita propria; sigillare tutti i
   moduli, comandi, antenati e snapshot, inizializzare il journal una sola volta.
   Non riutilizzare autorizzazione, unità o claim consumati R10.
3. Qualificare la chiusura completa dell'entrypoint con le reali interfacce e
   comporre la consegna immutabile. Entrypoint R11 qualificato al commit
   d0048f428bbe5bc499c5d5d5e9c3e407b573f835: 40 test mirati e apply reale
   in CI con systemd/DNS/nft. Replay e secondo worker rifiutati; due cicli attivi,
   pausa DNS, ripresa nello stesso processo, drift bloccato e stop con revoca.
   Metadati e autorità target sono fixture sintetiche dichiarate.
4. Eseguire il nuovo recupero sul target e acquisire stato attivo, rinnovi,
   membership e TTL positivi; dimostrare anche pausa/ripresa e revoca.

Solo questa ricevuta target chiude l'incidente operativo. CI o merge non lo
chiudono. CSV end-to-end resta successivo, come richiesto dall'owner.

Riferimenti: policy di piattaforma v3; Gateway1.5 T11/T11.3; Matrix1.7;
OUF_RESILIENCE_IMPLEMENTATION.md. Cinema e Teatri restano preservati.

## Consegna R11 e autorità tecnica

[Consegna immutabile](../releases/provider-resilient-r11-approved-20261011.sh),
[evidenza](../evidence/resilient-r11-entry-qualified-20261011.json).
La richiesta owner esplicita di recupero R10 delle 14:43:18 CEST autorizza
questa singola transizione tecnica; la finestra iniziale termina alle 16:43:18
CEST del 11 ottobre. Dopo scadenza non eseguire o modificare la consegna per
aggirarla: occorre una nuova decisione tecnica. Il servizio mantiene soltanto
le generazioni correnti di host, ruoli e peer; revoca, stop o drift ne impediscono
il recupero automatico. Nessuna nuova decisione semantica, container lifecycle,
riavvio automatico o avvio al boot. Il worker conserva CAP_NET_ADMIN; verifica
il peer tramite generazione, attachment Docker e link host reciproco, senza
nsenter runtime o CAP_SYS_ADMIN.

Tutti i 14 file sono scaricati dal medesimo commit e verificati prima di sudo;
l'entrypoint viene verificato nuovamente in memoria nel processo root isolato.
Il client GitHub portatile già presente viene scelto anche se gh manca da PATH.
Non vengono richiesti token, né scaricati file privati con curl anonimo.
28 posizioni di guasto download/alterazione e propagazione dell'exit tramite
tee sono verificate. Ricevuta target ancora necessaria: un merge non chiude R10.

## Osservazione target 15:38 CEST: recupero non riuscito

L'operatore ha applicato R11 una sola volta. Il worker è BLOCKED con zero tentativi,
zero rinnovi e set vuoti; claim R11 consumato, non rieseguire la consegna. Exit 0
indica soltanto che l'attivazione ha restituito la ricevuta del servizio parcheggiato,
non che il recupero sia riuscito. [Ricevuta riportata dall'operatore](../evidence/resilient-r11-blocked-target-20261011.json).

La prova native precedente sostituiva il controllo di scope di produzione con una
fixture: non copriva l'accesso /proc alle namespace di processi con UID diverso sotto
CAP_NET_ADMIN. Questa è una lacuna di qualificazione. La causa target resta da provare.
La nuova diagnosi read-only esegue il medesimo guard sigillato con root completo e,
in un processo figlio, con il solo NET_ADMIN e NoNewPrivileges; registra check/operazione,
classe e errno senza valori privati. Non chiama apply, crea claim, inizializza budget,
riavvia servizi o modifica lease/configurazioni. Nessun recupero target dichiarato.

## R12: causa provata e correzione senza aumento dei privilegi

La diagnosi target operatore del 11 ottobre, 15:47 CEST prova che il guard R11 passa
con root completo e viene negato sotto NET_ADMIN nella funzione generation, su
/proc/PID/ns/net (PermissionError errno 13). Non è un cambio reale di generazione.

R12 acquisisce tramite Docker il SandboxKey delle namespace dei due ruoli e del
Semantic esistente. In intake root verifica che il handle sia nsfs e corrisponda
alla stessa namespace /proc e generazione del PID, quindi sigilla path canonico,
device/inode e SandboxKey nel capsule. Il worker controlla quei valori, gli
antenati root protetti, PID/start ticks e metadati Docker correnti. Non aggiunge
SYS_PTRACE/SYS_ADMIN, non entra in namespace e mantiene NET_ADMIN soltanto.

Prima di creare il claim R12 esegue l'intero guard di produzione in un processo
figlio con gli stessi capability bounds e NoNewPrivileges del worker. Un errore
ferma l'apply senza claim e senza stop del predecessore; conserva una diagnosi
con il check specifico. Solo dopo il gate positivo ferma l'esatto R11 bloccato a
zero tentativi, conserva le sue fonti/claim e avvia la nuova unità sigillata.
IncidentRef, inizi del budget cumulativo e tentativi sono conservati dal journal
R11; i budget non ripartono da zero. Il vecchio journal resta nel suo snapshot.
Nessun cambio di container applicativo o decisione semantica THS.

[PR3](https://github.com/GioNob/ouf-deploy/pull/3),
[evidenza](../evidence/resilient-r12-qualified-20261011.json),
[consegna immutabile](../releases/provider-resilient-r12-approved-20261011.sh).
Qualificazione source 0149cc164ed57d76abb88e7346fe9e7648363e29: container Docker reale UID10001, vecchio
accesso negato e nuovo handle verificato con NET_ADMIN soltanto; inode/SandboxKey
drift negati. Pipeline reale systemd/DNS/nft: rifiuto preclaim senza consumo,
stop di predecessore transiente reale, due rinnovi, pausa/ripresa stesso PID,
budget conservato, blocco vivo e revoca. La metadata signed target della fixture
resta sintetica: il guard completo reale del VPS è verificato dal gate preclaim,
non dichiarato provato dalla fixture. Regressione outage virtuale quattro ore ed
esaurimento PASS. Consegna con 15 checksum e 30 posizioni download/alterazione.

La finestra iniziale resta 16:43:18 CEST; nessuna proroga automatica. Exit 0 richiede
due cicli attivi e lease native provate; una ricevuta parcheggiata usa exit 2 e
workerReason. Applicazione/preclaim target e ricevuta attiva sono ora confermati dall'operatore; vedere lo stato corrente in apertura.
