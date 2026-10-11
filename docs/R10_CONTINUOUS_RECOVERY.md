# R10: recupero continuo, qualificazione e applicazione target

Il vecchio R10 rimane consumato. Ultima osservazione target: worker failed dopo
250 rinnovi, NFT_SET_TTL_UNPROVEN con expires intero zero, QUIESCED e set vuoti.
Questo documento non dichiara recuperato il VPS.

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

## Chiusura necessaria sul VPS

1. Nuova lettura protetta corrente di custodia R10/claim/journal, complete OCI,
   owner e peer/generazioni. Il vecchio preflight rimane sospeso.
2. Nuovo entrypoint source-bound con autorità finita propria; sigillare tutti i
   moduli, comandi, antenati e snapshot, inizializzare il journal una sola volta.
   Non riutilizzare autorizzazione, unità o claim consumati R10.
3. Qualificare la chiusura completa dell'entrypoint con le reali interfacce e
   comporre la consegna immutabile. Il componente qui non è ancora quell'apply.
4. Eseguire il nuovo recupero sul target e acquisire stato attivo, rinnovi,
   membership e TTL positivi; dimostrare anche pausa/ripresa e revoca.

Solo questa ricevuta target chiude l'incidente operativo. CI o merge non lo
chiudono. CSV end-to-end resta successivo, come richiesto dall'owner.

Riferimenti: policy di piattaforma v3; Gateway1.5 T11/T11.3; Matrix1.7;
OUF_RESILIENCE_IMPLEMENTATION.md. Cinema e Teatri restano preservati.


## Qualificazione e blocco di accesso — 11 ottobre 2026

Candidato da92a02e8fc246dbf77ac0584321039d13d2436a, [PR1](https://github.com/GioNob/ouf-deploy/pull/1) integrata. Push38141352405 e PR38141355412 PASS:62 test unit/regression e due percorsi nativi. [Evidenza](../evidence/continuous-resilient-worker-qualified-20261011.json). Il primo candidato aveva un errore di scheduling del primo ACTIVE, corretto e coperto da una prova del serve loop.

Il [tentativo tramite runner38141352468](https://github.com/GioNob/ouf-deploy/actions/runs/38141352468) riporta NOT_EXECUTED_ROOT_PERMISSION_UNPROVEN_OPERATOR_REQUIRED, exit1: la lettura root non è stata eseguita. La conclusione SUCCESS qualifica la segnalazione del blocco, non i vincoli protetti. Serve l'esecuzione operatore della [consegna immutabile di sola lettura](../releases/resilient-worker-current-intake-20261011.sh), SHA2566a853ef53dce2457c66a6f8ff43c4f5e7b77b1599308ecff26f625ab0a69c7cf, disponibile al pin da92a02e8fc246dbf77ac0584321039d13d2436a. Il sorgente interno è letto dal pin00a65cb9758c8f8cac40b1be51f0d5cfb58f3f64 e verificato prima e dopo sudo. Output fino a OUF_RESILIENT_WORKER_INTAKE_EXIT; non include password o segreti. Questo è un nuovo intake, non il preflight storico sospeso e non un apply.

R10 sul target resta non recuperato fino all'applicazione e ricevuta del nuovo servizio completo. La lettura corrente abilita la preparazione dei binding; non autorizza il servizio da sola.


## Correzione della consegna — client fuori dal PATH

L'esecuzione operatore si è fermata prima del download con gh: command not found; non ha raggiunto sudo o il reader. Il repository è privato: curl anonimo non è una sostituzione valida. La consegna ora cerca prima il client già usato dai launcher riusciti, $HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh, poi command -v gh. Entrambi i livelli di consegna devono usare il client verificato. Nessuna installazione o nuova autenticazione richiesta.

Nuovo SHA256 del launcher:0d0c320377e1d605b144b5e88922610cf0d0a8173c979a735e5aaf83a037f0ee. Il pin da92a… e hash6a853… sopra sono la consegna precedente difettosa per questo host. Il reader interno e hash431124… restano invariati. Sette prove locali PASS, inclusa esecuzione con client portabile e senza gh nel PATH, blocco download/hash prima di sudo e quattro prove dei binding. Nessun recupero target dichiarato.
