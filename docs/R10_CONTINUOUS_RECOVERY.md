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
