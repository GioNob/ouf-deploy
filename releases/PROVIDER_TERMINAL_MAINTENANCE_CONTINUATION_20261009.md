# Ripresa della manutenzione terminale dopo la scadenza del 9 ottobre 2026

## Stato corrente — 16:07:45 Europe/Rome

Le sezioni successive sono il checkpoint storico precedente al rinnovo. Il tentativo approvato alle 15:20:18 ha consumato la propria claim ed è BLOCKED: entrambi i task restano STOPPED, wrapper R5 ripristinato, guardia vuota e tutti gli 83 file verificati conservati. Non rieseguire quel launcher. La diagnosi ha confermato il difetto del confronto lessicale del runtime root; la correzione ammette soltanto l’alias osservato e mantiene il controllo del root canonico.

Il recupero separato è stato esplicitamente autorizzato con “Autorizzo” alle 16:07:45, con scadenza invariata 17:20:18 del 9 ottobre 2026 Europe/Rome. Seguire [revisione, approvazione, CI e launcher correnti](PROVIDER_TERMINAL_ALIAS_RECOVERY_REVIEW_20261009.md). Usa la nuova claim monouso senza alterare quella fallita. Esecuzione operatore ancora da acquisire; nessun avvio provider autorizzato. Conservare le accettazioni precedenti. Il prossimo passo è il nuovo launcher fissato, una sola volta, poi lettura della ricevuta completa.

## Stato ricostruito storico

Ricostruzione dal commit `2e4aac731c6439e0b3399695a69756ea85ef9db6` di ouf-deploy, dal launcher, dall'esecutore e dalle ricevute conservate. I sei repository applicativi sono stati consultati tramite README, revisioni recenti e PR aperte; main non rappresenta automaticamente le revisioni installate.

L'approvazione umana delle 14:04:46 Europe/Rome rimane registrata con riferimento `OUF_TERMINAL_TASK_CLEANUP_HUMAN_APPROVAL_20261009_140446`. La finestra eseguibile termina il 9 ottobre 2026 alle 15:04:46 Europe/Rome, cioè 13:04:46Z. L'esecutore richiede `APPROVED_AT <= now < APPROVED_AT + 3600`: anche l'istante esatto di scadenza è escluso. Questa ricostruzione avviene dopo la scadenza.

Nessuna ricevuta di esecuzione della manutenzione sul VPS è presente nello stato GitHub esaminato. Questo non dimostra che un operatore non abbia eseguito il comando nel frattempo. Non è stato acquisito un nuovo inventario live in questa sessione e non sono stati emessi comandi verso il VPS.

## Perimetro già approvato e da conservare

- Southbound: `1fc5ae6a0db4600e0124bb1f9d2998780d533fd2b4de7cb086d8675b6afb5916`.
- Adapter: `f3d59af93fc90162681cee3a7562bdff3bf2af8c05cbdb7e270d1508fff18f67`.
- Una sola manutenzione dei due task STOPPED, con ctr all'endpoint esplicito `/run/containerd/containerd.sock`, namespace `moby`, senza force/kill/start.
- Conservare container Docker, immagini, snapshot, dati, metadati containerd, input, sorgenti, journal, claim, firme ed evidenze precedenti.
- Gate temporaneo delete-only per massimo 120 secondi e ripristino degli stessi bytes del wrapper R5, SHA256 `4bd86d0c27039a238ac4894cf0c151745c92814c94af7b5a2f2ed173b70d685a`.
- Nessun avvio provider, lease, chiamata provider, riavvio daemon, rimozione container o retry automatico.

La [revisione concreta già approvata](PROVIDER_TERMINAL_TASK_CLEANUP_REVIEW_20261009.md) descrive i controlli prima e dopo la mutazione. Le accettazioni delle immagini e dei sedici input/rootfs non vanno richieste di nuovo.

## Verifica del blocco temporale

Sul codice attualmente pubblicato sono passati i sei test locali di esecutore e gate. Una verifica aggiuntiva ha invocato main con il riferimento approvato e un loader sostituito con un errore sentinella: prima dell'inizio, alla scadenza esatta, un secondo dopo e all'ora corrente, il risultato è `LIVE_HUMAN_MAINTENANCE_APPROVAL_REQUIRED`, zero richieste di cancellazione, loader mai raggiunto e nessuna claim riservata. Sono prove locali, non osservazioni del VPS.

La CI nativa dopo il binding dell'approvazione è [37927796726](https://github.com/GioNob/ouf-deploy/actions/runs/37927796726), conclusione success. La CI precedente [37927151726](https://github.com/GioNob/ouf-deploy/actions/runs/37927151726) resta conservata. Entrambe sono prove dell'implementazione, non accettazione target.

## Passo concreto ora

1. Non eseguire il launcher scaduto e non modificare l'orologio o il limite di 3600 secondi.
2. Se l'operatore dispone già di una ricevuta della manutenzione, acquisirla integralmente prima di preparare qualsiasi nuova esecuzione. Una claim presente, un'esecuzione parziale o un wrapper diverso richiedono diagnosi della ricevuta e ripristino esplicitamente verificato; nessun replay.
3. Se la manutenzione è ancora ineseguita, ottenere soltanto il rinnovo temporale di una finestra di un'ora per il medesimo intervento concreto, senza ampliarne il perimetro. Conservare la vecchia approvazione; registrare il nuovo messaggio/timestamp reali in una nuova ricevuta e aggiornare soltanto il binding di approvazione dell'esecutore e i pin/hash del launcher. Non inventare un'approvazione o anticiparne il timestamp.
4. Verificare il binding e il launcher, quindi fornire il comando fissato alla nuova revisione. Riutilizzare il reader già presente `/home/oufadmin/ouf-terminal-review.aA1bun9h/read.py`. L'esecutore deve ricontrollare sul target tutti i fatti, le generazioni shim, i metadati, la guardia e l'assenza della claim prima di mutare.
5. Conservare l'intero risultato operatore e verificarne task assenti, metadati conservati, wrapper ripristinato, journal preservati e guardia vuota. Nessun avvio è implicato.
6. Solo dopo una ricevuta di successo, preparare un nuovo contesto di ammissione: R5 è consumato e non va rieseguito.

L'accesso GitHub in lettura/scrittura è disponibile. Il percorso documentato per questa scrittura root sul VPS resta l'operatore: il runner ha privilegi limitati e questa sessione non dispone di un canale terminale autenticato verso il target.

## Continuità del progetto

Il CSV Teatri è già caricato e profilato: asset `6609b245-86ed-4315-8ce0-73f2a8555bf3`, profilo `7984c39c-7396-4248-ab0a-f2efc390b49c`. Non ricaricarlo. Il percorso resta discovery nazionale, senza fallback locale, poi scelta/adozione/pubblicazione semantica con autorità umana, Onboarding governato, Ingestion e verifica UDP in chat. Le PR Semantic #31/#32, Gateway #57 e MCP #49 restano bozze; nessun merge o rilascio è implicato da questa manutenzione.

Il pacchetto allegato Reality Baseline v1.7 ha superato la verifica completa di SHA256SUMS. Consultati L0 Matrix v1.7, Blueprint e notice di supersession, nonché i confini e le sezioni operative pertinenti dei sette PET. L0/L1 correnti e contratti restano la base da consultare per ogni successiva modifica. In particolare: AUTH-05/06/07/08/09/12, conservazione delle evidenze, nessuna autorità umana inventata, Gateway mediation, ownership dei backend e distinzione tra CI, ricevuta operatore e accettazione live.
