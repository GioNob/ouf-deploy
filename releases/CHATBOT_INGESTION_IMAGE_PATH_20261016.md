# Ripresa governata fase 6: PATH dell'immagine e container fallito conservato

## Stato target e causa provata

Fasi 1–5 completate e conservate; fase6 sospesa, fasi7–8 pendenti, CSV0/6.
Il secondo readback mostra che Entrypoint coincide con immagine e richiesta,
è java cercato via PATH, e l'errore Docker è executable file not found in $PATH.
Il PATH esplicito ereditato esclude JAVA_HOME/bin dell'immagine; JAVA_HOME
coincide già. Il container cbf3067d946cf21a8f4abbb03ed47a217f2f39624ed1a5fb23a642325129ee35
è created, mai avviato, PID0/ExitCode127/restart0; claim ingestion.start conservato.
Worker cancellato, dieci grant cumulativi (9+1), admission BLOCKED.

## Nuovo intento

La ripresa legge la catena immutabile completa fino alla review
62c8837120f9079cbf2dd026105ccce7befbbbfbbd09b1c67fc813e6a468f91e e
all'autorità b6335ae592c469d253a345c29352a6fe2180e1297a29146b98bf1048016b4fe4,
con journal/hashes e sessione v9 esatti. La precedente prenotazione di ripresa
rimane consumata; questa usa un distinto claim tipizzato.

Una nuova revisione HUMAN v10 autorizza al massimo una rinomina del CID fallito
verso un nome storico esclusivo, con claim persistito prima dell'effetto.
Non lo elimina e non ripete il suo start. Un esito ambiguo della rinomina resta
CLAIMED e richiede riconciliazione; doppia invocazione/revoca bloccano.
I dieci effetti UDP/Onboarding sono copiati senza replay. La rinomina originale
del vecchio Ingestion viene osservata sotto il nuovo intento, senza POST.
Seguono un nuovo create/start dalla stessa immagine e gli usuali readiness e
ripristino policy. Il nuovo piano conserva ogni campo tranne PATH e le relative
dichiarazioni/hash. PATH viene ricavato dai metadati dell'immagine verificata,
non da un percorso o default installativo codificato. JAVA_HOME rimane invariato.
Il CID nuovo deve differire dal CID fallito e dall'originale; il proprietario
verifica il claim di conservazione prima di adottarlo. Le configurazioni e gli
intenti precedenti rimangono immutati nei relativi journal privati.

Quattro backup copiati/verificati senza nuovi dump o restore; migrazioni MCP e
audit CLEAN conservati; Registry dieci effetti senza replay, APISIX otto passi
senza lifecycle replay e 74 route/28 effetti completati senza PUT. Segue MCP
applicativo, verifica complessiva e nuova lettura MCP dei ruoli prima del
rilascio produttori. HUMAN applicativo resta nei THS.

Dieci grant conservati, prossimo nuovo undicesimo; nuova finestra HUMAN finita
128 tentativi/3600 secondi, jitter/Retry-After/revoca/scadenze persistenti,
nessun primo grant, reset di budget, rinnovo automatico o servizio perpetuo.

## Altri possibili blocchi, evidenza e limiti

| Segnale | Valutazione |
|---|---|
| UDP e Onboarding | Running, PID/generazione invariati, restart0; PATH/JavaHOME coerenti con le rispettive immagini. |
| ExposedPorts/Volumes false nella proiezione diagnostica | Confronto aggiuntivo che normalizza None a dizionario vuoto; i campi richiesti strict risultano conformi. Non prova deriva. |
| RestartPolicy false nella proiezione UDP/Onboarding | Confronto con policy no della create request; dopo la fase completa la policy originale è ripristinata. Il proprietario confronta restoreRestartPolicy. |
| Ingestion migrazioni/readiness | Ancora non provate sul nuovo processo. Il pacchetto c48ee4b... ha 18 migrazioni e readiness DB/Flyway; la ripresa deve verificare storia prevista e readiness prima di avanzare. |
| Dipendenza circolare Ingestion/MCP | Nel pacchetto qualificato il gruppo readiness include readinessState e ingestionReadiness (SQL PostgreSQL/Flyway), non chiama MCP. Non è una verifica della futura risposta target. |
| MCP non in esecuzione | Atteso: fase7 non ancora eseguita. Dockerfile f249b3d... usa /usr/local/bin/ouf-mcp assoluto, quindi non dipende dalla ricerca di java nel PATH. Avvio e accesso ai mount restano da provare. |
| Autorizzazioni e token | I ruoli conservati sono legati alla policy corrente; è obbligatoria una nuova lettura MCP dopo il suo avvio. Worker cancellato/admission bloccata sono coerenti con la sospensione. |
| databaseFenceProven=false | Non prova una nuova finestra DB fenced nell'installazione già avviata; non autorizza restore o rigenerazione dei backup. |
| Deploy distribuito | Questo adattatore storico è locale Docker/netns. Nessuna qualifica multi-host/multi-network; domini, secret e binding rimangono nei piani approvati, PET e resilience v3 vincolanti. |

La pianificazione generale ora rifiuta prima della create un PATH Java ereditato
che nasconde JAVA_HOME/bin del pacchetto, richiedendo una variazione esplicita
revisionata. Nessun aggiustamento silenzioso dei valori di altri Enti.

## Sorgenti operative

Runtime d7bbb768970aad1a001ca4d085bcc87c58a29cec.
Capsula131 SHA256 9f754dbcf7caf450d1d1eef50c0288f2102cfac191a65cfc60a5c1fcbf60ba5e.
Delivery SHA256 5cf2c1b37e8f28249d92060006d8176a9d001c26be30c6807cb6cc08a6d61d9a.
Launcher scripts/launch-chatbot-ingestion-image-path-20261016.sh,
SHA256 3bd2f8c8a883a59c805b3de7a1135fdc09afdcdc53f04ab966b16152f2e1e03d.

Le qualifiche non avanzano lo stato del VPS. Le prove native Java usano un
binario statico di pausa chiamato java per provare lookup/rename/start Docker;
non provano le migrazioni o la readiness dell'applicazione Ingestion target.
L'enrichment e l'adozione usano journal/file privati e firme reali con effetti
Engine simulati; il trasporto e gli effetti fisici sono qualificati separatamente.

## Qualifiche concluse e suite ancora in corso

CI 38882690699, job 116912944138: PASS, tre test nativi. Docker riproduce
il fallimento per PATH e conserva il CID fallito, verifica la rinomina senza
altre derive, poi avvia un nuovo CID cambiando soltanto PATH. APISIX reale
conferma l'adozione dei 28 effetti completati senza nuove PUT o lifecycle.
Job 116912944512: PASS, 29 test in otto suite senza skip; include vero grant
TLS undicesimo dopo dieci conservati, review completa v10, firme/revoca,
perdita ACK della rinomina, custodia, conservazione vecchi journal e assenza di replay.
CI backup 38882690674, job 116912943811: PASS.
Locali: sette test della nuova ripresa, 12 terminale e sette planner PASS;
controlli di consegna/capsula PASS. Nessun accesso al VPS da Codex.
La suite generale aggiuntiva 38882690718/job116912944574 è ancora in corso
al rilascio: non viene presentata come passata. Le qualifiche mirate completate
coprono la modifica e le interazioni interessate; la qualifica generale non
sostituisce comunque la readiness e le migrazioni applicative del target.
