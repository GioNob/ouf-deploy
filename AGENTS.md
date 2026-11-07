# OUF 2 — istruzioni operative

## Produttore token Semantic — correzione del 7 novembre 2026

**Aggiornamento 20:43 CET:** il ripristino Semantic v2 è HELD/TYPED_SERVICE_METADATA_READ_FAILED prima degli effetti. Override esatto e tre nomi omessi verificati; mancano fase D-Bus, exit code e stderr. I test precedenti simulavano D-Bus. Prossimo passo: [diagnosi di sola lettura](docs/OUF_SEMANTIC_SYSTEMD_BUS_DIAGNOSTIC_20261107.md); non rilanciare il mutatore finché non è noto l'errore.


Usare il servizio continuo `ouf-registry-token-7cb59501000058b5dc5030ad.service`. La coppia `ouf-policy-token@semantic.service/.timer` era già masked prima della cattura: non smascherarla. La cattura ha fermato/disabilitato il produttore operativo e installato `zzzz-ouf-storage-offline-20261106.conf` (Restart=no, SendSIGKILL=no, RuntimeDirectoryPreserve=yes, TimeoutStopSec=120s); l'avviatore generale lo omette. Due comandi del 7 novembre si sono fermati senza effetti: produttore legacy errato alle 19:06, poi SERVICE_METADATA_INCOMPLETE sul produttore corretto alle 19:18. La seconda ricevuta espone Restart=no ma non i nomi mancanti.

Le proprietà Exec vuote possono essere omesse dall'output testuale: riusare la lettura tipizzata D-Bus già presente in `scripts/storage-host-containment-20261106.py`, non inferire array vuoti dall'assenza. Il [comando v2](docs/OUF_SEMANTIC_TOKEN_RENEWAL_20261107.md) verifica gli hook tipizzati, conserva e rimuove solo l'esatto override di cattura del produttore fermo, verifica ripristino e altri drop-in invariati, poi avvia il servizio esistente. Nessun reset del registro. 19 scenari locali PASS; VPS pendente. Dopo successo provare ricerca MCP, rinnovo successivo e completare l'avviatore generale.

## Priorità corrente dell'owner — 7 novembre 2026

Far funzionare SeaweedFS, poi rendere ripetibile l'E2E CSV fino al grafo UDP. Industrializzazione, DR, RPO/RTO e chiusura formale dei gate di produzione sono rinviati: non usarli come prerequisiti della prova funzionale non produttiva.

Giovanni ha fermato il filone parallelo e affidato anche il 403/THS al solo agente principale. La correzione del grant upload è pubblicata nella policy :60; il selettore si apre e il primo handoff è STAGED. Il riuso dello stesso link per un altro file ha dato HTTP_500: preservare la prima ricevuta e riconciliare il secondo esito prima di ripetere. Il 502 della prova isolata Onboarding→SeaweedFS è distinto finché una prova non li collega.

## Regola MAC da consultare prima di modificare i container

Prima di creare/sostituire container o confrontare `Config`/`NetworkSettings`, leggere [la regola permanente MAC](docs/OUF_LEARNED_CONTAINER_MAC_INVARIANTS.md) e il [precedente del 25 ottobre](docs/handoffs/OUF_ACQUISITION_MAC_LESSON_AND_RETAINED_STATE_20261025.md). Distinguere `Config.MacAddress` legacy dagli endpoint per rete. La primitiva `tools/acquisition_read_native/retained_mac.py` copre soltanto il vecchio container dopo STOP/DETACH provati: non usarla per ammettere automaticamente differenze sui sostituti running. Vietate esclusioni globali del campo o riscritture delle impronte. Per un caso diverso riportare presenza/tipo del campo prima e dopo, corrispondenza con gli endpoint e fase del lifecycle; qualificare quel profilo prima di modificare il guard. Non riscoprire il problema come se il precedente non esistesse.

## Da leggere per riprendere

1. [Stato corrente](docs/STATE.md): blocco e prossima azione.
2. [MiniPET funzionale SeaweedFS → E2E](docs/OUF_STORAGE_MINIPET.md): risultati F1–F6 e criteri di riuscita.
3. [Registro funzionale e fonti](releases/storage-functional-status-20261107.json): fatti, limiti e stato delle prove.
4. [MiniPET M2](docs/OUF_M2_MINIPET.md), [PET/Matrix](docs/baseline/v1.7/README.md) e [policy di resilienza](docs/OUF_RESILIENCE_POLICY.md) per i contratti coinvolti. Non riaprire tutti i filoni di accettazione per correggere un binding.

## Come lavorare

- Agente principale, esecuzione sequenziale, senza subagenti o automazioni operative. Procedere con il lavoro autorizzato, aggiornando Giovanni su risultati e blocchi concreti.
- Non inventare cause, risultati, stati live, percentuali o scadenze. Separare codice, prove isolate, ricevute operatore e osservazioni attuali.
- Completare un percorso applicativo; non costruire nuove infrastrutture di test se non risolvono un difetto concreto. Riutilizzare le prove già valide.
- Non cambiare dati o proprietà per fingere successo. Conservare ID, URI, hash, lineage e decisioni HUMAN; niente bypass TLS/IAM o credenziali nei report.
- Non rigiocare claim/comandi consumati, resettare budget o cancellare parziali. Le autorizzazioni già espresse restano acquisite nel loro perimetro; non richiedere consensi generici ripetuti.
- Le vecchie dichiarazioni “tutti fermi” sono osservazioni storiche: stack MinIO e SeaweedFS risultano successivamente riavviati. Prima del cambio verificare i dati correnti e impedire scritture sui due backend contemporaneamente.
- Controllare HEAD e lavoro concorrente prima di scrivere. Per il 403/THS preservare i risultati del filone fermato e seguire lo stato corrente. Nessun merge o effetto runtime è attestato dal solo aggiornamento documentale.
- Aggiornare STATE e il registro funzionale; aggiungere gli eventi nel log, senza impilarli in questo file.

## Storico conservato

Il precedente AGENTS di 1.521 righe è [conservato integralmente nello snapshot Git](https://github.com/GioNob/ouf-deploy/blob/6c17d701221322ad8d5c8284254a6aa1eb0d727f/AGENTS.md). È cronologia delle singole operazioni, non una lista di comandi da rieseguire. Le ricevute originarie e i source-lock restano nei rispettivi percorsi.

