# OUF 2 — istruzioni operative

## Priorità corrente dell'owner — 7 novembre 2026

Far funzionare SeaweedFS, poi rendere ripetibile l'E2E CSV fino al grafo UDP. Industrializzazione, DR, RPO/RTO e chiusura formale dei gate di produzione sono rinviati: non usarli come prerequisiti della prova funzionale non produttiva.

Giovanni ha fermato il filone parallelo e affidato anche il 403/THS al solo agente principale. La proposta di correzione del grant upload richiede conferma umana THS e successiva verifica browser. Il 502 della prova isolata Onboarding→SeaweedFS è distinto finché una prova non li collega.

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

