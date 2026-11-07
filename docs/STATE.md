# Stato corrente OUF

Aggiornato il **7 novembre 2026**, Europe/Rome. Priorità: **SeaweedFS funzionante, poi E2E ripetibile; industrializzazione dopo**. Esecuzione sequenziale del solo agente principale.

## Risultato corrente

**Onboarding e UDP collegati a SeaweedFS. F1 PASS; F2 resta aperto per la normale operazione applicativa UDP. Il blocco semantico è osservato: nel container girano sh e sleep, nessun Java e nessun listener 8080. Il primo avvio si è fermato prima del segnale per RETAINED_CONFIGURATION_CHANGED; nuovo controllo con ambito Semantic e differenze esplicite pronto.**

- **Policy :61 verificata:** proposta `66ecf0fb-04e8-476b-9ce5-4fdc1dd496fa` PUBLISHED, revisione 1. Catalogo live identico al proposto: tre permessi admin corretti (profilazione, stato job, creazione bozza), altri 63 e tutte le 13 assegnazioni invariati. La pubblicazione è stata confermata da Giovanni nella THS.
- **Upload e lettura riusciti:** handoff `2de7b988-da47-4231-8443-0e5043214c42` → asset `c51745c5-1fc0-4d36-bdcf-1e9a8a049c94` STAGED → job `f460d4d5-c6f7-4b65-b305-08091e9849cf` SUCCEEDED → profilo `da3f17a2-5cbc-4d7d-9ed8-7f4b39a00342` letto via MCP. CSV UTF-8, separatore `;`, 13 righe e 20 colonne. Il sorgente installato verifica dimensione e hash del contenuto prima di salvare il profilo; il valore hash non è esposto dalla preview. [Evidenza](../evidence/onboarding-seaweedfs-profile-success-20261107.json).
- **Non ricaricare:** riprendere da questi riferimenti. Identità proposta `nome_teatro`, ancora PENDING_HUMAN_REVIEW. Coordinate inferite STRING, campione `4.565.094`/`1.376.850`: formato da chiarire prima del mapping, nessuna conversione automatica. Nessuna bozza sorgente o Ingestion avviata.

## Prossima azione: avviare Java nel registro semantico

**Passaggio UDP riuscito alle 17:59:28 UTC / 18:59:28 CET.** Stessa immagine `ae78f604…`, endpoint `https://ouf-seaweedfs-stage:9002`, bucket `ouf-udp`. A UDP fermo: 110 oggetti/181.364 byte coincidenti, nessuna copia aggiuntiva, sorgente invariata, nessuna sovrascrittura. Il diagnostico è rimosso e non restano oggetti extra a destinazione. Readiness e TLS verificati; 118 certificati JDK conservati più CA privata; vecchio container spento. [Ricevuta operatore](../evidence/udp-seaweedfs-ready-operator-20261107.json). Il cambio è concluso: non rilanciarlo.

Verifiche successive tramite capability `ouf-admin`:
- Profilo CSV già acquisito ancora leggibile, 13 righe e 20 colonne; nessuna nuova profilazione.
- Stato operativo MCP HEALTHY, senza azione richiesta: riguarda il modulo MCP.
- `semantic.search(q=teatro, limit=20)`: **HTTP 502**, causa non ancora identificata.
- `ouf.ingestion.status(limit=10)`: **authorization denied**, non ritentato. Nel catalogo corrente nessun grant `ouf.ingestion.status`; admin possiede `ouf.semantic.search`. I grant configurati non certificano la decisione effettiva della richiesta.

**Causa immediata osservata alle 18:18:23 UTC / 19:18:23 CET:** il container Semantic contiene soltanto `sh` e `sleep`; zero processi Java, nessun listener sulla porta 8080 configurata in APISIX. L'unico listener rilevato è locale e non appartiene a Java. DNS corretto. [Ricevuta](../evidence/semantic-no-java-operator-20261107.json).

Il sorgente del comando di attesa è identificato in `gated_creation_plan.py`: attende `SIGUSR1` e poi esegue Java nello stesso PID. La proiezione precedente non esponeva il comando completo: **il nuovo avviatore verifica la corrispondenza esatta sul VPS prima di inviare il segnale**, insieme a immagine, argomenti, UID, capability, gestione del segnale e generazione del processo.

Difetto dell'avviatore corretto: `running`/health assente era accettato anche con la sola shell. Il nuovo modo [`semantic`](OUF_SEMANTIC_APPLICATION_START_20261107.md) avvia soltanto l'applicazione Semantic nello stesso container, attende Java e HTTP readiness UP; nessun nuovo container o immagine. Se Java è già attivo controlla solo readiness. Un invio con esito incerto non viene ripetuto sulla stessa generazione. In `e2e`, Semantic viene ora avviato dopo Gateway/APISIX/Caddy.

**Primo comando di avvio: HELD `RETAINED_CONFIGURATION_CHANGED`**, prima di `start_role` e del segnale; `startedRoles` e `alreadyRunningRoles` vuoti. [Ricevuta](../evidence/semantic-start-retained-configuration-held-operator-20261107.json). Il confronto generico non indicava ruolo o campi: la differenza reale sul VPS resta sconosciuta.

Corretto l'ambito del modo `semantic`: tutte le differenze sono riportate senza valori sensibili, ma per l'avvio singolo sono richiesti la configurazione esatta di Semantic e le immagini attese/stato running di PostgreSQL, Keycloak, Gateway owner, APISIX e Caddy. I marker storage rimangono verificati. Il modo `e2e` conserva il confronto completo di tutti i ruoli; nessuna impronta attesa è stata riscritta e nessuna differenza ignota è accettata per Semantic.

Eseguire il [comando aggiornato](OUF_SEMANTIC_APPLICATION_START_20261107.md): avvia Semantic soltanto se il suo confronto passa; altrimenti restituisce `semanticConfigurationCheck` e `retainedConfigurationMismatches`. Quattro controlli locali PASS, compreso il rifiuto della differenza sullo stesso Semantic e la conservazione del controllo globale. **Esecuzione aggiornata VPS pendente.** L'applicazione può accedere al DB durante il normale avvio; nessuna query diretta dello script. Dopo il successo ripetere `semantic.search` via MCP.

**Ancora da provare:** normale scrittura/lettura applicativa lake di UDP e CSV fino al grafo. Si prosegue dai riferimenti già acquisiti: semantica locale, eventuale OntoPiA governata, Ingestion, riconciliazione, grafo e ripetizione. La lettura dello stato Ingestion è un ostacolo osservato separato; nessun ampliamento di permessi preparato per aggirarlo.

## Binding e prove da conservare

- **Onboarding collegato alle 17:42 CET:** endpoint `https://ouf-seaweedfs-stage:9002`, bucket `ouf-managed-files`, stessa immagine `7b9d3e91…`, readiness UP e TLS verificato. Originale conservato spento. A writer fermo: 12 oggetti/40.709 byte coincidenti, zero copie aggiuntive, manifest `9bcfd9b3…`. CA privata aggiunta conservando i 118 certificati del JDK VPS. [Ricevuta operatore](../evidence/onboarding-seaweedfs-ready-operator-20261107.json).
- [PUT/GET curl e Java installato](../evidence/storage-client-comparison-success-operator-20261107.json) e [allineamento corrente](../evidence/onboarding-current-copy-aligned-operator-20261107.json) restano validi per il loro ambito. La vecchia causa del 502 su un'altra configurazione non è provata.
- Il [passaggio Onboarding](OUF_ONBOARDING_SEAWEEDFS_SWITCH_20261107.md) è già eseguito: non rilanciarlo e non riavviare il vecchio writer MinIO dopo le nuove scritture SeaweedFS. Usare l'[avviatore aggiornato](../scripts/ouf-runtime-20261107.py), che riconosce separatamente i nuovi container Onboarding e UDP tramite i rispettivi marker.
- UDP usa ora il nuovo binding; il suo `applicationHttpLakeOperationTested` resta false. F2–F6 e il percorso fino al grafo sono ancora aperti; nessuna dichiarazione di produzione pronta.

## Problemi E2E ancora aperti

Il vecchio selettore è stato usato prima per Farmacie e poi per Teatri; il secondo invio ha dato HTTP_500. L'handoff `1d3c1a27-5a57-4e81-bbbc-2f6bc606c6ce` conserva l'asset `8061fad3-1a8b-4f65-9e4a-bfead7974cb7`, senza nome file esposto. Il rifiuto di riassociare lo stesso handoff è riprodotto sul sorgente, ma manca l'eccezione live; il secondo file potrebbe essere stato salvato. Correzione del selettore e riconciliazione restano aperte, senza cancellazioni. [Evidenza](../evidence/ths-upload-reuse-storage-next-20261107.json).

Non distribuire direttamente il vecchio commit diagnostico Onboarding `380e8dcb`: parte 20 commit prima del sorgente conservato `73498c17` e la build è fallita a Trivy. L'installazione funzionante resta quella conservata.

## Aggiornamenti

Aggiornare qui esito, blocco e prossima azione. Cronologia nel [log dei checkpoint](OUF_M2_CHECKPOINT_LOG.md); contratto E2E nel [MiniPET M2](OUF_M2_MINIPET.md). DR, RPO/RTO e industrializzazione rinviati.
