# Stato corrente OUF

Aggiornato il **7 novembre 2026**, Europe/Rome. Priorità: **SeaweedFS funzionante, poi E2E ripetibile; industrializzazione dopo**. Esecuzione sequenziale del solo agente principale.

## Risultato corrente

**F1 riuscito: Onboarding carica e profila il CSV dopo il passaggio a SeaweedFS. F2 aperto: UDP da collegare.**

- **Policy :61 verificata:** proposta `66ecf0fb-04e8-476b-9ce5-4fdc1dd496fa` PUBLISHED, revisione 1. Catalogo live identico al proposto: tre permessi admin corretti (profilazione, stato job, creazione bozza), altri 63 e tutte le 13 assegnazioni invariati. La pubblicazione è stata confermata da Giovanni nella THS.
- **Upload e lettura riusciti:** handoff `2de7b988-da47-4231-8443-0e5043214c42` → asset `c51745c5-1fc0-4d36-bdcf-1e9a8a049c94` STAGED → job `f460d4d5-c6f7-4b65-b305-08091e9849cf` SUCCEEDED → profilo `da3f17a2-5cbc-4d7d-9ed8-7f4b39a00342` letto via MCP. CSV UTF-8, separatore `;`, 13 righe e 20 colonne. Il sorgente installato verifica dimensione e hash del contenuto prima di salvare il profilo; il valore hash non è esposto dalla preview. [Evidenza](../evidence/onboarding-seaweedfs-profile-success-20261107.json).
- **Non ricaricare:** riprendere da questi riferimenti. Identità proposta `nome_teatro`, ancora PENDING_HUMAN_REVIEW. Coordinate inferite STRING, campione `4.565.094`/`1.376.850`: formato da chiarire prima del mapping, nessuna conversione automatica. Nessuna bozza sorgente o Ingestion avviata.

## Prossima azione: prova client UDP sul VPS

Lettura operatore delle **18:27 CET** riuscita: UDP immagine `ae78f604…`, JAR `/app/app.jar`, AWS SDK `2.54.17`. Ambiente dichiarato: MinIO HTTP, bucket `ouf-udp`, path-style true, regione us-east-1; nessuna rete condivisa con SeaweedFS e nessun truststore JVM personalizzato dichiarato. `SPRING_APPLICATION_JSON` presente: la lettura dei soli env non è una verifica della configurazione effettiva. [Ricevuta](../evidence/udp-current-storage-bindings-operator-20261107.json).

Eseguire il [blocco unico per il client installato](OUF_UDP_SEAWEEDFS_CLIENT_PROBE_20261107.md). Legge soltanto le voci storage del JSON, avvia un container temporaneo con la stessa immagine e chiama la factory e l'adapter UDP originali, verificati tramite SHA. Usa identità/CA SeaweedFS già preparate. HEAD di assenza su una chiave UUID nuova, un PUT logico, HEAD e GET con corpo/hash/metadati confrontati. Rimane un piccolo oggetto diagnostico, indicato nel risultato; container temporaneo e copia credenziali rimossi.

Nessuna fermata o cambio del servizio UDP, nessun avvio Spring/DB. Compilazione e controlli locali PASS; prova reale SDK/TLS sul VPS ancora pendente. La precedente assunzione errata sul nome JAR è corretta e il percorso ora è osservato, non ipotizzato.

Se il client passa: allineare i dati correnti UDP e cambiare il binding a writer fermo, conservando l'immagine. Poi proseguire l'E2E da asset/profilo già acquisiti: semantica locale, eventuale OntoPiA governata, Ingestion, riconciliazione e grafo. [MiniPET funzionale, PR #55](https://github.com/GioNob/ouf-deploy/pull/55).

## Binding e prove da conservare

- **Onboarding collegato alle 17:42 CET:** endpoint `https://ouf-seaweedfs-stage:9002`, bucket `ouf-managed-files`, stessa immagine `7b9d3e91…`, readiness UP e TLS verificato. Originale conservato spento. A writer fermo: 12 oggetti/40.709 byte coincidenti, zero copie aggiuntive, manifest `9bcfd9b3…`. CA privata aggiunta conservando i 118 certificati del JDK VPS. [Ricevuta operatore](../evidence/onboarding-seaweedfs-ready-operator-20261107.json).
- [PUT/GET curl e Java installato](../evidence/storage-client-comparison-success-operator-20261107.json) e [allineamento corrente](../evidence/onboarding-current-copy-aligned-operator-20261107.json) restano validi per il loro ambito. La vecchia causa del 502 su un'altra configurazione non è provata.
- Il [passaggio Onboarding](OUF_ONBOARDING_SEAWEEDFS_SWITCH_20261107.md) è già eseguito: non rilanciarlo e non riavviare il vecchio writer MinIO dopo le nuove scritture SeaweedFS. Usare l'[avviatore aggiornato](../scripts/ouf-runtime-20261107.py), che riconosce il nuovo container tramite marker.
- UDP mantiene il binding precedente. F2–F6 e il percorso fino al grafo sono ancora aperti; nessuna dichiarazione di produzione pronta.

## Problemi E2E ancora aperti

Il vecchio selettore è stato usato prima per Farmacie e poi per Teatri; il secondo invio ha dato HTTP_500. L'handoff `1d3c1a27-5a57-4e81-bbbc-2f6bc606c6ce` conserva l'asset `8061fad3-1a8b-4f65-9e4a-bfead7974cb7`, senza nome file esposto. Il rifiuto di riassociare lo stesso handoff è riprodotto sul sorgente, ma manca l'eccezione live; il secondo file potrebbe essere stato salvato. Correzione del selettore e riconciliazione restano aperte, senza cancellazioni. [Evidenza](../evidence/ths-upload-reuse-storage-next-20261107.json).

Non distribuire direttamente il vecchio commit diagnostico Onboarding `380e8dcb`: parte 20 commit prima del sorgente conservato `73498c17` e la build è fallita a Trivy. L'installazione funzionante resta quella conservata.

## Aggiornamenti

Aggiornare qui esito, blocco e prossima azione. Cronologia nel [log dei checkpoint](OUF_M2_CHECKPOINT_LOG.md); contratto E2E nel [MiniPET M2](OUF_M2_MINIPET.md). DR, RPO/RTO e industrializzazione rinviati.
