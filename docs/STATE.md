# Stato corrente OUF

Aggiornato il **7 novembre 2026**, Europe/Rome. Priorità: **SeaweedFS funzionante, poi E2E ripetibile; industrializzazione dopo**. Esecuzione sequenziale del solo agente principale.

## Risultato corrente

**F1 riuscito: Onboarding carica e profila il CSV dopo il passaggio a SeaweedFS. F2 aperto: UDP da collegare.**

- **Policy :61 verificata:** proposta `66ecf0fb-04e8-476b-9ce5-4fdc1dd496fa` PUBLISHED, revisione 1. Catalogo live identico al proposto: tre permessi admin corretti (profilazione, stato job, creazione bozza), altri 63 e tutte le 13 assegnazioni invariati. La pubblicazione è stata confermata da Giovanni nella THS.
- **Upload e lettura riusciti:** handoff `2de7b988-da47-4231-8443-0e5043214c42` → asset `c51745c5-1fc0-4d36-bdcf-1e9a8a049c94` STAGED → job `f460d4d5-c6f7-4b65-b305-08091e9849cf` SUCCEEDED → profilo `da3f17a2-5cbc-4d7d-9ed8-7f4b39a00342` letto via MCP. CSV UTF-8, separatore `;`, 13 righe e 20 colonne. Il sorgente installato verifica dimensione e hash del contenuto prima di salvare il profilo; il valore hash non è esposto dalla preview. [Evidenza](../evidence/onboarding-seaweedfs-profile-success-20261107.json).
- **Non ricaricare:** riprendere da questi riferimenti. Identità proposta `nome_teatro`, ancora PENDING_HUMAN_REVIEW. Coordinate inferite STRING, campione `4.565.094`/`1.376.850`: formato da chiarire prima del mapping, nessuna conversione automatica. Nessuna bozza sorgente o Ingestion avviata.

## Prossima azione: passaggio effettivo di UDP

**Prova client UDP riuscita alle 17:39:37 UTC / 18:39:37 CET.** Factory e adapter installati, AWS SDK `2.54.17`, hanno eseguito PUT/HEAD/GET su SeaweedFS: 33 byte, SHA-256 e metadati coincidenti. Container diagnostico rimosso; servizio originale invariato, Spring non avviato. Nel JSON dichiarato non risultano le proprietà storage selezionate; non è una lettura della configurazione effettiva Spring. [Ricevuta](../evidence/udp-seaweedfs-client-success-operator-20261107.json).

UDP mantiene per ora il binding MinIO e la rete `ouf-backend`; immagine `ae78f604…`, JAR `/app/app.jar`. Il [comando unico di passaggio](OUF_UDP_SEAWEEDFS_SWITCH_20261107.md) è pronto e verificato localmente: ferma temporaneamente UDP, confronta/copia il bucket corrente senza sovrascrivere oggetti diversi, ricontrolla la sorgente ferma e avvia il sostituto con la stessa immagine e il binding HTTPS SeaweedFS. Conserva il vecchio container spento e aggiorna il riferimento per le ripartenze. Rimuove soltanto il proprio oggetto diagnostico dopo verifica di hash; conserva gli altri oggetti aggiuntivi del target.

**Esecuzione VPS ancora pendente.** Il risultato atteso `UDP_SEAWEEDFS_READY` attesta cambio, readiness e TLS, non una normale operazione applicativa lake né l'E2E. Se il comando si ferma, riportare il JSON: dopo l'avvio del sostituto non riaccendere il writer MinIO.

Dopo il cambio: prova applicativa UDP e prosecuzione dai riferimenti CSV già acquisiti, con semantica locale, eventuale OntoPiA governata, Ingestion, riconciliazione e grafo. Nessuna nuova build necessaria. [MiniPET funzionale, PR #55](https://github.com/GioNob/ouf-deploy/pull/55).

## Binding e prove da conservare

- **Onboarding collegato alle 17:42 CET:** endpoint `https://ouf-seaweedfs-stage:9002`, bucket `ouf-managed-files`, stessa immagine `7b9d3e91…`, readiness UP e TLS verificato. Originale conservato spento. A writer fermo: 12 oggetti/40.709 byte coincidenti, zero copie aggiuntive, manifest `9bcfd9b3…`. CA privata aggiunta conservando i 118 certificati del JDK VPS. [Ricevuta operatore](../evidence/onboarding-seaweedfs-ready-operator-20261107.json).
- [PUT/GET curl e Java installato](../evidence/storage-client-comparison-success-operator-20261107.json) e [allineamento corrente](../evidence/onboarding-current-copy-aligned-operator-20261107.json) restano validi per il loro ambito. La vecchia causa del 502 su un'altra configurazione non è provata.
- Il [passaggio Onboarding](OUF_ONBOARDING_SEAWEEDFS_SWITCH_20261107.md) è già eseguito: non rilanciarlo e non riavviare il vecchio writer MinIO dopo le nuove scritture SeaweedFS. Usare l'[avviatore aggiornato](../scripts/ouf-runtime-20261107.py), che riconosce separatamente i nuovi container Onboarding e UDP tramite i rispettivi marker.
- UDP mantiene il binding precedente. F2–F6 e il percorso fino al grafo sono ancora aperti; nessuna dichiarazione di produzione pronta.

## Problemi E2E ancora aperti

Il vecchio selettore è stato usato prima per Farmacie e poi per Teatri; il secondo invio ha dato HTTP_500. L'handoff `1d3c1a27-5a57-4e81-bbbc-2f6bc606c6ce` conserva l'asset `8061fad3-1a8b-4f65-9e4a-bfead7974cb7`, senza nome file esposto. Il rifiuto di riassociare lo stesso handoff è riprodotto sul sorgente, ma manca l'eccezione live; il secondo file potrebbe essere stato salvato. Correzione del selettore e riconciliazione restano aperte, senza cancellazioni. [Evidenza](../evidence/ths-upload-reuse-storage-next-20261107.json).

Non distribuire direttamente il vecchio commit diagnostico Onboarding `380e8dcb`: parte 20 commit prima del sorgente conservato `73498c17` e la build è fallita a Trivy. L'installazione funzionante resta quella conservata.

## Aggiornamenti

Aggiornare qui esito, blocco e prossima azione. Cronologia nel [log dei checkpoint](OUF_M2_CHECKPOINT_LOG.md); contratto E2E nel [MiniPET M2](OUF_M2_MINIPET.md). DR, RPO/RTO e industrializzazione rinviati.
