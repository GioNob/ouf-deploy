# Stato corrente OUF

Aggiornato il **7 novembre 2026**, Europe/Rome. Priorità: **SeaweedFS funzionante, poi E2E ripetibile; industrializzazione dopo**. Esecuzione sequenziale del solo agente principale.

## Risultato corrente

**F1 PASS. Onboarding e UDP collegati a SeaweedFS. Il produttore del token Semantic è ripristinato: servizio active/enabled, nuovo token montato e GET policy :61 HTTP 200. Le successive chiamate MCP di ricerca e lettura della revisione Teatri riescono. F2–F6 restano aperti.**

- **Upload e lettura riusciti:** handoff `2de7b988-da47-4231-8443-0e5043214c42` → asset `c51745c5-1fc0-4d36-bdcf-1e9a8a049c94` STAGED → job `f460d4d5-c6f7-4b65-b305-08091e9849cf` SUCCEEDED → profilo `da3f17a2-5cbc-4d7d-9ed8-7f4b39a00342`. CSV UTF-8, separatore `;`, 13 righe e 20 colonne. Preview riletta dopo il ripristino Semantic. Il codice installato controlla dimensione/hash prima di salvare il profilo; il valore hash non è esposto dalla preview. [Evidenza F1](../evidence/onboarding-seaweedfs-profile-success-20261107.json).
- **Policy :61 già pubblicata e verificata:** nessun nuovo permesso modificato per recuperare Semantic. Proposta `66ecf0fb-04e8-476b-9ce5-4fdc1dd496fa` PUBLISHED. Il GET host del ripristino legge proprio la :61; la versione caricata in memoria dalla JVM non è letta direttamente.
- **Semantic applicativo riuscito:** `semantic.search(q=teatro)` e `q=Theatre` restituiscono liste vuote; `q=Teatri` restituisce l'ontologia ACTIVE 1.0.0. `semantic.get` con revisione e publication set esatti restituisce lo snapshot completo di 105 statement. Il precedente 403 non si presenta in queste chiamate. [Evidenza MCP](../evidence/semantic-recovery-functional-read-20261107.json).

## Prossimo passo concreto

[Mapping proposto per il nuovo CSV](OUF_TEATRI_SEAWEEDFS_MAPPING_REVIEW_20261107.md): riuso di Teatri 1.0.0, tutte le 20 colonne incluse, `RESTRICTED`, `IDENTITY`, chiave `nome_teatro`. Corrispondenza delle 20 colonne e presenza dei termini verificate sul profilo attuale e sulla revisione pubblicata. CAP e coordinate restano testo: nessuna conversione di `4.565.094`/`1.376.850` in coordinate numeriche.

**Manca la scelta dell'owner sul mapping/accesso del nuovo asset.** Il contratto di `source.onboarding.create` richiede profilo rivisto e scelte dei campi/semantica; il successo della vecchia sorgente non approva automaticamente quella nuova. Preparato il [payload esatto](../releases/TEATRI_SEAWEEDFS_MAPPING_REVIEW_20261107.json), non inviato. Dopo la scelta: creare una bozza idempotente, leggere versione/hash e preparare la review nativa THS, quindi proseguire Ingestion→UDP→grafo. L'approvazione HUMAN resta nella THS.

Non ricaricare o riprofilare. Non ripubblicare l'ontologia né riavviare il produttore già ripristinato. La sorgente storica `teatri-csv-6609b245` e le sue acquisizioni restano invariate; la proposta riguarda `teatri-seaweedfs-c51745c5`. Nessuna bozza applicativa, attivazione o nuova Ingestion inviata in questa fase.

## Ripristino Semantic acquisito

[Ricevuta operatore delle 21:07:05 CET](../evidence/semantic-operational-owner-active-operator-20261107.json): rimosso solo l'esatto override di cattura, conservato nel backup privato; altri drop-in invariati. Un avvio del servizio `ouf-registry-token-7cb59501000058b5dc5030ad.service`, ora active/running/enabled, Restart=on-failure. Pubblicazioni 6468→6469, registro ACTIVE, token montato cambiato, GET policy200. Applicazione Semantic invariata; zero cambi di permessi, zero SQL/S3/richieste business emesse dallo script.

Le unità legacy `ouf-policy-token@semantic.service/.timer` restano masked. Le precedenti diagnosi HELD sono storiche. Il [runbook](OUF_SEMANTIC_TOKEN_RENEWAL_20261107.md) conserva il comando eseguito, non una nuova azione da ripetere. Un secondo ciclo di rinnovo automatico non è ancora dimostrato.

## Binding storage acquisiti

| Servizio | Risultato documentato | Limite |
| --- | --- | --- |
| Onboarding | Stessa immagine `7b9d3e91…`, endpoint `https://ouf-seaweedfs-stage:9002`, bucket `ouf-managed-files`. 12 oggetti/40.709 byte coincidenti a writer fermo; readiness/TLS, 118 certificati JDK più CA. Vecchio container conservato spento. Upload/profilazione applicativi riusciti. | Non riavviare il vecchio writer MinIO dopo le nuove scritture. |
| UDP | Stessa immagine `ae78f604…`, stesso endpoint HTTPS, bucket `ouf-udp`. 110 oggetti/181.364 byte coincidenti a writer fermo; zero copie/sovrascritture; diagnostico rimosso; readiness/TLS e certificati verificati. Vecchio container spento. | `applicationHttpLakeOperationTested=false`: la normale operazione lake resta da provare. |

[Ricevuta Onboarding](../evidence/onboarding-seaweedfs-ready-operator-20261107.json) · [Ricevuta UDP](../evidence/udp-seaweedfs-ready-operator-20261107.json). I confronti curl/Java Onboarding e PUT/HEAD/GET dell'adapter UDP originale hanno avuto successo nei rispettivi ambiti: non ripeterli. La causa del vecchio 502 in una diversa configurazione resta non provata.

## Problemi ancora aperti

- **Riavvio generale e MAC:** vedere la [regola permanente](OUF_LEARNED_CONTAINER_MAC_INVARIANTS.md) e il [caso del 25 ottobre](handoffs/OUF_ACQUISITION_MAC_LESSON_AND_RETAINED_STATE_20261025.md). Il riferimento è in AGENTS. La primitiva storica copre il vecchio container dopo STOP/DETACH, non automaticamente i sostituti running. Onboarding e UDP differiscono soltanto per `Config.MacAddress` nel confronto osservato; immagini, ambiente, argomenti e mount coincidono. Non è stata applicata normalizzazione e le impronte attese non sono cambiate. Il modo generale `e2e` può ancora fermarsi; mancano presenza/tipo prima-dopo del campo legacy e corrispondenza con gli endpoint per rete. L'avviatore generale omette inoltre il produttore continuo ora ripristinato: integrare consapevolmente il suo lifecycle, senza inventare un timer.
- **F2–F6:** normale operazione lake UDP, nuovo CSV fino al grafo, seconda esecuzione e ripresa da altra sessione. Il blocco della ricerca Semantic è superato per le chiamate osservate; nessun E2E completo dichiarato.
- **Stato Ingestion:** `ouf.ingestion.status(limit=10)` era negato; nessun grant di quella capability nel catalogo letto. Lettura non ripetuta né permessi ampliati per aggirarla.
- **Riuso vecchio selettore Farmacie→Teatri:** HTTP_500, handoff `1d3c1a27-5a57-4e81-bbbc-2f6bc606c6ce` conserva asset `8061fad3-1a8b-4f65-9e4a-bfead7974cb7`. Rifiuto di riassociare il medesimo handoff riprodotto sul codice; manca l'eccezione live e resta da riconciliare la possibile seconda persistenza. Nessuna cancellazione. [Evidenza](../evidence/ths-upload-reuse-storage-next-20261107.json).

Non distribuire il vecchio commit diagnostico Onboarding `380e8dcb`: parte 20 commit prima del sorgente conservato `73498c17` e la build è fallita a Trivy. Conservare l'installazione funzionante. MCP HEALTHY non dimostra l'E2E.

## Riferimenti operativi

[MiniPET funzionale](OUF_STORAGE_MINIPET.md) · [Registro funzionale](../releases/storage-functional-status-20261107.json) · [Log cronologico](OUF_M2_CHECKPOINT_LOG.md). Non dichiarare produzione pronta o E2E concluso.
