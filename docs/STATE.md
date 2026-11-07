# Stato corrente OUF

Aggiornato il **7 novembre 2026**, Europe/Rome. Priorità: **SeaweedFS funzionante, poi E2E ripetibile; industrializzazione dopo**. Esecuzione sequenziale del solo agente principale.

## Risultato corrente

**F1 PASS. Onboarding e UDP collegati a SeaweedFS. Semantic ora esegue Java nello stesso container/immagine e risponde readiness 200/UP. La ricerca MCP supera il precedente blocco di connessione ma termina 403 `SEM_READ_RECEIPT_OR_POLICY_DENIED`. Causa interna del diniego ancora da distinguere.**

- **Policy :61 verificata:** proposta `66ecf0fb-04e8-476b-9ce5-4fdc1dd496fa` PUBLISHED, revisione 1, confermata da Giovanni nella THS. Tre permessi admin corretti per profilazione/stato job/creazione bozza; altri 63 permessi e tutte le 13 assegnazioni invariati.
- **Upload e lettura riusciti:** handoff `2de7b988-da47-4231-8443-0e5043214c42` → asset `c51745c5-1fc0-4d36-bdcf-1e9a8a049c94` STAGED → job `f460d4d5-c6f7-4b65-b305-08091e9849cf` SUCCEEDED → profilo `da3f17a2-5cbc-4d7d-9ed8-7f4b39a00342` letto via MCP. CSV UTF-8, separatore `;`, 13 righe e 20 colonne. Codice installato verifica dimensione/hash prima di salvare il profilo; valore hash non esposto dalla preview. [Evidenza](../evidence/onboarding-seaweedfs-profile-success-20261107.json).
- **Non ricaricare:** riprendere da asset/profilo. Identità proposta `nome_teatro`, ancora PENDING_HUMAN_REVIEW. Coordinate inferite STRING, campione `4.565.094`/`1.376.850`: formato da chiarire prima del mapping. Nessuna conversione automatica, bozza sorgente o Ingestion avviata.

## Blocco attuale e prossimo passo

La ricevuta operatore conferma il passaggio **GATE_WAITING → APPLICATION_RUNNING**, segnale ricevuto, Java come init, stessa immagine e stesso container, readiness HTTP 200/UP. Configurazione Semantic esattamente corrispondente a quella conservata. Non rilanciare l'avvio. [Ricevuta](../evidence/semantic-application-ready-operator-20261107.json).

Il tentativo MCP successivo `semantic.search(q=teatro, limit=20)`, account `ouf-admin`, restituisce **403 `SEM_READ_RECEIPT_OR_POLICY_DENIED`**; non ripetuto invariato. Il codice installato usa quel codice sia per ricevuta di delega invalida sia per policy assente/scaduta o decisione negativa. Il grant admin di ricerca è presente nel catalogo letto, ma non certifica la policy effettiva caricata in Semantic. [Evidenza e sorgenti esatti](../evidence/semantic-ready-search-denial-20261107.json).

**Prossima azione:** eseguire il [controllo corrente della policy](OUF_SEMANTIC_POLICY_READ_20261107.md): dichiarazioni selezionate, token visto nel mount del container e relativa scadenza, un GET HTTPS all'endpoint configurato. Zero nuovi token, modifiche di permessi, riavvii, richieste business/SQL/S3. Test locali PASS; VPS ancora da eseguire. Un 200 host non sarà presentato come verifica del trasporto JVM o della policy in memoria.

## Binding storage acquisiti

| Servizio | Risultato documentato | Limite |
| --- | --- | --- |
| Onboarding | Stessa immagine `7b9d3e91…`, endpoint `https://ouf-seaweedfs-stage:9002`, bucket `ouf-managed-files`. 12 oggetti/40.709 byte coincidenti a writer fermo; readiness/TLS, 118 certificati JDK più CA. Vecchio container conservato spento. Upload/profilazione applicativi riusciti. | Non riavviare il vecchio writer MinIO dopo le nuove scritture. |
| UDP | Stessa immagine `ae78f604…`, stesso endpoint HTTPS, bucket `ouf-udp`. 110 oggetti/181.364 byte coincidenti a writer fermo; zero nuove copie/sovrascritture; diagnostico rimosso; readiness/TLS e certificati verificati. Vecchio container spento. | `applicationHttpLakeOperationTested=false`: la normale operazione lake resta da provare. |

[Ricevuta Onboarding](../evidence/onboarding-seaweedfs-ready-operator-20261107.json) · [Ricevuta UDP](../evidence/udp-seaweedfs-ready-operator-20261107.json). Il confronto curl/Java Onboarding e il PUT/HEAD/GET dell'adapter UDP originale hanno avuto successo nei rispettivi ambiti. Non serve ripeterli. La causa del vecchio 502 in una diversa configurazione resta non provata.

## Problemi ancora aperti

- **Confronto di riavvio:** sulle sostituzioni Onboarding e UDP l'unico campo `Config` diverso osservato è `MacAddress`; immagini, ambiente, argomenti e mount coincidono. Non è stata applicata alcuna normalizzazione e le impronte attese non sono cambiate. Il modo `semantic` è riuscito; **il modo generale `e2e` può ancora fermarsi sul confronto completo**. Verificare le identità di rete prima di correggerlo.
- **F2–F6:** normale operazione lake UDP, CSV fino al grafo, seconda esecuzione e ripresa da altra sessione. Proseguire dopo il diniego semantico: registro locale, eventuale OntoPiA governata, Ingestion, riconciliazione, grafo e ripetizione.
- **Stato Ingestion:** `ouf.ingestion.status(limit=10)` era negato; nessun grant di quella capability nel catalogo letto. Lettura non ripetuta. Ostacolo separato, nessun ampliamento di permessi preparato per aggirarlo.
- **Vecchio selettore riusato Farmacie→Teatri:** HTTP_500, handoff `1d3c1a27-5a57-4e81-bbbc-2f6bc606c6ce` conserva asset `8061fad3-1a8b-4f65-9e4a-bfead7974cb7`. Rifiuto di riassociare lo stesso handoff riprodotto sul codice, eccezione live mancante; possibile seconda persistenza da riconciliare. Nessuna cancellazione. [Evidenza](../evidence/ths-upload-reuse-storage-next-20261107.json).

Non distribuire il vecchio commit diagnostico Onboarding `380e8dcb`: parte 20 commit prima del sorgente conservato `73498c17` e la sua build è fallita a Trivy. Resta l'installazione funzionante conservata. MCP HEALTHY riguarda il modulo MCP, non l'E2E.

## Riferimenti operativi

[MiniPET funzionale](OUF_STORAGE_MINIPET.md) · [Registro funzionale](../releases/storage-functional-status-20261107.json) · [Log cronologico](OUF_M2_CHECKPOINT_LOG.md). Non dichiarare produzione pronta o E2E concluso.
