# Stato corrente OUF

8 novembre 2026, Europe/Rome. Priorità dell'owner: **SeaweedFS funzionante, poi E2E ripetibile**. Requisiti aggiunti: 1024 colonne e budget proporzionato al lavoro, con discovery di proprietà OntoPiA. Solo agente principale; industrializzazione rinviata.

## Risultato acquisito

**F1 PASS; F2–F6 aperti.** Onboarding e UDP usano `https://ouf-seaweedfs-stage:9002`; i vecchi writer MinIO restano spenti. Upload e profilo Onboarding sono riusciti. La normale operazione lake UDP e l'E2E fino al grafo non sono ancora provati.

Conservare Teatri senza nuovo upload o profilo:

- asset `c51745c5-1fc0-4d36-bdcf-1e9a8a049c94`;
- profilo `da3f17a2-5cbc-4d7d-9ed8-7f4b39a00342`, 13 righe/20 colonne, UTF-8 e `;`;
- scelta owner: tutte le 20 colonne OPEN; associazione dei **nomi/concetti delle colonne a proprietà con URI condivisi**, non enumerazioni dei valori;
- policy `ouf-lab-authorization:61`; token owner Semantic ripristinato. Ricerca/lettura dell'ontologia locale Teatri via MCP riuscite, 105 statement. Questo non prova la discovery esterna.

Gateway già applicato e verificato: **87 route, otto modifiche, 79 conservate**, owner invariato. [Ricevuta](../evidence/gateway-analysis-applied-operator-20261108.json). Non rieseguire l'applicazione del delta.

## Blocco corrente e correzione

La lettura delle **18:29 CET** identifica il JAR installato: solo V1–V10, tutte coincidenti col prefisso candidato; V11/V12 e le classi `DiscoveryJobService`, `SemanticDiscoveryMcpApi`, `SemanticDiscoveryDelegation` sono assenti. [Estratto della ricevuta](../evidence/semantic-installed-package-operator-extract-20261108.json).

Il DB osservato è anch'esso a V10 (OID21558), con checksum coincidenti e nessuna richiesta discovery. Il tentativo precedente si è fermato **prima di Java/SQL**. Conservare `/var/lib/ouf-storage-migration/semantic-v11-v12-20261108`; non rilanciarlo. Era errata l'attribuzione del candidato al container corrente basata sul solo source-lock: l'assistente l'ha ritirata.

**Occorre aggiornare insieme applicazione Registry e schema.** Il candidato esatto `c2dae77b`, artifact13066396654, è stato scaricato e verificato: otto payload, 221 blob sorgente, JAR nell'immagine, V1–V12 e YAML. [Consegna e stato della verifica](OUF_SEMANTIC_APPLICATION_UPGRADE_20261108.md). La preparazione in Git non è un'installazione sul VPS.

**Consegna corretta dopo il risultato operatore:** `DELIVERY_INCOMPLETE / GITHUB_CLI_OR_LOCAL_CANDIDATE_ZIP_REQUIRED`, nessun servizio modificato e controller non avviato. Il [nuovo comando](OUF_SEMANTIC_APPLICATION_UPGRADE_20261108.md#comando-operatore) scarica senza gh l'artefatto pubblico tramite nightly.link e verifica il suo hash. Download completo verificato nell'ambiente dell'assistente; raggiungibilità VPS ed esecuzione dell'aggiornamento ancora attese. Controller e qualifica runtime invariati.

## Sequenza rimanente

1. Sostituire il Registry con il pacchetto verificato; migrare V11/V12 con il vecchio processo fermo, poi avviare Java e verificare readiness. Provider e worker restano disabilitati fino alla configurazione del loro percorso.
2. Distribuire il candidato MCP PR83 (analisi persistente, discovery e 1024 colonne) con migrazione14: DB corrente osservato a1–13. Comporre i candidati Onboarding/Ingestion/UDP da1024 conservando i binding SeaweedFS già funzionanti. [Contratti e rischi](OUF_WIDE_OBJECTS_1024_20261107.md).
3. Configurare e verificare credenziale, trasporto e delega discovery sul gateway southbound `ouf-semantic-southbound-v2:10443`; verificare grant e attivare gli strumenti previsti. Il mount della credenziale provider non è attualmente dichiarato; non dedurre disponibilità dalle route APISIX.
4. Usare l'analisi persistente sul profilo Teatri esistente e trovare proprietà condivise per le colonne. Nessun URI inventato o import manuale sostitutivo. [Budget](OUF_SEMANTIC_ANALYSIS_BUDGET_20261107.md) e [colonne](OUF_TEATRI_COLUMN_SEMANTIC_REFERENCES_20261107.md).
5. Completare review THS → Ingestion → UDP e leggere il grafo; ripetere con un secondo CSV senza riparazioni manuali, quindi provare la ripresa da una nuova conversazione.

Ogni passo si chiude con un risultato applicativo osservato. Non esiste ancora una data di completamento affidabile. [MiniPET funzionale](OUF_STORAGE_MINIPET.md), [registro strutturato](../releases/storage-functional-status-20261107.json), [cronologia](OUF_M2_CHECKPOINT_LOG.md).

Prima di confrontare frame o modificare container leggere [regola MAC](OUF_LEARNED_CONTAINER_MAC_INVARIANTS.md) e [precedente del25ottobre](handoffs/OUF_ACQUISITION_MAC_LESSON_AND_RETAINED_STATE_20261025.md). Non escludere globalmente MacAddress né riaprire scope storici consumati.
