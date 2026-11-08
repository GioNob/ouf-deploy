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

## Semantic, MCP e Onboarding pronti; prossimo componente Ingestion

**Semantic V12 è pronto.** La [ricevuta operatore delle 19:59 CET](../evidence/semantic-discovery-key-repaired-operator-20261108.json) conferma `SEMANTIC_DISCOVERY_KEY_REPAIRED_V12_READY`: nuovo container `ef35ea78dc8f5116255ce1c12186935451af6612293c95ecacab3165e220598a`, stessa immagine candidata c2dae77b, chiave esistente uguale al firmatario Gateway. Modificato soltanto `OUF_SEMANTIC_DISCOVERY_DELEGATION_KEY_FILE`; mount, indirizzi e alias conservati. Storia V1–V12 invariata, nessun migratore esplicito, nuova chiave, import immagine o route write. V10 e V12 fallito sono conservati spenti. Non ripetere la correzione.

Provider e worker restano disabilitati; nessuna richiesta discovery o business è stata eseguita. Readiness non equivale a discovery funzionante, mapping completo o E2E. [Runbook e qualifica](OUF_SEMANTIC_APPLICATION_UPGRADE_20261108.md).

**MCP PR83 è installato e pronto.** La [ricevuta operatore delle 20:26 CET](../evidence/mcp-analysis-ready-operator-20261108.json) conferma `MCP_ANALYSIS_V14_READY`, migrazione ordinaria 14 verificata, storia 1–13 e timestamp conservati, readiness HTTP 204. Nuovo container `41c1e01dfd86535d75d2db6d7bd0f9e3eae27c24684af0b149d6b51c54d90943`, immagine candidata `sha256:d76fda00f9340dcea62ed1be58b1db3ebfb4d64d4be5449ffc07ab2c845254ff`. ENV, mount, indirizzi e alias conservati; vecchio MCP spento. I file del permesso storico scaduto sono invariati. Non ripetere installer o migrazione. [Runbook](OUF_MCP_ANALYSIS_UPGRADE_20261108.md).

I sei strumenti analisi/discovery restano INACTIVE; nessuna analisi funzionale o discovery è dimostrata dall'avvio. Il percorso Teatri fino al grafo resta aperto.

**Onboarding 1024 è installato e pronto.** La [ricevuta delle 21:16 CET](../evidence/onboarding-wide-ready-operator-20261108.json) conferma `ONBOARDING_WIDE_1024_READY`: container d0b9ff84, immagine archiviata 880bbf92, readiness HTTP200. Entrambe le reti con indirizzi/MAC/alias, mount/truststore e argomenti Java conservati. Storia V38 e righe Teatri invariate; nessun migratore esplicito. Il predecessore SeaweedFS e il vecchio writer MinIO restano spenti. **Non ripetere l'installer.** La profilazione funzionale 1024 non è stata eseguita.

**Ingestion: preflight acquisito e installazione qualificata.** La [rilettura delle 22:11 CET](../evidence/ingestion-wide-preflight-repeat-operator-extract-20261108.json) conferma storia V18 e risorse coerenti, tre run SUCCEEDED, 34 handoff ACKED e zero lease non scadute alla lettura. Container, frame e JAR coincidono con la precedente lettura delle 21:43 CET; il vecchio JAR è ancora installato. Questa è una seconda ricevuta del preflight, non dell’installer. Il prossimo comando resta quello di installazione già consegnato; non ripetere il lettore. Il candidato archiviato c85d9fd3 è qualificato in [CI42522348023](https://github.com/GioNob/ouf-deploy/actions/runs/42522348023): Docker classic/containerd, sei test guard e due cicli nativi per backend senza skip, avvio con configurazione esterna/chiave Gateway sintetiche, HTTP200, storia/righe conservate e transizione MAC verificata. [Comando corrente di installazione](OUF_INGESTION_WIDE_UPGRADE_20261108.md). Nessun cambio Ingestion sul VPS è ancora attestato; attesa ricevuta.

## Sequenza rimanente

1. Eseguire una sola volta l’installer Ingestion qualificato e acquisire la ricevuta. Conserva V18, mount/argomenti/rete e confronta run/checkpoint/lineage/handoff/snapshot/schedule prima, da fermo e dopo avvio. Nessuna migrazione esplicita. Semantic, MCP e Onboarding sono pronti: nessun replay dei loro interventi.
2. Proseguire con Ingestion e UDP a 1024, conservando i binding SeaweedFS già funzionanti. MCP porta analisi persistente/discovery/pagine schema; il supporto completo1024 richiede anche i moduli proprietari. [Contratti e rischi](OUF_WIDE_OBJECTS_1024_20261107.md).
3. Configurare e verificare credenziale, trasporto e delega discovery sul gateway southbound `ouf-semantic-southbound-v2:10443`; verificare grant e attivare gli strumenti previsti. Il mount della credenziale provider non è attualmente dichiarato; non dedurre disponibilità dalle route APISIX.
4. Usare l'analisi persistente sul profilo Teatri esistente e trovare proprietà condivise per le colonne. Nessun URI inventato o import manuale sostitutivo. [Budget](OUF_SEMANTIC_ANALYSIS_BUDGET_20261107.md) e [colonne](OUF_TEATRI_COLUMN_SEMANTIC_REFERENCES_20261107.md).
5. Completare review THS → Ingestion → UDP e leggere il grafo; ripetere con un secondo CSV senza riparazioni manuali, quindi provare la ripresa da una nuova conversazione.

Ogni passo si chiude con un risultato applicativo osservato. Non esiste ancora una data di completamento affidabile. [MiniPET funzionale](OUF_STORAGE_MINIPET.md), [registro strutturato](../releases/storage-functional-status-20261107.json), [cronologia](OUF_M2_CHECKPOINT_LOG.md).

Prima di confrontare frame o modificare container leggere [regola MAC](OUF_LEARNED_CONTAINER_MAC_INVARIANTS.md) e [precedente del25ottobre](handoffs/OUF_ACQUISITION_MAC_LESSON_AND_RETAINED_STATE_20261025.md). Non escludere globalmente MacAddress né riaprire scope storici consumati.

