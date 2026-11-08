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

## Semantic ripristinato; prossimo componente MCP

**Semantic V12 è pronto.** La [ricevuta operatore delle 19:59 CET](../evidence/semantic-discovery-key-repaired-operator-20261108.json) conferma `SEMANTIC_DISCOVERY_KEY_REPAIRED_V12_READY`: nuovo container `ef35ea78dc8f5116255ce1c12186935451af6612293c95ecacab3165e220598a`, stessa immagine candidata c2dae77b, chiave esistente uguale al firmatario Gateway. Modificato soltanto `OUF_SEMANTIC_DISCOVERY_DELEGATION_KEY_FILE`; mount, indirizzi e alias conservati. Storia V1–V12 invariata, nessun migratore esplicito, nuova chiave, import immagine o route write. V10 e V12 fallito sono conservati spenti. Non ripetere la correzione.

Provider e worker restano disabilitati; nessuna richiesta discovery o business è stata eseguita. Readiness non equivale a discovery funzionante, mapping completo o E2E. [Runbook e qualifica](OUF_SEMANTIC_APPLICATION_UPGRADE_20261108.md).

**MCP PR83: prerequisiti target acquisiti; sostituzione qualificata, non ancora eseguita sul VPS.** La [lettura delle 20:09 CET](../evidence/mcp-analysis-preflight-operator-20261108.json) conferma database OID21560 con prefisso1–13 esatto, permessi ordinari per la14 e ruolo non superuser. Tutti i cinque file di avvio sono montati, coerenti col file host; il permesso storico di reprocessing è scaduto e rimane conservato senza rinnovo o reset.

Il controller usa l'archivio originale della PR83, conserva ENV/mount/IP/alias e sostituisce soltanto MCP. Invoca `migrate` come UID10005 con la configurazione applicativa corrente, verifica la sola aggiunta14 e la storia1–13 invariata, avvia il server e richiede HTTP204. Il vecchio MCP resta fermo. [Comando corrente](OUF_MCP_ANALYSIS_UPGRADE_20261108.md).

[CI42514478247](https://github.com/GioNob/ouf-deploy/actions/runs/42514478247), classic/containerd PASS, log letti: quattro test mirati, sei negativi MAC, due lifecycle nativi e una fixture firmata scaduta per backend; zero skip. Migrazione con ruolo ordinario, sessione e storia preservate, OAuth/policy su TLS, readiness204. Identità/dati sono sintetici; non è una prova del VPS o dell'E2E. [Qualifica](../evidence/mcp-analysis-upgrade-qualification-20261108.json). I sei nuovi strumenti restano INACTIVE anche dopo questa installazione.


## Sequenza rimanente

1. Eseguire l'installazione MCP qualificata e verificare schema14/readiness con storia conservata. Non riaprire il guasto Semantic chiuso, non ripetere il preflight e non rinnovare il permesso storico scaduto.
2. Comporre i candidati Onboarding/Ingestion/UDP da1024 conservando i binding SeaweedFS già funzionanti. MCP porta analisi persistente/discovery/pagine schema; il supporto completo1024 richiede anche i moduli proprietari. [Contratti e rischi](OUF_WIDE_OBJECTS_1024_20261107.md).
3. Configurare e verificare credenziale, trasporto e delega discovery sul gateway southbound `ouf-semantic-southbound-v2:10443`; verificare grant e attivare gli strumenti previsti. Il mount della credenziale provider non è attualmente dichiarato; non dedurre disponibilità dalle route APISIX.
4. Usare l'analisi persistente sul profilo Teatri esistente e trovare proprietà condivise per le colonne. Nessun URI inventato o import manuale sostitutivo. [Budget](OUF_SEMANTIC_ANALYSIS_BUDGET_20261107.md) e [colonne](OUF_TEATRI_COLUMN_SEMANTIC_REFERENCES_20261107.md).
5. Completare review THS → Ingestion → UDP e leggere il grafo; ripetere con un secondo CSV senza riparazioni manuali, quindi provare la ripresa da una nuova conversazione.

Ogni passo si chiude con un risultato applicativo osservato. Non esiste ancora una data di completamento affidabile. [MiniPET funzionale](OUF_STORAGE_MINIPET.md), [registro strutturato](../releases/storage-functional-status-20261107.json), [cronologia](OUF_M2_CHECKPOINT_LOG.md).

Prima di confrontare frame o modificare container leggere [regola MAC](OUF_LEARNED_CONTAINER_MAC_INVARIANTS.md) e [precedente del25ottobre](handoffs/OUF_ACQUISITION_MAC_LESSON_AND_RETAINED_STATE_20261025.md). Non escludere globalmente MacAddress né riaprire scope storici consumati.
