# Stato corrente OUF

9 novembre 2026, Europe/Rome. Priorità dell'owner: **SeaweedFS funzionante, poi E2E ripetibile**. Requisiti aggiunti: 1024 colonne e budget proporzionato al lavoro, con discovery di proprietà OntoPiA. Solo agente principale; industrializzazione rinviata.

## Risultato acquisito

**F1 PASS; F2–F6 aperti.** Onboarding e UDP usano `https://ouf-seaweedfs-stage:9002`; i vecchi writer MinIO restano spenti. Upload e profilo Onboarding sono riusciti. La normale operazione lake UDP e l'E2E fino al grafo non sono ancora provati.

Conservare Teatri senza nuovo upload o profilo:

- asset `c51745c5-1fc0-4d36-bdcf-1e9a8a049c94`;
- profilo `da3f17a2-5cbc-4d7d-9ed8-7f4b39a00342`, 13 righe/20 colonne, UTF-8 e `;`;
- scelta owner: tutte le 20 colonne OPEN; associazione dei **nomi/concetti delle colonne a proprietà con URI condivisi**, non enumerazioni dei valori;
- policy `ouf-lab-authorization:61`; token owner Semantic ripristinato. Ricerca/lettura dell'ontologia locale Teatri via MCP riuscite, 105 statement. Questo non prova la discovery esterna.

Gateway già applicato e verificato: **87 route, otto modifiche, 79 conservate**, owner invariato. [Ricevuta](../evidence/gateway-analysis-applied-operator-20261108.json). Non rieseguire l'applicazione del delta.

## Componenti aggiornati e pronti; discovery ancora da attivare

**Semantic V12 è pronto.** La [ricevuta operatore delle 19:59 CET](../evidence/semantic-discovery-key-repaired-operator-20261108.json) conferma `SEMANTIC_DISCOVERY_KEY_REPAIRED_V12_READY`: nuovo container `ef35ea78dc8f5116255ce1c12186935451af6612293c95ecacab3165e220598a`, stessa immagine candidata c2dae77b, chiave esistente uguale al firmatario Gateway. Modificato soltanto `OUF_SEMANTIC_DISCOVERY_DELEGATION_KEY_FILE`; mount, indirizzi e alias conservati. Storia V1–V12 invariata, nessun migratore esplicito, nuova chiave, import immagine o route write. V10 e V12 fallito sono conservati spenti. Non ripetere la correzione.

Provider e worker restano disabilitati; nessuna richiesta discovery o business è stata eseguita. Readiness non equivale a discovery funzionante, mapping completo o E2E. [Runbook e qualifica](OUF_SEMANTIC_APPLICATION_UPGRADE_20261108.md).

**MCP PR83 è installato e pronto.** La [ricevuta operatore delle 20:26 CET](../evidence/mcp-analysis-ready-operator-20261108.json) conferma `MCP_ANALYSIS_V14_READY`, migrazione ordinaria 14 verificata, storia 1–13 e timestamp conservati, readiness HTTP 204. Nuovo container `41c1e01dfd86535d75d2db6d7bd0f9e3eae27c24684af0b149d6b51c54d90943`, immagine candidata `sha256:d76fda00f9340dcea62ed1be58b1db3ebfb4d64d4be5449ffc07ab2c845254ff`. ENV, mount, indirizzi e alias conservati; vecchio MCP spento. I file del permesso storico scaduto sono invariati. Non ripetere installer o migrazione. [Runbook](OUF_MCP_ANALYSIS_UPGRADE_20261108.md).

I sei strumenti analisi/discovery restano INACTIVE; nessuna analisi funzionale o discovery è dimostrata dall'avvio. Il percorso Teatri fino al grafo resta aperto.

**Onboarding 1024 è installato e pronto.** La [ricevuta delle 21:16 CET](../evidence/onboarding-wide-ready-operator-20261108.json) conferma `ONBOARDING_WIDE_1024_READY`: container d0b9ff84, immagine archiviata 880bbf92, readiness HTTP200. Entrambe le reti con indirizzi/MAC/alias, mount/truststore e argomenti Java conservati. Storia V38 e righe Teatri invariate; nessun migratore esplicito. Il predecessore SeaweedFS e il vecchio writer MinIO restano spenti. **Non ripetere l'installer.** La profilazione funzionale 1024 non è stata eseguita.

**Ingestion 1024 è installato e pronto.** La [ricevuta delle 22:48 CET](../evidence/ingestion-wide-ready-operator-20261108.json) conferma INGESTION_WIDE_1024_READY, readiness 200 e nuovo container `a1bec344c54493232e52117d7e515c4f465ff0e9136eecc67dd86efa6aae9020`, immagine `sha256:562e4c6e19d5227f00fb3159deb506da256d2245ee4a40a652b0c03865704baa`. Storia delle migrazioni, sei tabelle di lavoro e campi stabili delle pianificazioni invariati; entrambe le pianificazioni DISABLED, consumate e senza lease. In questa finestra anche i due metadata polling sono invariati: non è una prova di rinnovo periodico. Endpoint/IP/MAC/alias, mount, ENV e argomenti conservati; Flyway disabilitato, vecchio trattenuto spento. Nessun nuovo import/stop/migratore esplicito; tre letture READ ONLY. **Non ripetere installer o continuazione.** La prova funzionale1024 resta aperta. [Esito e limiti](OUF_INGESTION_WIDE_UPGRADE_20261108.md).

**UDP 1024 è installato e pronto.** La [ricevuta delle 06:58 CET del 9 novembre](../evidence/udp-wide-ready-operator-20261109.json) conferma `UDP_WIDE_1024_READY`: nuovo container `ab8549a93e83ecf43dfb2d7d89e469405736c39bed3815fa9d15d7f8b92005e7`, immagine `sha256:c99b53016a1928e1536ab2cdae316b48e441e7ee80f41f0b10581afc324bbdec`, readiness HTTP 200. Storia delle migrazioni e 59 tabelle conservate, entrambe le reti/IP/MAC/alias, mount, truststore e argomenti Java preservati; vecchio UDP e vecchio writer MinIO spenti. Tre letture DB READ ONLY, nessun migratore esplicito o richiesta business/S3 dello script. Il normale avvio può accedere a DB e S3. **Non ripetere l'installer.** La prova funzionale1024 e la normale operazione lake restano aperte.

## Sequenza rimanente

1. Verificare i binding attuali del provider/southbound, la credenziale montata e il meccanismo di attivazione degli strumenti. L'ultima lettura riportava provider/worker disabilitati e nessun mount della credenziale; questi punti richiedono una lettura corrente mirata, non un altro rollout UDP.
2. Configurare e verificare trasporto, credenziale, delega e grant discovery; attivare gli strumenti previsti. Il gateway southbound dichiarato è `ouf-semantic-southbound-v2:10443`; le route APISIX pubbliche da sole non ne provano il funzionamento.
3. Verificare il supporto funzionale1024 dei moduli aggiornati su un fixture distinto; per l'E2E conservare asset/profilo Teatri. [Contratti e rischi](OUF_WIDE_OBJECTS_1024_20261107.md).
4. Usare l'analisi persistente sul profilo Teatri esistente e trovare proprietà condivise per le colonne. Nessun URI inventato o import manuale sostitutivo. [Budget](OUF_SEMANTIC_ANALYSIS_BUDGET_20261107.md) e [colonne](OUF_TEATRI_COLUMN_SEMANTIC_REFERENCES_20261107.md).
5. Completare review THS → Ingestion → UDP e leggere il grafo; ripetere con un secondo CSV senza riparazioni manuali, quindi provare la ripresa da una nuova conversazione.

Ogni passo si chiude con un risultato applicativo osservato. Non esiste ancora una data di completamento affidabile. [MiniPET funzionale](OUF_STORAGE_MINIPET.md), [registro strutturato](../releases/storage-functional-status-20261107.json), [cronologia](OUF_M2_CHECKPOINT_LOG.md).

Prima di confrontare frame o modificare container leggere [regola MAC](OUF_LEARNED_CONTAINER_MAC_INVARIANTS.md) e [precedente del25ottobre](handoffs/OUF_ACQUISITION_MAC_LESSON_AND_RETAINED_STATE_20261025.md). Non escludere globalmente MacAddress né riaprire scope storici consumati.


