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

## Blocco corrente e prossima azione

**Alle 19:09 CET l'aggiornamento ha applicato e validato V11/V12, poi il nuovo Semantic è terminato durante l'avvio.** [Ricevuta operatore completa](../evidence/semantic-application-upgrade-held-operator-20261108.json): `HELD / APPLICATION_EXITED`, due migrazioni eseguite, storia precedente preservata e colonna `recovery_state` presente. Questo supera lo stato storico “DB a V10”.

Il replacement è `11d9362c7db484a2204266062fd54b5c08fbf1da7382076fb2a164bc1a9dd070`, immagine esatta `sha256:89e84f7a6208afa74039de7057c46ad5c9981fb283b22d9b93fa014e92d1b048`. Il pacchetto contiene le dodici migrazioni coincidenti col sorgente. Il vecchio container è stato fermato e scollegato; la transizione MAC prevista è stata riconosciuta. Nessun rollback automatico, richiesta S3, scrittura Gateway o attivazione provider.

**La causa dell'uscita Java non è ancora nota.** La ricevuta non contiene il log d'avvio. Il [comando corrente di sola lettura](OUF_SEMANTIC_APPLICATION_UPGRADE_20261108.md#diagnosi-corrente) legge stato e log del CID esatto, mantiene i log completi privati sul VPS e restituisce simboli/diagnostiche riconosciuti senza valori di configurazione. Non avvia processi applicativi e non interroga il database.

Conservare `/var/lib/ouf-storage-migration/semantic-application-upgrade-20261108` e il vecchio scope `semantic-v11-v12-20261108`. Non rilanciare installer o migratore e non riavviare il vecchio JAR contro lo schema aggiornato. La precedente qualifica CI resta valida nel suo ambito, ma non ha provato tutte le configurazioni reali del VPS.

## Sequenza rimanente

1. Leggere il motivo d'uscita del nuovo Registry, correggere il difetto osservato e completare l'avvio del sostituto a V12 senza ripetere le migrazioni. Verificare readiness prima di continuare. Provider e worker restano disabilitati fino alla configurazione del loro percorso.
2. Distribuire il candidato MCP PR83 (analisi persistente, discovery e 1024 colonne) con migrazione14: DB corrente osservato a1–13. Comporre i candidati Onboarding/Ingestion/UDP da1024 conservando i binding SeaweedFS già funzionanti. [Contratti e rischi](OUF_WIDE_OBJECTS_1024_20261107.md).
3. Configurare e verificare credenziale, trasporto e delega discovery sul gateway southbound `ouf-semantic-southbound-v2:10443`; verificare grant e attivare gli strumenti previsti. Il mount della credenziale provider non è attualmente dichiarato; non dedurre disponibilità dalle route APISIX.
4. Usare l'analisi persistente sul profilo Teatri esistente e trovare proprietà condivise per le colonne. Nessun URI inventato o import manuale sostitutivo. [Budget](OUF_SEMANTIC_ANALYSIS_BUDGET_20261107.md) e [colonne](OUF_TEATRI_COLUMN_SEMANTIC_REFERENCES_20261107.md).
5. Completare review THS → Ingestion → UDP e leggere il grafo; ripetere con un secondo CSV senza riparazioni manuali, quindi provare la ripresa da una nuova conversazione.

Ogni passo si chiude con un risultato applicativo osservato. Non esiste ancora una data di completamento affidabile. [MiniPET funzionale](OUF_STORAGE_MINIPET.md), [registro strutturato](../releases/storage-functional-status-20261107.json), [cronologia](OUF_M2_CHECKPOINT_LOG.md).

Prima di confrontare frame o modificare container leggere [regola MAC](OUF_LEARNED_CONTAINER_MAC_INVARIANTS.md) e [precedente del25ottobre](handoffs/OUF_ACQUISITION_MAC_LESSON_AND_RETAINED_STATE_20261025.md). Non escludere globalmente MacAddress né riaprire scope storici consumati.
