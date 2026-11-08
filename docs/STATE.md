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

## Blocco corrente e correzione pronta

**V11/V12 sono migrate e validate; Semantic è fermo per un riferimento a file privo di mount.** La [ricevuta delle 19:40 CET](../evidence/semantic-discovery-key-binding-operator-20261108.json) precisa il difetto: discovery cerca `/run/secrets/semantic-discovery-owner.key`, senza mount; il file `/run/secrets/semantic-read-owner.key` è già montato read-only, UID/GID 10001 e modo 0400. Le tre route discovery e la route search usano attualmente `OUF_SEMANTIC_READ_OWNER_KEY`, distinto dal riferimento della delegazione MCP. Issuer/audience/workload dichiarati coincidono. I byte del file e della chiave Gateway non sono ancora stati confrontati sul VPS.

Il container V12 fallito è `11d9362c7db484a2204266062fd54b5c08fbf1da7382076fb2a164bc1a9dd070`, fermo con ExitCode 1 e senza OOM. Il vecchio V10 è ancora fermo. [Migrazione](../evidence/semantic-application-upgrade-held-operator-20261108.json) e [diagnosi del log](../evidence/semantic-application-exit-operator-20261108.json) restano acquisite.

**Correzione qualificata, applicazione VPS attesa:** cambiare soltanto `ouf.semantic.discovery-delegation.key-file` al percorso read già montato. Prima di ogni modifica il controller confronta i byte con il firmatario Gateway corrente, verifica che la chiave sia diversa dalla delegazione MCP e legge lo schema V12. Crea il sostituto con la stessa immagine e gli stessi mount/endpoint; conserva sia V10 sia V12 fallito spenti. Non genera, copia o ruota chiavi, non modifica route, non importa immagini e non invoca il migratore. [Comando corrente](OUF_SEMANTIC_APPLICATION_UPGRADE_20261108.md#correzione-corrente).

Sorgente `bece4c5b3dbaf20dcec05b19b4352284a23cc92e`, [CI 42511861759](https://github.com/GioNob/ouf-deploy/actions/runs/42511861759): classic/containerd PASS, ciascuno 2 prove native, 5 controlli mirati e 6 negativi MAC, zero skip, log letti. L'immagine archiviata riproduce l'errore della chiave configurata mancante, poi raggiunge readiness con la correzione; storia V12 e ricevuta sintetica invariate. Questa prova chiude la lacuna della fixture precedente per il parametro chiave, non prova IAM/policy/provider o E2E del VPS.

Conservare tutti i journal precedenti. La correzione usa `/var/lib/ouf-storage-migration/semantic-discovery-key-repair-20261108`, senza replay o rollback automatico; l'eventuale errore di nuovo avvio viene raccolto nello stesso risultato pubblico.

## Sequenza rimanente

1. Eseguire la correzione qualificata del riferimento alla chiave discovery e verificare readiness e storia V12 invariata. Verificare readiness prima di continuare. Provider e worker restano disabilitati fino alla configurazione del loro percorso.
2. Distribuire il candidato MCP PR83 (analisi persistente, discovery e 1024 colonne) con migrazione14: DB corrente osservato a1–13. Comporre i candidati Onboarding/Ingestion/UDP da1024 conservando i binding SeaweedFS già funzionanti. [Contratti e rischi](OUF_WIDE_OBJECTS_1024_20261107.md).
3. Configurare e verificare credenziale, trasporto e delega discovery sul gateway southbound `ouf-semantic-southbound-v2:10443`; verificare grant e attivare gli strumenti previsti. Il mount della credenziale provider non è attualmente dichiarato; non dedurre disponibilità dalle route APISIX.
4. Usare l'analisi persistente sul profilo Teatri esistente e trovare proprietà condivise per le colonne. Nessun URI inventato o import manuale sostitutivo. [Budget](OUF_SEMANTIC_ANALYSIS_BUDGET_20261107.md) e [colonne](OUF_TEATRI_COLUMN_SEMANTIC_REFERENCES_20261107.md).
5. Completare review THS → Ingestion → UDP e leggere il grafo; ripetere con un secondo CSV senza riparazioni manuali, quindi provare la ripresa da una nuova conversazione.

Ogni passo si chiude con un risultato applicativo osservato. Non esiste ancora una data di completamento affidabile. [MiniPET funzionale](OUF_STORAGE_MINIPET.md), [registro strutturato](../releases/storage-functional-status-20261107.json), [cronologia](OUF_M2_CHECKPOINT_LOG.md).

Prima di confrontare frame o modificare container leggere [regola MAC](OUF_LEARNED_CONTAINER_MAC_INVARIANTS.md) e [precedente del25ottobre](handoffs/OUF_ACQUISITION_MAC_LESSON_AND_RETAINED_STATE_20261025.md). Non escludere globalmente MacAddress né riaprire scope storici consumati.
