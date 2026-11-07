# Restore33 dai soli backup esportati — 2026-11-05

Stato: **PASS**, recupero sintetico dai soli export qualificato; nessuna admission target.

## Scopo e sorgente immutabile

Il common-cut fisico è già qualificato dal producer `7444df039a8b4990d1518a343f4f57a698db0b74`, [run41914041465](https://github.com/GioNob/ouf-deploy/actions/runs/41914041465). Questa prova ripristina quel medesimo stato in una nuova esecuzione hosted, senza directory del laboratorio produttore e senza generare dati sostitutivi.

Originale artifact13362874826,6018250byte, SHA256 `33b5a7124d3990dce5c0049ff0a33653fec2d6fb29f07edb767a9680b8a441e3`. Il job verifica metadata, successo nativo originale, tutti i checksum e30sorgenti al commit originale. L'originale invariato viene incluso nelle nuove prove.

| Componente | File | Byte estratti |
|---|---:|---:|
| Basebackup PostgreSQL |1282|46885503|
| WAL |5|67109203|
| Cold backup SeaweedFS |104|22305|

## Procedura verificabile

1. Rifiuto di componenti alterati, percorsi non validi, link, duplicati, collisioni file/directory e destinazioni esistenti prima dell'estrazione. Confronto completo con gli inventari originali.
2. I tar originali conservano file regolari, non directory vuote: si ricrea la sola struttura vuota PostgreSQL17 e le directory dei ruoli SeaweedFS. Zero file di stato generati; permessi privati.
3. PostgreSQL17.11 compilato dalla stessa sorgente fissata; pg_verifybackup sul base estratto, prima delle modifiche di configurazione applicate alla sola copia di ripristino.
4. Replay WAL al target `ouf_joint33_frozen_epoch2`, LSN0/4008E28, timeline1. Sonde readonly finite60/20s prima di SQL. Stesso system ID fisico7704428212093439541, ledger FROZEN epoch2/version2 e6eventi identici, canary=cut, reserve/finish=FENCED dopo promotion.
5. Solo dopo verifica DB, avvio della stessa OCI33 sulla copia indipendente del cold backup estratto. GET/HEAD/LIST dei2oggetti/77byte identici al risultato originale,3dinieghi mutativi espliciti.
6. Arresti puliti dei4container e del clone PostgreSQL, invariabilità dello ZIP originale e dei tre input estratti. Readback indipendente di ogni byte,34sorgenti correnti e30originali, SQL/WAL/log/S3/stati finali. Nessun ulteriore restore nel job di readback.

## Validazione e limiti

9nuovi test locali PASS;15regressioni fisiche PASS. La copia locale parziale non include vendor-profile e test PITR: common-cut10PASS/1errore di preparazione, PITR0eseguiti; non si dichiara la suite completa locale. La suite completa44test è obbligatoria sul checkout hosted.

Il restore non ricrea una sorgente né un bucket e non risemina oggetti. I3PUT/DELETE di prova devono essere negati; zero PUT di recupero e retry mutativi. MiniPET18,3/46=39,78%,0/8gate,0/21AT,0/120oggetti reali invariati. Le prove pregresse, incluse quelle fallite, restano conservate. Nessuna nuova qualifica target, power-loss, RPO/RTO o admission.

## Esito hosted

**PASS** al commit `c096897c119f6cfc375d16260ff2ab44a23d52c7`, [run41976132880](https://github.com/GioNob/ouf-deploy/actions/runs/41976132880), attempt1 completed/success. Nativo127075295372 e readback indipendente127076271029 SUCCESS.44test Linux PASS; nessun nuovo tentativo nativo fallito.

Il recupero è avvenuto usando soltanto i tre payload esportati.15directory PostgreSQL vuote ricreate, zero file di stato generati; pg_verifybackup PASS. Tre sonde pg_isready prima di SQL. Medesimo system ID, target, ledger FROZEN, ACK e6eventi; canary=cut distingue il punto nominato dalla fine WAL. Reserve e finish respinti dal fence persistente dopo promotion. S3 avviato dopo il gate DB:2oggetti/77byte, body e metadati identici,3AccessDenied.4container e1clone PostgreSQL arrestati puliti. Tutti gli input originali invariati.

Readback hosted e locale identici:86membri/85checksum/34sorgenti del nuovo archivio; nell'originale annidato213checksum/30sorgenti, tutti1391file/114017011byte dei backup. Il job indipendente controlla l'evidenza; il secondo restore nativo è quello del job principale di questo nuovo run.

| Prova | Artifact | Byte | SHA256 |
|---|---:|---:|---|
| Restore originale |13391179599|6128331|`95b8281329907bb4e4e519412db8fe1d59a9209f5f8fe42e64aef5f4ab025b21`|
| Readback con copia invariata |13391443633|6121194|`274ab26178f7d1fc1b690b66f9c0a6ccf69fec52b57844fa625d46eae51b75df`|

Custodia Actions fino2027-02-03; entrambi contengono l'originale del nuovo restore, che a sua volta contiene il vecchio export13362874826 invariato. Nessuna nuova custodia durevole Git dei ZIP dichiarata. Receipt completa: `evidence/storage-exported-restore33-hosted-readback-20261105.json`; preflight locale e relativo limite documentati separatamente.

La lacuna “restore dai soli export su nuova esecuzione hosted” è chiusa per questa fixture quiescente. Prossimo ambito delimitato: riesaminare i gate MiniPET e mappare i writer applicativi OUF PostgreSQL/S3 e i requisiti di fencing effettivi, senza modifiche al target. RPO/RTO rappresentativi, carico concorrente/power-loss, writer target e admission restano aperti.
