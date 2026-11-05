# Restore33 dai soli backup esportati — 2026-11-05

Stato: **PENDING**, qualifica sintetica separata dal target.

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

Da completare con commit/run/job, archivio originale del nuovo restore e readback terminale.
