# Onboarding owner — drain, common cut fisico e recupero

## Perimetro dei due passi

1. Collegare l'owner Onboarding V39 al protocollo di drain, riconciliazione e freeze. L'implementazione usa le tabelle e i budget esistenti: nessuna nuova autorità runtime, endpoint operativo o migrazione SQL.
2. Qualificare il recupero fisico di quelle tabelle insieme al contenuto SeaweedFS, usando esclusivamente backup esportati e verificando il blocco dei writer obsoleti.

Codice nella [PR Onboarding54](https://github.com/GioNob/ouf-source-onboarding/pull/54). Coordinamento nella [PR deploy54](https://github.com/GioNob/ouf-deploy/pull/54). Questa qualifica riguarda due oggetti sintetici, non il target OUF.

## Protocollo implementato

`ManagedFileStorageRecovery` è un componente interno del package applicativo, senza endpoint/scheduler o comando di riapertura. `beginDrain(expectedEpoch)` prende il lock esclusivo del controllo e passa ACTIVE→DRAINING con confronto della generazione. Reserve e ACK applicativi restano bloccati dal coordinatore V39.

`reconcile(intentId, expectedEpoch, store)` richiede DRAINING e la stessa generazione dell'intento. Prima del GET consuma, in una transazione breve, il budget durevole già esistente: massimo128letture/24ore. Il GET avviene senza transazione aperta. Hash e lunghezza devono coincidere; prima della pubblicazione vengono ricontrollate generazione e scadenza del budget, bloccando l'intento. Il limite include quindi il tempo trascorso nel GET; lo stesso controllo finale è applicato anche al coordinatore upload ordinario. Asset, ricevuta delegata e ACK vengono salvati atomicamente. Un concorrente trova la stessa ricevuta; non viene inviato un nuovo PUT.

`freeze(expectedEpoch)` richiede che ogni intento sia ACKED e prende il lock esclusivo del controllo. Un intento irrisolto, anche di una vecchia generazione, impedisce il punto comune. Ripetere drain/freeze nello stesso stato è idempotente; non viene azzerato alcun budget. Una variazione di generazione durante il GET impedisce la pubblicazione tardiva.

L'arresto fisico dei writer storage è responsabilità del chiamante operativo. Nel laboratorio tutti i processi SeaweedFS vengono fermati, poi ripartono con la stessa identità S3 ridotta a Read/List. Tre PUT di controllo, su entrambi gli oggetti esistenti e su una chiave nuova, devono ricevere AccessDenied. Solo dopo questa verifica avvengono riconciliazione e freeze. Il componente Java da solo non revoca credenziali né protegge altri moduli.

## Prova fisica

La fixture usa PostgreSQL17.11 da immagine acquisita e identificata per digest, e l'esatta OCI SeaweedFS33 qualificata in precedenza. Lo stesso image ID PostgreSQL viene usato per sorgente e ripristini; non si trasferisce una scansione di sicurezza precedente a questa immagine PostgreSQL.

Il basebackup precede gli intenti. Un primo upload è confermato; nel secondo, il PUT termina, viene avviato il drain e il normale ACK applicativo è respinto. La presenza dell'intento pendente impedisce il freeze. Dopo l'arresto e la riduzione delle autorizzazioni storage, la riconciliazione rilegge l'oggetto e chiude l'intento senza rispedirlo.

Il punto PostgreSQL nominato `ouf_onboarding_upload_frozen_v39` lega le tabelle reali dell'owner al cold backup di master, volume, filer e configurazione S3. Il segmento WAL del target deve essere successivo al basebackup. Un canary cambia dopo il target per distinguere il PITR corretto dal replay fino all'ultimo WAL.

Sorgente PostgreSQL e storage vengono fermati; basebackup, WAL e cold copy sono esportati in tre tar. Il ripristino usa nuove directory estratte esclusivamente da questi tar. Prima il negativo rimuove il WAL richiesto da una copia e deve fallire senza avviare S3. Poi il positivo deve promuovere il database al punto esatto, preservando integralmente controllo, intenti, ricevute, asset e riconciliazioni owner. Nuovi upload e riconciliazioni obsoleti devono essere respinti prima di accedere allo storage. Soltanto dopo questo gate riparte S3 dai dati ripristinati: corpi, hash, MIME, HEAD e LIST devono coincidere; altri tre PUT devono essere negati.

## Prove ed errori conservati

- Primo incremento `58e092b476ba198bfbc82111e30139359737884a`, [run41993548186](https://github.com/GioNob/ouf-source-onboarding/actions/runs/41993548186):22scenari nativi eseguiti,2fallimenti per diversa proiezione della risposta tra prima riconciliazione e replay. Stesso asset, ma `tenant_id` era restituito soltanto la prima volta. Corretto il metodo, mantenute le asserzioni. [Diagnosi e artifact originali](../evidence/onboarding-common-cut-first-failure-20261105.json).
- `13fb6970c1727751ab15767319ae5cd6b2f69ddc`, [run41994377586](https://github.com/GioNob/ouf-source-onboarding/actions/runs/41994377586):22scenari nativi +8test API/storage PASS. I primi sette nuovi scenari coprono drain/freeze, assenza, corruzione, epoch durante GET, budget, concorrenza e ACK tardivo durante PUT.
- Primo laboratorio fisico [run41994377678](https://github.com/GioNob/ouf-source-onboarding/actions/runs/41994377678):FAILED prima del ripristino, per interpretazione Python dei segnaposto PostgreSQL `%f/%p`. Backup originali e seconda copia conservati. [Diagnosi](../evidence/onboarding-common-cut-restore-settings-failure-20261105.json). Correzione della configurazione con regressione locale PASS.
- Sorgente `00ff6943d6bdd746b23479192be8fd9bd326150c`; [run fisico41994840822](https://github.com/GioNob/ouf-source-onboarding/actions/runs/41994840822) e [regressioni41994840678](https://github.com/GioNob/ouf-source-onboarding/actions/runs/41994840678):PASS, incluso readback32membri/31checksum/263sorgenti/1671file dei backup e5negativi. [Ricevuta storica](../evidence/onboarding-common-cut-before-deadline-20261105.json).
- Revisione finale:controllo della scadenza anche dopo I/O, prima di pubblicare un nuovo ACK. Due test aggiunti con scadenza durante GET, per upload normale e recupero. Fonte finale `bf6bcf926727b5ea738155ac70a71b73f1b21f68`; [regressioni41995519285](https://github.com/GioNob/ouf-source-onboarding/actions/runs/41995519285) e [recupero/readback41995519200](https://github.com/GioNob/ouf-source-onboarding/actions/runs/41995519200) entrambi SUCCESS.24scenari nativi +8test API/storage PASS, zero errori/fallimenti/skip. Un test Python della configurazione PASS anche in locale; nessuna esecuzione Java/Docker locale dichiarata.

Il readback su un secondo runner acquisisce lo ZIP originale verificando ID, run, commit, dimensione e SHA256 GitHub. Controlla ogni membro, l'insieme esatto dei sorgenti e ogni byte dei tre backup; verifica inoltre le identità owner, i dinieghi S3, il target nativo e gli arresti puliti. Cinque copie alterate, con checksum esterni ricalcolati, devono comunque essere respinte. Questo è un readback indipendente dei bytes, non un secondo restore nativo.

## Esito finale della qualifica nativa

[Receipt completa](../evidence/onboarding-common-cut-qualified-20261105.json). Fonte `bf6bcf926727b5ea738155ac70a71b73f1b21f68`:24scenari dell'owner e8test API/storage PASS. Recupero fisico e readback indipendente entrambi PASS, con cinque negativi del verificatore respinti anche ricalcolando i checksum esterni.

- Originale artifact13399518195:7088032byte SHA256`59c53ae342458350e25c7fe9a628983aae3b6310f10347a76991d65ba95da0cf`.
- Readback artifact13399883382:7086781byte SHA256`ce3b2ba4e5b5f5311b3291cb05f39b5c778f900aef273b2e1e2dea0e2eddd2c7`, include originale invariato e ricevuta indipendente.
-32membri ZIP/31checksum/263sorgenti e1671file dei backup verificati sul secondo runner;2oggetti/36byte,6AccessDenied,12arresti storage e2PostgreSQL puliti, oltre al recupero negativo terminato come atteso.
- System identifier sorgente e ripristinato `7704603305971687464`; identico punto nominato, canary post-target escluso e tabelle owner identiche prima e dopo le riletture S3.
- Artifact owner13400107144:69793byte SHA256`5db1c2e7d9d3e1264b3b1ceb5eaca68dde75bb86b08724fceb30cc9c6a41f433`.
- Custodia Actions fino2027-02-03. In questa sessione non è stato scaricato lo ZIP per un terzo readback locale; la verifica byte-per-byte dichiarata è quella del secondo runner. Sorgenti/checkpoint sono disponibili nel checkout Git locale.
- Checkpoint deploy precedente99594c8:50/50workflow SUCCESS. CI completa Onboarding sul nuovo head:8/8workflow SUCCESS,compresi test del modulo,build,scansione bloccante e avvio container(PR41995525291/push41995519218).

## Limiti e prosecuzione

Restano aperti il binding operativo, gli altri writer UDP/Ingestion, rollout misto, riapertura governata con nuova generazione, revoca coordinata di tutte le identità e obiettivi rappresentativi RPO/RTO/power-loss. La fixture non esegue profiling, ingestion, purge o rebuild; non qualifica il grafo completo. Non espone un endpoint amministrativo o attribuisce autorità al solo chiamante Java.

Prossima coppia proposta:1) predisporre un ingresso operativo autorizzato e auditabile per il protocollo owner, legato a una prova di quiescenza storage;2) verificarne concorrenza, revoca, scadenza e mancata riapertura senza nuova autorità. Prima riesaminare i contratti owner esistenti; nessuna nuova HUMAN authority implicita.

MinIO, source-lock e MiniPET18,3/46=39,78% invariati;0/8gate,0/21AT,0/120oggetti reali. Nessun merge, deploy, target operation, replay, reset, grant o nuova acquisizione. Tutte le prove storiche sono conservate.
