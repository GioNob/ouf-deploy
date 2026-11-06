# Consegna operatore — preparazione input G0

## Checkpoint 2026-11-06 — binding e connessioni privati, senza blocco sul backup

Giovanni ha chiesto di proseguire senza attendere la ricognizione DR/backup. Non riproporre ora quella domanda come prerequisito della preparazione: backup indipendente e DR restano non provati e non accettati per il passaggio operativo. Nessuna approvazione HUMAN/runtime, deploy o creazione volumi implicita.

Due passi implementati: bozza tecnica con13binding storici attesi/due reti e preparazione delle quattroconnessioni locali. Il helper verifica bundle9053aa38,17ricevute,seed canonico e cinquegenerazioni kernel; legge quattroenvironment e riusa tre moduli MinIO originali per i file dichiarati. Può copiare segreti soltanto nella nuova area root0600; il rapporto espone conteggi/codici, non valori. URL DB estraneo, override/configurazione ambigua o sorgente symlink restano in HOLD/review, senza hostfallback. Nessun Docker/S3/SQL/check/collect; nessun vecchio scope rigiocato. Binding Docker, configurazione Spring effettiva e profilo retained restano da rivedere.

Qualifica `6c9de0f4cd7fe1831ebbfdc2104b32f544ce719d`, run42194949283/job127815743474 SUCCESS:14test locali e14CI (stessi casi, non28distinti), zero skip. Process reader iniettati nella fixture; nessuna nuova qualifica nativa dei provider. Readback6membri/5checksum/11sorgenti Git esatti,8file bundle; due alterazioni respinte con checksum ricalcolati. Quattro verifiche locali dell'installer, senza eseguire il preparatore target. Archivio13492110156,46525byte,SHA256 d7240d8cd40acb8e0177daa3b7c7198a142cfa1f8b5e10311248ab2a78240be8,scadenza2027-02-04T09:25:32Z; non custodia durevole.

Comando stabile: `scripts/download-and-prepare-storage-g0-inputs-20261106.py`, SHA256 43897499e5c5aed41da6ac33250ed7c3078cb6c9e85d33c266742aa90c456b24. Scarica sette sorgenti dal commit qualificato con hash fissi, poi li installa root0400 sotto staging/input-tools-6c9de0f4. L'installer non contatta servizi OUF. Il preparatore crea soltanto inputs/binding-draft-20261106; ripetizione dopo risultato legge il risultato senza rileggere segreti; area parziale conservata in HOLD. Vecchia bozza, pacchetto e storico intatti; directory dati/backup proposte non create.

Prossima coppia: esecuzione operatore del nuovo helper e review del JSON redatto; risolvere soltanto gli input effettivamente mancanti per il check locale e successiva decisione esatta di raccolta. Non chiedere password in chat, non richiedere di nuovo DR/backup per far partire questa preparazione e non ripetere prove riuscite. MiniPET18,3/46=39,78%,0/8gate,0/21AT,0/120oggetti reali, credito0. Source d5155899, MinIO/source-lock e piano congelato invariati; PR54 draft/open. CI del checkpoint documentale distinta dalla qualifica dedicata.

Ricevuta `evidence/storage-g0-input-preparation-qualified-20261106.json`, consegna `docs/OUF_STORAGE_G0_INPUT_DELIVERY_20261106.md`, contratto `docs/OUF_STORAGE_G0_INPUT_PREPARATION_20261106.md`, reader `scripts/readback-storage-g0-inputs-20261106.py`.


## Uso

Scaricare il downloader dal commit di questo checkpoint, verificando SHA256 `43897499e5c5aed41da6ac33250ed7c3078cb6c9e85d33c266742aa90c456b24`, poi eseguire con Python3 isolato come oufadmin. Lo script usa sudo solo per installazione privata e preparazione; richiede il bundle9053aa38 già preparato. I download usano commit Git e digest fissi, senza collegamenti artifact a scadenza. Nessuna nuova installazione psql o modifica del bundle già qualificato.

L'esecuzione può leggere credenziali esistenti e copiarle nei file privati della nuova bozza; non ne modifica le sorgenti, non ne stampa valori e non prova autenticazione ai servizi. Incollare soltanto il JSON redatto finale, mai passfile, seed o contenuti della bozza privata. Un risultato HELD va interpretato prima di ulteriori operazioni; non cancellare area o claim per riprovare.

Le connessioni sono candidati: il profilo retained deve essere verificato contro l'installazione e il confronto delle immagini/configurazioni Docker resta aperto. La correlazione installationRef non è identità IAM. Non lanciare collect per il solo fatto che la preparazione riesce: check, review e decisione applicabile restano separati.

## CI generale separata

 run42194962745, sealed-worker127815791533 e unico retry127818825693 falliti entrambi in phase.observe/provider_profiles.window con PROTOCOL_AUTHORITY_EXPIRED_OR_NOT_YET_VALID. File runtime/fixture coinvolti non modificati da questo candidato; gli altri tre job matrix conservano i timestamp originali. Nessun altro retry o guard allentato. Problema generale aperto; non dichiarare tutta la CI verde. Il run dedicato input42194949283 resta SUCCESS.

