# Backup freddo MinIO → SeaweedFS: pacchetto v2

Stato: produttore v2 qualificato al commit562f2ca3efe0dd9052d3dce3f5abffb25380a918, [run42280383267](https://github.com/GioNob/ouf-deploy/actions/runs/42280383267) SUCCESS. Preparazione v2 sul VPS eseguita e HELD/PROTECTED_REGULAR_INPUT_REQUIRED; nessun fermo, cattura o restore target autorizzato da questo documento.

## Stato corrente: v2 già eseguita, non ripetere

Il predicato fallito comprende tipo regolare, UID0, nlink1, assenza scrittura gruppo/altri, dimensione non vuota entro limite. Input e condizione esatti ancora sconosciuti. Conservare aree e programmi v1/v2; nessun chmod/chown, reset o replay. La consegna installer più sotto è STORICA, già eseguita.

Prossima azione: scripts/read-storage-cold-v2-metadata-20261106.py (5479byte,SHA256689811fce4d95aa582e3a3db1253c25625c5d3a77b3b7e34615ce31a13e4c701). Usa una sola lettura dell'inventario v1 già hash-pinned e soli metadati O_PATH/O_NOFOLLOW dei5path /run, programma v2 e BASE. Stampa tutti i predicati non soddisfatti, non i contenuti o i percorsi privati. Nessuna chiamata Docker/provider o modifica. Sei test locali PASS; esecuzione VPS pendente. Non prova binding corrente dei processi né il sito esatto dell'errore passato. [Ricevuta del diniego](../evidence/storage-cold-v2-held-operator-20261106.json).

## Correzione dei due blocchi osservati

Il primo prepare v1 è HELD. Il readback conservato identifica40mount:7binding RO riferiti a5path distinti sotto /run, e31mount condivisi con container fuori roster non running al momento dell'inventario. [Ricevuta operatore](../evidence/storage-cold-mounts-operator-20261106.json). Nessun socket Docker/vista /proc tra i7binding. Non conosciamo ancora i tipi/contenuti correnti dei cinque path: non sono automaticamente considerati file sicuri.

La v2 ammette solo i sette binding esatti ruolo/hash-percorso/destinazione identica/RO. Richiede file regolare non vuoto, root, massimo1MiB, senza hardlink/symlink o ancestry scrivibile da gruppo/altri; rileva stabilità e vincola hash e metadati nel piano privato. Directory, dispositivi, socket, altri percorsi /run, /proc,/sys,/dev,/tmp restano respinti. I file sono inclusi nell'archivio e ricontrollati prima e dopo la copia. Non esiste un'esclusione generica delle configurazioni sotto /run. Il contenuto effettivamente visibile nei mount dei processi non è dimostrato dalla sola sorgente host; questo resta parte della review operativa prima del fermo.

Le condivisioni con container fuori roster sono registrate per ID/mount/generazione solo quando non running/paused/restarting e PID0. Alla cattura devono coincidere col piano e avere restart=no. L'utility NON cambia quella policy, non avvia/ferma alcun container e non prova l'assenza di ricreatori o strumenti amministrativi. Un container assente, nuovo condividente o mutato blocca. Non sommare i31mount per dedurre il numero di container coinvolti: il piano lo calcola per ID univoco.

## Consegna operatore: solo prepare v2

Installer: scripts/install-storage-cold-backup-v2-20261106.sh,1074byte,SHA2568177d6efaea7578051e0726c2369c3fb43e3b0f68f6987bedd930bc1bf91dee8. Scaricare da commit Git immutabile, verificarne SHA256 prima dell'esecuzione. L'installer scarica il produttore dal commit qualificato562f2ca3, confronta27538byte/SHA25674164357d05631f71c2dd86cf4a071abed61fa2a132e1652d77b927f86a58c2a, crea un nuovo file root0600 con O_EXCL/fsync e invoca soltanto prepare.

Nuovo programma /var/lib/ouf-storage-cold-backup-v2.py; nuova area /var/lib/ouf-storage-migration/cold-backup-20261106-v2. Il file /var/lib/ouf-storage-cold-backup.py e l'area v1 restano intatti. Un file/area v2 già presente non viene adottato né sovrascritto. Non cancellare i parziali o rilanciare dopo errore. Restituire solo il JSON stdout redatto; mai command private, piano privato, segreti o chiave privata.

Prepare legge un nuovo inventario locale Docker, controlla metadati delle fonti e i contenuti limitati dei cinque file /run, scrive il piano privato. È una nuova preparazione dopo correzioni esplicite, non replay del vecchio scope. Non ferma servizi e non produce il backup. Non eseguire capture ora.

## Perimetro e passaggio operativo

La proposta comprende14ruoli, MinIO, etcd, intero cluster PostgreSQL condiviso, fonti montate, immagini esatte e filesystem container per conservare il layer scrivibile. Richiede review esplicita dell'impatto sul cluster e degli altri DB. I container fuori roster condividenti sono vincoli di contenimento, non vengono inclusi automaticamente come ruoli da ripristinare. Le configurazioni originali sono conservate privatamente nella preparazione.

Sequenza dopo il piano: review di configurazioni/custodia e piano; destinatario pubblico age/SSH compatibile e prova di decifratura sul PC; finestra, contenimento dei writer/amministratori/ricreatori e decisione operativa applicabile; fermo pulito documentato; cattura; trasferimento cifrato sul PC Windows; verifica SHA256/decifratura/manifest e restore isolato. Il riferimento decision-reference registra l'intento, non autentica HUMAN/THS. Delega di sviluppo e scelta PC non autorizzano fermo/deploy/grant. Nessun comando operativo di stop è contenuto nel produttore o nell'installer.

PostgreSQL/MinIO/etcd richiedono exit0; applicativi143 indicano soltanto cessazione, non drain. Niente OOM137, pausa, restart o generazione mutata. Ambiguità da riconciliare senza replay. Backup fisico integro non dimostra consistenza applicativa DB/oggetti, autorità di riapertura o G0/G3 chiusi. Restore isolato e originali conservati; nessun restart/traffico automatico. Questo backup di migrazione non sostituisce il profilo continuativo full+WAL/PITR del PET UDP §81.

Cattura eventuale nella v2: un tentativo, massimo3600s,256comandi,192container,64fonti,100000entry,64GiB complessivi prodotti incluse copie intermedie, almeno1GiB libero. Prepare massimo300s e piano24h senza rinnovo automatico. Sono budget tecnici, non RTO/finestra accettati. Lettura completa hash/metadati, GNUtar UID/GID/ACL/xattr/sparse, verifica tutti i corpi archiviati e fonti alla fine; eventi container incompatibili bloccano. Le query al Docker Engine non costituiscono un fence globale da sole.

Archivio futuro, non ancora esistente: /var/lib/ouf-storage-migration/cold-backup-20261106-v2/capture/backup.tar.age, root0600. Plaintext conserva root0700/0600, nessun cleanup automatico. Trasferire soltanto dopo risultato positivo con dimensione/hash reali. Il ricevitore Windows scripts/receive-storage-backup-windows.ps1 verifica dimensione/SHA256 e non sovrascrive; runtime Windows ancora non qualificato. Chiave privata sempre sul PC; non pubblicare endpoint/percorso personale in Git.

## Prove e limiti

[Qualifica v2](../evidence/storage-cold-backup-v2-qualified-20261106.json):17test locali e hosted (stessi17casi); restore nativo3DB+1oggetto118784byte, file /run ripristinato con modo0600, file scrivibile respinto, container CREATED condividente vincolato, replay respinto, layer scrivibile conservato, originali fermi. Cifratura SSH e verifica dei membri PASS. Archivio sintetico1538608068byte: NON stima del VPS. ZIP rapporto576byte/SHA575c8dd3 verificato, singolo membro conservato in Git, quattro sorgenti Git esatti confrontati. Stesso Docker daemon/radici nuove, non secondo host o coorte14ruoli.

Fixture PostgreSQL: attesa postmaster definitivo PID1; pg_ctl exec137 riconciliato con serverexit0 e pg_controldata shut down, nessun replay. Storia v1 conservata nella precedente ricevuta storage-cold-backup-qualified-20261106.json. Questa nuova prova è giustificata dalle modifiche del produttore e dai due nuovi casi reali; non rinnova qualifiche senza delta.

MiniPET18,3/46=39,78%,0/8gate,0/21AT,0/120migrati;120corpi verificati. Nessun credito target aggiunto.
