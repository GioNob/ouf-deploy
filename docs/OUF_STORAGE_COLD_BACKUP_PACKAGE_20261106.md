# Pacchetto di cattura fredda per il backup MinIO → SeaweedFS

Stato: **qualifica nativa del produttore PASS**, run42276891427 al commit a38a61273543653b125e0ae1c51fd0c92ba9bbd0; preparazione VPS eseguita e HELD su mount da classificare; **nessun fermo o backup VPS eseguito o ammesso da questo documento**. Il comando di preparazione e quello di cattura sono distinti. Lo script non esegue stop, update della restart policy, restart, deploy, grant o restore.

## Blocco osservato sul VPS

Il tentativo prepare è già eseguito: non ripeterlo o cancellarne l'area. Il controllo rigetta sorgenti sotto /proc,/sys,/dev,/run,/tmp, ma il messaggio non identifica il mount. Non presumere che quelle sorgenti siano omissibili. Il prossimo comando usa scripts/read-storage-cold-preparation-20261106.py verificato per SHA256 e legge solo i file di inventario già conservati. Non chiama Docker, non legge i corpi delle sorgenti, non scrive nel tentativo e non prepara/cattura nuovamente. Il riepilogo redatto raggruppa tutti i mount e le condivisioni, verifica i binding e non mostra environment, percorsi privati o segreti. Stato di lettura conservato, non live. Sei test locali mirati PASS; esecuzione VPS del reader ancora pendente. Consegna con URL Git immutabile e digest del reader; eseguire con sudo python3 -I -B -S dopo verifica, restituire solo stdout.

## Scelta e impatto

Il backup fisico comprende l'intero PostgreSQL condiviso, MinIO e i dati/configurazioni montati dai tredici ruoli OUF più etcd. Comprende immagini Docker esatte e filesystem dei container, per conservare anche modifiche nel layer scrivibile. Questa scelta evita dump parziali e perdita dei ruoli/ACL del cluster. Richiede un fermo OUF più ampio dei soli tre owner: **deve essere approvato esplicitamente sul piano privato risultante**, insieme alla finestra e al contenimento degli strumenti amministrativi/dei ricreatori. Non è un'estensione automatica al resto del VPS.

Un backup PostgreSQL fisico richiede l'intero cluster fermo: [documentazione PostgreSQL17](https://www.postgresql.org/docs/17/backup-file.html). L'utility richiede uscita0 per PostgreSQL/MinIO/etcd e rifiuta provider ancora attivi, uscita non pulita, restart automatico abilitato, generazione/configurazione mutata, mount non supportati, symlink esterni e fonti condivise con container fuori perimetro. Gli eventuali tablespace/WAL esterni non vengono omessi silenziosamente. I tmpfs standard /tmp, /run, /var/run sono effimeri, non salvati; altri tmpfs richiedono review.

Per i ruoli applicativi, uscita143 dopo SIGTERM è accettata soltanto come processo terminato, non come prova di drain: applicationDrainProven resta false. OOM, SIGKILL137, pausa o restart restano respinti. La cattura conserva anche eventuali intenti o esiti applicativi da riconciliare. **Fermo fisico e copia integra non dimostrano consistenza applicativa DB/oggetti**, né chiudono G0/G3. Nessuna modifica ai dieci tenant NULL o ai diciotto rilievi. Un restore resta isolato e senza riapertura finché riconciliazione e autorità applicabili non sono soddisfatte. Questo backup puntuale non sostituisce il profilo continuativo full+WAL/PITR del PET UDP §81.

## File e sequenza

Utility autonoma: `scripts/storage-cold-backup.py`, Python standard library, GNU tar, Docker CLI sul socket locale. La sola cattura richiede anche `/usr/bin/age`. Non richiede installare server PostgreSQL, nuove credenziali SQL o cambiare privilegi. Usa i binding privati G0 esistenti con SHA256 dc0ab6d4bf36c03b8086ecbae1be1c3e2e381c94152be01dd1ff6bfbfcd04f6e; non riusa né modifica gli scope delle raccolte consumate.

1. **Preparare**, una volta: `sudo python3 -I -B -S /var/lib/ouf-storage-cold-backup.py prepare`. Legge l'inventario Docker corrente e le sole fonti montate previste, scrive un piano privato nella nuova area `/var/lib/ouf-storage-migration/cold-backup-20261106-v1`. Nessun stop, export di corpi, copia di dati o cambio runtime. Riporta soltanto ruoli, conteggi, hash, limiti e condizioni aperte. Le configurazioni private non vanno incollate in chat. Non rilanciare in caso di esito incerto o area già esistente.
2. **Review operativa** del piano esatto: finestra, fermo dei quattordici ruoli, riavvio automatico e ricreatori disabilitati, accesso amministrativo ai file sospeso, conseguenze sugli altri DB dello stesso cluster. La decisione deve autorizzare gli effetti reali; lo sviluppo e il riferimento testuale passato all'utility non sono un'approvazione HUMAN/THS.
3. **Cifrare per il custode**: age può usare una singola chiave pubblica SSH RSA/Ed25519, mantenendo la privata sul PC. [Contratto age](https://github.com/FiloSottile/age/blob/main/doc/age.1.ronn). Non leggere automaticamente tutte le authorized_keys e non esportare la privata. Se la chiave SSH non è supportata, usare un destinatario age dedicato generato fuori VPS. Verificare la decifratura con un piccolo file di prova prima del fermo; non assumere che SCP dimostri la custodia della chiave.
4. **Applicare il contenimento approvato**, con ricevute separate. La cattura non lo applica e non converte il solo possesso di root in autorità OUF. Verificare il fermo pulito, preservare intenti/esiti ambigui e non ripetere ciecamente un comando interrotto.
5. **Catturare**, un tentativo: comando sotto. Il risultato contiene il vero percorso, byte e SHA256 dell'archivio cifrato. Qualunque errore mantiene file privati e parziali; nessun reset, cleanup o restart automatico.
6. **Trasferire** sul PC con lo script Windows già preparato; verificare dimensione/SHA256, decifratura, manifest e restore isolato. Solo le evidenze del target e i criteri complessivi permettono credito G3.

Il comando di cattura, da completare con i valori reali dopo review, è:

```sh
sudo python3 -I -B -S /var/lib/ouf-storage-cold-backup.py capture \
  --plan-sha256 HASH_DEL_PIANO_PREPARATO \
  --recipient-file /var/lib/ouf-storage-migration/recipient.pub \
  --decision-reference RIFERIMENTO_DELLA_DECISIONE_OPERATIVA
```

I segnaposto non sono valori eseguibili. Il riferimento registra la decisione: **l'utility non ne autentica la provenienza e non è un nuovo endpoint di autorità**. Non usarla per aggirare il percorso HUMAN/THS applicabile. Gli accessi e i writer esterni vanno effettivamente contenuti nella finestra: un JSON dichiarativo non ne costituisce prova.

## Contenuto, limiti e verifiche

Area nuova e privata; script/manifest/input legati per hash. Un tentativo, massimo3600s di cattura,256 comandi figli,192container osservabili,64fonti persistenti,100000entry sorgente,64GiB complessivi prodotti (copie intermedie incluse), almeno1GiB libero durante ogni comando. Preparazione separata: massimo300s; piano utilizzabile entro24h, senza rinnovo automatico. Questi sono limiti tecnici proposti, non RTO o finestra già accettati.

Per ogni fonte: hash completo e metadati prima della copia, tar con UID/GID/ACL/xattr/sparse, lettura di ogni contenuto archiviato e confronto col manifest, nuova verifica delle fonti alla fine. Ispezione container prima/dopo e rifiuto degli eventi container diversi dagli export prodotti dall'utility. Nessun cambio generazione viene adottato. Tutti i dati e i segreti restano nei file privati, cifrati nell'archivio finale; stdout riporta soltanto il riepilogo.

La cifratura usa esclusivamente il destinatario pubblico fornito. I materiali in chiaro rimangono nel VPS, root0700/0600; nessuna cancellazione automatica. L'archivio cifrato finale è root0600: dopo verifica si può creare una **nuova** copia nella home dell'operatore per SCP, senza cambiare i permessi degli originali. Con Bash, dall'utente oufadmin:

```sh
( umask 077; set -C; sudo cat /var/lib/ouf-storage-migration/cold-backup-20261106-v1/capture/backup.tar.age > "$HOME/ouf-storage-backup-20261106.tar.age" )
```

Questo comando non sovrascrive un file già esistente. Eseguirlo soltanto dopo esito positivo della cattura, confrontare SHA256/byte con result.json e non trattare un parziale come backup verificato. Il percorso finale Windows predefinito resta `%USERPROFILE%/OUF-backup`. Chiave privata, endpoint SSH e percorso personale della chiave non sono pubblicati nel repository.

## Qualifica e limiti della prova

Suite locale nuova: dinieghi su writer attivo, stop sporco, generazione/configurazione/restart mutati, condivisione fuori roster, percorsi esterni, replay; round-trip reale GNU tar con hardlink, symlink interno e xattr, alterazione respinta.

Workflow `storage-cold-backup.yml`: fixture PostgreSQL e MinIO con digest già usati dalla qualifica G0; MinIO usa direttamente /usr/bin/minio e SIGTERM, come selezione esplicita del laboratorio; tre DB completi e un oggetto binario; cattura fredda, cifratura con destinatario SSH, decifratura, verifica di tutti i membri, restore su directory distinte e lettura SQL/S3. Conserva solo un rapporto redatto; non carica archivi, chiavi o configurazioni in Actions. L'immagine viene riletta dall'archivio nello stesso daemon CI: non è prova di recupero su un secondo host vuoto. Non qualifica automaticamente tutti i quattordici ruoli o il target.

Stato MiniPET invariato18,3/46=39,78%,0/8gate,0/21AT,0/120migrati. Questa implementazione rimuove la mancanza del produttore di archivio; la sua esecuzione VPS, le autorità e il restore del backup reale restano da completare.

## Esito della qualifica e consegna

[Qualifica e storia dei dinieghi](../evidence/storage-cold-backup-qualified-20261106.json):12test PASS; tre DB e un oggetto binario118784byte recuperati, cifratura SSH e rilettura di tutti i membri riuscite. ZIP del rapporto537byte verificato contro SHA2564cf2c962f84d96ba2ea2de4fdbd6a60e5d83ffc46b4e558763f0c835eaaeea07; unico membro conservato in Git. Non è secondo restore indipendente. La dimensione1538597828byte è del SOLO archivio sintetico CI, non del futuro backup VPS.

La fixture aspetta il postmaster definitivo PID1 prima del seed. Arresto PostgreSQL con pg_ctl fast: l'exec ausiliario è terminato137, ma l'esito del server0 e pg_controldata shut down sono verificati senza replay. L'uso del solo docker stop aveva prodotto un137 del server e il controllo lo ha correttamente respinto. Sul VPS il metodo deve essere legato al processo/PGDATA effettivi e alle autorità applicabili, non copiato dalla fixture senza review.

Programma da consegnare: commit a38a61273543653b125e0ae1c51fd0c92ba9bbd0,24677byte,SHA2563f8f255bf80cf2e077260ecf5ff2c31f14a624529864c8d3fac956877359cac8. Installare una nuova copia root0600 in /var/lib/ouf-storage-cold-backup.py dopo confronto integrale del digest; non sovrascrivere una versione già presente. Comando storico già eseguito, NON ripetere: `sudo python3 -I -B -S /var/lib/ouf-storage-cold-backup.py prepare`. Esito acquisito: HELD/EPHEMERAL_OR_DEVICE_MOUNT_REQUIRES_REVIEW; la preparazione non ha prodotto il piano. Non lanciare capture e non fermare servizi prima della review del piano e della decisione applicabile.

