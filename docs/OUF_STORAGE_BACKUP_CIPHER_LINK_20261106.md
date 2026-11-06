# Collegamento cifratura VPS → PC Windows

Due ricevute reali acquisite: [impatto VPS](../evidence/storage-cold-plan-impact-operator-20261106.json) e [custodia PC](../evidence/storage-backup-windows-custody-operator-20261106.json). Non ripetere le rispettive preparazioni. Il PC ha già age1.3.2,chiave privata locale e area con ACL esclusiva; il VPS non ha /usr/bin/age. Pubblico completo,endpoint e percorso personale della chiave restano fuori Git.

## Consegna Linux qualificata

[Run42289795526](https://github.com/GioNob/ouf-deploy/actions/runs/42289795526),commit2fd593888a9773a238e4c297abe5c3c72933ec9c: SUCCESS. [Ricevuta verificata](../evidence/storage-backup-linux-cipher-qualified-20261106.json). Nuova qualifica dell'installer/prova,nessun rerun backup. Sorgente scripts/prepare-storage-backup-cipher-linux.py6177byte,SHA146c14ca41b928e62a5791ce7b7ffec458052fd4e6ab7959f7908c79d79b1c5e.

Scaricare una volta lo script dal commit esatto e verificare SHA; scaricare [age-v1.3.2-linux-amd64.tar.gz](https://github.com/FiloSottile/age/releases/download/v1.3.2/age-v1.3.2-linux-amd64.tar.gz),19405817byte,SHA cbe24006683f8eb669266162894b9a522a1af52f2665fbc63a4bb032ed26ac10. Il preparatore legge il download una volta,verifica hash/dimensione e seleziona soltanto membro regolare age/age in memoria; non estrae percorsi tar. Poi crea /usr/bin/age root0755 senza sovrascrivere file/symlink preesistenti. Non è un servizio o deploy applicativo.

Invocazione root isolata: python3 -I -B -S SCRIPT --archive ARCHIVIO --recipient PUBBLICO --recipient-sha256 20582d7f592199d5964fc64ece8d035bdf3b93df026c5e222eca615c0f8bb2c0. Il pubblico viene fornito privatamente dall'operatore,non sostituito o generato sul VPS. Nuova area root0700 /var/lib/ouf-storage-cipher-preparation-20261106,recipient.pub e ricevute0600; prova512byte casuali non applicativi,cripta tramite age e stampa JSON con ciphertext Base64/hash/dimensione. Privata non richiesta né letta. Non legge container,DB,S3 o dati applicativi; nessun fermo/policy/capture o rinnovo del piano. Se errore,preservare area/binario e risultato; niente retry o cancellazione per sbloccare.

## Decifratura Windows dopo il JSON Linux

Usare il workspace già preparato %USERPROFILE%/OUF-backup-custody-20261106,senza rieseguire il client iniziale. Verificare age.exeSHA2821a4ed191da07372acd302e5f6feae7a7985e285e1417765ebe74025af45f0 e recipient.pubSHA20582d7f592199d5964fc64ece8d035bdf3b93df026c5e222eca615c0f8bb2c0 prima della prova. Il nuovo JSON deve avere schemaouf.storage-backup-linux-cipher.v1,statoLINUX_CIPHER_PREPARED_WINDOWS_DECRYPT_REQUIRED,ageBinarySHAeb7dd1b518f0a307c99cd97782623c5321da049154b04acd2d98d21aa7bc9b2c,recipientSHA coincidente,probe512byte e ciphertext<4096byte.

Decodificare Base64 in un NUOVO file ciphertext locale,verificarne byte/SHA rispetto al JSON,poi age.exe -d -i CHIAVE_LOCALE su quel file verso NUOVO output. Confrontare512byte/SHA del plaintext con probeSha256. Nessun download/trasferimento della privata. Riportare soltanto hash/dimensioni/esito;chiave/passphrase mai in chat. Comando specifico da consegnare con il JSON Linux,per evitare sostituzioni manuali di ciphertext/hash. Questa prova non è trasferimento/restore del backup reale.

## Impatto e criterio ancora aperto

Piano backupSHA1c0bb62ceba85f748e43465d36f016b4c575c586d40390dc92095a1dbc71bd0f,scadenza7novembre2026ore20:53:39Europe/Rome.35policy da modificare:13ruoli selezionati +22condividenti fermi;semantic e81condividenti già no. Nessuno dei103va avviato. Dati conservati,non stato live. Budgetcapture3600s/64GiB prodotti,non finestra disservizio o dimensione archivio.

Il backup comprende l'intero PostgreSQL condiviso e14ruoli. Prima del fermo restano comandi/binding correnti,contenimento ricreatori/amministratori/esterni,drain esiti in-flight,fermo pulito,finestra e decisioni applicabili. Nessun consenso operativo derivato dall'installazione age. G3 richiede ancora backup completo,copia indipendente e restore rappresentativo; MiniPET invariato39,78%,0/8gate,0/21AT,0/120migrati,120verificati.
