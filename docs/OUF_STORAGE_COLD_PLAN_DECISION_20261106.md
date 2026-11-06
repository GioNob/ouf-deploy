# Piano backup v3: custodia e impatto prima del fermo

Stato: PREPARAZIONE TARGET RIUSCITA, NESSUNA AUTORITÀ DI FERMO. Il piano privato è vincolato a SHA2561c0bb62ceba85f748e43465d36f016b4c575c586d40390dc92095a1dbc71bd0f. [Ricevuta operatore](../evidence/storage-cold-v3-prepared-operator-20261106.json). Non ripetere installer/prepare né cambiare la scadenza del piano.

| Dato acquisito | Valore | Limite della prova |
|---|---|---|
| Ruoli |14:apisix,caddy,etcd,gateway-owner,ingestion,ingestion-evidence-read,keycloak,mcp,minio,onboarding,postgres,semantic,udp,udp-evidence-read |Proposta di perimetro; nessuno stop eseguito |
| Fonti |34, incluse5directory /run verificate dal preparatore |Non è ancora un archivio o restore |
| Condivisioni fuori roster |103container già fermi alla preparazione |Non significa103policy da modificare e non autorizza avvio/fermo |
| PostgreSQL |Intero cluster condiviso |Fermo coinvolge anche eventuali altri DB; impatto da approvare |
| Budget cattura |3600s;64GiB complessivamente prodotti incluse copie intermedie |Non è durata approvata del disservizio, dimensione attesa dell'archivio o RTO |
| Destinazione |PC Windows di Giovanni |Spazio/custodia/decrypt/restore effettivi ancora da verificare |

## 1. Lettura dell'impatto esatto sul VPS

scripts/read-storage-cold-plan-impact-20261106.py,5481byte,SHA469be254e07b04e9cf1616d344803a1b5b1ca7e38ddd727d2b4a68dd80a25713. Verifica il programma v3 installato e il piano esatto; legge i documenti inventory già salvati nel prepare, controlla completezza,fingerprint ruoli e103binding di condivisione. Riporta policy dei14ruoli, conteggi delle policy condividenti, quante richiederebbero un cambio a no, epoch creazione/scadenza e stato di scadenza. Somma solo i corpi/file delle fonti /run già nel piano; non li scansiona di nuovo e non misura tutto il backup.

Nessuna chiamata Docker o provider,nessun corpo sorgente letto,nessun cambio di policy/stato/file. Controlla soltanto presenza /usr/bin/age e spazio locale corrente. Le policy riportate sono della raccolta conservata, non una nuova attestazione live; la presenza di age non ne qualifica versione o integrità. Piano scaduto viene segnalato, non rinnovato. Restituire solo JSON redatto, mai piano o command private.4test locali PASS su conteggi/redazione,scadenza,drift policy e generazione.

## 2. Prova di custodia sul PC Windows

scripts/prepare-storage-backup-custody-windows.ps1,6294byte,SHAa1cf932f340fb24d896299a1fe1c4ab84eb4183f33ba52954d686eb6f4e3d41c, qualificato al00c567d8795a0d4060f4ea2da868e7937af2b933. Usare PowerShell normale,non amministratore. Parametro IdentityFile: chiave privata SSH locale già fornita in conversazione; il percorso personale non è pubblicato nel repository. Non cambiare ExecutionPolicy. Lo script è invocabile come scriptblock dopo verifica integrale SHA256 del testo scaricato.

Deriva il pubblico della chiave esistente tramite ssh-keygen; supporta RSA/Ed25519 come il produttore. Se chiave cifrata, l'eventuale passphrase si inserisce soltanto nel prompt locale. Non incollare la privata o la passphrase in chat. Il client non le copia,non le invia a server e non tocca le ACL della chiave originale.

Crea una nuova area %USERPROFILE%/OUF-backup-custody-20261106 con ACL limitata all'utente, senza adottare/sovrascrivere aree esistenti. Scarica20.250.704byte dalla [release age1.3.2](https://github.com/FiloSottile/age/releases/tag/v1.3.2), pubblicata29agosto2026; verifica SHA256f48d8f8f9ebe903ab5027ed067652f2cc1db94bc206976430133b905dcd8e8c7 prima dell'esecuzione. Estrae solo age.exe in quella cartella; non installa servizi o modifica PATH/ExecutionPolicy. Pacchetto per AMD64: architetture diverse bloccano prima del download.

Cifra e decifra4096byte casuali non sensibili con il pubblico e la privata locale, confronta SHA256 e dimensione. Stampa un JSON con pubblico (condivisibile),hash del recipient.pub,versione/hash tool,esito prova e spazio disponibile. Il campo remoteConnections=0 riguarda connessioni VPS/SSH; externalDownloads=1 dichiara il download HTTPS GitHub. Nessun backup o accesso al VPS avviene. Minimo128MiB è per tool/prova, NON accettazione della capacità del backup. Mantiene tool/prova/risultato e pubblico nel nuovo workspace; privata originale invariata. Non rilanciare dopo errore o area già presente.

[Qualifica Windows](../evidence/storage-backup-windows-custody-qualified-20261106.json): run42284908808/job128123098311 SUCCESS, Windows2022/PowerShell5.1.20348.5773, chiave sintetica,roundtrip,ACL esclusiva,privata invariata e replay/overwrite negato. ZIP527byte/SHA9c67b8de verificato; unico rapporto conservato in Git. Primo tentativo42284741360 fallito per più copie ssh-keygen risolte come array; corretto selettore sia nel client che nella fixture. Non è esecuzione sul PC di Giovanni, né decrypt di un ciphertext prodotto sul VPS o restore target. Il test backup Linux riuscito non è stato ripetuto.

## Decisione operativa da rendere concreta dopo i due output

Legare al piano esatto: recipient pubblico verificato e digest,tool di cifratura VPS compatibile,policy da cambiare davvero,modalità di inibizione dei ricreatori/accessi amministrativi,drain e riconciliazione in-flight,fermo pulito dell'intero cluster e degli altri ruoli,inizio/fine finestra e budget della singola operazione. Nessun comando di mutazione operativo è ancora consegnato o approvato da questo documento. Il solo numero103 non autorizza modifiche in massa.

La finestra di disservizio deve includere i passi operativi ammessi e la verifica necessaria prima di riaprire; non confonderla con il budget capture3600s. Non chiedere un sì generico al fermo finché perimetro/policy/comandi e finestra non sono concretamente reviewabili. La decisione utente richiesta a quel punto resta distinta dal grant HUMAN/THS applicabile: il campo decision-reference del produttore non autentica autorità runtime.

Dopo custodia/containment/decisioni: capture una volta,verifica archivio,trasferimento al PC tramite ricevitore già predisposto,decifratura/manifest e restore isolato rappresentativo. Nessuna riapertura automatica dopo backup o restore,nessuna cancellazione originali. Restano criteri MiniPET complessivi;18,3/46=39,78%,0/8gate,0/21AT,0/120migrati;120verificati,credito0.
