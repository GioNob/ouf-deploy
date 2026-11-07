# Preparazione delle directory di capacità G0

Il primo check composto è riuscito sull'input SHA2568643c92990916d9717d92d3dcc18d1c89f1a33e4d31e4c2a3f4b7dae91ce6a7b. Il precheck operatore ha però trovato destination e backup assenti: collect fallirebbe dopo aver consumato il claim e osservato Docker. La correzione riguarda solamente lo staging locale.

## Cambio di piano concreto

Nuovo candidato:
- /var/lib/ouf-storage-migration/seaweedfs — directory dati proposta, vuota;
- /var/lib/ouf-storage-migration/backup-staging — staging locale backup, vuoto.

Viene creata anche la loro radice comune; massimo3mkdir, root0700. Questi percorsi sostituiscono esplicitamente le precedenti proposte /var/lib/ouf/seaweedfs e /opt/ouf/backup/seaweedfs nel SOLO nuovo input. Non si toccano directory backup esistenti. Due directory sullo stesso filesystem non costituiscono backup indipendente, DR o capacità sufficiente. Il codice non monta volumi, installa servizi, dà permessi a utenti applicativi o cambia il traffico.

Se la nuova radice esiste già, qualunque sia contenuto/owner/mode, il comando nega l'adozione. Nessun mkdir -p, chmod, chown, unlink o pulizia automatica. Parent /var/lib e sorgente devono già soddisfare ancestry root protetta senza symlink. La scelta mantiene separata la custodia nuova da quella delle vecchie aree; non assume una nuova misura dell'owner di /opt/ouf.

## Esecuzione e risultato

scripts/prepare-storage-g0-capacity-directories-20261106.py viene consegnato al commit immutabile con SHA256. Esecuzione root isolata -I -B -S senza argomenti. Prima di importare il pacchetto installato verifica manifest e tutti i file, esclude aggiunte/symlink e sorgenti alterati. Poi richiede inputSHA e sei binding esatti già restituiti dall'operatore, con metadata private/custodite e hash, senza leggere i passfile o chiavi S3 in questa fase.

Scope nuovo inputs/capacity-directory-preparation-20261106, claim prima dei mkdir. Un tentativo,60secondi cooperativi,tre creazioni dati. Scope/claim e nuovi file0600 root privati, directory0700 e fsync. Qualunque errore preserva ciò che è stato creato e riporta tentativi/successi; ripetizione con result legge solo result, parziale senza result resta HELD. Non cancellare scope o area per riottenere budget.

Dopo creazione verifica figli vuoti/root0700, riusa g0_host.capacity originale per filesystem/memoria, scrive capacity-observation.private.json e capacity-evidence.review.json. Quest'ultimo è TECHNICAL_OBSERVATION e dichiara esplicitamente capacitySufficiencyProven:false, growthAndThroughputProven:false, independentBackupVerified:false, operatorAcceptance:false, sourceCustodyAdmitted:false.

Un nuovo package-input.review.json conserva operazione, source, connessioni, rete, runtime e17ricevute; modifica solo due percorsi capacità e il riferimento alla nuova evidenza CAPACITY. collectionDecisionRef resta null. g0_package.preflight originale verifica il nuovo input e rilegge le cinque copie locali di credenziali: nessun valore stampato, nessuna copia nuova né autenticazione. I sei binding già osservati devono coincidere anche nel nuovo check. Il cambio input giustifica questo check; non ripetere quello vecchio.

Esito atteso CAPACITY_DIRECTORIES_PREPARED_LOCAL_INPUTS_BOUND_REVIEW_REQUIRED, nuovo inputSha256 e lista mancanze aggiornata. L'assenza di OPERATOR_CAPACITY dalla lista prova solo che esiste un documento tecnico valido, non la chiusura di G0-CAPACITY. ACCESS/CUSTODY/WINDOW/WRITERS e decisione rimangono espliciti. La raccolta non viene avviata.

## Prove e limiti

11casi mirati locali/CI, stessi casi e non22distinti. Le prove usano directory/file temporanei e preflight/capacity originali; nessun Docker/S3/SQL. Nel sandbox locale manca /proc/meminfo: primo tentativo8PASS/2FAIL, poi fixture della sola memoria; CI usa il file kernel reale senza fallback. Aggiornamento successivo: digest binding esatti e relativo test,11PASS. Manifesto, script e test esatti qualificati dal workflow storage-g0-capacity-directories.yml; esito run/artifact nella PR54.

Non eseguito dall'agent sul VPS: la conferma verrà dal solo JSON operatore. MiniPET18,3/46=39,78%,0/8gate,0/21AT,0/120oggetti reali,credito0. Nessun merge, deploy, grant, collect, stop writer o reset. Custodia/backup/RPO/RTO/capacità rappresentativa restano criteri da soddisfare, senza fermare questa preparazione su una nuova domanda generica di DR.
