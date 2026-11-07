# Passaggio del solo Onboarding a SeaweedFS

Stato: **preparato e verificato localmente; esecuzione VPS pendente**. Lo stack usa ancora MinIO finché il comando non produce la ricevuta di passaggio.

## Base verificata

La [ricevuta delle 16:15 UTC](../evidence/onboarding-current-copy-aligned-operator-20261107.json) conferma 12 oggetti Onboarding per 40.709 byte: 10 già coincidenti e 2 copiati con readback. Il client Java MinIO 8.6.0 dell'immagine installata aveva già superato PUT/GET su SeaweedFS con TLS. Entrambi gli esiti sono ricevute dell'operatore, non nuove esecuzioni VPS dell'agente.

## Un solo comando di passaggio

[Script](../scripts/switch-onboarding-to-seaweedfs-20261107.py), SHA-256 `1048b02e5ce9890d809af1a96973120ec5f48513ae58567f426dd0501089dc58`. Contiene il copiatore già usato, verificato per SHA-256; non scarica dipendenze né avvia laboratori isolati.

Durante l'esecuzione non avviare nuovi upload o altri comandi di riavvio. Il comando prende lo stesso lock dell'avviatore OUF e interrompe temporaneamente soltanto Onboarding.

1. Verifica immagine e readiness originali, ricevuta della copia, sorgente MinIO e destinazione SeaweedFS.
2. Prepara un truststore PKCS12 conservando tutti i certificati del truststore Java originale e aggiungendo la CA SeaweedFS. Usa `keytool` dell'immagine installata; il file temporaneo viene rimosso. Credenziali e truststore persistono in un mount privato, di sola lettura per il container.
3. Ferma Onboarding; rilegge e allinea il bucket corrente, poi ricontrolla che l'elenco sia invariato. Mantiene le regole del copiatore: nessuna riscrittura di oggetti esistenti diversi e nessuna perdita silenziosa dei tag.
4. Conserva fermo il container originale. Crea il sostituto con la stessa immagine `7b9d3e91…`, configurazione e risorse conservate, indirizzo/MAC/alias backend originali e rete privata aggiunta. Cambiano solo binding staging, parametri del truststore, mount relativo e label di tracciamento. Database e servizi diversi da Onboarding non vengono fermati.
5. Avvia il sostituto, verifica configurazione, mount, rete, readiness HTTP e TLS dalla rete del container. Conserva JSON e log di avvio nella directory privata indicata dal risultato.

Nessuna query DB viene emessa dallo script. Il normale riavvio dell'applicazione può accedere al proprio database; non si cambia immagine e non si aggiungono migrazioni.

## Esito e fallimenti

`ONBOARDING_SEAWEEDFS_READY` significa che il binding sostitutivo è avviato e pronto. **Non certifica ancora l'upload HTTP, la registrazione dell'asset o l'E2E.** Questi sono il prossimo risultato da verificare con le capability effettive.

Se fallisce prima dell'invio del comando di avvio del sostituto, prova a ripristinare l'originale e lo dichiara nel JSON. Dopo l'invio dello start, anche se la risposta manca, non riattiva automaticamente il writer MinIO: potrebbero esserci nuove scritture su SeaweedFS. In caso di `INCOMPLETE`, conservare il JSON e leggere l'esito prima di qualsiasi altro avvio. Non ripetere alla cieca il comando.

Il marker `/var/lib/ouf-storage-migration/onboarding-seaweedfs-current.json` identifica lo stato del passaggio. Il vecchio piano dei container resta intatto. L'[avviatore aggiornato](../scripts/ouf-runtime-20261107.py) usa il nuovo Onboarding quando il marker è completato, mantiene spento il precedente e avvia SeaweedFS prima del percorso E2E. Non usare copie precedenti dell'avviatore: contengono il vecchio ID Onboarding.

UDP mantiene per ora il binding precedente. MinIO resta acceso per gli altri percorsi ancora da migrare.

## Verifiche locali e limiti

Sei casi di configurazione/sequenza passano: risorse/mount/indirizzi conservati, override staging, copia a writer fermo, ripristino prima dello start, risposta create persa e mancato ritorno a MinIO dopo start incerto. `keytool` reale locale ha conservato 125 certificati e aggiunto una CA sintetica. Il controllo dell'avviatore sceglie il nuovo container e rifiuta passaggi incompleti o due owner in esecuzione.

Queste verifiche non eseguono Docker né il JDK 21 del VPS. La compatibilità nativa del nuovo container, l'accesso ai mount e l'avvio Spring saranno verificati dal comando sul VPS. [Registro delle verifiche](../evidence/onboarding-seaweedfs-switch-prepared-20261107.json).
