# Consegna G0 per le reti private — 6 novembre 2026

Il blocco del trasporto rilevato sul VPS è coperto dal candidato qualificato9053aa38. La raccolta reale resta da preparare e ammettere. Contratto tecnico: [profilo reti](OUF_STORAGE_G0_NETWORK_20261106.md). Esiti/digest completi: [ricevuta](../evidence/storage-g0-network-qualified-20261106.json).

## Checkpoint 2026-11-06 — accesso G0 alle reti private qualificato

- Output di Giovanni recepito: preparazione v1 sul VPS riuscita,17ricevute legate, nessuna credenziale/provider letto; MinIO e PostgreSQL con process pin storico ancora corrispondente, listener IPv4/IPv6 nelle reti diverse dall'host. Prova locale riportata dall'operatore, non raccolta agent né binding Docker completo corrente. Supera lo stato precedente «esecuzione preparatore pendente».
- Due passi completati: profilo G0 v2 con child nella sola rete del provider e qualifica della composizione completa in CI. Parent/host preservato; binding esatto boot/PID/startTicks/net/mnt, pidfd/FD e liveness durante l'attesa; nessun rebind/fallback/replay. Collector S3, SQL e7pin qualificati invariati.
- Candidato `9053aa382e8058b4bc30123750e719614a5ef564`, run42180924811/job127770098161 **SUCCESS**:13test composizione+14rete, zero skip sul runner; scansioni separate dei due eseguibili senza rilievi. Fixture MinIO/PostgreSQL in due reti none senza porte pubblicate:95migrazioni originali,2corpi/6byte,3export,join senza rilievi,4child,28GET Docker (80con i52storici sintetici),13esiti di uscita puliti. FD scambiato, owner terminato e replay respinti. Non servizi completi né dati target.
- Readback24membri/23checksum/120sorgenti Git esatti,15file pacchetto; tre alterazioni con checksum ricalcolati respinte. Archivio13485118791,SHA256 `50e92187370f92aac3dc19b8399a4f9c3edbfa5acfff46336117c2f8e38441fe`,7396253byte,scadenza2027-02-04T07:26:49Z. Non custodia durevole né secondo run nativo indipendente.
- Fallimenti91c733bf e158348d9 conservati: copia del collector per Trivy senza bit eseguibile, prima rapporto incompleto poi Results assente. Corretto copy2 e diniego esplicito per report assente; nessun provider fixture avviato nei due tentativi e nessun controllo indebolito. Codice operativo identico fra i tre candidati.
- Nuovo preparatore `scripts/prepare-storage-g0-network-private-20261106.py`, tre verifiche locali PASS/dinieghi attesi. Consegna in area nuova; verifica17digest contro la preparazione precedente, conserva storico e vecchia area. **Non ancora eseguito sul VPS**. Bundle9053aa38 e manifest sono nella ricevuta; non usare il vecchio helper e7c46c73 per il nuovo archivio.
- MiniPET invariato **18,3/46=39,78%;0/8gate,0/21AT,0/120oggetti reali**, credito0. Nessun merge/deploy/grant/collect target/riapertura/reset. Source d5155899, MinIO/source-lock e piano JSON congelato invariati. Qualifica del candidato distinta dalla CI del checkpoint documentale.
- Prossima coppia: (1) preparare il nuovo bundle e compilare privatamente binding/connessioni correnti per ottenere check; (2) completare/revisionare census writer, ACL, capacità, custodia e finestra e presentare il comando concreto al gate applicabile prima dell'unica raccolta G0. Il riferimento collectionDecisionRef non autentica HUMAN. Non richiedere di nuovo canale VPS o installazione psql; non ripetere prove riuscite né scope storici.

Dossier `docs/OUF_STORAGE_G0_NETWORK_DELIVERY_20261106.md`, ricevuta `evidence/storage-g0-network-qualified-20261106.json`, reader `scripts/readback-storage-g0-network-20261106.py`. Le sezioni seguenti conservano lo storico e non prescrivono la sequenza corrente.

## Pacchetto esatto e preparazione locale

[Artifact GitHub Actions](https://github.com/GioNob/ouf-deploy/actions/runs/42180924811/artifacts/13485118791). Nel relativo ZIP: `operator-package.tar.gz`,7274165byte,SHA256 `a1b477789a08b109b54b7decf5ca66099c8ad4dcd63d07c147f283d24d3aef67`. Salvare sul VPS come `/home/oufadmin/ouf-g0-package-9053aa38.tar.gz`. ManifestSHA256 `1e542f786ac1606cf72f273bc079eaa5b06b6bd22a210d615c10d13a9d9f8adf`.

Il nuovo helper crea `/var/lib/ouf-g0-network-preparation-20261106` solo se assente. Verifica archivio/manifest,17ricevute correnti e corrispondenza con i digest nella precedente bozza. Se sono diversi, HOLD prima della creazione: nessun reset o riallineamento automatico. Il vecchio pacchetto e la vecchia area restano intatti. Bozza v2 root0600 con networkBindingFile ancora assente: non è check superato né comando di raccolta pronto.

Scaricare lo script dal commit documentale che lo contiene, verificarne SHA256 riportato nella ricevuta e usare `sudo /usr/bin/python3 -I -B -S /home/oufadmin/prepare-storage-g0-network-private-20261106.py`. Lo script non accetta argomenti, non entra nei namespace, non apre connessioni, non legge credenziali e non invoca collect. Conserva anche un'area parziale in caso di errore; non cancellarla per ripetere.

Per la successiva compilazione mancano operation/installation identity,13ruoli/immagini correnti,network binding completo,quattroconnessioni,capacity paths e prove operatore. I process pin storici verificati dall'operatore aiutano il binding ma non sostituiscono la verifica corrente prima/dopo la raccolta. Non usare il solo listener TCP come prova di autenticazione, stato DB o autorità.

MiniPET fermo perché G0 richiede le otto sezioni reali complete: la fixture dimostra la nuova composizione e non fornisce dati di produzione, quiescenza o custodia. Dopo G0 restano G1–G7 e gli AT previsti; la qualifica non li chiude implicitamente.
