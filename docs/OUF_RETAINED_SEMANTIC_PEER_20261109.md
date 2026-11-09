# Peer Semantic corrente: ricetta indipendente e lettura nativa

Il pacchetto è qualificato in CI ed è pronto per la lettura sul VPS. **La lettura sul VPS non è ancora avvenuta.** Serve a sostituire il solo riferimento storico BRIDGE_PORT 1377 con una dichiarazione completa e verificabile del Semantic corrente, prima di comporre la nuova coppia provider.

Il lettore ricostruisce la richiesta pre-CREATE della riparazione dell'8 novembre usando il produttore già qualificato e la sola correzione della variabile della chiave discovery. Confronta la ricostruzione con `request.private.json`, i riferimenti di creazione/completamento e il frame corrente API 1.44 già fissato per hash. Le copie private restano sul VPS; non legge i contenuti dei mount o i file delle credenziali.

Il compilatore usa la baseline indipendente Docker 29.8.1/containerd overlayfs e la richiesta conservata. Risolve i percorsi Docker, conserva l'hostname esplicito ereditato e riproduce gli argomenti iniziali del gate. La successiva esecuzione di Java non sostituisce gli argomenti nell'OCI salvata. User, ambiente, limiti e quattro bind readonly derivano dalla richiesta; gli altri campi OCI restano quelli della baseline qualificata. Nessun campo dell'OCI osservata diventa un'aspettativa.

Il confronto richiede l'intero documento OCI, quindi usa il collettore peer esistente per PID/generazione, tutte le NIC e collegamenti reciproci host/container, con doppia lettura. Il MAC legacy viene verificato con il confronto già qualificato della sostituzione e con il frame API 1.44 completo; non è escluso globalmente. Un'eventuale differenza produce HELD con soli percorsi dei campi, mentre i valori restano nell'evidenza privata.

## Qualificazione

- Sorgente: [8f99ad0a91e7276cf479b65b24d646a227328fc6](https://github.com/GioNob/ouf-deploy/commit/8f99ad0a91e7276cf479b65b24d646a227328fc6).
- [CI 42620047391](https://github.com/GioNob/ouf-deploy/actions/runs/42620047391), job 129169531485: 13 test unitari e 2 test nativi PASS, nessun test saltato; log diretti letti.
- Immagine esatta archiviata, digest e attestazione del produttore verificati. Fixture con Binds e Mounts, hostname esplicito o generato e poi conservato, CPU finita o default. Richiesta completa ricavata dall'inspect del predecessore prima della CREATE del sostituto isolato. OCI completa coincidente e link reciproci osservati; Java non avviato.
- Negativi: hash OCI errato, file OCI scrivibile da altri, comandi runtime mutanti, override kernel/privilegi, proprietà host sconosciute, mount scrivibili o sovrapposti, namespace condiviso e canali di override delle feature.
- [Ricevuta di qualifica](../evidence/retained-semantic-peer-qualification-20261109.json) con limiti e due correzioni della fixture/lettura. Il bundle OCI root-owned 0644 segue un lettore distinto; le ricevute private continuano a richiedere permessi privati.

## Invocazione e risultato

[Wrapper](../scripts/deliver-retained-semantic-peer-20261109.sh), SHA256 `3c66249e0526546afeb11c5336bdc1663d9fe2ad16e797f698cd3efe32e15739`. Scarica e verifica nove sorgenti dal commit qualificato; esegue Python isolato come root. Il comando consegnato all'operatore vincola anche il wrapper a commit e hash.

Scrive esclusivamente una nuova directory privata `/var/lib/ouf-storage-migration/semantic-peer-recipe-*` con ricetta, dichiarazione, osservazione e risultato. Richieste Engine GET finite e comandi nativi di lettura; nessun avvio/stop, CREATE, daemon-reload, modifica nft, firma, aggiornamento del puntatore o journal storico. Nessuna chiamata al provider, database, token o S3. I download di consegna da GitHub precedono il lettore e non rientrano nei suoi contatori applicativi.

L'esito atteso è `SEMANTIC_PEER_RECIPE_MATCHED_NOT_AUTHORIZED`. Incollare soltanto il JSON finale, anche in caso di HELD; nessun replay automatico. Una ricevuta positiva prova il confronto della generazione osservata, non ammissione, custodia dei contenuti montati, rootfs, TLS/issuer, readiness del provider o E2E. Non è uno snapshot atomico.

La dichiarazione diventa obsoleta se Semantic cambia CID, ricetta o generazione. L'installazione futura di credenziale/truststore e l'abilitazione provider richiedono aspettativa coerente con la richiesta selezionata e nuova osservazione. Poi integrare creazioni governate, sigilli rootfs nuovi e autorità con gli owner esistenti di pubblicazione, switch e avvio. Gli input preparati e i vecchi journal restano conservati.
