# Tappa funzionale1/6 — diagnosi del rifiuto semantico

Il catalogo aggiornato espone i quattro tool richiesti. Il tentativo unico
semantic.propose è stato rifiutato con403 SEM_CAPABILITY_REQUIRED:ouf.semantic.propose.
Authorization mostra due grant configurati e assegnazione nominale admin nella
policy40; questo non dimostra i permessi effettivi del Registry. Nessuna nuova
DRAFT o richiesta THS è provata. Non ripetere la mutazione né aggiungere grant.

Fasi tecniche8/8 conservate, tappe funzionali0/6. La finestra applicativa precedente
è scaduta; nessun rinnovo, primo grant, installer o repair va rigiocato.

## Lettura sul VPS

Il launcher scripts/launch-chatbot-semantic-denial-readback-20261016.sh scarica
solo il reader al commit c7645f4d63056e16dedaaf847810693cc3a3ba45, verificando SHA256
233f23f28f89f7282e7ed77c001d0c658a95d7b8e6a98a75a5c6b72c7adce51e. Usa il client gh già autenticato, poi una copia root privata
con ulteriore controllo hash. Non richiede il processo finito ancora attivo.

Il reader controlla review, authority e bundle originali, legge delivery-status,
quattro record del worker, systemctl show dell'unità esatta e al massimo200 righe
dei log dell'esatto container Registry già selezionato. Espone solo stati,
contatori presenti, hash e conteggi di marker; nessun log grezzo, token o chiave.
Massimo120 secondi. Nessuna chiamata DB/IAM/MCP/owner API, restart o scrittura Gateway.
I record dinamici sono osservazioni successive, non uno snapshot atomico.
Il last reported status non prova liveness attuale. CumulativeGrantAttempts
assente resta sconosciuto: non sommare o inventare il totale.
Un campione senza marker non prova salute o permesso; non rivela il bundle
owner effettivo né una causa esatta del403. L'eventuale errore di custody/identità
ferma il reader e non autorizza modifiche dei permessi filesystem.

## Qualifica

Cinque test locali PASS in tests/test_chatbot_semantic_denial_reader.py:
flusso con authority scaduta e processo fermo con I/O simulato; redazione;
contatori non inferiti; marker delimitati; sottoprocesso reale con bound/drain
stdout e stderr. bash -n sul launcher PASS. Nessuna esecuzione VPS o accettazione
della tappa funzionale è ricavabile da questi test.

## Dopo l'output

Conservare la chiave teatri-semantic-draft-be74308e098aa3a6-20261016 e riconciliare
lo stato del tentativo mediante receipt read se autorizzato, prima di una ripresa
semanticamente identica. Per il403 serve una diagnosi del contesto/bundle effettivo
owner, non una policy allargata per tentativi. Qualunque correzione target va
preparata e qualificata nel suo scope; HUMAN THS resta l'unico percorso per
approvazione/pubblicazione. Le tappe2–6 attendono i rispettivi gate e autorità.
