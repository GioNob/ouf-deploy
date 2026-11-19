# Generazione29 — binding separato dei laboratori runtime

Implementazione faseB, preparata durante la pipelineA: wrapper operativo, validatore e workflow separati. La suite locale passa28 test. Nessun lock runtime29, artifactID, digest di ZIP o esito OCI hosted viene fabbricato. Nessun laboratorio29 è già dichiarato eseguito da questo lotto.

## Identità e fonti

Il build manifest29 ha SHA256 `cddbcd4f40c13cb8e86d49d9bf30dc85109aeb3fa50334d92c4690e622d952c9`; il binario osservato è `a0c74718e584942f58c02214f6b3abe46b71cd47d4995b8da3aa002dcdadeef7`. La pipelineA resta la fonte dei fatti producer effettivi. L'agente cohort29 prepara il nuovo lock soltanto dopo verifica di quei fatti:

`releases/seaweedfs-452-generation29-candidate-lock-20261103.json`, schema `ouf.storage-candidate-lock.v2`, generation29, orderedPatchCount29. Il validatore usa il contratto concordato: producerCommit, buildProfile.binarySha256, image, qualification, producerArtifact, independentReadback e buildManifest. I campi operativi conservano i nomi del lock15; buildManifest lega path, SHA e patchedSourceTree. Il digest del lock finale e quello della ricevuta verranno passati dagli output reali del job cohort precedente, soltanto dopo verifica e upload riusciti.

Le fonti legacy riusate restano byte-identiche:

| Fonte | SHA256 |
|---|---|
| scripts/run-seaweedfs-452-cold-recovery.py | a4cbc41ec35ff220868c616ce323612d8e89eec42e0cbd9c47332c25f4344089 |
| scripts/run-seaweedfs-452-identity-tls.py | 50f75e99b0f3f012b2651e6856fecfc3f1742d20676c70c36499f30e84e75185 |

La CLI15 diretta mantiene il lock15 e gli identificatori15. Non modificare il reader15, il qualifier15, i loro sorgenti sigillati o i dati storici per adattarli alla29.

## Adattatore piccolo, senza duplicare il laboratorio

L’entrypoint `scripts/run-seaweedfs-452-generation29-labs.py` riusa entrambe le modalità `cold` e `identity` e il validatore puro. Il codice è implementato; la sua esecuzione resta subordinata al lock reale e alla ricevuta cohort hosted effettiva. Non estendere la CLI15 con parametri che rendano opzionale il suo controllo identità.

1. Prima di importare harness o produrre effetti, il wrapper29 carica il lock dal percorso fisso e controlla il digest committed atteso, manifest build esatto, tree, binary29, producer/readback con ID e digest effettivi, producer PASS e assenza di finding HIGH/CRITICAL/UNKNOWN. Verifica anche gli SHA delle due fonti harness. Il validatore restituisce un oggetto distaccato; non effettua import dinamici, network, subprocess, unpack o Docker.
2. Un import fresco del modulo cold legacy crea uno spazio globale locale al processo29. Per identity si usa il suo proprio modulo `cold` appena importato: le funzioni delle classi base risolvono i globali di quel modulo. Non riutilizzare cache di moduli condivise tra generazioni.
3. In questo solo spazio locale, l'adattatore lega `LOCK_SHA`, `IMAGE_ID`, `MANIFEST`, `BINARY_SHA` ai valori29 verificati e sostituisce `prepare_image` con una funzione29. Nessuna riscrittura su disco dei sorgenti15. Non usare sostituzioni testuali dell'intero sorgente.
4. `prepare_image29` verifica dimensione e SHA dello ZIP producer; invoca il reader29 completo (`verify`) per riprodurre source closure, build evidence e assessment, confronta il risultato col lock, quindi usa `unpack` e `verify_layout(profile=PROFILE29)` per ottenere l'immagine. Verifica il dockerArchiveSha256 prima di `docker load` e l'ID effettivo dopo il load. Il doppio unpack, se si usa il reader attuale senza modificarlo, è I/O locale bounded: evitare una copia del reader solo per ottimizzarlo. La provenienza publisher resta verificata dal cohort workflow; non dichiararla verificata dal solo reader.
5. Una sottoclasse di `Lab` sostituisce soltanto `client`. È indispensabile: l'implementazione originale rilancia `Path(__file__)`, quindi tornerebbe alla CLI15. Il nuovo client rilancia l'entrypoint29 con modalità, azione, percorso lock fisso e SHA atteso, nello stesso namespace `nsenter`, con Python `-I -B -S`. Ogni child riverifica binding e hash degli harness. Mantiene diagnostica bounded e timeout90s readiness,180s cold,240s identity.
6. Per cold, la sottoclasse viene assegnata al solo `cold.Lab` fresco prima di chiamare `cold.run`. Per identity, la sottoclasse deriva da `identity.Lab` e viene assegnata al solo `identity.Lab` fresco; il suo modulo `cold` riceve gli stessi binding verificati. Start, stop, network, mount, backup e TLS rimangono quelli revisionati.

Questo adattamento evita la duplicazione di circa400 righe del cold lab e delle primitive identity/TLS; la parte nuova riguarda esclusivamente identità della generazione, ingresso dei processi child e obbligatorietà del risultato MIME.

## MIME obbligatorio e prove che non si ereditano

Il cold helper attuale separa quattro fixture recovery con MIME personalizzato da una fixture `octet-stream.txt`. Questo permette di misurare il difetto15 senza perdere il resto della prova. Per29, il wrapper deve applicare `require_octet_stream_pass` sia dopo `seed` sia dopo `verify`: statusPASS, findings vuoti, GET e HEAD entrambi `application/octet-stream`. Un FAIL/MISSING non può produrre un successo29, anche se la copia dei byte passa. La guardia pura è inclusa e testata.

Il `cold.run` originale già verifica stop di tutti i writer, backup con filer+volume, rinomina delle radici originali, restore da radici indipendenti, parità degli oggetti e parità della fixture MIME. Riutilizzare queste verifiche. Non riscrivere il risultato15 per farlo apparire risolto: il FAIL15 resta storico. Per29 generare una ricevuta additiva distinta che lega risultati grezzi, lockSHA29, manifest29, binary29 e helperSHA, e dichiara `octetStreamRegression=PASS` solo dopo il successo di entrambe le fasi. Non cambiare `s3MetadataCompatibilityQualified=false` in una qualifica generale: questa è una sola regressione sintetica.

Ripetere integralmente le23 richieste identity,2 handshake TLS negativi e2 probe egress sulla nuova immagine. Il PASS15 non si trasferisce. La CA resta effimera; nessuna chiave privata nelle prove. Un namespace loopback condiviso non prova isolamento laterale tra ruoli, mTLS o policy di rete target.

## Sequenza e controlli

Il workflow `storage-452-generation29-runtime-labs.yml` è riusabile tramite workflow_call. Il job del workflow cohort29 usa `needs: qualify-cohort`, quindi passa quattro output reali: `cohort-artifact-id`, `cohort-archive-sha256`, `lock-sha256`, `cohort-receipt-sha256`. Nessun dispatch manuale o ricevuta inventata nel repository. Il digest dell’upload è normalizzato a64 caratteri esadecimali dal caller.

Prima di Docker, il workflow verifica il lock committed, scarica il bundle del predecessore e verifica SHA archivio, esatti9 membri, budget32MiB compresso/64MiB espanso, assenza di path/duplicati pericolosi, manifest completo e hash di tutti gli8 membri, copia byte-identica del lock e hash/campi della ricevuta. Il parser accetta path checksum bare o un solo prefisso `./`, rifiutando duplicati anche dopo normalizzazione. Verifica inoltre il legame con il testo di licence-rebinding. La ricevuta estratta passa al wrapper e a ogni child tramite percorso esplicito e SHA; non viene creata o modificata dal lab.

Concurrency dedicata, cancel-in-progress false, budget job30minuti. Cold e identity sono sequenziali nello stesso job, massimo4 container attivi e un solo download dello ZIP producer esatto, con directory nuove distinte. Ogni modalità rilegge indipendentemente il binding; non applicare la configurazione del secondo lab ai container del primo. Il cleanup del primo deve terminare prima di avviare il secondo.

Test richiesti al momento di implementare l'entrypoint: digest lock errato e lock15 rifiutati prima di ogni effetto; artefatti sconosciuti/rifiutati; cambio helperSHA rifiutato; source manifest29 alterato rifiutato; binding di entrambi i moduli identity/cold; argv child puntato al wrapper29 e non agli script15; MIME FAIL prima o dopo restore rifiutato; provenienza ed exact image identity non sostituibili; ricevuta29 senza stati ereditati15; entrypoint15 invariato. I28 test coprono validatore, receipt gate, integrità del bundle predecessore, normalizzazione checksum senza duplicati, guardia MIME, import freschi con sorgenti15 invariati, child argv29 e budget, rifiuto profilo/archivio errato prima di Docker, blocco fuori CI, sequenza dei due lab e ricevuta finale. Non eseguono Docker: le chiamate esterne sono isolate con mock.

Dopo producer e readback effettivi, completare il lock29 e il suo verifier; quindi congelare gli SHA dei sorgenti dell’adattatore dopo review e avviare le prove hosted. Questo è lavoro repository/CI già autorizzato: non richiede un nuovo grant target. Restano zero gate/AT chiusi, nessuna release, deploy o migrazione, scope17/52GET e risultati Teatri/Farmacie preservati.

## Artifact runtime

Il collector conserva separatamente il bundle cohort verificato, evidence cold e identity e risultato/fallimento29. Non raccoglie directory di configurazione, backup o chiavi TLS private. Il manifest runtime include anche i manifest SHA256SUMS annidati; esclude soltanto il proprio file radice. L’attestazione è eseguita solo dopo successo; i fallimenti mantengono diagnostica e job FAIL. Tutto il codice15 rimane invariato.
