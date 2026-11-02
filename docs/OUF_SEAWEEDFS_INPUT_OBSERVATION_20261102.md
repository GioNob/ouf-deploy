# SeaweedFS — inventario dopo lo STOP sui metadati delle credenziali

2 novembre 2026. Il controllo 15 è consumato: 15 controlli e 50 GET Docker cumulativi. Si è fermato in CREDENTIAL_PREFLIGHT con PRIVATE_BOUNDED_REGULAR_CREDENTIAL_SOURCE_REQUIRED; 5 candidati verificati, nessun file di credenziale aperto e nessun byte letto. S3 non è stato raggiunto. Config.Env era già passato in RAM nell'inspect. La ricevuta non distingue il predicato fallito: tipo, proprietario, permessi, collegamenti o dimensione. Non attribuire al VPS una causa non osservata.

**Tutti e tre i comandi precedenti sono consumati: non ripeterli.** Conservare file, installazioni ed evidenze. Non cambiare permessi o proprietario dei file per aggirare lo STOP.

Il precedente collector applicava agli input già esistenti gli stessi requisiti di custodia richiesti per le nuove evidenze. La continuazione separa osservazione e ammissione: classifica prima tutti i riferimenti dichiarati, poi può leggere file regolari, di dimensione limitata, stabili e senza symlink. Proprietario, permessi e numero di collegamenti vengono riportati, senza modificarli e senza dichiarare la fonte ammessa per la custodia operativa. I valori restano solo in RAM e descrittori anonimi sigillati; nuove evidenze root/private. Non è un'ammissione delle credenziali, del runtime o della futura produzione SeaweedFS.

Se un input necessario è speciale, symlink, troppo grande, non osservabile o invalido, il controllo restituisce la classificazione completa prima di aprire contenuti o interrogare S3. File assenti e directory di prefisso inutilizzate mantengono la precedenza MinIO già verificata. Nessuna shell o credenziale predefinita.

## Una nuova esecuzione necessaria

L'agente non dispone di shell VPS o API Docker/S3 target. Sul VPS OUF, dallo stesso account operativo usato prima, eseguire **una sola volta** questo nuovo blocco qualificato:

```bash
(
  set -eu
  umask 077
  inventory_inputs_dir="$(mktemp -d /tmp/ouf-storage-inputs.XXXXXX)"
  trap 'rm -rf -- "$inventory_inputs_dir"' EXIT
  curl --fail --silent --show-error --proto '=https' --tlsv1.2 --max-time 60 \
    https://raw.githubusercontent.com/GioNob/ouf-deploy/7e4106199ca17ed1bde82981c4ed81aef76a5de9/releases/seaweedfs-inventory-inputs-20261102/run-inputs.py \
    -o "$inventory_inputs_dir/run-inputs.py"
  printf '%s  %s\n' da9fcbb5caaef59276fbad44eb14e201bb6414f591f319699edcc8ade49d58c5 "$inventory_inputs_dir/run-inputs.py" | sha256sum --check --strict
  sudo /usr/bin/python3 -I -B -S "$inventory_inputs_dir/run-inputs.py"
)
```

Restituire **solo il JSON finale**, anche in caso di STOP o risultato parziale. Non inviare credenziali, configurazioni, inventari privati o nomi degli oggetti. Non rilanciare il comando in caso di errore. Il risultato include classificazione dei candidati, fase e contatori disponibili; i vecchi scope restano intatti.

## Effetti e limiti del controllo 16

Scope separato `/etc/ouf/deploy-snapshots/seaweedfs-inventory-inputs-20261102-v1`; installazione della sola nuova capsula e manifesto in `/usr/local/lib/ouf-storage-inventory-inputs-20261102`. Reader statico già installato SHA256 `430631fe4dfd1b844229637373ea176c2e84e81e1491919f4a25cc36c68359a8` riusato senza reinstallazione.

Verifica lo STOP 15 esatto e conserva tutti i precedenti scope. Riusa lo snapshot dei 13 container del controllo 14: non ripete la scansione di 13 GET. Al massimo due nuovi inspect del solo MinIO, massimo 52 GET cumulativi. Le altre 12 configurazioni non vengono rinfrescate; RAM e capacità restano osservazioni esplicitamente datate al controllo 14, senza prova di snapshot atomico o assenza di consumer esterni.

Limiti: 9 candidati metadata, fino a 4 file segreti e 1 configurazione,4096 byte per segreto/65536 per configurazione/81920 totali. S3 solo GET/HEAD,10000 richieste,25000 record di oggetti/versioni,300 secondi,64 MiB inventario privato. Controllo 600 secondi, sorveglianza esterna 630. Nessun corpo oggetto, scrittura S3, SQL, lifecycle container, deploy o migrazione. La comparazione per destinazione unica dei mount riguarda soltanto le osservazioni; contratti e sorgenti congelati restano intatti.

## Qualifica

- Source `91dc1f079bf7f6760d6dcf1f613b6c8a418f03d2`, [CI 41446908345](https://github.com/GioNob/ouf-deploy/actions/runs/41446908345): 20 test Python senza skip e 12 test Java di contratto/ripristino PASS. Quattro casi con Docker reale riproducono lo STOP 15 esatto, inclusi 0 file/0 byte/5 candidati, e conservano gli snapshot precedenti. I casi permessi 0644, proprietario UID 10001 e hardlink completano ciascuno 1010 record sintetici con due soli nuovi inspect. Il caso file troppo grande restituisce tutti i metadati, 0 letture di contenuto e non raggiunge il call site S3. STOP precedente alterato negato prima di Docker/S3.
- Storico dei 15 scope MODELLATO, ruolo MinIO waiter sintetico su rete host con server S3 reale separato. Kernel, Docker, namespace e S3 reali: non è una prova della configurazione VPS o della topologia finale.
- Reader SDK originale riusato senza reinstallazione e riscan a zero findings. Installazione root della sola capsula/manifesto verificata. 28 sorgenti, tutte le 26 precedenti (incluse le 23 storiche) invariate; payload 296642 byte, nuovo limite esplicito 327680 byte. Nessun vecchio loader o budget modificato, nessun riarmo.
- [CI indipendente 41447457400](https://github.com/GioNob/ouf-deploy/actions/runs/41447457400): 18 membri checksum, sorgenti e loader esatti, firma Sigstore del produttore/workflow/ref esatti su runner hosted; 2 file pubblicati/407097 byte confrontati byte per byte, entry/bootstrap e launcher verificati. Pubblicazione `14006308605553483b9a5ba0df9bf51ed56761f2`; launcher `7e4106199ca17ed1bde82981c4ed81aef76a5de9`, SHA256 `da9fcbb5caaef59276fbad44eb14e201bb6414f591f319699edcc8ade49d58c5`.
- Il primo tentativo CI 41446529251 si è fermato per nome casuale immagine Docker non valido; è stato corretto il solo nome della fixture e ripetuta la qualifica completa. Non è un errore VPS e non costituisce qualifica positiva.
- [Ricevuta 15](../evidence/seaweedfs-inventory-input-stop-target-20261102.json), [dossier e archivi originali](../evidence/seaweedfs-input-observation-qualified-20261102.json). Nessuna esecuzione target del nuovo controllo 16.

La migrazione non è iniziata e le vulnerabilità del MinIO corrente non sono ancora rimosse. Il gate grezzo del server SeaweedFS resta HELD per 1 UNKNOWN; tutti gli 8 gate e i 21 AT del MiniPET sono OPEN. Teatri e la stessa Farmacie restano preservati, senza nuovi upload o profiling.
