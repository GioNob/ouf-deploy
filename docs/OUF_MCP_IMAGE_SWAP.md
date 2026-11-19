# R-033 · Sostituzione dell’immagine MCP su schema 14

Il candidato è il commit `b4c1091bcbbb374d7d4a190f58a818e1d17deac7` di `GioNob/ouf-mcp-server`, PR #85, Go 1.27.4. La [ricevuta dell’8 novembre](../evidence/mcp-analysis-ready-operator-20261108.json) identifica il rilascio precedente. Il CID corrente, il database e il binario in esecuzione si rilevano nuovamente sul VPS. Il launcher ha il commit di consegna a zeri fino alla review.

## Selezione del pacchetto e qualifica su GitHub

Claude identifica il run riuscito di `ci.yml` sul candidato e l’artefatto `acquisition-mcp-image-<runId>`. Registra repository, run, artifact ID, commit del publisher in `source-commit.txt`, alberi Git del publisher e del candidato. Per una build del merge di prova deve risultare lo stesso albero. Conserva i digest dello ZIP originale, di `image.tar.gz`, del manifest delle capacità e del binario estratto, oltre ai digest OCI del config e del manifest immagine. Confronta col rilascio precedente il manifest delle capacità e i layer del runtime, inclusi Alpine e pacchetti di sistema, e documenta le differenze attribuibili alla build.

Nel workflow [MCP archived analysis application upgrade](../.github/workflows/mcp-analysis-upgrade.yml) lanciare il dispatch GitHub-hosted con `candidate` (oggetto JSON descritto sotto con image ID containerd), `classic_image_id` (digest OCI del config, prefisso `sha256:`) e `govulncheck_version` (versione fissata del modulo `golang.org/x/vuln`). Il workflow verifica il legame run/artefatto/commit, usa lo ZIP selezionato su entrambi gli store e verifica `go version -m` e `govulncheck -mode=binary` sull’eseguibile copiato dal candidato. Conservare i log dei due backend e l’esito per R-033.

La fixture usa PostgreSQL con le 14 migrazioni già registrate, binding e credenziali sintetici, Docker 29.8.1 e API 1.44. Il predecessore sintetico deriva dalla stessa build con una label diversa e ha un image ID distinto. Entrambi i profili di creazione, legacy esplicito e MAC sul solo endpoint, devono mostrare la MAC legacy iniziale, il distacco, il trasferimento dell’endpoint e il ripristino del CID originario. Leggere gli esiti senza skip prima di qualificare la consegna VPS. [Regola MAC](OUF_LEARNED_CONTAINER_MAC_INVARIANTS.md)

## Preparazione della consegna e fotografia

Claude fissa `C` in [mcp-image-swap.sh](../ops/vps/mcp-image-swap.sh) al commit immutabile che contiene i sei file elencati nelle righe `fetch`. Verifica i sei SHA-256 sui byte Git (LF). Consegna all’operatore il launcher fissato e il suo SHA-256 finale tramite il canale di review. L’operatore ne verifica il digest prima di invocarlo da un account ordinario con `sudo`. Il download HTTPS usa l’UID dell’operatore. Socket Docker, namespace, metadati dei bind e journal privato richiedono root.

Sotto `/etc/ouf/deploy-snapshots/mcp-image-swap-r033` il launcher conserva la consegna, lo ZIP e il journal. La directory è di root, modalità 0700. Claude individua il CID completo del PostgreSQL a cui punta MCP e acquisisce la fotografia con il launcher verificato.

```bash
umask 077
sudo bash mcp-image-swap.sh snapshot "$POSTGRES_CID" > snapshot.json
```

La fotografia espone CID, image ID, hash del binario in esecuzione, schema, HTTP 204 e digest di frame, binding e storia SQL. Il frame copre Config con label ed ENV, HostConfig, mount, NetworkSettings, comando, generazione e stato. La verifica dei cinque file montati usa metadati e identità del file rispetto alla sorgente host. La lettura SQL usa il ruolo applicativo e una transazione read-only con timestamp in UTC. Claude confronta anche i riferimenti operativi attivi al vecchio CID, inclusi quelli dei lettori e cutover storici, prima di concordare il cambio.

Preparare `inputs.json` root:root 0600 nella directory sopra indicata. Inserire in `snapshot` l’intero oggetto JSON restituito. `expectedOldImageId` deriva dall’identità del rilascio atteso approvata dall’owner. I segnaposto indicano valori da sostituire.

```json
{
  "expectedOldImageId": "sha256:<ID completo del predecessore atteso>",
  "snapshot": {},
  "candidate": {
    "runId": 0,
    "artifactId": 0,
    "sourceCommit": "b4c1091bcbbb374d7d4a190f58a818e1d17deac7",
    "publisherCommit": "<commit del publisher>",
    "sourceTree": "<albero del candidato>",
    "publisherTree": "<albero del publisher>",
    "zipSha256": "<SHA-256 ZIP Actions>",
    "archiveSha256": "<SHA-256 image.tar.gz>",
    "capabilitiesSha256": "<SHA-256 capabilities.json>",
    "binarySha256": "<SHA-256 /usr/local/bin/ouf-mcp qualificato>",
    "imageId": "sha256:<ID del candidato per lo store del VPS>"
  }
}
```

I due ID numerici devono essere positivi. I commit e gli alberi hanno 40 cifre esadecimali minuscole, i digest SHA-256 ne hanno 64. Il controller distingue il digest del config (classic) dal digest del manifest (containerd).

## Plan, apply e finestra

```bash
sudo bash mcp-image-swap.sh plan > r033-plan.json
# PLAN_SHA256 è il planSha256 che l’umano ha riesaminato in r033-plan.json.
sudo bash mcp-image-swap.sh apply "$PLAN_SHA256" > r033-apply.json
```

Il plan opera in sola lettura su Docker, MCP e database. Controlla i cinque payload elencati in `SHA256SUMS`, i blob OCI, le impostazioni dell’immagine e il frame vivo rispetto alla fotografia. L’umano verifica i due image ID, entrambe le provenienze, l’hash della richiesta CREATE e i nomi di custodia prima di autorizzare l’apply. Riservare 15–30 minuti con l’operatore presente e senza altri interventi sul servizio durante la finestra. È una stima di pianificazione. L’indisponibilità effettiva va dallo stop del predecessore alla risposta 204 del server verificato.

Apply ricostruisce il plan, verifica ancora ZIP e archivio e crea il journal esclusivo `attempt-<CID-precedente>`. Assegna all’immagine precedente un tag di custodia per CID, importa il candidato, verifica a cosa punta `ouf-mcp:ci` e ripete la lettura del frame, della storia SQL e della readiness immediatamente prima dello stop. Ferma, scollega e rinomina il predecessore. Crea `ouf-mcp` per image ID; conserva l’ENV, i bind, il gate, IP, MAC e alias, aggiornando le due label di provenienza. Docker aggiunge l’alias breve del nuovo CID. I guard distinguono il campo MAC legacy dall’endpoint in ogni fase.

Dietro il gate il controller verifica comando, handler USR1, hash dell’eseguibile, metadati dei file e storia SQL. Dopo USR1 verifica il processo server, l’hash anche tramite `/proc/<pid>/exe`, il 204, il frame del candidato e il predecessore trattenuto. Lo schema resta alla versione 14 per tutta la procedura. L’avvio ordinario del server può contattare i servizi di identità e di policy.

## HELD e rollback

Un esito `HELD` termina con exit nonzero. Conservare output, consegna e journal. Ogni effetto Docker ha un’intenzione registrata prima della chiamata e un esito registrato dopo la risposta. Il file `load.done` attesta l’import verificato. Ispezioni e richiesta CREATE complete restano nella directory privata.

Prima dello stop, riconciliare l’eventuale tag di custodia e l’import con il servizio ancora attivo. Dopo lo stop, Claude riconcilia gli ID, il nome in servizio, l’ultima intenzione e il relativo esito. L’umano può autorizzare questo comando anche dopo un apply riuscito, finché il candidato registrato è il successore immediato.

```bash
sudo bash mcp-image-swap.sh rollback "$PLAN_SHA256" > r033-rollback.json
```

Il rollback usa il journal del plan approvato e i file già consegnati. Controlla la storia SQL e il frame del predecessore prima di isolare il candidato registrato, fermandolo, scollegandolo e rinominandolo. Ripristina il nome e il binding di rete sul vecchio CID, lo riavvia, verifica il suo gate, binario e binding, invia USR1 e attende la readiness 204. Il tag di custodia e i container restano disponibili per la riconciliazione. Una CREATE con risposta persa, una generazione ambigua o un rollback interrotto richiedono review del journal e dello stato vivo. Conservare ogni tentativo; evitare replay e pulizie durante la diagnosi. Il ritorno al predecessore riapre R-033.

## Accettazione in esercizio

- L’operatore conserva la ricevuta `attempt-<CID>/receipt.json` e l’output redatto. Devono risultare `READY`, il digest del plan approvato, il CID e l’image ID selezionati, l’hash del binario Go 1.27.4 qualificato e HTTP 204. Per un ripristino la ricevuta è `rollback/receipt.json` con `ROLLED_BACK`, vecchio CID, vecchio hash e HTTP 204.
- Claude rilegge il frame in servizio, le due label, i binding e il digest SQL con checksum e timestamp delle 14 versioni. Verifica la custodia del predecessore e confronta manifest e capacità con il pacchetto approvato.
- Claude esegue una lettura MCP autorizzata già disponibile e registra l’esito redatto. L’owner decide il merge della PR #85 dopo la verifica in esercizio.
