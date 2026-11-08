# Ingestion 1024: lettura del pacchetto e del lavoro pendente

8 novembre 2026. Onboarding 1024 è pronto, con Teatri e SeaweedFS conservati. Il candidato Ingestion è `c85d9fd3be215e518dc6e7d075797720b5afbd91`, un commit sul baseline `4165b9e149be467d5d7c6bed35e4e1af4e249db1`: adapter CSV e test cambiati, nessun delta alle 18 migrazioni o application.yml.

## Cosa manca per la sostituzione

La CI storica 42416624781 è riuscita e contiene report di test/scansione, ma **non un'immagine o JAR installabile archiviato**. È stata completata una nuova build dell'esatto commit: [CI 42519952111](https://github.com/GioNob/ouf-deploy/actions/runs/42519952111). Non è il vecchio binario CI recuperato e non è una nuova versione funzionale del sorgente. Workflow con test CSV a 384 MiB già esistenti, immagine nonroot, probe SQLite/XLSX, scansione secondo policy modulo e archivio immagine con hash/provenienza. Nove test CSV riusciti, probe SQLite/XLSX riuscita, zero HIGH/CRITICAL nella scansione. Archivio 13633320899 scaricato integralmente e verificato: ZIP SHA256 `83e15e242528d9128ddf5a813d0a9d4512f4076d07f845bab6a63ca1456b0109`, 18 blob OCI, JAR e risorse di migrazione/YAML coerenti con il sorgente. [Record del pacchetto](../evidence/ingestion-wide-candidate-package-20261108.json). Avvio applicativo e sostituzione sul VPS non ancora provati.

Il preflight VPS è indipendente dalla build e non richiede di importare o avviare un candidato. Legge il JAR in esecuzione, confronta le risorse con i [byte sorgente fissati](../scripts/ingestion-wide-source-resources-20261108.json), rileva la presenza e gli hash delle classi CSV. Questi confronti non provano l'appartenenza del vecchio binario alla nuova immagine.

## Effetti della lettura

Verifica il container corrente d69c3f76 e il frame osservato alle 09:11 CET, immagine e PostgreSQL retained, processo Java e JAR non coperto da mount. Conserva inspect e stderr in una directory privata, verifica nuovamente frame/processo/JAR alla fine. Non normalizza MAC o fingerprint; espone forma/coerenza del legacy osservato. Una lettura non autorizza una successiva mutazione.

Una sola sessione SQL esplicitamente READ ONLY nel database dichiarato legge:

- storia Flyway: versioni, checksum, timestamp, esiti e ruolo/database;
- conteggi run per stato e handoff per stato;
- numero di lease di partizione non scadute.

Non legge identificativi, payload o contenuti dei checkpoint. I conteggi sono una fotografia nel tempo, **non una prova di assenza di lavoro al futuro riavvio**. Nessuna nuova run, reset di budget, migrazione, stop, import, richiesta business/S3/token o modifica credenziale. Le dichiarazioni ENV/argomenti non sono descritte come configurazione Spring effettiva: i file esterni non vengono letti.

## Qualifica

[CI 42519952141](https://github.com/GioNob/ouf-deploy/actions/runs/42519952141), job 128851048745, source 4a58cd82: cinque test PASS, zero skip, log letti. La query esatta è eseguita su PostgreSQL 17 con un ruolo non superuser dotato soltanto di USAGE/SELECT: storia e righe sintetiche invariate, conteggi corretti, stati non riconosciuti trasformati in OTHER. Test mirati verificano differenze storia/JAR, vincolo del database sul PostgreSQL retained e mancata esposizione di valori di configurazione. [Evidenza e limiti](../evidence/ingestion-wide-preflight-qualification-20261108.json).

Il lettore riusa soltanto funzioni pure/parser e trasporto dei helper già qualificati; non riesegue il preflight Onboarding o i suoi interventi. Limite complessivo 55 secondi. Cinque file scaricati a commit immutabile e verificati tramite SHA256 prima di sudo.

## Comando corrente sul VPS

```bash
(
  set -eu
  ouf_read=$(mktemp /tmp/ouf-ingestion-wide-read.XXXXXX)
  trap 'rm -f -- "$ouf_read"' EXIT
  curl --fail --silent --show-error --proto '=https' --tlsv1.2 \
    --connect-timeout 10 --max-time 30 \
    'https://raw.githubusercontent.com/GioNob/ouf-deploy/4302953411eaa1f359f2c8fd1757eb421cebaf56/scripts/deliver-ingestion-wide-preflight-20261108.sh' \
    -o "$ouf_read"
  printf '%s  %s\n' \
    '3f665f50627d46e731ed55fa269822ba93ebcd33d31954f17be49b35f9166321' \
    "$ouf_read" | sha256sum -c -
  bash "$ouf_read"
)
```

Restituire il JSON finale. Esito previsto: `INGESTION_WIDE_PREFLIGHT_READ`. L'esito attesta il completamento della lettura: i booleani del confronto e i conteggi decidono il prossimo passo. Non prova avvio candidato, flusso Ingestion/UDP o E2E. Se READ_INCOMPLETE, conservare la directory privata e leggere il motivo prima di altre azioni.
