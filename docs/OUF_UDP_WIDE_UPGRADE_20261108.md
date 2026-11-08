# UDP 1024: lettura corrente prima della sostituzione

8 novembre 2026. Ingestion 1024 è pronto sul VPS; non ripetere i suoi installer. UDP rimane collegato a SeaweedFS con il codice precedente. Il prossimo passo è una lettura, senza stop, import, migrazione o richieste S3.

## Candidato e pacchetto

[PR49](https://github.com/GioNob/ouf-udp-object-resolution/pull/49), source `c0cf1702b2eb971718996a959414caee004af494`: limite dei segnali d'identità da 32 a 1024, copertura delle proprietà e regole d'identità conservate. Nessuna migrazione nuova nel delta. La build storica42416490615 conserva rapporti, non un'immagine distribuibile.

[CI 42527648108](https://github.com/GioNob/ouf-deploy/actions/runs/42527648108), job 128874710495, ha costruito e archiviato quel sorgente esatto:19 test identità a384 MiB PASS senza skip, immagine non-root10004:10004, gate HIGH/CRITICAL superato. I36 script e application.yml estratti dal JAR coincidono con il sorgente; quattro classi selezionate identificate. Artifact 13635797332, `udp-wide-image-42527648108`, ZIP 113722451 byte, SHA256 `f0f55c74a4674e78e6982ffa3575f2c7bcc96741dfdcde5da288863f0cf78340`.

Sono prove CI e metadata del provider: i byte scaricati dell'archivio non sono ancora stati riletti indipendentemente; nessun import o avvio candidato sul VPS. Il prossimo installer dovrà usare quel pacchetto verificato e qualificare il lifecycle a due reti preservando TLS/credenziali esistenti. [Registro archivio](../evidence/udp-wide-archive-ci-20261108.json).

## Lettura qualificata

`scripts/read-udp-wide-preflight-20261108.py`, source deploy `b5a0a7b7177471218e42ce3e2ba2602c3fdf63f1`, SHA256 `fa8239a9c6ddd99ea6cddd9a11ae5246d3e63440a54d70c7c6eeef8f87d2664f`.

- Osserva il CID UDP già sostituito `ab0ce29e39cfd616e5eee4bff32c0babdd04a0efe5d918dcc85e9e363d488005`, immagine `sha256:ae78f604ef485dda3751222ce418e03027d2db87bc49d8cb1faf8de3e2b60b52`, tramite Docker API1.44; verifica che il vecchio writer MinIO sia spento.
- Legge il JAR indicato dal processo Java e confronta migrazioni/YAML col candidato. Raccoglie la forma MAC e il frame corrente senza introdurre normalizzazioni o autorità per una sostituzione.
- Controlla dichiarazioni SeaweedFS negli argomenti e nell'ENV, metadata del file credenziale e hash del truststore montato. Non legge il contenuto delle credenziali né emette argomenti, ENV o log grezzi. Queste dichiarazioni non equivalgono alla configurazione Spring effettiva completa.
- Esegue una sessione SQL REPEATABLE READ / READ ONLY con timeout: storia migrazioni e conteggi di handoff, job di materializzazione, oggetti lake, pianificazioni manutenzione, piani shadow e lease non scadute. Nessun identificativo, payload o checkpoint applicativo viene restituito. I conteggi non sono garanzia di quiete futura o autorizzazione al riavvio.
- Ricontrolla frame e JAR al termine. Salva prove private nel percorso riportato nel JSON, sotto `/var/lib/ouf-storage-migration`.

[CI 42527648147](https://github.com/GioNob/ouf-deploy/actions/runs/42527648147), job 128874710706: sei test PASS, zero skip, log letti. Query esatta su PostgreSQL17/PostGIS3.5 dopo applicazione dei 36 script nel database usa-e-getta, ruolo con soli SELECT, dati fixture invariati; rilevazione lavoro PAUSED e lease attiva verificata. Non è una prova di avvio candidato o E2E. [Qualifica](../evidence/udp-wide-preflight-qualification-20261108.json).

## Comando corrente sul VPS

Delivery `73d98958ca93a38cbb34ecf14c9e4b3651fcac4d`; cinque file riletti/hash verificati, helper e manifest importati senza main, sintassi Bash e wrapper verificati.

```bash
(
  set -euo pipefail
  ouf_udp_read=$(mktemp /tmp/ouf-udp-preflight.XXXXXX)
  trap 'rm -f -- "$ouf_udp_read"' EXIT
  curl --fail --silent --show-error --proto '=https' --tlsv1.2 \
    --connect-timeout 10 --max-time 30 \
    'https://raw.githubusercontent.com/GioNob/ouf-deploy/73d98958ca93a38cbb34ecf14c9e4b3651fcac4d/scripts/deliver-udp-wide-preflight-20261108.sh' \
    -o "$ouf_udp_read"
  printf '%s  %s\n' '3840a8899299cb961c205e26aff80fb1d54f4a68d696730fc6edacff975b2c6f' "$ouf_udp_read" | sha256sum -c -
  bash "$ouf_udp_read"
)
```

Restituire il JSON finale, atteso `UDP_WIDE_PREFLIGHT_READ`. La lettura lascia servizi e database invariati. Dopo il risultato: verifica indipendente dell'archivio e sostituzione qualificata, poi provider/strumenti discovery, mapping Teatri conservato e percorso fino al grafo. Readiness Ingestion e archiviazione UDP non chiudono F2–F6.
