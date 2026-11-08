# MCP: lettura mirata prima dell'analisi persistente

8 novembre 2026. **Preflight completato alle20:09 CET:** [ricevuta](../evidence/mcp-analysis-preflight-operator-20261108.json), schema1–13 esatto, ruolo ordinario con permessi14 e cinque file montati. Permesso storico scaduto, nessun rinnovo. Prossimo passo: [installazione qualificata](OUF_MCP_ANALYSIS_UPGRADE_20261108.md). Semantic V12 resta pronto; provider/worker disabilitati.

## Perché serve questo passo

La lettura precedente ha provato che MCP usa il database OID21560 con migrazioni1–13 coincidenti col candidato. Non ha verificato i file necessari all'avvio, i metadata della configurazione firmata di reprocessing o i permessi del ruolo applicativo per creare le due tabelle della migrazione14. Sono informazioni necessarie per preparare la sostituzione senza spegnere prima un servizio funzionante.

L'archivio originale MCP PR83 è stato scaricato e verificato: artifact13593930449, run42420569963, ZIP SHA256 `2eae47d8c90b00b992bc916e5ce5a5bd32d9e724abe27d2838bd5d08ebc68d5e`. Il sorgente dichiarato dal publisher è il merge di prova `e2a474ea09bf9c3cb130103ca142f1a128942a80`; il suo albero Git `3354e594938fc0c9131b1532a93ae7b5105b832d` è identico alla testa candidata `907ace32100d44a0fcf1fcbda5d713ee7bd8fd94`. Verificati tutti i cinque payload, dieci blob OCI e il manifest rispetto al blob Git; gli stessi byte del manifest sono presenti nel binario. Questo non prova il comportamento del pacchetto sul VPS. [Evidenza](../evidence/mcp-analysis-candidate-package-20261108.json).

## Comando eseguito — non ripetere

Il lettore verifica il frame MCP osservato l'8 novembre, identifica il processo e il binario installato, legge soltanto i metadata dei file credenziale dal mount effettivo e confronta una seconda volta i frame. Se configurati, legge i tre file pubblici della configurazione firmata di reprocessing per riassumere hash/scadenza; non ne verifica la firma e non rinnova permessi o budget.

Esegue una sola sessione SQL esplicitamente READ ONLY con il ruolo applicativo: migrazioni/checksum, presenza delle tabelle analisi, permessi CREATE/USAGE sullo schema e SELECT/INSERT sulla storia. Nessuna migrazione, avvio/stop, import immagine, richiesta token/provider/S3 o chiamata business. Gli inspect e gli eventuali errori restano in una directory privata0700, file0600. Restituire soltanto il JSON pubblico.

```bash
(
  set -eu
  ouf_read=$(mktemp -d /tmp/ouf-mcp-preflight.XXXXXX)
  trap 'rm -rf -- "$ouf_read"' EXIT
  for name in read-mcp-analysis-preflight-20261108.py read-discovery-contract-20261108.py read-analysis-discovery-runtime-20261107.py; do
    curl --fail --silent --show-error --proto '=https' --tlsv1.2 \
      --connect-timeout 10 --max-time 30 \
      "https://raw.githubusercontent.com/GioNob/ouf-deploy/fd55b2735601d147905a51eca4d0dd243454bea5/scripts/$name" \
      -o "$ouf_read/$name"
  done
  (
    cd "$ouf_read"
    sha256sum -c <<'SHA256'
bf27b875fbc0fd90beb7cf5866835762faddaaa9df9dd353b1bc22c0e32d964a  read-mcp-analysis-preflight-20261108.py
468660ed73a24c7b8a842f5b99a9c268890c99bb4206ca2e4719865326b27277  read-discovery-contract-20261108.py
ef8dc8c4887122f2b2d76c05eaff7a8850c31004fcd661de2b3e49f51d6cc1b4  read-analysis-discovery-runtime-20261107.py
SHA256
  )
  sudo python3 -I -B "$ouf_read/read-mcp-analysis-preflight-20261108.py"
)
```

Esito di lettura acquisito: `MCP_ANALYSIS_PREFLIGHT_READ`. Non equivale ad autorizzazione di rilascio, compatibilità completa o installazione. Un file mancante o un privilegio assente resta visibile; i permessi non vengono modificati. Un frame diverso produce READ_INCOMPLETE: va riconciliato, non normalizzato.

## Prove e seguito

[CI42513291665](https://github.com/GioNob/ouf-deploy/actions/runs/42513291665), job128830770569: sei test del nuovo lettore PASS, zero skip, inclusa query nativa PostgreSQL17 con ruolo non superuser; storia invariata e rilevazione della revoca CREATE. Nove test del helper esistente PASS; il suo precedente test native Docker è saltato in questo job, con la qualifica dedicata storica conservata. Localmente cinque test puri PASS; PostgreSQL non eseguito. [Dettagli](../evidence/mcp-analysis-preflight-qualification-20261108.json).

La sostituzione MCP con archivio esatto e migrazione ordinaria14 è ora qualificata: [comando successivo](OUF_MCP_ANALYSIS_UPGRADE_20261108.md). Il vecchio migratore privilegiato12→13 non è un migratore generico. I sei strumenti nuovi sono ancora INACTIVE: installare l'immagine non attiva automaticamente analisi/discovery. Seguono configurazione del provider, delega/grant, attivazione degli strumenti e prova sul profilo Teatri esistente. Nessuna nuova profilazione o reset del lavoro già consumato.
