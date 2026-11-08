# Ingestion 1024: intervento fermato dopo lo stop

8 novembre 2026, 22:14 CET. [Ricevuta operatore](../evidence/ingestion-wide-upgrade-held-operator-20261108.json): `HELD`, motivo `RETAINED_DATABASE_STATE_CHANGED`. L’immagine candidata è stata importata. Il vecchio stop è stato inviato, l’applicazione candidata non è stata avviata. Il controllo che ha fermato il controller segue la conferma del vecchio fermo e precede detach, rename e create.

**Non rieseguire l’installer e non riavviare il vecchio container.** Journal e archivio rimangono in `/var/lib/ouf-storage-migration/ingestion-wide-upgrade-20261108`. Nessun rollback o replay automatico. Il motivo non specifica ancora quale sezione è cambiata: non attribuirlo a una migrazione, perdita dati o normale attività del servizio senza la lettura seguente.

## Prossima azione: leggere il delta conservato

Il lettore standalone confronta `before-database.private.json` e `stopped-database.private.json`: espone sezioni cambiate, versioni/campi di storia cambiati, conteggi attività e nomi delle tabelle con conteggi/impronte differenti. Non espone impronte, righe, identificativi, payload o checkpoint. Legge inoltre gli inspect già salvati e fa un solo nuovo inspect del vecchio CID per riportarne lo stato corrente. I confronti Config sono esatti e soltanto informativi; nessuna regola MAC viene allentata.

Nessuna nuova query SQL, lettura di file credenziali, richiesta business/S3, start/stop, import, scrittura o modifica delle prove. Le impronte precedenti consentono di localizzare la tabella cambiata, **non di ricostruire le singole righe o la causa**. Eventuali informazioni successive saranno limitate a ciò che il risultato richiede.

Qualifica del lettore: cinque test locali su fixture sintetiche, tutti PASS, zero skip: sezione/tabella esatta, differenze storia/conteggi, rifiuto di metadati arbitrari, preservazione dei file e un solo inspect simulato, risultato parziale se inspect fallisce. Nessuna prova target ancora eseguita. Fonte `1aa15097ce855a069c18b72899c44bb49795f8f6`, SHA256 `d04eb75ec6aafec7fe82c6a7bf91e88814bd47e7fee829a32eeb83e4a6e7fb8c`.

## Comando corrente sul VPS

```bash
(
  set -eu
  ouf_read=$(mktemp /tmp/ouf-ingestion-held-read.XXXXXX)
  trap 'rm -f -- "$ouf_read"' EXIT
  curl --fail --silent --show-error --proto '=https' --tlsv1.2 \
    --connect-timeout 10 --max-time 30 \
    'https://raw.githubusercontent.com/GioNob/ouf-deploy/1aa15097ce855a069c18b72899c44bb49795f8f6/scripts/read-ingestion-wide-held-state-20261108.py' \
    -o "$ouf_read"
  printf '%s  %s\n' \
    'd04eb75ec6aafec7fe82c6a7bf91e88814bd47e7fee829a32eeb83e4a6e7fb8c' \
    "$ouf_read" | sha256sum -c -
  sudo python3 -I -B "$ouf_read"
)
```

Restituire il JSON: atteso `INGESTION_HELD_STATE_READ_COMPLETE`, oppure `READ_PARTIAL`/`READ_INCOMPLETE` con informazioni disponibili. Il lettore non fa ripartire Ingestion. La continuazione residua verrà preparata sul risultato, conservando import e stop già compiuti.

## Qualifica e limiti

[CI 42522348023](https://github.com/GioNob/ouf-deploy/actions/runs/42522348023), source `5d926783e3ec3d277b70d4962aa82f37cf2e1b18`: Docker 29.8.1 classic e containerd, sei test dei guard e due cicli nativi per backend, zero skip, log diretti letti. L'archivio esatto parte con PostgreSQL17/V18 e ruolo applicativo non superuser; Flyway resta disabilitato. Configurazione esterna, execution beans e Gateway-read con chiave sintetica sono esercitati. Readiness HTTP200, storia e righe sintetiche conservate.

Entrambe le fixture MAC partono con `Config.MacAddress` realmente presente: configurazione legacy esplicita e compatibilità endpoint-only. Dopo STOP/DETACH deve essere assente; seguono rename e sostituzione con IP/MAC/alias preservati. Il controller riusa la primitiva stretta già qualificata; non ignora globalmente il campo. [Regola MAC](OUF_LEARNED_CONTAINER_MAC_INVARIANTS.md), [evidenza della qualifica](../evidence/ingestion-wide-upgrade-qualification-20261108.json).

Il predecessore CI usa il candidato archiviato, non una copia del vecchio binario VPS. Configurazione e dati CI sono sintetici: non riproducono integralmente la configurazione Spring effettiva del VPS. La qualifica dimostra avvio e sostituzione nativi, **non l'ingestione funzionale di 1024 colonne o l'E2E fino al grafo**. La successiva ricevuta VPS riporta HELD dopo lo stop. La causa della differenza fra le letture del database è ancora da classificare; non chiamare il candidato installato e pronto.

