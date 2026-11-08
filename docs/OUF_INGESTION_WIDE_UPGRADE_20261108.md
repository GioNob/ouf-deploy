# Ingestion 1024: installazione dell'archivio qualificato

8 novembre 2026. Il [preflight operatore delle 21:43 CET](../evidence/ingestion-wide-preflight-operator-extract-20261108.json) è acquisito: V1–V18 coincidono con il candidato, tre run SUCCEEDED, 34 handoff ACKED e zero lease di partizione non scadute al momento della lettura. Il servizio corrente usa ancora il vecchio JAR. **Non ripetere il lettore.**

## Intervento

Installare l'immagine archiviata del sorgente `c85d9fd3be215e518dc6e7d075797720b5afbd91`, artifact 13633320899 della CI 42519952111. È la nuova build dello stesso sorgente già documentata, non un rebuild durante l'intervento VPS. [Pacchetto](../evidence/ingestion-wide-candidate-package-20261108.json).

Il controller verifica il frame esatto d69c3f76, il vecchio JAR e la generazione osservata, PostgreSQL retained, readiness e dichiarazioni Flyway false sia nell'ambiente sia negli argomenti Java. Rilegge la storia V18 e lo stato prima dello stop, a servizio fermo e dopo l'avvio. PostgreSQL calcola impronte aggregate di `ing_run`, `ing_partition`, `processing_attempt`, `ing_lineage`, `handoff_outbox`, `runtime_configuration_snapshot`, `ing_schedule`: identificativi, payload e checkpoint non vengono trasferiti nel report. Le impronte sono confronti di invarianza delle righe, non prove crittografiche contro modifiche intenzionali.

Conserva i quattro mount in sola lettura, l'ambiente applicativo, gli argomenti Java, IP/MAC/alias della rete backend e lo stato applicativo confrontato. Cambiano immagine, etichette di provenienza e metadato JAVA_VERSION. Il vecchio container viene fermato, scollegato e conservato con suffisso `-before-wide-20261108`; il sostituto parte inizialmente in attesa, verifica il JAR archiviato e poi avvia Java. Nessuna migrazione esplicita, richiesta business, replay, reset di budget o modifica Gateway/credenziali. Onboarding e UDP non vengono sostituiti da questo comando.

È prevista un'interruzione di Ingestion durante il cambio. L'applicazione avviata può accedere al database e al lavoro già presente: i conteggi non costituiscono una garanzia di quiescenza futura. Se i confronti falliscono, il controller conserva le prove e restituisce HELD; non riavvia automaticamente il vecchio servizio e non ripete operazioni. Non rilanciare il comando dopo HELD.

## Qualifica e limiti

[CI 42522348023](https://github.com/GioNob/ouf-deploy/actions/runs/42522348023), source `5d926783e3ec3d277b70d4962aa82f37cf2e1b18`: Docker 29.8.1 classic e containerd, sei test dei guard e due cicli nativi per backend, zero skip, log diretti letti. L'archivio esatto parte con PostgreSQL17/V18 e ruolo applicativo non superuser; Flyway resta disabilitato. Configurazione esterna, execution beans e Gateway-read con chiave sintetica sono esercitati. Readiness HTTP200, storia e righe sintetiche conservate.

Entrambe le fixture MAC partono con `Config.MacAddress` realmente presente: configurazione legacy esplicita e compatibilità endpoint-only. Dopo STOP/DETACH deve essere assente; seguono rename e sostituzione con IP/MAC/alias preservati. Il controller riusa la primitiva stretta già qualificata; non ignora globalmente il campo. [Regola MAC](OUF_LEARNED_CONTAINER_MAC_INVARIANTS.md), [evidenza della qualifica](../evidence/ingestion-wide-upgrade-qualification-20261108.json).

Il predecessore CI usa il candidato archiviato, non una copia del vecchio binario VPS. Configurazione e dati CI sono sintetici: non riproducono integralmente la configurazione Spring effettiva del VPS. La qualifica dimostra avvio e sostituzione nativi, **non l'ingestione funzionale di 1024 colonne o l'E2E fino al grafo**. La ricevuta di installazione VPS è ancora attesa.

## Comando sul VPS

Consegna `e1bf9e3a9194992feeceed88d67167509903b916`; otto file letti nuovamente da GitHub e verificati contro i pin, ZIP verificato integralmente, sintassi shell controllata. Il wrapper non richiede GitHub CLI.

```bash
(
  set -eu
  ouf_install=$(mktemp /tmp/ouf-ingestion-wide-install.XXXXXX)
  trap 'rm -f -- "$ouf_install"' EXIT
  curl --fail --silent --show-error --proto '=https' --tlsv1.2 \
    --connect-timeout 10 --max-time 30 \
    'https://raw.githubusercontent.com/GioNob/ouf-deploy/e1bf9e3a9194992feeceed88d67167509903b916/scripts/install-ingestion-wide-public-archive-20261108.sh' \
    -o "$ouf_install"
  printf '%s  %s\n' \
    'd1d3b916401add3f7e3740379e1cf4fe1872c414fe6008bafba5e697c8cd2bc7' \
    "$ouf_install" | sha256sum -c -
  bash "$ouf_install"
)
```

Restituire il JSON finale: risultato atteso `INGESTION_WIDE_1024_READY`, oppure HELD con motivo e directory delle prove. Successo significa candidato installato e pronto, con stato confrontato invariato. Dopo la ricevuta: UDP1024, discovery/strumenti, mapping del profilo Teatri già esistente, THS→Ingestion→UDP→grafo e ripetizione. Nessun nuovo upload o profilo Teatri per questo aggiornamento.
