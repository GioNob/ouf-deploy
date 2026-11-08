# Onboarding 1024: pacchetto e prerequisiti del cambio

8 novembre 2026. MCP PR83 è pronto con schema 14; Semantic V12 è pronto. Prossimo componente: Onboarding, conservando asset/profilo Teatri e binding SeaweedFS.

Il candidato `cc6c7869b308c695460d8491a121084893a3c323` è avanti di cinque commit sul sorgente installato `73498c17596ae155a3ed9ab36acfd6bb69da9846`, senza modifica alle migrazioni o application.yml. L'archivio originale 13592211485 del run 42416934327 è verificato: ZIP SHA256 `0894eceebb12bb8e81aceb6293713374ce6a3f2e6cdf50bb1be36f6b478bd0d0`, 24 blob OCI, JAR e 38 migrazioni coerenti con i blob Git. Il publisher CI cddc891e e il candidato hanno lo stesso albero. [Record del pacchetto](../scripts/onboarding-wide-candidate-package-20261108.json). Nessuna nuova build o import sul VPS.

## Lettura necessaria

Il lettore verifica l'esatto container SeaweedFS corrente, il frame osservato l'8 novembre e il vecchio writer MinIO spento. Legge il JAR in esecuzione dal filesystem del processo; confronta nomi/hash delle migrazioni e YAML con il candidato. Controlla gli argomenti storage del processo, i metadata dei due file credenziale senza leggerne i contenuti, e l'hash del truststore dello switch. La configurazione dichiarata non è presentata come configurazione Spring effettiva.

Una sola sessione SQL esplicitamente READ ONLY, con ruolo applicativo ricavato dal binding dichiarato, legge esclusivamente la storia Flyway, checksum, timestamp e metadata del ruolo/database; nessun dato Teatri, profilo o job. Non avvia Java, migrazioni o richieste S3/token/business. Confronta di nuovo frame, processo e JAR alla fine. Inspect e stderr rimangono in una directory privata 0700 con file 0600; il JSON pubblico espone solo metadata selezionati. Il limite complessivo è 55 secondi.

Il container ha **due reti**, backend e SeaweedFS. Il controller MCP/Semantic a rete singola non è il controller di questo aggiornamento. Nessuna esclusione generale del MAC: la sostituzione dovrà essere qualificata sul profilo a due reti effettivo. Questa lettura non crea né sostituisce container.

## Consegna

Lettore qualificato: [CI 42516065460](https://github.com/GioNob/ouf-deploy/actions/runs/42516065460), job 128839231269, cinque test PASS e zero skip, log letti. La prova PostgreSQL 17 usa un ruolo non superuser con solo SELECT sulla storia e ne verifica l'invarianza. Le prove coprono checksum/versioni mancanti o cambiati, binding JDBC, redazione dei valori e confronto delle risorse JAR. [Qualifica e limiti](../evidence/onboarding-wide-preflight-qualification-20261108.json). Non è una prova della sostituzione a due reti o dell'avvio del candidato. Esito previsto della lettura: `ONBOARDING_WIDE_PREFLIGHT_READ`. Tale esito non certifica l'avvio del candidato o l'E2E: i booleani di confronto distinguono esplicitamente eventuali differenze. La ricevuta permette di scegliere una sostituzione senza migrazione oppure di fermarsi su una differenza concreta.


Eseguire sul VPS:

```bash
(
  set -eu
  ouf_read=$(mktemp /tmp/ouf-onboarding-wide-read.XXXXXX)
  trap 'rm -f -- "$ouf_read"' EXIT
  curl --fail --silent --show-error --proto '=https' --tlsv1.2 \
    --connect-timeout 10 --max-time 30 \
    'https://raw.githubusercontent.com/GioNob/ouf-deploy/e0377f5c67a5320ce8bc6954ed063b225067c97c/scripts/deliver-onboarding-wide-preflight-20261108.sh' \
    -o "$ouf_read"
  printf '%s  %s\n' \
    'bce96bc653bf89e1d8b15bb8f11266bd778c38ebebb162cd692f87062a38428d' \
    "$ouf_read" | sha256sum -c -
  bash "$ouf_read"
)
```

Restituire il JSON finale. L'esecuzione crea soltanto i file privati di evidenza e la sessione SQL di lettura descritta; nessuna modifica ai servizi o ai dati applicativi.
