# Onboarding 1024: pacchetto e prerequisiti del cambio

8 novembre 2026. MCP PR83 è pronto con schema 14; Semantic V12 è pronto. Prossimo componente: Onboarding, conservando asset/profilo Teatri e binding SeaweedFS.

Il candidato `cc6c7869b308c695460d8491a121084893a3c323` è avanti di cinque commit sul sorgente installato `73498c17596ae155a3ed9ab36acfd6bb69da9846`, senza modifica alle migrazioni o application.yml. L'archivio originale 13592211485 del run 42416934327 è verificato: ZIP SHA256 `0894eceebb12bb8e81aceb6293713374ce6a3f2e6cdf50bb1be36f6b478bd0d0`, 24 blob OCI, JAR e 38 migrazioni coerenti con i blob Git. Il publisher CI cddc891e e il candidato hanno lo stesso albero. [Record del pacchetto](../scripts/onboarding-wide-candidate-package-20261108.json). Nessuna nuova build o import sul VPS.

## Lettura necessaria

Il lettore verifica l'esatto container SeaweedFS corrente, il frame osservato l'8 novembre e il vecchio writer MinIO spento. Legge il JAR in esecuzione dal filesystem del processo; confronta nomi/hash delle migrazioni e YAML con il candidato. Controlla gli argomenti storage del processo, i metadata dei due file credenziale senza leggerne i contenuti, e l'hash del truststore dello switch. La configurazione dichiarata non è presentata come configurazione Spring effettiva.

Una sola sessione SQL esplicitamente READ ONLY, con ruolo applicativo ricavato dal binding dichiarato, legge esclusivamente la storia Flyway, checksum, timestamp e metadata del ruolo/database; nessun dato Teatri, profilo o job. Non avvia Java, migrazioni o richieste S3/token/business. Confronta di nuovo frame, processo e JAR alla fine. Inspect e stderr rimangono in una directory privata 0700 con file 0600; il JSON pubblico espone solo metadata selezionati. Il limite complessivo è 55 secondi.

Il container ha **due reti**, backend e SeaweedFS. Il controller MCP/Semantic a rete singola non è il controller di questo aggiornamento. Nessuna esclusione generale del MAC: la sostituzione dovrà essere qualificata sul profilo a due reti effettivo. Questa lettura non crea né sostituisce container.

## Consegna

Lettore preparato; qualifica PostgreSQL CI in corso. Comando operatore ancora da pubblicare. Esito previsto della lettura: `ONBOARDING_WIDE_PREFLIGHT_READ`. Tale esito non certifica l'avvio del candidato o l'E2E: i booleani di confronto distinguono esplicitamente eventuali differenze. La ricevuta permette di scegliere una sostituzione senza migrazione oppure di fermarsi su una differenza concreta.
