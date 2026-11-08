# Ingestion 1024: lettura per riprendere l’intervento fermato

8 novembre 2026. Ingestion è fermo dopo lo stop dell’installer delle 22:14 CET. L’immagine candidata è già importata. **Non rilanciare l’installer, non reimportare e non riavviare il vecchio servizio.** Il journal è conservato in `/var/lib/ouf-storage-migration/ingestion-wide-upgrade-20261108`.

## Risultato acquisito

La [ricevuta delle 22:20 CET](../evidence/ingestion-wide-held-state-operator-20261108.json) localizza il delta prima/dopo stop nella sola `ing_schedule`: due righe prima e dopo, impronta diversa. Restano identici storia V18, tre run, tre partizioni/checkpoint, 34 lineage, 34 handoff ACKED, 36 processing attempt e tre snapshot. Il vecchio container è fermo, PID0, exit143, non OOM; stessa identità, generazione, nome, mount, HostConfig e argomenti. Non risultano intenti di detach, rename, create o start candidato.

Il confronto Config/rete del precedente lettore usava la CLI senza API fissata mentre le catture originali usano API1.44. È un difetto di quel confronto: differenze di rappresentazione non bastano per dichiarare un cambiamento reale. La nuova lettura usa API1.44 per entrambi i lati e affianca la vista CLI; non ignora MacAddress.

## Limite del controllo precedente

Nel [sorgente ActivationRepository](https://github.com/GioNob/ouf-ingestion-runtime/blob/c85d9fd3be215e518dc6e7d075797720b5afbd91/src/main/java/it/comune/trieste/ouf/ingestion/ActivationRepository.java), la riconciliazione aggiorna `discovery_verified_at` e incrementa `lock_version` anche sulla medesima pubblicazione. ActivationLoop ha polling predefinito di10secondi quando abilitato. Il guard che pretendeva l’impronta completa immutata mentre il servizio girava era troppo rigido. La fixture nativa precedente non esercitava questo polling con pianificazioni presenti.

Questo **non prova quali campi siano cambiati nel caso VPS**. Le vecchie prove conservano soltanto impronte aggregate e non permettono di ricostruirli retroattivamente; inoltre il comportamento del vecchio binario installato non è dimostrato dal sorgente candidato. Non chiamare il delta già spiegato o accettato e non riscrivere le prove.

## Lettura corrente

Un solo comando raccoglie:

- differenze esatte dei nomi campo Config e NetworkSettings/endpoint, forma della MAC nelle tre catture e corrispondenze con l’endpoint originale; nessun valore sensibile;
- confronto API1.44/CLI senza dedurre automaticamente una nuova policy di lifecycle;
- una sessione SQL REPEATABLE READ READ ONLY, timeout statement5s/lock1s, nel database dichiarato sull’esatto PostgreSQL retained: storia, conteggi e impronte correnti delle sette tabelle confrontati con la lettura dopo stop;
- metadata delle pianificazioni: stato, one-shot, pubblicazione consumata/abilitata, lease, contatori e date; nessun identificativo, payload o sync_profile trasferito;
- una nuova impronta privata dello scheduler che esclude soltanto i due campi del polling e continua a coprire gli altri campi. È una misura aggiuntiva dello stato attuale, non un’approvazione del delta storico.

Quattro inspect nominativi complessivi: due API1.44 del vecchio container, una vista CLI e PostgreSQL. Nessuna modifica a servizi, immagini, permessi o database; nessuna richiesta business/S3/token né lettura di file credenziali. Le nuove prove sono salvate in una directory privata separata; le vecchie restano identiche.

## Qualifica

[CI42525366640](https://github.com/GioNob/ouf-deploy/actions/runs/42525366640), job128867703808, source `e22ef8e3758b216789c20c0d2aa5b5d717126c41`: sette test PASS, zero skip, log letti. Query esatta eseguita su PostgreSQL17 con ruolo non superuser dotato soltanto di SELECT; le letture conservano le righe sintetiche. Il test riproduce il cambio dell’impronta completa dopo gli aggiornamenti dei due campi polling, la stabilità dell’impronta ristretta e il suo cambiamento per un diverso checksum di pubblicazione. Test delle viste Docker puri/sintetici, non una nuova qualifica di STOP/DETACH. [Prove e limiti](../evidence/ingestion-resume-prerequisites-qualification-20261108.json).

## Comando sul VPS

```bash
(
  set -eu
  ouf_read=$(mktemp /tmp/ouf-ingestion-resume-read.XXXXXX)
  trap 'rm -f -- "$ouf_read"' EXIT
  curl --fail --silent --show-error --proto '=https' --tlsv1.2 \
    --connect-timeout 10 --max-time 30 \
    'https://raw.githubusercontent.com/GioNob/ouf-deploy/cd143d9df586d1a9f76d71cc48cb82994d157ab3/scripts/deliver-ingestion-resume-prerequisites-20261108.sh' \
    -o "$ouf_read"
  printf '%s  %s\n' \
    '2c5ea6d606eb97e87ea067f1e3b6647405fe651963ec35b38c1e31cdd6c25548' \
    "$ouf_read" | sha256sum -c -
  bash "$ouf_read"
)
```

Restituire il JSON finale, atteso `INGESTION_RESUME_PREREQUISITES_READ`. Il comando lascia Ingestion fermo. Il risultato serve a preparare la continuazione residua conservando import e stop già compiuti; l’E2E e l’ingestione funzionale1024 restano aperti.
