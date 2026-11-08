# Ingestion 1024: continuazione dal container già fermo

8 novembre 2026. Continuazione qualificata e consegnata; **risultato VPS ancora atteso**. L'immagine candidata è già importata, il vecchio Ingestion è fermo. Non ripetere l'installer originario o il vecchio avvio.

## Stato target acquisito

La [ricevuta integrale delle 22:32 CET](../evidence/ingestion-resume-prerequisites-operator-20261108.json) conferma frame Docker API1.44 esatto rispetto al post-stop, stessa identità/generazione e PID0. La CLI non fissata omette invece Config.MacAddress e rappresenta diversamente gli alias: i precedenti booleani cross-API non provavano una mutazione runtime.

Database identico al post-stop: storia V18, tutte le sette impronte, tre run SUCCEEDED, 34 handoff ACKED, nessuna lease di partizione non scaduta. Entrambe le pianificazioni sono DISABLED, triggerOnce, pubblicazione già consumata, senza lease o errori di attivazione. Journal prima di detach/rename/create/start, nessun marker sostituto.

I campi storicamente cambiati fra prima e dopo lo stop non sono recuperabili dalle vecchie impronte aggregate. Il [codice](https://github.com/GioNob/ouf-ingestion-runtime/blob/c85d9fd3be215e518dc6e7d075797720b5afbd91/src/main/java/it/comune/trieste/ouf/ingestion/ActivationRepository.java) aggiorna `discovery_verified_at` e `lock_version` sulla stessa pubblicazione; la nuova prova nativa esercita questo comportamento.

## Operazione residua

Controller [9f1dfd3a](https://github.com/GioNob/ouf-deploy/blob/9f1dfd3af254606afc28b85d4eef5c9d54d35b3a/scripts/resume-ingestion-wide-20261108.py), SHA256 `ab43c6d02e7d8ada08a3325f1e0b9a8559fff7324338b98d117371497bf54390`.

1. Verifica prefisso, frame API1.44 e byte della lettura fissati dalla ricevuta. Controlla l'immagine nativa già importata `sha256:562e4c6e19d5227f00fb3159deb506da256d2245ee4a40a652b0c03865704baa` e l'uguaglianza esatta fra richiesta CREATE ricostruita e conservata.
2. Legge il database READ ONLY: uguaglianza completa con il post-stop verificato. Scollega/rinomina il vecchio, conservandolo spento; crea un solo sostituto con IP/MAC/alias, quattro mount read-only, ENV e argomenti Java conservati. Riusa la regola MAC stretta.
3. Avvia il gate, verifica il JAR archiviato, ricontrolla il database prima di Java, poi avvia l'applicazione e verifica readiness. Flyway resta disabilitato in ENV e argomenti.
4. Confronta integralmente storia e sei tabelle di lavoro. Per ing_schedule conserva l'impronta di tutti i campi eccetto i due del polling, ammessi solo con avanzamento monotono. Entrambe le pianificazioni devono rimanere DISABLED, consumate e senza lease. Cambi di pubblicazione, stato, checksum, checkpoint, payload o schema non vengono assorbiti dal guard.

Tre sessioni SQL READ ONLY previste; zero SQL write dello script. L'avvio applicativo può eseguire normale lavoro e letture Gateway. Nessun nuovo import, stop, migratore esplicito, comando business, replay o rollback automatico. Un fallimento dopo CREATE/START conserva CID, intenti e log privati: non rilanciare alla cieca.

Vecchio journal `ingestion-wide-upgrade-20261108`; nuovo journal esclusivo `ingestion-wide-resume-20261108`, entrambi sotto `/var/lib/ouf-storage-migration`. Lettura fissata `ingestion-resume-read-pycdpafx`, frame SHA256 `8531475a2343ba3640d50f18afe4e3b45f33ed1eebe72ee55e02875a8e4073a4`, database SHA256 `e9d395e58d4ac98c54ff36c6c4df8fbf66db12361bc0b31f8974899cbb939929`. Originali e impronte storiche restano intatti.

## Qualifica e limiti

[CI42526435616](https://github.com/GioNob/ouf-deploy/actions/runs/42526435616), source9f1dfd3a: Docker29.8.1 classic/containerd, job128870984249/128870984118. Per backend: sei test guard precedenti, sette nuovi e due cicli nativi; zero skip, log letti. Entrambi i profili richiedono MAC legacy presente all'origine e dopo STOP, assente solo dopo DETACH. Il candidato archiviato si avvia; ActivationLoop riconcilia almeno due volte le medesime pubblicazioni consumate. V18 e sei tabelle identiche, solo metadata polling cambiati. Readiness200 e endpoint preservati, nessuno stop/import nel percorso residuo.

Il predecessore CI usa il candidato, non il vecchio binario VPS; dati, token, chiavi e Gateway sono sintetici. Non riproduce tutta la configurazione Spring target né prova la causa storica. Readiness non è ingestione funzionale1024 o E2E. [Evidenza](../evidence/ingestion-wide-resume-qualification-20261108.json).

## Comando corrente sul VPS

Delivery `468fb612447f14d7dd022cdbd7d138cc69012fe7`. Otto file riletti e verificati; catena moduli importata senza main, wrapper riletto e sintassi Bash verificata. Riusa l'immagine già presente.

```bash
(
  set -euo pipefail
  ouf_resume=$(mktemp /tmp/ouf-ingestion-resume.XXXXXX)
  trap 'rm -f -- "$ouf_resume"' EXIT
  curl --fail --silent --show-error --proto '=https' --tlsv1.2 \
    --connect-timeout 10 --max-time 30 \
    'https://raw.githubusercontent.com/GioNob/ouf-deploy/468fb612447f14d7dd022cdbd7d138cc69012fe7/scripts/deliver-ingestion-wide-resume-20261108.sh' \
    -o "$ouf_resume"
  printf '%s  %s\n' '51a207cc40479be8b88e43e9621210d6657c3777269a393a5a58be7eb36ddf41' "$ouf_resume" | sha256sum -c -
  bash "$ouf_resume"
)
```

Restituire il JSON finale, atteso `INGESTION_WIDE_1024_READY`. Se HELD, leggere il punto raggiunto senza replay. Dopo readiness target: UDP1024, provider/strumenti discovery, mapping del profilo Teatri conservato, THS→Ingestion→UDP e ripetizione E2E.
