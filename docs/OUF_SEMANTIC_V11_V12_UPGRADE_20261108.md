# Semantic: completare le migrazioni V11 e V12

**SOSPESO — tentativo eseguito e fermato alle 18:16 CET. Non ripetere il comando sotto.** [Ricevuta](../evidence/semantic-v11-v12-held-operator-20261108.json): package installato diverso dal candidato, zero sessioni DB/Java/migrazioni. La compatibilità del codice installato non è dimostrata dal source-lock. [Passo corrente: lettura del JAR](OUF_SEMANTIC_INSTALLED_PACKAGE_READ_20261108.md).

La [ricevuta delle 17:56 CET dell'8 novembre](../evidence/gateway-analysis-applied-operator-20261108.json) conferma le otto route Gateway applicate/rilette, 87 totali e 79 conservate. Il comando Gateway è concluso: non ripeterlo.

Semantic: database OID 21558, Flyway V1–V10 riuscite, `recovery_state` assente e zero richieste discovery nella lettura. I dieci checksum coincidono con i file del sorgente trattenuto `c2dae77b42f1811b704465f6ab813c91d808ade4`. Mancano V11 e V12. Questo non chiude la verifica della versione dei file dentro il JAR installato: la esegue il nuovo comando prima di qualsiasi migrazione.

## Intervento

Il comando usa l'immagine Semantic corrente e il Flyway incluso nel suo JAR. Verifica le dodici migrazioni confezionate contro il sorgente e la configurazione dichiarata; ricostruisce la configurazione con le librerie Spring installate, inclusa la password nel configtree. Non avvia un secondo Spring applicativo. La configurazione ricostruita non è una lettura della memoria della JVM già in esecuzione.

Il binding JDBC risolto deve coincidere con quello dichiarato verso il PostgreSQL trattenuto e con OID21558. Provider/worker devono risultare disabilitati. Flyway valida la storia senza repair/baseline/clean; le sole versioni ammesse in attesa sono11 e12, con checksum esatti. La validazione preliminare ammette queste due pending già verificate, quella finale è ordinaria.

- V11 aggiunge i campi e il vincolo di idempotenza discovery.
- V12 aggiunge stato di ripresa, scadenze/generazioni e tabelle/funzioni per il worker discovery.
- Flyway registra le migrazioni nella sua storia. Nessun inserimento manuale nella storia e nessun ALTER improvvisato.
- Migrazioni raggruppate in transazione; lock timeout3s, statement timeout20s, connessione5s, socket35s, chiamata Java90s. Contesa o esito incerto fermano il comando senza retry automatico.
- La storia preesistente viene confrontata integralmente nei campi rank/version/type/script/checksum/success; il test nativo verifica anche la conservazione dell'intera storia e di una ricevuta applicativa sintetica.

Nessuna sostituzione/stop di container, modifica di route, permessi, provider o worker. Il piccolo helper pubblico viene copiato temporaneamente in /tmp del container, eseguito dalla sua JVM e rimosso; il journal root0700 e i log privati0600 restano sul VPS. Non legge o pubblica credenziali nei risultati; il processo Java legge la password già disponibile all'applicazione per collegarsi al suo database.

Non rilanciare gli scope o gli strumenti storici di migrazione: questo comando è legato al database attuale V10 e alla ricevuta corrente. Una directory di tentativo già presente interrompe prima degli effetti. Nessun tentativo di ripristino automatico a V10 dopo un esito incerto.

## Qualifica

Sorgente applicatore `33c54cf4b57a7577b9b9a8221e82d6c476976ffa`, consegna `03d2e7acf11ee3bc1f4b4a7ef164364896273831`. [CI42503772280](https://github.com/GioNob/ouf-deploy/actions/runs/42503772280), job128801887169: **6 test nativi riusciti, zero skip**, log letti. PostgreSQL17 reale, JRE21 nel container con UID10001 verificato e ruolo proprietario del database non amministratore verificato. Password risolta da configtree; V11/V12 applicate con Flyway, intera storia precedente e ricevuta applicativa sintetica conservate, nessun job/attempt prodotto. Rifiutati secondo tentativo, checksum alterato, descrizione Flyway alterata, backlog inatteso, OID errato, package/configurazione non corrispondenti.

Il JAR CI è ricostruito dal sorgente trattenuto; non è un'esportazione dei byte OCI del VPS. Il comando controlla sul target migrazioni e YAML esatti prima di usare le librerie lì installate. I byte del piccolo helper consegnato sono gli stessi verificati nella prova riuscita. I test completi del modulo non sono stati rieseguiti in questo workflow; sono sei prove mirate di migrazione/trasporto e rifiuto.

La prima validazione preliminare respingeva le versioni pending; è stata corretta senza repair né allentare i controlli sulle versioni ammesse. La prima fixture non amministrativa tentava di modificare il superuser bootstrap PostgreSQL, operazione rifiutata: ora usa un ruolo distinto. Esiti precedenti e limiti conservati nell'[evidenza](../evidence/semantic-v11-v12-upgrade-qualification-20261108.json). Tutti e cinque i workflow PR del sorgente sono success. Nessuna prova VPS/mapping/E2E derivata dalla CI.

## Comando storico sospeso — non ripetere

I tre script precedenti vengono importati come librerie: non viene rieseguito il comando Gateway.

```bash
(
  set -eu
  ouf_migrate=$(mktemp -d /tmp/ouf-semantic-migrate.XXXXXX)
  trap 'rm -rf -- "$ouf_migrate"' EXIT
  ouf_base='https://raw.githubusercontent.com/GioNob/ouf-deploy/03d2e7acf11ee3bc1f4b4a7ef164364896273831'
  for ouf_file in \
    scripts/read-analysis-discovery-runtime-20261107.py \
    scripts/read-discovery-contract-20261108.py \
    scripts/apply-gateway-analysis-delta-20261108.py \
    scripts/upgrade-semantic-v11-v12-20261108.py \
    releases/semantic-migration-source-20261108.json \
    releases/semantic-migration-helper-20261108.json
  do
    curl --fail --silent --show-error --proto '=https' --tlsv1.2 \
      --connect-timeout 10 --max-time 30 \
      "$ouf_base/$ouf_file" -o "$ouf_migrate/${ouf_file##*/}"
  done
  (
    cd "$ouf_migrate"
    sha256sum -c - <<'SHA256'
ef8dc8c4887122f2b2d76c05eaff7a8850c31004fcd661de2b3e49f51d6cc1b4  read-analysis-discovery-runtime-20261107.py
468660ed73a24c7b8a842f5b99a9c268890c99bb4206ca2e4719865326b27277  read-discovery-contract-20261108.py
7064c8443bb323c12a56846267e4faa9cb25bf3e6dfb35455e753fbe71ce8b01  apply-gateway-analysis-delta-20261108.py
af319a963f8556f5feb7459d369afe1e362f482562cb674d8a6028c5f1a128cc  upgrade-semantic-v11-v12-20261108.py
b1ae156656b6b89f4fb20e3a7611d23a46bbcda8bc05aa2c27c42becde21c438  semantic-migration-source-20261108.json
13ea1d621cadc703e2f67b099f4f719ffcb46447a093454233efa7f64c40c4b0  semantic-migration-helper-20261108.json
SHA256
  )
  sudo python3 -I -B "$ouf_migrate/upgrade-semantic-v11-v12-20261108.py"
)
```

Restituire soltanto il JSON. Se `HELD`, conservare la directory e i file: nessuna ripetizione automatica o cancellazione per aggirare il controllo. `databaseWrites:null` significa che l'esito non è ancora dimostrato. L'intento privato identifica l'invocazione già tentata; una riconciliazione eventuale leggerà prima la storia, senza rilanciare la migrazione.

## Dopo il risultato

Questo passo completa lo schema discovery; non accende ancora la ricerca OntoPiA. Restano MCP PR83/migrazione14 e servizi compatibili1024, binding/trasporto del provider, grant e attivazione delle capacità. Poi discovery PROPERTY sul profilo Teatri conservato, mapping, review THS, Ingestion→UDP e ripetizione E2E. Non ripetere upload/profilazione né le otto scritture Gateway.
