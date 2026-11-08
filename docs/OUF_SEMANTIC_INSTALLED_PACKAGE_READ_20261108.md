# Semantic: identificare il JAR installato dopo il blocco della migrazione

[Ricevuta delle 18:16:23 CET dell'8 novembre](../evidence/semantic-v11-v12-held-operator-20261108.json): `HELD / INSTALLED_MIGRATIONS_DIFFER_FROM_SOURCE`. Zero sessioni DB, avvii Java, migrazioni, file helper nel container o stop di servizi. Il controllo si è fermato sul confronto dei file SQL; il dettaglio mancante non permette di dire se alcuni file siano assenti, aggiuntivi o modificati.

**Errore nella ricostruzione dell'assistente:** il [source-lock del candidato](../releases/m2-current-core-source-lock-20261101.json) dichiara `allRuntimeArtifactMembershipProven:false`. L'uguaglianza dell'immagine corrente con quella trattenuta non prova che il suo JAR sia il candidato c2dae77b. È ritirata l'affermazione che il Registry in esecuzione sia già quella versione più recente. Le prove native del migratore usavano un JAR ricostruito dal candidato; non dimostravano il contenuto del JAR sul VPS.

Gateway resta applicato: otto modifiche verificate, 87 route totali/79 conservate. Il database Semantic letto in precedenza resta documentato a V10 con checksum coincidenti col prefisso del candidato; questo tentativo non ha emesso nuove query. La migrazione V11/V12 è sospesa finché non viene riconciliata anche la compatibilità dell'applicazione installata.

## Lettura mirata

Il lettore usa due GET Docker e legge il JAR indicato dal processo Java corrente. Confronta Config/HostConfig/reti/MAC come nella precedente lettura; rende irrilevante soltanto l'ordine dei record completi dei mount. Nessun lifecycle container.

Restituisce:

- elenco delle migrazioni installate con dimensione, SHA256 e CRC32 in stile Flyway quando decodificabili UTF-8;
- file del candidato mancanti, aggiuntivi o con byte diversi, senza accettarli come migrazioni compatibili;
- hash del JAR e dello YAML, nomi/hash delle librerie Flyway/Spring/JDBC selezionate;
- presenza/hash di sei classi discovery del candidato, manifest selezionato, eventuale copertura del JAR da un mount e dichiarazioni ENV Flyway;
- eventuale revision label come sola dichiarazione, non attestazione di provenienza.

Nessun contenuto SQL, classi, YAML, argomento grezzo, ambiente completo o credenziale viene pubblicato. Nessuna query SQL, exec/Java, richiesta provider/token/S3/business, modifica schema o route. Le funzioni dei vecchi script sono soltanto importate: i loro comandi principali non sono rieseguiti.

Il lettore richiede che il tentativo fermato contenga soltanto `attempt.json`, come previsto dal punto di stop; lo rilegge e lo lascia invariato. Conserva il nuovo resoconto in una directory separata. Non cancellare `/var/lib/ouf-storage-migration/semantic-v11-v12-20261108` né rilanciare il migratore.

## Comando operatore corrente

```bash
(
  set -eu
  ouf_read=$(mktemp -d /tmp/ouf-semantic-package.XXXXXX)
  trap 'rm -rf -- "$ouf_read"' EXIT
  ouf_base='https://raw.githubusercontent.com/GioNob/ouf-deploy/f636440dac4df2469e97d919c44fd64693b1fcea'
  for ouf_file in \
    scripts/read-analysis-discovery-runtime-20261107.py \
    scripts/read-discovery-contract-20261108.py \
    scripts/apply-gateway-analysis-delta-20261108.py \
    scripts/read-semantic-installed-package-20261108.py \
    releases/semantic-migration-source-20261108.json
  do
    curl --fail --silent --show-error --proto '=https' --tlsv1.2 \
      --connect-timeout 10 --max-time 30 \
      "$ouf_base/$ouf_file" -o "$ouf_read/${ouf_file##*/}"
  done
  (
    cd "$ouf_read"
    sha256sum -c - <<'SHA256'
ef8dc8c4887122f2b2d76c05eaff7a8850c31004fcd661de2b3e49f51d6cc1b4  read-analysis-discovery-runtime-20261107.py
468660ed73a24c7b8a842f5b99a9c268890c99bb4206ca2e4719865326b27277  read-discovery-contract-20261108.py
7064c8443bb323c12a56846267e4faa9cb25bf3e6dfb35455e753fbe71ce8b01  apply-gateway-analysis-delta-20261108.py
9d409461d89debecdd682d541a34b226354895a5e4808b2504024760717340c1  read-semantic-installed-package-20261108.py
b1ae156656b6b89f4fb20e3a7611d23a46bbcda8bc05aa2c27c42becde21c438  semantic-migration-source-20261108.json
SHA256
  )
  sudo python3 -I -B "$ouf_read/read-semantic-installed-package-20261108.py"
)
```

Restituire soltanto il JSON pubblico. `SEMANTIC_INSTALLED_PACKAGE_READ` significa lettura completata, anche quando espone differenze; non autorizza migrazioni né dichiara una versione applicativa compatibile.

## Verifiche e passo successivo

Sorgente `f636440dac4df2469e97d919c44fd64693b1fcea`. [CI42504819787](https://github.com/GioNob/ouf-deploy/actions/runs/42504819787), job128805066674: **6 test riusciti, zero skip**, log letti; stessi sei test locali riusciti. Fixture di archivi per file mancanti/modificati/aggiuntivi, repeatable/non-UTF8, duplicati/limiti, hash e redazione. Non è una prova del contenuto del JAR VPS. I guard del frame sono quelli già qualificati, senza nuove transizioni container. [Evidenza](../evidence/semantic-installed-package-read-qualification-20261108.json).

Se il JAR contiene solo un prefisso o file diversi, ricostruire prima la provenienza e la compatibilità del codice: potrà essere necessario aggiornare insieme Registry e database. La sola presenza di classi o una label OCI non prova il comportamento. Nessun allentamento dell'attuale controllo e nessun SQL esterno iniettato per superarlo.

Dopo questa riconciliazione restano MCP14/rollout1024, binding e trasporto provider, grant/attivazione discovery, mapping del profilo Teatri conservato e Ingestion→UDP. Non ripetere upload, profilo o scritture Gateway.
