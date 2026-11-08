# Semantic: aggiornamento coerente dell'applicazione e del database

8 novembre 2026, Europe/Rome. **V11/V12 migrate e validate; avvio bloccato dal file chiave discovery non trovato.**

## Diagnosi corrente

La [ricevuta delle 19:25 CET](../evidence/semantic-application-exit-operator-20261108.json) identifica la catena: `semanticDiscoveryDelegation` → `SEM_DISCOVERY_DELEGATION_KEY_UNAVAILABLE` → `java.nio.file.NoSuchFileException`. Replacement fermo, ExitCode 1 e OOMKilled false; vecchio container fermo, nessun marker di completamento. V11/V12 restano migrate e validate dalla ricevuta precedente delle 19:09 CET. Non rilanciare installer, migratore o vecchio JAR.

Nel sorgente candidato il costruttore legge il file configurato in `ouf.semantic.discovery-delegation.key-file`. Se il parametro è vuoto il componente si costruisce ma non verifica ricevute; se è valorizzato e il file manca l'avvio fallisce. La fixture nativa usata per la qualifica non impostava questo parametro: mancava la copertura del binding reale. La diagnosi è provata dal log, mentre il motivo preciso dell'assenza del file (mount, sorgente o percorso) è ancora da leggere.

Il nuovo lettore raccoglie in un solo passaggio le dichiarazioni ENV/JSON/argomenti e l'esatto path nel log conservato; ispeziona i mount e i metadata dei soli percorsi host corrispondenti. Il container è fermo: questi metadata non equivalgono alla vista filesystem di un processo in esecuzione. Legge inoltre le quattro route Semantic selezionate mediante un GET Admin APISIX, mostrando soltanto nomi dei riferimenti ENV, formato della chiave e confronti di issuer/audience/workload.

La preparazione Gateway precedente aveva ricavato le costanti delle nuove route discovery dalla route consultation/read. Il lettore verifica la configurazione corrente e segnala se i riferimenti coincidono; non presume quale chiave sia quella corretta e non ne copia il valore. Chiave owner e delegazione MCP devono restare distinte come richiesto dal materializzatore Gateway. Nessuna prova di firma funzionale è ancora prodotta.

Codice `d5ac065cd92f6f2b21b313009fc5c703b8a98547`; tre test locali PASS per conflitti di dichiarazione, metadata senza lettura contenuti/symlink e proiezione del firmatario senza valori sensibili; compilazione Python riuscita. [Ambito e limiti](../evidence/semantic-discovery-key-binding-reader-qualification-20261108.json). Riusa due helper già fissati e verificati. Nessuna modifica di servizi, chiavi, route, autorizzazioni o database; lettura della credenziale Admin già esistente, nessuna lettura dei contenuti dei file chiave Semantic.

```bash
(
  set -eu
  ouf_work=$(mktemp -d /tmp/ouf-semantic-key.XXXXXX)
  trap 'rm -rf -- "$ouf_work"' EXIT
  ouf_base='https://raw.githubusercontent.com/GioNob/ouf-deploy/d5ac065cd92f6f2b21b313009fc5c703b8a98547/scripts'
  for ouf_file in \
    read-semantic-discovery-key-binding-20261108.py \
    read-discovery-contract-20261108.py \
    read-analysis-discovery-runtime-20261107.py
  do
    curl --fail --silent --show-error --proto '=https' --tlsv1.2 \
      --connect-timeout 10 --max-time 30 \
      "$ouf_base/$ouf_file" -o "$ouf_work/$ouf_file"
  done
  (
    cd "$ouf_work"
    sha256sum -c - <<'SHA256'
dad3bca82b930b2dded125183323fcb124ecb9ca127b699109498fb4ca2780a2  read-semantic-discovery-key-binding-20261108.py
468660ed73a24c7b8a842f5b99a9c268890c99bb4206ca2e4719865326b27277  read-discovery-contract-20261108.py
ef8dc8c4887122f2b2d76c05eaff7a8850c31004fcd661de2b3e49f51d6cc1b4  read-analysis-discovery-runtime-20261107.py
SHA256
  )
  sudo python3 -I -B "$ouf_work/read-semantic-discovery-key-binding-20261108.py"
)
```

Restituire il JSON pubblico. Esito della lettura: `SEMANTIC_DISCOVERY_KEY_BINDING_READ`, oppure `READ_PARTIAL` con quanto è stato acquisito. I file completi restano privati root in `/var/lib/ouf-storage-migration/semantic-key-binding-*`. Dopo il risultato preparare la correzione nominativa del binding e la ripresa del sostituto, con la chiave configurata inclusa nella prova. La lettura precedente dei log è completata e non va ripetuta.

## Stato precedente all'intervento

La [lettura operatore delle 18:29 CET](../evidence/semantic-installed-package-operator-extract-20261108.json) prova che il JAR corrente contiene soltanto V1–V10, tutte coincidenti col candidato. Mancano V11/V12 e tre classi del percorso discovery. Il database letto alle17:56 CET è anch'esso a V10. Il precedente tentativo non ha eseguito Java o SQL; la sua directory resta intatta.

## Pacchetto individuato e verificato

| Elemento | Riferimento |
|---|---|
| Sorgente candidato | `GioNob/ouf-semantic-registry@c2dae77b42f1811b704465f6ab813c91d808ade4` |
| Build dell'archivio | [run41263544004](https://github.com/GioNob/ouf-semantic-registry/actions/runs/41263544004), workflow al commit `4c8bcdeffd7c7cd239fc5a18bc28569f07b9bd08` |
| Artifact | `13066396654`, `m2-native-credential-discovery-offline-candidate-41263544004`, 203.419.418 byte |
| ZIP SHA256 | `1a7045ffb39486f2579fb342d7fd881f5a123f74a0810d353bce3c755bfc76ba` |
| Docker archive SHA256 | `7f6482b79589fd1063eaf96508ea948d6411a7b4f0dbe76d663746a08953a223` |
| JAR SHA256 | `e69f961a06fa37d019f4015d98dd5419ee9da1fa1387b5b0edaac4214a0cb016` |
| Config image SHA256 | `a6f00cda30f1c570082c94cb49d5564f40d512758441f6b6eac75e21f423d14f` |
| Manifest OCI nel medesimo archivio | `89e84f7a6208afa74039de7057c46ad5c9981fb283b22d9b93fa014e92d1b048` |

Verificati localmente l'intero ZIP e gli otto payload; i221 file dell'archivio sorgente coincidono coi blob Git del commit candidato. Il JAR separato coincide col JAR nel layer dell'immagine. Tutti i12 SQL e lo YAML coincidono col manifesto sorgente già verificato. Le tre classi mancanti nel vecchio pacchetto sono presenti. La label del vecchio container resta una dichiarazione: lo YAML della revisione dichiarata `eccef11a` coincide col suo YAML installato, ma non viene dedotta da questo la provenienza di tutto il JAR.

Il sorgente `c2dae77b` è avanti di8 commit rispetto a `eccef11a`; aggiunge le API discovery e il relativo modello persistente. Il candidato più vecchio `4f8fb581` non è selezionato. L'identificativo nativo `d06aeb52` riportato da vecchie qualifiche apparteneva al loro envelope: il nuovo import diretto usa il manifest presente nell'archivio esatto, senza inventare equivalenze tra digest.

## Intervento

1. Verificare archivio, JAR corrente, frame e database attuali; preparare il replacement con gli stessi mount/configtree, identità, endpoint, IP, alias e MAC. Importare soltanto l'immagine pinned.
2. Fermare e scollegare il vecchio Registry; conservarlo col suffisso `-before-discovery-20261108`. Il confronto del MAC distingue assenza dopo detach e valore esplicito invariato, con la primitiva e le prove del precedente25ottobre; nessuna esclusione globale.
3. Creare il replacement con la stessa attesa prima di Java. Aggiornare immagine, label di revisione e metadato JAVA_VERSION. Rendere esplicito `OomKillDisable:false` quando il vecchio valore è null; verificare false dopo CREATE e il ritorno a null dopo START nel profilo osservato. Docker aggiunge l'alias del nuovo CID; tutti gli alias precedenti restano richiesti.
4. Verificare il JAR nuovo. Eseguire il helper Flyway già qualificato usando le librerie del pacchetto e il configtree effettivo: OID21558, storia V1–V10 e assenza di richieste discovery ricontrollati prima di V11/V12. Nessun repair, clean o aggiornamento manuale della history.
5. Avviare Java solo dopo migrazione e validate riusciti; verificare readiness e conservazione dei binding. Worker/provider restano false. I normali accessi applicativi a database, IAM e policy possono iniziare con Java.

Non viene effettuato rollback automatico del processo vecchio contro lo schema nuovo. Un'interruzione conserva journal, log privati e container per la riconciliazione; non rilanciare il comando alla cieca. Sono previsti un breve disservizio del solo Semantic e due migrazioni reali. SeaweedFS, Teatri, Gateway e produttore del token non vengono riscritti da questo intervento.

## Qualifica e limiti

La verifica usa l'**artefatto originale**, Docker29.8.1 classic/containerd, PostgreSQL17 con proprietario DB non amministratore, mount configtree e processo UID10001. Due profili legacy MAC per backend esercitano stop→detach→rename→create→start in attesa→migrazione→avvio applicativo. La fixture precedente usa un processo in attesa e un DB aV10; non simula richieste utente simultanee al vecchio servizio.

IAM, provider esterno, delega discovery e policy dell'Ente non sono qualificati dalla sola readiness CI. Il percorso discovery completo resta subordinato a MCP14/attivazione, mount credenziale, delega, trasporto e grant. Lo stesso aggiornamento non installa le modifiche1024 degli altri moduli.

Sorgente `c52804add2b26f5f9dad6e84073844cdc75aa880`. [CI42506812587](https://github.com/GioNob/ouf-deploy/actions/runs/42506812587): job128811107718 containerd e128811107823 classic **PASS**, per ciascuno2 test nativi e6 negativi MAC, zero skip. Log diretti letti. Entrambi i profili hanno Config.MacAddress inizialmente presente e assente dopo detach; il replacement conserva la MAC endpoint e il vecchio CID resta fermo. L'applicazione archiviata raggiunge readiness dopo V11/V12; storia e ricevuta sintetica restano identiche. [Qualifica e limiti](../evidence/semantic-application-upgrade-qualification-20261108.json).

Conservati i tentativi CI falliti prima della correzione: identità containerd, OomKillDisable tra CREATE/START e alias del nuovo CID. Non sono stati errori sul VPS. Le ulteriori sei prove negative del helper Flyway restano quelle della qualifica precedente, non vengono contate come prove del nuovo target.

## Consegna precedente — non rieseguire

La prima consegna si è fermata con `GITHUB_CLI_OR_LOCAL_CANDIDATE_ZIP_REQUIRED`: [ricevuta operatore](../evidence/semantic-delivery-incomplete-operator-20261108.json), nessuna modifica ai servizi. Non è stato avviato il controller.

La nuova consegna **non richiede gh o autenticazione GitHub**: scarica l'artefatto pubblico esatto tramite nightly.link, un servizio terzo che rimanda allo storage degli artifact GitHub. Il download integrale di203.419.418 byte è stato eseguito nell'ambiente dell'assistente e l'hash coincide con quello già qualificato. Una precedente connessione era scaduta; la successiva richiesta dell'intero intervallo è riuscita. [Verifica del trasporto](../evidence/semantic-public-delivery-qualification-20261108.json). La raggiungibilità dal VPS non è ancora osservata e resta applicabile la retention dell'artifact GitHub.

Lo script `5e61cc23259a9bae3b18e76ea147c0c9bcaf6ff7` verifica lo ZIP e la consegna interna pinned `b2ef4a4d343716b40ae35a409c6a910a63f88721`, passa lo ZIP con `OUF_SEMANTIC_CANDIDATE_ZIP` e usa lo stesso controller qualificato `c52804a`. Nessuna modifica al codice di aggiornamento, nessuna nuova qualifica runtime dedotta da questa prova di download. I controlli avvengono prima di sudo e dell'intervento sui servizi.

```bash
(
  set -eu
  ouf_install=$(mktemp /tmp/ouf-semantic-install.XXXXXX)
  trap 'rm -f -- "$ouf_install"' EXIT
  curl --fail --silent --show-error --proto '=https' --tlsv1.2 \
    --connect-timeout 10 --max-time 30 \
    'https://raw.githubusercontent.com/GioNob/ouf-deploy/5e61cc23259a9bae3b18e76ea147c0c9bcaf6ff7/scripts/install-semantic-public-archive-20261108.sh' \
    -o "$ouf_install"
  printf '%s  %s\n' \
    '3793349ceef493ec120f47d0c592c9c458fc1d7680af63fd4b13cdd6fc9ee6e8' \
    "$ouf_install" | sha256sum -c -
  bash "$ouf_install"
)
```

L'esito previsto della consegna originaria era `SEMANTIC_APPLICATION_V12_READY`; il risultato effettivo è invece riportato nella diagnosi corrente. La readiness non è ancora una prova di discovery o E2E. Se il risultato è HELD dopo un effetto, conservare le prove e non rilanciare. La directory di questo intervento è `/var/lib/ouf-storage-migration/semantic-application-upgrade-20261108`, separata dal tentativo V11/V12 precedente. A successo si scrive il marker privato `semantic-discovery-current.json` con nuovo CID/immagine/riferimento prove. I vecchi avviatori e i lettori pinned al CID precedente non vanno usati per avviare o attestare il sostituto.

Il reader installato e il migratore precedente sono comandi storici da non ripetere. Il nuovo controller importa soltanto le funzioni del vecchio migratore: non ne esegue il main o lo scope consumato.
