# Semantic: aggiornamento coerente dell'applicazione e del database

8 novembre 2026, Europe/Rome. **Consegna qualificata, esecuzione VPS attesa.**

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

## Comando operatore

La consegna scarica l'archivio originale con **GitHub CLI già autenticata**, oppure usa il percorso esplicito nella variabile `OUF_SEMANTIC_CANDIDATE_ZIP`. La disponibilità di gh/accesso o dello ZIP sul VPS non è stata osservata: se manca, la consegna si ferma prima di modificare servizi e restituisce `DELIVERY_INCOMPLETE`. Non installa software o configura account. L'archivio è di203MB e tutti gli hash sono fissati.

```bash
(
  set -eu
  ouf_install=$(mktemp /tmp/ouf-semantic-install.XXXXXX)
  trap 'rm -f -- "$ouf_install"' EXIT
  curl --fail --silent --show-error --proto '=https' --tlsv1.2 \
    --connect-timeout 10 --max-time 30 \
    'https://raw.githubusercontent.com/GioNob/ouf-deploy/b2ef4a4d343716b40ae35a409c6a910a63f88721/scripts/install-semantic-application-20261108.sh' \
    -o "$ouf_install"
  printf '%s  %s\n' \
    'a60efbfd90f386ab7718dca9a3b5b8daa448122629edf318631f91af6ea3d8bd' \
    "$ouf_install" | sha256sum -c -
  bash "$ouf_install"
)
```

Esito atteso: `SEMANTIC_APPLICATION_V12_READY`. Restituire il JSON pubblico. La readiness non è ancora una prova di discovery o E2E. Se il risultato è HELD dopo un effetto, conservare le prove e non rilanciare. La directory di questo intervento è `/var/lib/ouf-storage-migration/semantic-application-upgrade-20261108`, separata dal tentativo V11/V12 precedente. A successo si scrive il marker privato `semantic-discovery-current.json` con nuovo CID/immagine/riferimento prove. I vecchi avviatori e i lettori pinned al CID precedente non vanno usati per avviare o attestare il sostituto.

Il reader installato e il migratore precedente sono comandi storici da non ripetere. Il nuovo controller importa soltanto le funzioni del vecchio migratore: non ne esegue il main o lo scope consumato.
