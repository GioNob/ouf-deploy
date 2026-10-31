# OUF — V35 corretta e verifica della lineage corrente, 24 ottobre 2026

## Risultato VPS e correzione della base

La riconciliazione c831dc09f4f54c99f41d4ea563c7b0629c13648f0e8c82a5f00dba5c74f299d7 è completa, Exit0. Il socket storico differisce per inode; ma anche CID/immagine/configurazione/generazione Onboarding non corrispondono al vecchio owner del17ottobre. PostgreSQL conserva CID/immagine/mount hash ma ha altre differenze. I pin /proc catturati sono ancora osservabili e uguali. Nessun Engine/SQL/exec/subprocess o mutazione; vecchio scope DB e marker SQL osservati assenti. Log /home/oufadmin/ouf-engine-reconciliation.nyUSqFTp/operator.log. Scope consumato, niente replay/reset o allentamento della guardia.

L'indagine repository ha trovato il deployment successivo documentato: source-revision-execution-uow4n8lp, preparazione source-revision-human-recovery-inmfuoj2, fonte Onboarding be388e1462778438a208c2e00e166370fee32189, migration V34__source_property_revision.sql. Il primo candidato budget431c601/main84828 omette quei contratti e riusa V34 per SQL diverso. È un errore di selezione della base: archivio ee8b7756 **BLOCCATO da import/apply**, non cancellare/modificare. Nessun suo import, migrazione, attivazione o grant è avvenuto. La CI precedente prova soltanto quella base storica, non compatibilità target.

## Delta corretto qualificato

Draft source PR51 retargeted a feat/source-property-revision-chat-20261018; history integrata senza force/rebase distruttivo. Head029c9670550a0a854a6b007011b2895acd72c5e0, merge testato bb58c2eba8b5696e6ac0af755fa7faa12b80d5fd, tree identico7580a85caae4875b9d245e57e68acae5032e3110. V1–V34 byte-identiche al ramo distribuito; nuovo journal budget V35. Preservati API/journal revisioni e parent guards, lettura esatta workload e ripresa HUMAN403. Resume applica il budget della sessione corrente mantenendo start/cumulativi/storico; grant distinto da attivazione. Nessun nuovo IAM/MCP grant.

CI40089469978/job120859019570:272moduloPASS,zeroFailure/Error/Skipped, incl16managed/7revision e upgradePG reale V34→V35. Upgrade conserva Flywayhistory/risorsaV34/journalrevisioni/triggerappend-only/3tentativi4generazione e zero sessioni concesse. SDK/build/nonroot/scan/boot/exportPASS. Browser40089469983/job120859019453:4Playwright+2latencyPASS. Log diretti letti e14file modificati riletti uguali. Primo merge95573 aveva2errori di fixture: conteggio audit non isolato e budget su fonteAPI non gestita, correttamente negato. Corrette le aspettative/isolation senza ampliare il dominio; confine managed-asset ownership intatto. Warning TrivyUbuntu26.04EOLcatalogue e ActionsNode20→24 conservati.

Artifact12557584376/run40089469978 esatto dopo test/scan/boot: ZIP210886629byte SHA4d2570d23f5a1f5814cf304edcf219b916bae1ea00f25814d51940c192a14485; immaginegzip210885116byte SHAc80b7bda886fd58250557868bd7fe2a38f28bcd2beb7c3f4f8f1ddc854b41379; manifest SHAfb039c80483841a93d2ff8a96a20382667ffba9ef6b9a09cbc4d57984f4f36e0. Scaricati e verificati indipendentemente senza Dockerload/run. Config imageID0b241eb7461bff8d9d4a00bc65d16c1591721c8a06743c3e755faac8ff2ffe9c/User10003:10003/linuxamd64 e revisionlabel=testedcommit verificati. Label aggiunta DURANTE build prima della qualifica, mai alterato il vecchio artifact. Il nuovo pacchetto non è ancora consegnato/staged/importato sul VPS.

Queste prove non qualificano il deployment corrente, la fonteGOVERNED_IDENTITY o E2E. Prima di un altro download di210MB bisogna matchare la generazione catturata con la lineage giusta.

## Lettore della lineage successiva

scripts/read-current-onboarding-source-revision-lineage-20261024.py al commit 5a389f3bcc8d5b368c3ecd7f4683bad2a5164114, SHA4afbab94d27472c7584e7d16ceb92e6aa3468707152dfc3dc4c25ea7bd432399, sorgente riletta uguale. CI40091123700/job120863833996 e PR40091127068/job120863843798:5PASS/zeroSkipped, log letti. Test filesystem/socket/proc reali; piani/runtime/storici sono fixture sintetiche, NON target/daemonAPI/SQL/firme correnti.

Nuovo scope fisso current-source-revision-lineage-v1, max45sec, **zero Engine/SQL/exec/subprocess/servicecall/credenziali/chiavi**. Riusa i vecchi helper solo come definizioni/bootstrap hash-checkati, MAI prepare/main/query. Legge inputb804 e riconciliazionec831, risultato preparazione3eb2 e originaleb398 con hash fissati, piano/review/authority/journal del deployment successivo. Verifica24stageAPPLIED/version57/intent/closure/hashlink e contratto originaleV34. Confronta i binding catturati con il completamento successivo, dichiara il SourceCommit della label solo se40hex, controlla /proc e metadati filesystem socket su due passaggi stabili. Riporta anche mismatch/precedenze non risolte senza inventare salute.

La proposta d'identità DB viene dalla riga Onboarding dell'originale legato alla preparazione successiva, confrontata con plan.database.before.onboarding. Non viene usata l'identità DB Ingestion; solo la porta fisica già trattenuta per confrontare la dichiarazione URL corrente. Non apre configurazioni/secretfile né SQL. Proposta privata, databaseAdmissionProven/lifecycleOwnershipProven/newSqlAttemptAuthorized/newBindingAcceptedForRuntimefalse. Firme storiche non riverificate né riemesse. La directory ee8b7756 è soltanto contenitore di evidenze già raccolte: l'immagine al suo interno resta BLOCCATA.

## Un comando, una volta

Come oufadmin; checksum prima/dopo root copy0400, root esclusiva0700 e log/exit conservati. NessunAPPROVO o nuovo login.

```bash
(
  set -euo pipefail
  umask 077
  work=$(mktemp -d "$HOME/ouf-current-lineage.XXXXXXXX")
  log="$work/operator.log"
  : > "$log"
  trap 'rc=$?; trap - EXIT; set +e; printf "\nExit=%s\nDirectory=%s\nLog=%s\n" "$rc" "$work" "$log" | tee -a "$log"; exit "$rc"' EXIT
  {
    gh_bin="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
    if [ ! -x "$gh_bin" ]; then gh_bin=$(command -v gh || true); fi
    if [ -z "$gh_bin" ] || [ ! -x "$gh_bin" ]; then
      printf '%s\n' 'STOP: client gh esistente assente; nessun sudo eseguito.'
      exit 2
    fi
    "$gh_bin" api --hostname github.com --method GET \
      -H 'Accept: application/vnd.github.raw+json' \
      'repos/GioNob/ouf-deploy/contents/scripts/read-current-onboarding-source-revision-lineage-20261024.py?ref=5a389f3bcc8d5b368c3ecd7f4683bad2a5164114' \
      > "$work/read.py"
    printf '%s  %s\n' '4afbab94d27472c7584e7d16ceb92e6aa3468707152dfc3dc4c25ea7bd432399' "$work/read.py" | sha256sum -c -
    sudo -- /bin/bash -c '
      set -euo pipefail
      umask 077
      root=/etc/ouf/deploy-snapshots/onboarding-current-lineage-4afbab94d27472c7
      mkdir -m 0700 -- "$root"
      chown 0:0 -- "$root"
      install -o 0 -g 0 -m 0400 -- "$1" "$root/read.py"
      printf "%s  %s\n" 4afbab94d27472c7584e7d16ceb92e6aa3468707152dfc3dc4c25ea7bd432399 "$root/read.py" | sha256sum -c -
      /usr/bin/python3 -I -B -S "$root/read.py"
    ' ouf-current-lineage "$work/read.py"
  } 2>&1 | tee "$log"
)
```

Atteso CURRENT_SOURCE_REVISION_LINEAGE_OBSERVED/complete:true. Servono i booleani di match Onboarding/PG/label/DB dichiarato e path/hash privati, non i file. Incollare solo JSON pubblico, Exit e log. Anche complete:true non concede SQL/apply/budget. InSTOP conservare tutto e non rilanciare sotto altro tempdir/cancellare/rootreset.

## Restante lavoro e 502

Dopo il vero risultato: bind della lineage e identità corrente, primo snapshot SQL read-only ammissibile sul DB giusto e confronto dello storico V34→V35/privilegi/pressione; consegna nuova immagine, piano esplicito del solo delta con closure/entry qualificata e autorità lifecycle corrente; revisione firmata concreta dal terminale prima di applicare. Non abilitare migrazioni implicite aggirando validate-only. Nessun vecchio executor o claim viene riaperto. Solo dopo deployment provato: decisioneHUMAN finita distinta, poi attivazione separata stessa source/version/hash, niente reset/recreazione/dedup perso.

502: resta la prova VPS GET originale200/exactACTIVE/currentcredential+TLS e rinnovi ripetuti. La vista privata usa gli stessi file lookup correnti del caller; non forza DNS diversi. Questo nuovo comando non ripete la GET e non dimostra un nuovo esito applicativo. Chiusura del processo applicativo effettivo/E2E e tenuta futura restano aperte. WorkerRegistry indipendente, nessun restart/reinstall/reset;420/pub5 storici non congelati.8/8tecnico4/6funzionale/G3OPEN/F5F6E2Eacceptance pendenti; Supervisor dopo.
