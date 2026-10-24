# OUF — DB corrente dell'owner Onboarding, 24 ottobre 2026

## Risultato ricevuto e identificazione

Il VPS ha completato CURRENT_SOURCE_REVISION_LINEAGE_OBSERVED/Exit0. Ricevuta privata6c7aecaae138c31b35a7adbc20e2fa53c5657aba477f92d52e82c77d53fe8f32, log /home/oufadmin/ouf-current-lineage.Km3FiNwK/operator.log. PostgreSQL, socket/Engine dichiarato e boot coincidono con il deployment source-revision; i due pin/proc sono stabili. Onboarding invece dichiara b0f5e3dacbe59ebf87e22dd6af2575e41249f51d e non coincide con be388. Nessuna chiamata Engine/SQL/exec/subprocess o mutazione. Scope consumato, non rilanciare.

La revisione è il successivo owner con precondizioni InstallationConfiguration, completato in /etc/ouf/deploy-snapshots/installation-owner-update-execution-hnfn0zwg. Riferimenti: evidence/installation-owner-completed-readback-20261019.json e releases/installation-owner-candidate-20261019.json. Non basta il numero di migrazione per scegliere una base applicativa.

Il candidato intermedioV35/artifact12557584376 conserva be388, ma omette quell'owner successivo: NON ammissibile sul target, non consegnato né applicato. Vecchio archivioee8/V34budget sempre BLOCCATO, conservare entrambi. Fonte corretta draftPR51/head1b1222ceaa5af85a25c20857e7c8c1b548b12dc1 integra anche b0 senza force/rebase. Sei blob originali e tutte le34migrazioni uguali al target source; cambiamenti produzione limitati al budget e UI, aggiuntaV35. Conservati ETag forte/generazione/precondizioni, idempotenza e assenza di rete sotto lock/transazione.

CI40092379187/job120867533456:281moduloPASS/zeroFailureErrorSkip, incl16managed/7revision/10installation e upgradePG V34→V35. SDK/build/nonroot/scan/boot/exportPASS. Browser40092379245/job120867533517:4Playwright+2latencyPASS. Log diretti letti. Merge194b586508c6661b40a74d9c7f99ed3b876f5fbc e head hanno tree69914e9d188e59716a7e3b32e4c074fae1806248 uguale. Artifact12559990549 scaricato/verificato indipendentemente senza Dockerload/run: ZIP074bde3ecc348c9c9481683412f2c1ac376b2b2fdae409d688d71397a8c322e8 (210895493byte), inner54d86bbcd2ea47fdbda133699b914674c766bdef8554132a308eae36d38f3358 (210893865byte), manifest63d96c781cf88f55f672ac65d86de9e7c4b87056801dfd1c32129e638ba32553, imageb121ebbcd4eae569de243748b01a7d51e7faabd7693ec1003c424a0442575e57/User10003:10003/revisionlabel=merge. Non staged/importato/applicato. Prove e limiti in evidence/onboarding-finite-budget-b0-v35-qualified-20261024.json.

## Lettura qualificata distinta

scripts/read-current-onboarding-database-20261024.py a e8008bf40c99dfd5dc1af67da5c0966630b7290b, SHA7fa2cd6dae5d47306ebf8c1122643fa9a5449c3fbb43571b33c9bf856511588e, sorgente/test/workflow riletti uguali. CI push40092794664/job120868752132 e PR40092798636/job120868763599:7PASS/zeroSkipped,13.494/14.053sec, log letti. Test con PostgreSQL17 reale, descrittoreV34/trigger, transazioneREADONLY, rifiuto effettivo scritture, API1.44 con due container reali, stop per drift primaSQL e scope fallito non ripetibile. Histories/review/authority/identità e altri CID sono fixture sintetiche: non prova target, firme correnti o bootstrap completo.

Nuovo scope fisso current-onboarding-database-snapshot-v1, max90sec,4GET esatti Engine e UNA sessione SQL tramite Dockerexec; nessuna credenziale/chiave/HTTP applicativo/OAuth/lifecyclewrite/migrazione/grant/attivazione. Non chiama gli entrypoint storici prepare/main; usa solo definizioni/bootstrap verificati e la query pura preesistente, estesa alla metadata del trigger revisioni. Verifica ricevuta6c/inputb804; history owner b0 completa11stage/version29, stessoengine/boot, plan/source/review/authorityhash/intent e runtimefinale esatto del readback pubblico. Poi verifica generazioni/PID/configurazioni/restart prima e dopoSQL. Il vecchio scope DB deve restare assente; nessun rebind dei profili o scrittura negli owner.

L'identità DB è la riga Onboarding privata legata alla preparazione source-revision; dal profilo Ingestion si usa solo il trasporto nativoPG già catturato, MAI la sua identità DB. Ambiente corrente/admin devono corrispondere. Le precedenzeJVM/configfile restano unresolved: la sessione legge quel DB indipendentemente legato, NON dichiara di provare la selezione effettiva dell'applicazione. Nessun fileconfig/credenziale viene aperto. READONLY/timeout/locktimeout/searchpath chiusi, dockerconfig nuova vuota e fallback password disabilitati. Hash/righe SQL e metadati rimangono privati0400; solo booleani/conteggi safe in stdout. La snapshot non concede admission/migrazione/lifecycle/authority/apply.

## Un comando, una volta

Come oufadmin, stessa sessione; checksum prima/dopo copia root0400, root esclusiva0700 e log conservato. Nessun nuovo login o APPROVO per questa sola osservazione.

```bash
(
  set -euo pipefail
  umask 077
  work=$(mktemp -d "$HOME/ouf-current-database.XXXXXXXX")
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
      'repos/GioNob/ouf-deploy/contents/scripts/read-current-onboarding-database-20261024.py?ref=e8008bf40c99dfd5dc1af67da5c0966630b7290b' \
      > "$work/read.py"
    printf '%s  %s\n' '7fa2cd6dae5d47306ebf8c1122643fa9a5449c3fbb43571b33c9bf856511588e' "$work/read.py" | sha256sum -c -
    sudo -- /bin/bash -c '
      set -euo pipefail
      umask 077
      root=/etc/ouf/deploy-snapshots/onboarding-current-database-7fa2cd6dae5d4730
      mkdir -m 0700 -- "$root"
      chown 0:0 -- "$root"
      install -o 0 -g 0 -m 0400 -- "$1" "$root/read.py"
      printf "%s  %s\n" 7fa2cd6dae5d47306ebf8c1122643fa9a5449c3fbb43571b33c9bf856511588e "$root/read.py" | sha256sum -c -
      /usr/bin/python3 -I -B -S "$root/read.py"
    ' ouf-current-database "$work/read.py"
  } 2>&1 | tee "$log"
)
```

Incollare solo JSON pubblico e righe Exit/Directory/Log. Atteso CURRENT_ONBOARDING_DATABASE_SNAPSHOT_OBSERVED/complete:true; verificare esitoV34, storia, schema, tentativi/generazione/configurazione e hash/path privati. InSTOP/interruzione conservare root/claim/log; non cancellare/rilanciare sotto un altrotempdir. Nessun errore autorizza fallback o un secondoSQL.

## Prossimo gate e 502

Prima di applicareV35: confronto esatto storia/checksum/schema/privilegi/capacità e precedenzeconfig, admissionDB e autoritàlifecycle corrente; consegna dell'immagine corretta e piano esplicito del solo delta con ingresso/closure nativa qualificati, revisione concreta e fresca firmata dal terminale. Non abilitare migrazioni implicite aggirando validate-only. Nessun grantHUMAN anticipato; dopo deployment provato, distinta decisione finita e distinta attivazione, stessa source/version/hash e storico/cumulativi/dedup conservati.

Il502 resta esplicito: vera GET originale200/exactACTIVE con credenziale e TLS correnti e rinnovi ripetuti già osservati. Lookupfiles correnti copiati identici, nessun DNS forzato/fallbackhost. Nessuna nuovaGET/502 osservata da questi controlli. Chiamata del processo applicativo, E2E/F5/F6, tenuta futura e releaseacceptance restano aperti. Registryworker indipendente, niente restart/reinstall/reset/replay.8/8tecnico4/6funzionale/G3OPEN; Supervisor dopoE2E.
