# OUF — applicazione nativa V35, comando singolo del24 ottobre2026

Il piano VPS è congelato e consumato: b17c2c99cc791cced8ee00ed190e30b75c518ae84e2dd4a9ae7eef521390c8bd. Questo è il NUOVO ingresso applicativo qualificato, non una ripetizione del freeze. Ultimo target: immagine staged, V35 non applicata,3tentativi/generazione4/PAUSED,0sessioni/grant/attivazioni. Conservare /home/oufadmin/ouf-v35-native-plan.q7UJXZS8/operator.log e tutte le root precedenti.

## Prova e confine

Codice immutabile4cc62e49539a8e52a823ac5cba95bf92d64613fd. [CI40119375591](https://github.com/GioNob/ouf-source-onboarding/actions/runs/40119375591), job120947367347,137.251sec e [PR40119378683](https://github.com/GioNob/ouf-source-onboarding/actions/runs/40119378683), job120947377574,137.102sec: tutti7PASS/zeroSkip, log diretti letti. Nuovo constructor/operator, DockerAPI1.44/PG17/B0→V35/backup/Ed25519/TTY/parentSIGKILL reali.13stageAPPLIED, esattaV35, tutti campi fonte/revisioni e3/gen4 conservati/0sessioni/6peer invariati; negativa arresta solo nuovo candidato una volta senza vecchio restart/restore/replay. Sourcebootstrap privato iniziale e identitàstoriche sono fixture,5peer sono holdcontainer; non prova target o applicazioneE2E. Evidenza strutturata evidence/onboarding-v35-native-entry-qualified-20261024.json.

Riusa esclusivamente package /etc/ouf/deploy-snapshots/onboarding-budget-v35-54d86bbcd2ea47fd e l’originale artifact12559990549/source1b1222ceaa5af85a25c20857e7c8c1b548b12dc1/tested194b586508c6661b40a74d9c7f99ed3b876f5fbc. Nessun nuovo download/rebuild/relabel della immagine. Cinque file piccoli pinned; helperimport originale2e solo2funzioniAST, sealed142intatto. ID config/nativomanifest provati dal completedownerB0; richiesta frozen invariata salvoID nativo. Docker [merge delle label](https://github.com/moby/moby/blob/v28.5.1/daemon/commit.go) aggiunge default immagine solo per chiavi assenti: mappa effettiva esatta firmata, solo eventuale org.opencontainers.image.source ereditata, tutte le precedenti conservate/managerextra rifiutati; nessun cambioconfigurazione oSourceEnv.

Questo comando propone una breve indisponibilità della SOLA Onboarding: controlli correnti, snapshotDBfresh/read-only, revisione privata completa, APPROVO hash (scrivere esattamente APPROVO come mostrato dal programma) sul controllingTTY e firme esistenti PRIMA di effetti. Quindi import esatto, vecchio restart disabilitato/stop, backup custom verificato mediante parsing senza restore, endpoint/nome conservati, nuovo container/V35Flyway ESPLICITA, readiness e storia/schema/dati/tentativi/zero sessioni, ripristino sola restartpolicy del nuovo, ricevuta firmata. Vecchio container trattenuto fermo.0grant/attivazioni/OAuthcontroller/originalGET/Registryazioni. Nessuna nuova migrazione implicita per aggirare validate-only/Flywayrepair o SQL manuale.

Authority positiva900sec; chiavi devono già coprire930sec, non vengono rinnovate. Startup180sec; negativo30secaggiuntivi massimo1stop del SOLO candidato creato/configverificata non ancora provato. Watchdog effimero con handshake/liveness, nessun servizio persistente; controllererrore/revoca/perdita parent/scadenza convergono a stessa claimCAS negativa. Livepolicy sempre necessaria per positivo; sola copia pubblica originaria firmata per il minimo negativo. Dopo readiness+dati provati, negativa finisce. Guasto contemporaneo host/Engine/watchdog e resilienza permanente non provati. Nessun rollback automatico o vecchio restart.

## Eseguire una sola volta come oufadmin

Il programma mostrerà un NUOVO hash della revisione completa. La decisione richiesta è `APPROVO <hash mostrato>` nel terminale: non incollare vecchi hash e non inviare la revisione privata in chat. Le approvazioni di sviluppo non sostituiscono questa decisione concreta.

```bash
(
  set -euo pipefail
  umask 077
  work=$(mktemp -d "$HOME/ouf-v35-native-apply.XXXXXXXX")
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
    for item in \
      'scripts/apply-onboarding-v35-native-20261024.py:apply.py:55addc8768319abaecfd5501c489edeb6fba18aa5ca61ee1bed9b62b0f146eb2' \
      'tools/onboarding_v35_native/protocol.py:protocol.py:034bb7572905903cca52033e9af098fdbe351d244a531302bf30831df338e43d' \
      'tools/onboarding_v35_native/ports.py:ports.py:a3997298bdb5ff0675bdf81506ec36600d7f6783f741aeff4ee7960d414881be' \
      'tools/onboarding_v35_native/quarantine.py:quarantine.py:69dcb537d1e8d6b4603078339fc7eb1b79a74a8357666d60f7937693a44f69c2' \
      'tools/ingestion_readiness_patch_execution/image_import.py:image_import.py:2e7255c7222cfe69a2fd115fcb9b05cf4f31bd6cc24af6532718621bce9f112d'
    do
      path="${item%%:*}"; rest="${item#*:}"; name="${rest%%:*}"; checksum="${rest#*:}"
      "$gh_bin" api --hostname github.com --method GET -H 'Accept: application/vnd.github.raw+json' \
        "repos/GioNob/ouf-deploy/contents/$path?ref=4cc62e49539a8e52a823ac5cba95bf92d64613fd" > "$work/$name"
      printf '%s  %s\n' "$checksum" "$work/$name" | sha256sum -c -
    done
    sudo -- /bin/bash -c '
      set -euo pipefail
      umask 077
      root=/etc/ouf/deploy-snapshots/onboarding-v35-native-code-a0ce9d7ffb2e4500
      mkdir -m 0700 -- "$root"
      chown 0:0 -- "$root"
      for name in apply.py protocol.py ports.py quarantine.py image_import.py
      do
        install -o 0 -g 0 -m 0400 -- "$1/$name" "$root/$name"
      done
      printf "%s  %s\n" \
        55addc8768319abaecfd5501c489edeb6fba18aa5ca61ee1bed9b62b0f146eb2 "$root/apply.py" \
        034bb7572905903cca52033e9af098fdbe351d244a531302bf30831df338e43d "$root/protocol.py" \
        a3997298bdb5ff0675bdf81506ec36600d7f6783f741aeff4ee7960d414881be "$root/ports.py" \
        69dcb537d1e8d6b4603078339fc7eb1b79a74a8357666d60f7937693a44f69c2 "$root/quarantine.py" \
        2e7255c7222cfe69a2fd115fcb9b05cf4f31bd6cc24af6532718621bce9f112d "$root/image_import.py" | sha256sum -c -
      /usr/bin/python3 -I -B -S "$root/apply.py"
    ' ouf-v35-native-apply "$work"
  } 2>&1 | tee "$log"
)
```

Rootcodice nuova esclusiva0700/file0400, doppio checksum, log ed exit conservati. Rootautorità/logica fissa nel piano: cambiare versione olauncher non riapre claim e non azzera contatori. Il comando NON riscarica immagine e NON ripete preparazioni consumate.

Atteso finale `ONBOARDING_V35_APPLIED_SOURCE_PRESERVED`, complete=true/Exit0, V35checksum1095739786, backupVerified/nativeFlywayHistoryVerified/applicationReadinessProven=true, sourcePAUSED/3/gen4, budgetSessionCount0/humanBudgetsGranted0/sourceActivations0, firma finale verificata, releaseAcceptance=false. Il JSON issued/runtimeAuthorityIssued non è completamento. Incollare solo JSON pubblici e Exit/Directory/Log, mai review/piano/config/database rows/chiavi/token.

InSTOP/interruzione conservare root/claim/backup/log e output: nessun rilancio/cancellazione/reset/restore/vecchio restart. Effetti parziali o ambigui richiedono riconciliazione, non una seconda esecuzione.

## Dopo il vero risultato VPS

Solo dopo V35 target provata, decisione HUMAN finita nuova separata (3tentativi/900sec proposta, NON concessa da questa procedura), poi attivazione separata stessa source/version/hash. Preservare start originale/cumulativi/fencing/dedup/approvazione confermata. E2E/F5/F6 ancora aperti; Supervisor dopo. Il recupero originale502/403 ha già prova VPS GET200/exactACTIVE/TLS; nessuna nuovaGETqui né promessa di tenuta futura.8/8tecnico4/6funzionale,G3OPEN. Registryworker autonomo, niente restart/reinstall/reset. Nessuna merge/release/acceptance.
