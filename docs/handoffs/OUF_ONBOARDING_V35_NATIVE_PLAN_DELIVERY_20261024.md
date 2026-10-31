# OUF — configurazione corrente e piano nativo V35, 24 ottobre 2026

## Risultato VPS

Pacchetto corretto e review-inputs completati, Exit0. Root /etc/ouf/deploy-snapshots/onboarding-budget-v35-54d86bbcd2ea47fd, hash proposta d52bb83265daff3d07ce04131249c0ab7465315ef35e83af13115ad79c5a1a0e. Tutti34checksum SQL target coincidono, history riuscita/1record nonSQL noto, V35 assente, precondizioni e privilegi del runtime per V35 presenti/capacità snapshot positiva.3tentativi/generazione4/PAUSED e pinproc conservati.0Engine/SQL/exec/subprocess/effetti nuovi; nessun load/migrazione/grant/attivazione/autorità. Stage e review-inputs sono CONSUMATI. Conservare i log /home/oufadmin/ouf-budget-v35-package.hFhNJLt3/operator.log e /home/oufadmin/ouf-v35-delivery.BuuvH1TT/bootstrap.log. Non riscaricare o ripetere il vecchio comando.

OwnerOverlayRootAncestryCustodied=false non impone chown: il reader originale ha già custodia nominativa per /opt/ouf/secrets/onboarding-ths.yaml (file UID/GID10003/0400, /opt/ouf1000:1000/0750 e secrets1000:1000/0700). Metadati esatti e mountreadonly osservati, ma contenuti non letti, quindi configurazione non ancora provata sul VPS.

## Componente qualificato

scripts/freeze-onboarding-v35-native-plan-20261024.py a ebe10b5856db74f5de0c84743b973ba75781eecf, SHAc12c1435b8717924a2051a0d51b32775fed35688ba15cf744c2a1da68b1bee23. Usa definizioni/bootstrap del preparatore1ce già protetto senza chiamare vecchi entrypoint. Carica solo funzioni AST nominate di DUE sorgenti originali byte immutati:

- tools/source_revision_update/configuration.py, SHA d3bb5a29d4e0e626cd34c797326e868050c3c16421901357faa8c73b48e83018: application_json_metadata/owner_json_overlay/overlay_text/additional_location/verify.
- tools/source_revision_update/plan.py, SHA df3261a259b405f73e646b93f178d24435246cb3b32dcd214dfef61cf645f3f5: replacement.

Nessun import/entry operativo di quei moduli. Stessi corpi funzione, wrapper bindano soloJARcandidato e l'UNICO ownerfile atteso con hash+metadati. Il reader nominativo è quello dei142sealed originali, nessuna eccezione aggiunta o chmod/chown della configurazione. La storia Git della configuration.py conferma ultima modifica6f8493ec372f8ca3e12c8a4e6df19552e28fd383 del18ottobre20:40:57Z, precedente al completedsource-revision e b0. Si richiede uguaglianza della classificazione INTERA con quella del completedowner, senza indebolire confronti.

CI40102469896/job120897259344 e PR40102474115/job120897270928:5PASS/zeroSkipped,7.455/8.233sec, log letti. Due container veri/API1.44/proc/rootfs, file10003/0400 e antenato1000/0750, mountreadonly, pin/hash e rifiuto mode alterato, namespaceJSON chiuso, richiesta esatta e replay rifiutato. Storici/proposta/schema, candidatoConfig/JAR e5CID di coorte sono sintetici; non prova Java/Flyway/applicazione target, bootstrap completo o mutazioni. Locale4PASS+1skip (runnerRoot/Docker richiesto).3file modificati riletti uguali, bytehash dei due sorgenti originali verificati dalla CI.

## Confine operativo

Nuovo native-plan-v1 nel package giàstaged, max90sec/4GET esatti (Onboarding/PG prima-dopo), zeroSQL/exec/subprocess/Dockerwrites/signingkeys/bearer/altri credentialfile. Legge DUE volte il medesimo ownerconfig già legato: può contenere valori THS/OAuth sensibili, mai emessi; nessun altro filecredenziale o APIkey viene aperto. Lo registra esplicitamente come ownerConfigurationFileContentReads, non nasconde la lettura dentro un generico zero.

Verifica origine JAR/YAML e configurazione corrente: JSON owner, singolo overlay readonly a pin/hash identico, default/classpath/config loading/JVM/profile channels; origina solo l'endpoint DB giàapprovato. Confronta la classificazione completa, usa il compilatore originale per immagine esatta e richiesta di creazione con Env/mount/endpoint IPv4+MAC+alias/restart/altrelabels conservati. Immagine e sola label source diventano il candidato testato194b; fonte sorgente review1b resta distinta. Non carica immagine o avvia processo.

Il piano privato contiene13stage PLANNED, incluso gate freshadmission+signedreview, import, quiescenza solaOnboarding, backupverificato, sostituzione, V35FlywayESPLICITA, history/schema/dati/3counter-gen4/zero budgetsessioni, restartpolicy e finalproof. Nessuna configurazione migrate modificata. applyEntryQualified/targetApplyAuthorized/runtimeAuthorityIssued/databaseAdmissionProven/lifecycleMutationAuthorizedfalse. Counts3/gen4 sono osservazione SQL giàtrattenuta, NON nuova lettura. Plan freeze risolve configurazione e specifica della richiesta; non rende fresco lo snapshotDB perapply e non qualifica l'ingresso mutante.

## Un comando, una volta, come oufadmin

```bash
(
  set -euo pipefail
  umask 077
  work=$(mktemp -d "$HOME/ouf-v35-native-plan.XXXXXXXX")
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
      'scripts/freeze-onboarding-v35-native-plan-20261024.py:plan.py:c12c1435b8717924a2051a0d51b32775fed35688ba15cf744c2a1da68b1bee23' \
      'tools/source_revision_update/configuration.py:configuration.py:d3bb5a29d4e0e626cd34c797326e868050c3c16421901357faa8c73b48e83018' \
      'tools/source_revision_update/plan.py:replacement.py:df3261a259b405f73e646b93f178d24435246cb3b32dcd214dfef61cf645f3f5'
    do
      path="${item%%:*}"; rest="${item#*:}"; name="${rest%%:*}"; checksum="${rest#*:}"
      "$gh_bin" api --hostname github.com --method GET -H 'Accept: application/vnd.github.raw+json' \
        "repos/GioNob/ouf-deploy/contents/$path?ref=ebe10b5856db74f5de0c84743b973ba75781eecf" > "$work/$name"
      printf '%s  %s\n' "$checksum" "$work/$name" | sha256sum -c -
    done
    sudo -- /bin/bash -c '
      set -euo pipefail
      umask 077
      root=/etc/ouf/deploy-snapshots/onboarding-v35-plan-c12c1435b8717924
      mkdir -m 0700 -- "$root"
      chown 0:0 -- "$root"
      for name in plan.py configuration.py replacement.py
      do
        install -o 0 -g 0 -m 0400 -- "$1/$name" "$root/$name"
      done
      printf "%s  %s\n" \
        c12c1435b8717924a2051a0d51b32775fed35688ba15cf744c2a1da68b1bee23 "$root/plan.py" \
        d3bb5a29d4e0e626cd34c797326e868050c3c16421901357faa8c73b48e83018 "$root/configuration.py" \
        df3261a259b405f73e646b93f178d24435246cb3b32dcd214dfef61cf645f3f5 "$root/replacement.py" | sha256sum -c -
      /usr/bin/python3 -I -B -S "$root/plan.py"
    ' ouf-v35-native-plan "$work"
  } 2>&1 | tee "$log"
)
```

Checksum prima/dopo copia root0700/file0400, log conservato. Nessun nuovo download dell'immagine. Atteso ONBOARDING_V35_CURRENT_CONFIGURATION_AND_PLAN_FROZEN, privatePlanHash/path, quattroGET e dueletture dello stesso ownerconfig, noSQL/noeffects. Incollare solo JSON pubblico ed Exit/Directory/Log, mai piano o contenuti privati. InSTOP/interruzione conservare root/claim/log; nessun rilancio/reset o fallback/chown.

## Dopo

Dal piano reale comporre/qualificare il solo nuovo ingresso nativo con guardie correnti, freshDBadmission, backupquiescente verificato, DDLV35 esplicito e dati/counterproof; poi revisione concreta dual-role firmata dal terminale con APPROVO prima di qualsiasi effetto. Non riusare owner/authority/claim vecchi, non fare Flywayrepair/SQLmanuale per bypassare validate-only, né grantHUMAN/attivazione anticipati. La nuova immagine è soltanto staged, le due vecchie restano bloccate. Solo dopo deployment provato si concede il nuovo budgetHUMAN finito, distinto dall'attivazione, stessa source/version/hash e storico/cumulativi/dedup.

Il502 rimane esplicito: vera GET originale200/exactACTIVE/currentcredential+TLS giàprovata, nessuna nuovaGET o nuovo502 qui. E2E/F5/F6/processo applicativo, continuità futura e releaseacceptance non provati. Registryworker indipendente, no restart/reinstall/counterreset.8/8tecnico4/6funzionale,G3OPEN; Supervisor dopoE2E.
