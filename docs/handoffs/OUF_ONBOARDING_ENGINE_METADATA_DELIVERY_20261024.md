# OUF — riconciliazione metadati Engine, 24 ottobre 2026

## 502: evidenza e limite preciso

Resta acquisita la prova VPS POST_NETWORK_ORIGINAL_CALLER_GET_OBSERVED/Exit0: GET originale HTTP200, reference esatta ACTIVE, credenziale corrente caller e TLS verificati, quattro ulteriori pubblicazioni owner1→5 senza reinstall/restart/reset. Evidenza registry-original-request-200-target-20261024.json; log /home/oufadmin/ouf-post-network-get.tWLPFZo0/operator.log. Non è prova CI e non viene ripetuta.

Chiarimento dal codice sigillato caller_lookup: la vista privata COPIED_CALLER_FILES_PRIVATE_MOUNTS_V1 usa copie IDENTICHE dei file correnti del caller resolv.conf/hosts/nsswitch.conf, con hash/metadati/generazione riverificati, senza risposteDNS sostitutive o fallback al resolver host. Il namespace privato serve a isolare il figlio. Non implica che siano stati usati input DNS diversi. Restano da provare la chiamata del processo applicativo/Java effettivo e le sue cache, E2E completo e tenuta futura/reboot/cambioIP. Nessuna nuova GET o nuova rootcause502 stabilita da questa riconciliazione.

## STOP reale da conservare

Il lettore DB precedente ha riportato STOP_RECONCILE/SAME_RETAINED_ONBOARDING_ENGINE_REQUIRED/Exit2, EngineGET0/SQL0/containerExec0/migrazioni0/attivazioni0/HUMANgrants0. Log /home/oufadmin/ouf-onboarding-database.EOGUXcGV/operator.log. La guardia confronta prepared.engine, plan.engine e input corrente.engineBinding; lo STOP non identifica il campo divergente. Non dimostra nuovo502 o erroreDB. È prima del claim nuovoDB e di ogni dispatch; non confondere questo punto con la root helper già creata dalla consegna. Esistenza di eventuali altri marker da osservare, non dedurre cancellazioni o reset.

Preservare helper root/log/vecchi file. NON rilanciare il precedente comando DB, neppure cambiando tempdir. Nuova lettura metadata-only con scopo distinto, nessun secondo tentativo SQL.

## Lettore qualificato e limiti

scripts/reconcile-onboarding-engine-metadata-20261024.py al commit 1a8b5c1bf6c34e856ee28666f76d7ffeac11c216, SHA25616cbb89e42b8dfed0e3a32b9248224d86fa21ed000b5d1e10c95c5ca04461ded, sorgente pubblicata riletta uguale. CI40084404503/job120844257867:8PASS/zeroSkipped/0.036sec; PR40084408317/job120844268630/testedmerge70771c23b03c39b9738fd7dc2209ffe5929992da:8PASS/zeroSkipped/0.018sec. Log diretti letti, warning checkoutNode20 forzato24 conservato.

Test nativi con socket Unix/inode/alias reali root protetti e /proc reale; nessuna connessione, HTTP, Docker, SQL o subprocess durante la cattura. Test bloccano esplicitamente Engine.get, vecchi prepare/query, trasporto SQL, Popen e socket.socket. Verificati mancanti/drift/permessi non protetti, comparazioni di entrambi i profili mount senza riscrivere hash storici, riservatezza e claim esclusivo/no replay. Review/journal/binding runtime e receipt14GET sono fixture sintetiche. Non sono prova del target/continuitàdaemon/fullbootstrap.

Il nuovo scope fisso engine-binding-reconciliation-v1 sotto il pacchetto predisposto viene creato una sola volta. Usa il DBreader root0400 già presente solo per definizioni/bootstrap verificati, MAI prepare/main/query. Riusa la closure142 immutata per funzioni pure. Legge i file protetti legati all'inputb804 e alle review storiche, confronta i tre profili Engine, osserva solo filesystem/alias/inode/mode dei socket e due volte i pin /proc catturati. Nessun open/connect del socket; nessun EngineGET/SQL/exec/containerHTTP/servicecredentialfile/chiave/grant/workeraction. Marker DB precedenti solo osservati, mai scritti.

Le classi distinguono alias soltanto, vecchio pin cambiato, piano diverso dal prepared, STOP non riprodotto o differenza da riesaminare. La classificazione non prova identità API del daemon, non rende equivalenti engine diversi e non accetta automaticamente un binding corrente. Eventuali pin processo non più osservabili sono riportati, senza inventare salute o nuova generazione. File vecchi e budget restano intatti; nuove evidenze root0400/0700 soltanto nello scope distinto.

## Comando fissato

Una sola volta come oufadmin. Checksum prima/dopo copia root esclusiva, log/exit conservati, zero Engine/SQL. Nessuna revisioneAPPROVO perché non concede autorità o applica modifiche.

```bash
(
  set -euo pipefail
  umask 077
  work=$(mktemp -d "$HOME/ouf-engine-reconciliation.XXXXXXXX")
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
      'repos/GioNob/ouf-deploy/contents/scripts/reconcile-onboarding-engine-metadata-20261024.py?ref=1a8b5c1bf6c34e856ee28666f76d7ffeac11c216' \
      > "$work/reconcile.py"
    printf '%s  %s\n' '16cbb89e42b8dfed0e3a32b9248224d86fa21ed000b5d1e10c95c5ca04461ded' "$work/reconcile.py" | sha256sum -c -
    sudo -- /bin/bash -c '
      set -euo pipefail
      umask 077
      root=/etc/ouf/deploy-snapshots/onboarding-engine-reconcile-16cbb89e42b8dfed
      mkdir -m 0700 -- "$root"
      chown 0:0 -- "$root"
      install -o 0 -g 0 -m 0400 -- "$1" "$root/reconcile.py"
      printf "%s  %s\n" 16cbb89e42b8dfed0e3a32b9248224d86fa21ed000b5d1e10c95c5ca04461ded "$root/reconcile.py" | sha256sum -c -
      /usr/bin/python3 -I -B -S "$root/reconcile.py"
    ' ouf-engine-reconciliation "$work/reconcile.py"
  } 2>&1 | tee "$log"
)
```

Atteso ONBOARDING_ENGINE_METADATA_RECONCILED/complete:true con classification, confronti pubblici e privateReconciliationPath/hash. Incollare soltanto JSON pubblico, Exit e percorso log, mai i file privati. InSTOP conservare tutto e non ripetere/cancellare/reset. Anche complete:true NON autorizza altro SQL o una sostituzione.

## Dopo il risultato vero

Determinare il delta preciso senza cambiare i binding storici. Se alias o drift spiegano lo STOP, servono comunque custodia attuale e lineage applicazione/Postgres dimostrate, eventuale nuovo piano esplicito e nuova qualificazione del solo delta; nessun semplice allentamento della guardia o rilancio del reader vecchio. Poi primo snapshot SQL autorizzato distinto, se ammissibile; nessuna query è già stata eseguita dal tentativo fermato.

502 resta criterio esplicito: chiudere il percorso applicativo reale e l'E2E con evidenze, oltre al200 originale controllato già acquisito. Il lavoro Onboarding è il gate E2E per la fonte PAUSED/3tentativi/generazione4/sessione originaria scaduta; V34 solo codice/CI/pacchetto, NON applicata. Deployment soltanto con piano DB/candidato/privilegi/authoritylifecycle/closure qualificata e nuova revisione firmata concreta. Poi decisioneHUMAN finita distinta e attivazione separata sullo stesso source/version/hash, senza reset/recreazione/dedup perso. Nessun login oAPPROVO anticipato.

Registry normale indipendente;420/pub5 storici non congelati. Scope repair/GET/vecchi403/native11/input14GET consumati.8/8tecnico4/6funzionale/G3OPEN/F5F6E2Eacceptance pendenti; Supervisor dopo.
