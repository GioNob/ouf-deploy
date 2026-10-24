# Onboarding — una lettura database distinta, 24 ottobre 2026

## Ultimo risultato VPS vero

CURRENT_ONBOARDING_COHORT_INPUTS_CAPTURED/Exit0:14GET, coorte stabile, archivio/config immagine e provenienza CI verificati. Input privato /etc/ouf/deploy-snapshots/onboarding-finite-session-ee8b7756f72f82a6/input-preparation-v1/inputs.json, SHA256 b8040ef1c49af2455d9a28d26bac4ef4bbf297315c69c0b48256aa83f18b614b. Log /home/oufadmin/ouf-onboarding-inputs.Yqa2iXyE/operator.log. Scope consumato, nessun replay/reset. SQL0/migrazioni0/imports0/attivazioni0/budgetHUMAN0. NO_RECOGNIZED_MANAGER_LABEL non prova ownership; ammissione DB e lifecycle restano da provare.

## Nuovo lettore qualificato in CI

scripts/read-onboarding-finite-database-20261024.py al commit65b12ea71a01c9745976588352473cafd8463ba1, SHA256 97212fa426ac13ad353f67dc0dd9e8be903bf75d09b2203e2dddac84131dbca7. Sorgente pubblicata riletta uguale. CI40082658534/job120839219197:6PASS/zeroSkipped/10.361sec; PR40082662064/job120839228867/testedmerge834c46407f213533bd99b37a65097f7548f0000d:6PASS/zeroSkipped/13.377sec. Log diretti letti.

PostgreSQL17 reale, Dockerexec reale, due container reali/API1.44/PID/net+mountnamespace, query fissa completa, identità DB distinta da quella Ingestion, file privati0400/root0700, claim esclusivo e un solo tentativo SQL persistito prima del dispatch. Verificati rifiuto reale delle scritture, storico fixtureV33 e3tentativi/generazione4/PAUSED invariati, mancato riuso del claim anche dopo dispatch fallito. Fixture storiche di review/authority/prepared/input14GET e cinque altri IDcoorte sintetici: non sono prova del target né nuova autorità. Il primo test si fermava nel setup perché vedeva il server temporaneo Unix dell'immagine Postgres; ora la fixture attende il listener TCP finale. Nessun controllo di produzione indebolito. Warning checkoutNode20 forzato24 conservato.

La qualificazione riguarda componenti/query/trasporto nativi. Full bootstrap dell'installazione, attuale DB/storico/privilegi/ownership/migrazione non sono provati dalla CI. Questo lettore produce osservazioni, NON ammissione finale o autorità di modifica.

## Provenienza dell'identità e limiti

Il binding database viene esclusivamente dalla riga onboarding del databasePlan già legato al precedente owner Onboarding. La review storica21ca88f1c5aa682eb74612ead95c9bc6154ddf79a18a52af8f5d281e32abc605 e il journal11APPLIED/version29 devono corrispondere al piano e alla generazione Onboarding appena catturata, inclusi gli hash completi e il binding ordinato originale. Authority/decision/human sono letti come metadati storici: linkage hash, NON firme nuovamente verificate né consenso corrente. Nessuna entry o effetto vecchio viene richiamato.

Dal profilo Ingestion viene preso SOLO il trasporto nativo PostgreSQL già legato alla stessa generazione/Engine: eseguibileDocker, programmi/env vuoto/socket/porta. Identità, schema, SQL e profilo nuovi sono Onboarding; database/user/OID Ingestion non sono copiati o usati per la query. I valori OUF_ONB_DB_URL/USER o SPRING_DATASOURCE_URL/USERNAME correnti devono concordare col binding Onboarding. Opzioni JDBC ambigue/altro database/role/porta negati. Configurazioni esterne/JVM dichiarate rendono allCurrentConfigurationPrecedenceResolvedfalse: nessuna lettura nascosta dei loro contenuti e nessuna falsa risoluzione completa.

Nuovo scope fisso onboarding-database-snapshot-v1 sotto il pacchetto già predisposto. QuattroGET massimi, solo Onboarding/Postgres prima e dopo; un solo tentativo SQL/Dockerexec, query fissa in transazione REPEATABLE_READ/READ_ONLY con timeoutstatement5sec/lock1sec. Dockerexec avvia un processo finito per leggere: viene contato esplicitamente, non mascherato come zero operazioni. Nessuna modifica lifecycle/config/container, migrazione, attivazione, pubblicazione, budget, grant/login/IAM o ledger Registry. Ambiente client vuoto, psql-X/-w, PGPASSFILE=/dev/null, PGSERVICEFILE=/dev/null e nessun fallback a credenziali/config Docker.

La query raccoglie identità DB/OID/role/porta, versione17UTF8/capacità/transazioni preparate, schema/owner/privilegi/catalogo, Flywayhistory, review esatta source/version/config e lease attive. Le righe sono root-private, mai stampate. highestSqlVersion/V34AlreadyRecorded/contatori sono osservazioni target soltanto DOPO il vero JSONVPS; fixtureV33 non implica targetV33. databaseAdmissionProven e migrationAuthorized restanofalse. La migrazione propostaV34 dovrà essere confrontata con questo storico e l'intero candidato qualificato, con piano/closure/revisione firmata distinti. Non attivare migrazioni implicite aggirando validate-only.

## Comando operatore fissato

Una sola volta come oufadmin. Copia root esclusiva0700/file0400, checksum prima/dopo e log/exit conservati. Non richiedeAPPROVO, runtime authority o nuovo loginHUMAN perché non applica il delta.

```bash
(
  set -euo pipefail
  umask 077
  work=$(mktemp -d "$HOME/ouf-onboarding-database.XXXXXXXX")
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
      'repos/GioNob/ouf-deploy/contents/scripts/read-onboarding-finite-database-20261024.py?ref=65b12ea71a01c9745976588352473cafd8463ba1' \
      > "$work/read.py"
    printf '%s  %s\n' '97212fa426ac13ad353f67dc0dd9e8be903bf75d09b2203e2dddac84131dbca7' "$work/read.py" | sha256sum -c -
    sudo -- /bin/bash -c '
      set -euo pipefail
      umask 077
      root=/etc/ouf/deploy-snapshots/onboarding-finite-database-97212fa426ac13ad
      mkdir -m 0700 -- "$root"
      chown 0:0 -- "$root"
      install -o 0 -g 0 -m 0400 -- "$1" "$root/read.py"
      printf "%s  %s\n" 97212fa426ac13ad353f67dc0dd9e8be903bf75d09b2203e2dddac84131dbca7 "$root/read.py" | sha256sum -c -
      /usr/bin/python3 -I -B -S "$root/read.py"
    ' ouf-onboarding-database "$work/read.py"
  } 2>&1 | tee "$log"
)
```

Atteso ONBOARDING_DATABASE_SNAPSHOT_OBSERVED/complete:true, max4EngineGET/1SQLattempt. Incollare soltanto JSON pubblico, Exit e percorso log. Non stampare snapshot privati, profilo/SQLrows o EngineEnv. InSTOP conservare root helper/claim/log/risposte e non cancellare o rilanciare sotto altro tempdir. Contatori sono tentativi, non prova di completamento. Nessun replay automatico, nemmeno dopo fallimento prima del dispatch.

## Passo successivo

Dal vero risultato: ammissione DB e privilegi/storico candidati, risoluzione delle eventuali precedenze/configurazioni ancora incerte, controllo dell'autorità lifecycle corrente, piano V34 esplicito e closure/entry qualificata, quindi revisione firmata concreta dal terminale per il solo delta. Scope e journal completati restano intatti. Solo dopo deployment provato: decisioneHUMAN distinta sullo stesso source/version/hash per3tentativi aggiuntivi/900sec, quindi attivazione separata. Nessun reset di started_at,attempts,generation o dedup.

Registry originaleGET200 resta prova storica valida, worker normale indipendente senza restart/reinstall/reset;420/pub5 non congelati. Scope repair/GET/vecchi403/native11 consumati.8/8tecnico4/6funzionale/G3OPEN,F5/F6/E2E/acceptance aperti. Supervisor dopo E2E.
