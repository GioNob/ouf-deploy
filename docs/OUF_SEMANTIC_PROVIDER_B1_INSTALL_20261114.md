# Controller B1: installazione inattiva e switch del wrapper

Task sprint-01/task-25, D-011, D-013, D-014, D-019, D-022, D-024.
Implementazione locale sul branch dedicato; nessuna installazione VPS attestata.

## Contratto

`scripts/install-semantic-provider-b1.py` compone un piano in memoria, autentica
l'accettazione B1 v2 e pubblica una nuova root privata soltanto in apply.
Lo switch usa **invariata** `switch_existing_wrapper`, con tutta la catena
di import consegnata dal launcher e verificata per hash prima dell'import.
Non usa `wrapper_bytes`, il renderer storico che seleziona il sorgente v4.

Sono obbligatori root:root, umask 077 e Python isolato senza bytecode.
Il launcher usa `sudo -n /usr/bin/python3.13 -I -B`. Nessun path o hash CLI
ha un valore implicito. Gli argomenti di osservazione P sono gli stessi di P;
`--revise-from-sha256`, se presente, deve coincidere con il pin del P corrente.
B1 non pubblica né revisiona P.

Prima di applicare serve il chiarimento richiesto sul requisito 3 del task:
il loader v5 reale richiede `armingRoot` già esistente, mentre la root B1
deve essere assente. Il codice proposto valida la sintassi in memoria prima
delle scritture, poi chiama il loader reale subito dopo la pubblicazione,
prima dello smoke e dello switch. Questa sequenza non equivale a sostenere
che il loader reale abbia verificato una directory ancora inesistente.

Il piano contiene tutti gli hash e le identità degli input, le prove del peer
Docker e gli ID delle reti di P, i frame dei successor, il wrapper precedente,
la configurazione v5 completa e i byte esatti del wrapper proposto: testo,
base64, lunghezza e SHA256. Include directory/file previsti e identità del lock
ottenuta da `custody(P.paths.guard.lock, 0o600)`.

Il controller non scrive in plan e non prende alcun flock. Sono ammessi solo
i temporanei pubblici privati dell'autenticatore, rimossi dalla verifica,
e gli effetti transitori dei figli di sola lettura già previsti da P (giro r2).
La consegna del launcher è un passo preliminare distinto: crea una directory
di sorgenti privata e conservata; il successivo controller plan non la modifica.

## Fonti e origine dei campi

| Campo o controllo | Origine |
| --- | --- |
| Profilo P | Ricalcolato da `observe_profile` di P sulla A CLI; byte identici al P fissato |
| Guard, lock, nft, peer, reti, runtime | Medesima composizione di osservazione P |
| CID, immagini, frame, transazioni | `successors.json` di A2, già legato al piano A2 |
| Stato successor | Inspect API 1.44 tramite P: created, PID 0, StartedAt zero, RestartCount 0 |
| Ricreazione | Binding path/hash da `successors.lineage.recreation` di A2 |
| Quattro file A2 | Hash di manifest, result, semantic-peer e successors ricalcolati |
| Accettazione | Manifest/firma CLI, `verify_acceptance`, mandato ACTIVE alla verifica |
| Issuer accettazione | `authority.authorities.approvalIssuerRef` di P |
| Scope e trust policy | P e policy B1/B2 fissata; binding di autorità e policy base identici |
| Generazione minima | 1, senza selezioni latest o nuovi mandati |
| Closure | Esattamente i tre file dell'accettazione, dal commit fissato sotto |
| schema, CONFIG_FIELDS | Contratto v5 invariato |
| runtimePath, runtimeSha256 | Configurazione v4 corrente; custodia/hash come in v5 |
| pythonPath, pythonSha256 | Configurazione v4 corrente; custodia/hash come in v5 |
| driverPath, driverSha256 | Configurazione v4 corrente; file root:root 0600 e hash |
| admissionPath, admissionSha256 | Configurazione v4 corrente; file root:root 0600 e hash |
| registryRoot, runtimeStateRoot | Copia dalla configurazione v4 corrente |
| sourceHash | SHA256 del runtime v5 nella closure accettata |
| acceptance | Binding path/hash CLI del manifest firmato |
| b1b2TrustPolicy | Binding path/hash CLI della policy separata |
| armingRoot | `<root>/arming`, directory 0700 vuota |
| armingVerifierPath, armingVerifierSha256 | Copia installata del verifier della closure |
| b1b2AuthorityModule | Binding della copia installata di authority.py della closure |
| opensslBinding | Path, hash e versione espliciti CLI |
| armingIssuerRef | Riferimento esplicito CLI per la futura verifica B2 |
| candidates | Solo i due CID A2, phase INACTIVE, bundleParents dalla CLI |

La closure è scaricata dal commit
`1cd6ea7c9c1da35a745cfd2c0d3755d99dfc7efd`, separatamente dal commit
del controller. Gli hash completi sono nel launcher e nel controller:

- `tools/semantic_runtime_v5/semantic_provider_docker_runtime_v5.py`
- `tools/semantic_runtime_v5/arming_verifier.py`
- `tools/semantic_b1b2_authority/authority.py`

Gli altri sorgenti sono fissati ai blob Git della base locale
`e111c5cb5a8a1db114fe955a4f77596d954e7c99`, con l'eccezione del P estratto:
il launcher B1 ne fissa i nuovi byte LF. Il launcher autonomo di P non viene
modificato; Claude dovrà rifissarlo dopo la review dell'estrazione.
I due segnaposto del launcher B1 sono intenzionali fino al commit D-001:
`__PIN_COMMIT__` e `__PIN_CONTROLLER_SHA256__`.

## Apply e checkpoint

1. Ricalcola il piano da input e osservazioni freschi; un digest diverso
   produce HELD senza creare la root B1.
2. Crea la root assente tramite mkdir esclusivo, directory 0700 e file 0600.
   Pubblica solo i tre sorgenti, configurazione, arming vuota e directory switch.
   Usa O_EXCL/nofollow, fsync dei file e delle directory, custodia e rilettura.
3. Valida con `load_configuration` reale e verifica tutti i file della v5.
   Esegue lo smoke `--version` attraverso il sorgente installato con ambiente
   minimo e timeout. Un fallimento conserva il parziale e non chiama lo switch.
4. Chiama la primitiva con wrapper/hash/byte proposti, `<root>/switch`, lock
   e sua identità del piano. Il callback usa il descriptor già detenuto:
   non prende un secondo flock. A BEFORE_CLAIM, BEFORE_RENAME e AFTER_RENAME
   riosserva P/A, frame, firma e mandato, closure, pubblicazione e arming vuota.
5. Dopo rename ammette soltanto i byte/config v5 proposti; tutti gli altri
   input e le loro identità restano fissati. Rilegge anche sorgente/config v4
   conservati, che P dopo lo switch non visita più. Il profilo P resta identico.
6. Rilegge il wrapper, esegue `--version` tramite il wrapper e riosserva tutto.
   Pubblica `result.json`, schema `ouf.semantic-provider-b1-installation.v1`,
   stato `SEMANTIC_PROVIDER_B1_INSTALLED_INACTIVE`.

La ricevuta contiene digest del piano, root, wrapper prima/dopo, hash della v5,
payload accettato, CID e risultato della primitiva. I contatori restano zero
per operazioni lifecycle, richieste Docker start, scritture nft, chiavi e firme;
`daemonRestarted`, `startAuthorized` e `leaseAuthorized` sono false.
Questi risultati descrivono l'invocazione, non readiness, TLS o E2E.

## Sequenza per l'operatore

Comandi da eseguire umanamente sul target dopo review, chiarimento del
requisito 3 e CI. Non sono stati eseguiti durante questo task.
I pin forniti dal mandato non sono nuove osservazioni del VPS.

Usare la medesima consegna per plan e apply: una nuova directory del launcher
cambia i path/hash del piano. Conservare report, digest e directory consegnata.

In Bash impostare i pin noti e i due input della precedente invocazione P
che P non conserva nel proprio profilo. Non ricostruirli da nomi presunti:

```bash
set -euo pipefail
umask 077
snap=/etc/ouf/deploy-snapshots
inst=/etc/ouf/installations
p="$inst/ouf-lab-netcup-01/semantic-provider.json"
p_sha=5d8500161bfc5f57d7ed94a93868e3fba5e26bfcde781ee1d38354b04dbee76d
a2=/var/lib/ouf-storage-migration/semantic-provider-preparation-a2-20261113
a2_sha=a435f29bd107fbb61d4f5d3ca594e42d2851a82beadeafb1aef13bcbe997cad2
trust="$snap/semantic-provider-b1b2-trust-policy-20261112/trust-policy.json"
trust_sha=6ef247ee727484777557cdb5adb05428e6d020da1e2e49773a84eedc56be4f95
accepted="$snap/semantic-provider-b1-acceptance-20261113-v1"
payload_sha=74b860dd0f4d8b5c609fd5e688bc89772ef6d6ef29e6548574bfb2c031976753
signature_sha=8da24a058748be9b9d4eef84e49a8c5ed47ebe000d53bf3a181e3051d0d7530e
openssl_sha=acc10176d038aeb7b2a77d9ec972ac2985857a7191f7aecb7c54ef0e2c7e9549
: "${GENERATION_RECEIPT:?path esatto della precedente invocazione P}"
: "${GENERATION_RECEIPT_SHA256:?hash approvato della stessa ricevuta}"
```

Estrarre i valori stabili dal P fissato e dalla policy fissata. Il codice
seguente legge solo i due documenti pubblici e produce argomenti NUL separati;
non legge né stampa `keyPaths` e non usa eval:

```bash
mapfile -d '' -t p_args < <(
  sudo -n /usr/bin/python3.13 -I -B - "$p" "$p_sha" "$trust" "$trust_sha" <<'PY'
import hashlib, json, pathlib, sys
def pinned(path, expected):
    raw = pathlib.Path(path).read_bytes()
    assert hashlib.sha256(raw).hexdigest() == expected
    return json.loads(raw)
p = pinned(sys.argv[1], sys.argv[2])
t = pinned(sys.argv[3], sys.argv[4])
paths = p['paths']
guard = paths['guard']
owner = p['dockerSocketOwnership']
assert paths['authorityProfile'] == t['authorityProfile']['path']
assert paths['trustPolicy'] == t['basePolicy']['path']
values = {
    'installation-ref': p['installationRef'],
    'installation-root': str(pathlib.Path(sys.argv[1]).parents[1]),
    'guard-pointer': guard['pointer'],
    'guard-service-unit': p['guardServiceUnit'],
    'guard-service-file': guard['unitFiles']['guardService'],
    'docker-drop-in-file': guard['unitFiles']['dockerDropIn'],
    'docker-socket': paths['dockerSocket'],
    'docker-socket-activation': p['dockerSocketActivation'],
    'docker-socket-unit': p['dockerSocketUnit'],
    'docker-service-unit': p['dockerServiceUnit'],
    'docker-socket-owner': owner['owner'],
    'docker-socket-group': owner['group'],
    'docker-socket-mode': owner['mode'],
    'dockerd': p['dockerdExecutable']['path'],
    'authority-profile': t['authorityProfile']['path'],
    'authority-sha256': t['authorityProfile']['sha256'],
    'trust-policy': t['basePolicy']['path'],
    'trust-policy-sha256': t['basePolicy']['sha256'],
}
for name, value in values.items():
    sys.stdout.write('--' + name + '\0' + value + '\0')
PY
)
(( ${#p_args[@]} == 36 ))
common=(
  "${p_args[@]}"
  --a-root "$a2"
  --a-plan-sha256 "$a2_sha"
  --generation-receipt "$GENERATION_RECEIPT"
  --generation-receipt-sha256 "$GENERATION_RECEIPT_SHA256"
  --p-profile-sha256 "$p_sha"
  --acceptance-manifest "$accepted/manifest.json"
  --acceptance-manifest-sha256 "$payload_sha"
  --acceptance-signature "$accepted/$payload_sha.ARTIFACT_ACCEPTANCE.json"
  --acceptance-signature-sha256 "$signature_sha"
  --b1b2-trust-policy "$trust"
  --b1b2-trust-policy-sha256 "$trust_sha"
  --openssl /usr/bin/openssl
  --openssl-sha256 "$openssl_sha"
  --openssl-version 3.5.7
  --arming-issuer-ref ouf-lab-infrastructure-installer
  --bundle-parent /run/docker/containerd/daemon/io.containerd.runtime.v2.task/moby
  --output-root "$snap"
  --output-name semantic-provider-b1-install-20261114-v1
)
```

Il bundle-parent è quello indicato nel task: va confrontato col layout Docker
effettivo durante la review; B1 non crea né esporta bundle. Tutti i flag sono
espliciti. L'array non include la vecchia modalità di revisione di P.

Con il launcher già fissato da Claude dopo il commit:

```bash
plan_output=$(bash scripts/deliver-semantic-provider-b1-install.sh \
  --plan "${common[@]}")
printf '%s\n' "$plan_output"
delivery=$(printf '%s\n' "$plan_output" | sed -n 's/^OUF_B1_INSTALL_DELIVERY=//p')
plan_json=$(printf '%s\n' "$plan_output" | sed -n '/^{/p')
read_plan='import json,sys; p=json.load(sys.stdin); '
read_plan+='assert p["status"]=="PLAN_READY"; print(p["planSha256"])'
plan_sha=$(printf '%s\n' "$plan_json" | /usr/bin/python3.13 -I -B -c "$read_plan")
```

Revisionare il testo completo del wrapper, base64/hash, ogni input, la
configurazione inattiva e il digest. Dopo la review umana conservare gli
stessi argomenti ed eseguire sulla stessa consegna, senza rilanciare il launcher:

```bash
sudo -n /usr/bin/python3.13 -I -B \
  "$delivery/scripts/install-semantic-provider-b1.py" \
  --apply --plan-sha256 "$plan_sha" "${common[@]}"
```

## Cosa resta a B2 e annullamento

B1 non emette firme, non apre chiavi private, non alloca journal di ammissione,
non concede lease e non esegue create/start, restart Docker o scritture nft.
La v5 rifiuta create e start fino all'armatura e allo staging B2 richiesti dal
suo contratto. Un smoke `--version` delega soltanto a runc e non autorizza start.

L'annullamento è fuori perimetro. La primitiva conserva claim irreversibile,
`switch/prior-runtime-wrapper.sh`, receipt oppure denial e, in alcuni errori,
il file di staging adiacente al wrapper. Nessun rollback o cleanup automatico.
Il report propaga `switchOutcome` (UNCHANGED, REPLACED, UNPROVEN) e
`doNotRerunApply`. Dopo il claim l'apply non va rilanciato; anche una root
parziale senza claim viene conservata e richiede riconciliazione umana.

## Verifica e limiti

Il workflow nuovo esegue con sudo nativo la fixture B1, i test P esistenti e
la primitiva di switch invariata. La fixture usa file root, flock, CAS, fsync,
firme Ed25519 reali su chiavi effimere e processi v5 reali. Docker, peer,
systemd, reti e nft sono confini di lettura sintetici nella fixture B1;
la composizione `observe_profile`, `receipt_a`, `read_roles` e `runtime` di P
restano reali. Non è una prova Docker, kernel nft o VPS.

Il positivo invoca la CLI plan/apply, ricalcola P prima/dopo lo switch e prova
che create/start sono negati dalla v5 senza armatura, senza journal o task nuovi.
I negativi coprono drift P, firma/mandato, closure/wrapper, digest, smoke
fallito e callback BEFORE_RENAME con wrapper invariato e diagnosi UNCHANGED.
La fixture controlla che il plan lasci input/output e temporanei invariati;
non vieta i temporanei transitori dell'autenticatore ammessi dal giro r2.

Verifica locale Windows: 6 test di contratto passati; 11 test nativi non eseguiti
(skip esplicito). Parsing/compilazione Python e `bash -n` passati.
WSL restituisce E_ACCESSDENIED. CI Linux e regressione P native restano da
acquisire dopo la pubblicazione a cura di Claude; nessun PASS CI è attestato.
La suite P locale si ferma all'import di `grp`, assente in Python Windows.
