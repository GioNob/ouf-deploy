# Emissione dell'accettazione B1 v2 — task-24, 13 novembre 2026

Il controller `scripts/issue-semantic-provider-b1-acceptance.py` costruisce il
manifest `ouf.semantic-provider-b1-artifact-acceptance.v2` con il builder di
task-23. Firma soltanto i byte approvati nel piano, usando la chiave installer
esistente e il mandato `ARTIFACT_ACCEPTANCE` della policy B1/B2 di task-14.
Le due librerie preesistenti restano invariate. Nessuna operazione Docker,
avvio, lease, upload, provisioning o modifica della configurazione v5.

## Contratto e custodia

Esecuzione root:root, `umask 077`, Python isolato senza bytecode (`-I -B`).
Tutti i path/hash CLI sono obbligatori, senza valori reali impliciti nel codice.
Ogni lettura richiede file regolare root:root, nlink 1, nessun symlink, file e
antenati non scrivibili da gruppo/altri. Il lettore confronta metadati del
descriptor e del path prima/dopo la lettura e verifica gli hash; riosserva gli
input prima della firma e dopo la verifica immediata. Policy e chiave usano
anche la custodia 0600 richiesta dalle primitive di autenticazione.
Gli eseguibili sono vincolati per path, hash e versione OpenSSL.

`--plan` legge soltanto input pubblici sotto custodia. Non apre né osserva i
metadati del path della chiave privata e non scrive file. Esegue solo
`openssl version`, con output in memoria. `manifestRaw` nella risposta JSON è
la stringa integrale dei byte ASCII canonici, incluso l'unico LF finale;
`payloadSha256` è il loro hash. Il piano comprende tutti gli hash osservati,
i path finali e il mandato con keyRef, issuerRef e finestra. `planSha256` è
SHA256 del piano JSON canonico (senza i campi esterni `status` e `planSha256`).
Non include un tempo generato dal programma. `issuedAt` e `generation` sono
interi CLI espliciti. Le lacune devono arrivare già ordinate e uniche.
I path delle chiavi dichiarate nel profilo di autorità vengono esclusi dalle
letture pubbliche: neppure una ricetta o un'evidenza può referenziare una di
quelle chiavi per indurre una sua lettura nel plan.

`--apply --plan-sha256` ricostruisce il piano dagli input. Se il digest cambia,
restituisce `HELD`, senza leggere chiavi e senza scritture. Dopo il confronto
crea esclusivamente una nuova directory 0700: `mkdir` è la primitiva atomica
per l'esclusività delle directory; `O_CREAT|O_EXCL|O_NOFOLLOW` protegge i file
0600, ciascuno seguito da fsync. Un output già esistente viene rifiutato.

Il nuovo `tools/semantic_b1b2_authority/signer.py` verifica hash/custodia della
chiave installer, deriva il public DER con `openssl pkey -pubout -outform DER`
e lo confronta con il mandato. Firma un frame pubblico temporaneo 0600 con
`pkeyutl -sign -rawin`. Nessuna copia della chiave, nessuna chiave nei report o
nei log. Rilegge l'hash della chiave dopo la firma e la policy dopo la verifica.
I soli temporanei creati dal firmatario sono il frame pubblico e la sua
directory; il verificatore immutato di task-14 usa i propri temporanei pubblici.

D-024 punto 2: `privateKeysRead: 1` conta **una chiave privata distinta**, la
installer. Sono ammesse le due letture per hash prima/dopo e le due aperture
del path da OpenSSL per derivazione pubblica e firma. Non vengono emesse
altre firme. Il dominio è `OUF-SEMANTIC-PROVIDER-B1B2-EVIDENCE\0V1\0`, envelope
`ouf.semantic-provider-b1b2-detached-signature.v1`, ruolo `ARTIFACT_ACCEPTANCE`.
La firma non verifica nel dominio dell'envelope deployment preesistente.

La firma è verificata immediatamente, anche tramite `verify_acceptance` con
aspettative provenienti dagli input verificati. Dopo la pubblicazione il
controller rilegge manifest e firma, controlla i rispettivi hash e chiama di
nuovo `verify_acceptance`. Pubblica infine `result.json` con schema
`ouf.semantic-provider-b1-acceptance-issuance.v1`, stato
`SEMANTIC_PROVIDER_B1_ACCEPTANCE_ISSUED`, binding di manifest/firma,
`payloadSha256`, `privateKeysRead: 1`, `signaturesIssued: 1`,
`startAuthorized: false`, `leaseAuthorized: false`.

Gli errori precedenti alla creazione dell'output danno `HELD`; quelli successivi
danno `PARTIAL`, con fase, contatori, file completati e osservazione dei file
conservati, anche se una scrittura è fallita prima di completarsi. Dopo l'invio
del comando di firma, un errore che impedisca di determinarne l'esito lascia
`signaturesIssued: null` e `signingAttempted: true`. Non equivale a zero firme.
Non c'è rollback, pulizia dei parziali o ritentativo automatico: serve una
riconciliazione umana prima di una successiva emissione.

## Provenienza dei campi

| Campo | Fonte verificata |
| --- | --- |
| schema | Costante v2 della libreria acceptance |
| installationRef | P, confrontato con la policy B1/B2 e il profilo di autorità |
| entityRef | Policy B1/B2, confrontata con P e il profilo di autorità |
| issuerRef della firma | Unico mandato ACTIVE ARTIFACT_ACCEPTANCE con issuedAt nella finestra; confronto con intentIssuerRef/approvalIssuerRef e keyRefs.installer del profilo di autorità |
| profile | Path/hash CLI di P; P.paths.authorityProfile deve coincidere col path CLI dell'autorità |
| preparationA | root/plan CLI A2; result e manifest devono concordare come in receipt_a di P; i due documenti semantic-peer/successors sono verificati con i pin filesCreated; tutti e quattro sono inoltre confrontati con preparationA delle ricette |
| creation.evidence | PREPARATION_A2 |
| creation.roles | Transazioni CLI, confrontate con rows/transactions di A2 |
| creation.recreation | Binding CLI della ricevuta; schema/stato, newCid/newTransaction devono corrispondere al southbound A2 |
| creation.declaredGaps | CLI ordinata/unica, grammatica di acceptance v2; valori decisi da D-024 sotto |
| roles.containerId/imageId | A2, confrontati con rootfs result; CID/transazioni confrontati anche con recipes result |
| roles.recipe | Quattro binding per ruolo da recipes result; ogni file è riletto e verificato |
| roles.rootfs | Tre binding e effectiveSeal da rootfs result; ogni file referenziato è riletto e verificato; aSuccessors deve coincidere col binding A2 |
| softwareClosure | Commit CLI e hash dei tre file letti nella directory consegnata dal launcher, con i loro path relativi |
| trustPolicy | Binding CLI della policy B1/B2; authorityProfile e basePolicy devono coincidere coi binding dell'autorità |
| generation / issuedAt | CLI, senza tempo implicito; issuedAt >= 0, nella finestra del mandato, massimo 300 secondi nel futuro rispetto all'orologio |
| startAuthorized / leaseAuthorized | Sempre false |

A2 conserva nomi, CID, immagini e transazioni, non gli endpoint Docker. Il
controller usa i nomi dei ruoli conservati in P per selezionare le righe A2,
verificando anche che la SNI del certificato A2 sia un alias del solo ruolo
southbound in P. È la classificazione per alias della preparazione di P,
riconciliata con le informazioni effettivamente conservate. Non deduce i ruoli
dall'ordine delle righe o dai CID degli esempi. Non ispeziona container live.

D-024 punto 1 chiude la closure **esattamente** su:

- `tools/semantic_runtime_v5/semantic_provider_docker_runtime_v5.py`
- `tools/semantic_runtime_v5/arming_verifier.py`
- `tools/semantic_b1b2_authority/authority.py`

Ogni altro insieme, inclusi duplicati, produce `HELD` con
`ACCEPTANCE_CLOSURE_SET_UNEXPECTED`. Il launcher scarica questi file dallo
stesso commit fissato del controller e del firmatario e richiede che quel
commit coincida con `--closure-source-commit`. Offline, il controller prova i
byte/hash consegnati; la provenienza Git è garantita dalla consegna fissata,
non da una chiamata Git o da una consultazione remota del controller.

D-024 punto 3 decide queste sole lacune, entrambe per l'adapter:

- `ADAPTER_CREATION_PLAN_DIGEST_RECONSTRUCTED`
- `ADAPTER_CREATION_RECEIPT_NOT_RETAINED`

Nessuna lacuna per il southbound. Il controller valida sintassi, ordine e
unicità, senza trasformare questi due codici in default o in una nuova policy.

## Plan, revisione umana, apply

Questi sono comandi da eseguire dall'operatore sul VPS dopo review e consegna.
Non sono stati eseguiti nell'implementazione del task. I tre segnaposto del
launcher vanno fissati dal reviewer dopo il commit D-001; gli altri sei hash
sono dei byte Git di HEAD `8067207958013b59ff63383435fdd628c4a563b9`.
La stessa authority.py è sia libreria sia terzo file della closure: si scarica
una sola volta. Il pin Python3.13 è riusato dai launcher B1 precedenti e va
verificato sul target; non è una nuova osservazione del binario VPS.

In una sola sessione Bash, con il launcher già revisionato e fissato:

```bash
set -euo pipefail
umask 077
source_commit='__PIN_COMMIT__'  # stesso commit immutabile fissato nel launcher
controller_sha='__PIN_CONTROLLER_SHA256__'
signer_sha='__PIN_SIGNER_SHA256__'
[[ "$source_commit" =~ ^[0-9a-f]{40}$ ]]

# Fissa l'epoch UNA VOLTA; conservalo per plan e apply. Non rigenerarlo dopo
# la review. Verificare umanamente la finestra del mandato prima dell'emissione.
issued_at=$(date -u +%s)
printf 'issuedAt fissato: %s\n' "$issued_at"

rootfs_result='/var/lib/ouf-storage-migration/semantic-provider-b1-rootfs-20261113-a2/result.json'
recipes_result='/etc/ouf/deploy-snapshots/semantic-provider-b1-recipes-20261113-v1/result.json'
rootfs_sha=$(sudo sha256sum -- "$rootfs_result" | cut -d ' ' -f 1)
recipes_sha=$(sudo sha256sum -- "$recipes_result" | cut -d ' ' -f 1)
printf 'rootfs-result sha256: %s\nrecipes-result sha256: %s\n' "$rootfs_sha" "$recipes_sha"
# L'umano fornisce/conferma questi due hash; il controller li richiederà
# invariati. Non si inventano gli hash dei result dai prefissi dei loro piani.

openssl_path=$(readlink -e /usr/bin/openssl)
openssl_sha=$(sudo sha256sum -- "$openssl_path" | cut -d ' ' -f 1)
openssl_version=$("$openssl_path" version | awk '{print $2}')

# Pin espliciti noti degli altri tre file A2, oltre a successors e plan CLI.
printf '%s  %s\n' \
  817e178b8615766569a4278a3288a4774fc940217667eeeb79b97fa09440f777 /var/lib/ouf-storage-migration/semantic-provider-preparation-a2-20261113/manifest.json \
  c7cfa4e9e1f93451527fda22027af1d30b6f525eab083066208a315e15ac69ae /var/lib/ouf-storage-migration/semantic-provider-preparation-a2-20261113/result.json \
  192baba5a5a96ec92c9ed7740511bfb457475445681378f4ff0c0a9976607221 /var/lib/ouf-storage-migration/semantic-provider-preparation-a2-20261113/semantic-peer.json \
  | sudo sha256sum --check --status

# Il path reale dell'autorità si legge da P; non è dedotto dal nome directory.
authority_profile=$(sudo /usr/bin/python3.13 -I -B -c '
import hashlib, json
p="/etc/ouf/installations/ouf-lab-netcup-01/semantic-provider.json"
raw=open(p,"rb").read()
assert hashlib.sha256(raw).hexdigest()=="5d8500161bfc5f57d7ed94a93868e3fba5e26bfcde781ee1d38354b04dbee76d"
print(json.loads(raw)["paths"]["authorityProfile"])
')

common=(
  --installation-profile /etc/ouf/installations/ouf-lab-netcup-01/semantic-provider.json
  --installation-profile-sha256 5d8500161bfc5f57d7ed94a93868e3fba5e26bfcde781ee1d38354b04dbee76d
  --trust-policy /etc/ouf/deploy-snapshots/semantic-provider-b1b2-trust-policy-20261112/trust-policy.json
  --trust-policy-sha256 6ef247ee727484777557cdb5adb05428e6d020da1e2e49773a84eedc56be4f95
  --authority-profile "$authority_profile"
  --authority-profile-sha256 7fb7880d58e43ab40f9f53dac07a5dbad462d12e3a96f3b1287c6763b1d7ce18
  --a2-root /var/lib/ouf-storage-migration/semantic-provider-preparation-a2-20261113
  --a2-plan-sha256 a435f29bd107fbb61d4f5d3ca594e42d2851a82beadeafb1aef13bcbe997cad2
  --a2-successors-sha256 394562b4162e8d1b615a6b61897446c8316b37e7a438fa99b389dbb5f119dfdb
  --recreation-receipt /etc/ouf/deploy-snapshots/southbound-recreate-20261113-d022-v1/result.json
  --recreation-receipt-sha256 56528cb24df9ce1d48f18ee67ac8105d308db8ee1602dd604a9573b08b22b79c
  --rootfs-result "$rootfs_result" --rootfs-result-sha256 "$rootfs_sha"
  --recipes-result "$recipes_result" --recipes-result-sha256 "$recipes_sha"
  --adapter-transaction 7ff12b95c3f70c5eaebb1d0a12ab931d
  --southbound-transaction 864a28dbbd5ccc402f9406e500359123
  --declared-gap ADAPTER_CREATION_PLAN_DIGEST_RECONSTRUCTED
  --declared-gap ADAPTER_CREATION_RECEIPT_NOT_RETAINED
  --generation 1 --issued-at "$issued_at"
  --closure-source-commit "$source_commit"
  --closure-file tools/semantic_runtime_v5/semantic_provider_docker_runtime_v5.py=572912ece0af4d84a8bc1e473df3fd6ac8f7fd7a61b11d3f86202dab3d898255
  --closure-file tools/semantic_runtime_v5/arming_verifier.py=c3c0dc68ec390ffa1e27b5a838ecfa623310a0de7a206564744917b527bd3338
  --closure-file tools/semantic_b1b2_authority/authority.py=04510e275622cde812da86599e5a191a0f7575650b32aa3208d1b6d47768c728
  --openssl "$openssl_path" --openssl-sha256 "$openssl_sha" --openssl-version "$openssl_version"
  --output-root /etc/ouf/deploy-snapshots
  --output-name semantic-provider-b1-acceptance-20261113-v1
)
```

La lettura del path dell'autorità nel comando verifica il pin di P; il controller esegue
comunque tutti i controlli di custodia e confronta quel path con P. Nessun
path di chiave viene passato alla CLI o letto da questi comandi preparatori.

```bash
plan_log=$(bash scripts/deliver-semantic-provider-b1-acceptance-issuance.sh --plan "${common[@]}")
printf '%s\n' "$plan_log"
delivery=$(printf '%s\n' "$plan_log" | sed -n 's/^OUF_B1_ACCEPTANCE_DELIVERY=//p')
plan_json=$(printf '%s\n' "$plan_log" | sed -n '/^{/p')
plan_sha=$(printf '%s\n' "$plan_json" | /usr/bin/python3.13 -I -B -c 'import json,sys; print(json.load(sys.stdin)["planSha256"])')
printf '%s\n' "$plan_json" | /usr/bin/python3.13 -I -B -c 'import json,sys; sys.stdout.write(json.load(sys.stdin)["manifestRaw"])'
```

**Fermarsi qui per la review umana dei byte completi**, delle lacune, dei pin,
del mandato e dell'epoch conservato. Conservare `plan_log`, `plan_json`,
`plan_sha`, `delivery` e l'array `common` per la successiva esecuzione. Il
launcher crea una directory di consegna nuova a ogni invocazione: **apply
deve usare la stessa consegna del plan**, perché il piano lega anche i path
assoluti degli input software osservati. Non rilanciare il downloader per
applicare un digest costruito in una directory diversa.

Dopo l'approvazione dei byte, nello stesso ambiente Bash:

```bash
# Riautenticare il codice della consegna conservata prima di eseguirlo.
printf '%s  %s\n' \
  "$controller_sha" "$delivery/scripts/issue-semantic-provider-b1-acceptance.py" \
  "$signer_sha" "$delivery/tools/semantic_b1b2_authority/signer.py" \
  b1cddc8e0de31b27e96120f5a55079f238ac683eddd31eb602d23a80a8f6880d "$delivery/tools/semantic_b1_acceptance/__init__.py" \
  5179cf466af5e823a75caf68d3e3f772c3e3cc44d5f57f875e848ba02cd25708 "$delivery/tools/semantic_b1_acceptance/acceptance.py" \
  19342edb368bf1c6bf439c615fc2c2452c16a1742f858311a2d65fe9d752a8a7 "$delivery/tools/semantic_b1b2_authority/__init__.py" \
  04510e275622cde812da86599e5a191a0f7575650b32aa3208d1b6d47768c728 "$delivery/tools/semantic_b1b2_authority/authority.py" \
  572912ece0af4d84a8bc1e473df3fd6ac8f7fd7a61b11d3f86202dab3d898255 "$delivery/tools/semantic_runtime_v5/semantic_provider_docker_runtime_v5.py" \
  c3c0dc68ec390ffa1e27b5a838ecfa623310a0de7a206564744917b527bd3338 "$delivery/tools/semantic_runtime_v5/arming_verifier.py" \
  889c603f0d17cb54060951bcf4c4f9b8c9ebd9e52b392c70209bbb9755d797d9 /usr/bin/python3.13 \
  | sudo sha256sum --check --status
sudo /usr/bin/python3.13 -I -B "$delivery/scripts/issue-semantic-provider-b1-acceptance.py" \
  --apply --plan-sha256 "$plan_sha" "${common[@]}"
```

I file pubblicati sono `manifest.json`,
`<payloadSha256>.ARTIFACT_ACCEPTANCE.json`, `result.json` nella nuova directory.
La futura configurazione B1 v5 potrà referenziarne i binding verificati:
questo task non la modifica e non attesta readiness o accettazione operativa.

## Validazione e limite temporale

Il workflow PR dedicato esegue con sudo nativo su Ubuntu, root:root e OpenSSL
reale, generando esclusivamente chiavi Ed25519 e policy di fixture. La variabile
`OUF_B1_ISSUANCE_NATIVE=1` impedisce di mascherare prerequisiti mancanti con skip.
I test portabili coprono piano, pin, lacune, transazioni e closure; quelli nativi
coprono firma/readback, custodia, mancato accesso alla chiave nel plan, drift,
output preesistente, separazione di dominio, CLI e report dei parziali.
La verifica locale su Windows/Python 3.12 ha superato 10 test (inclusa firma e
verifica con OpenSSL reale, con sola custodia POSIX adattata); i 10 test nativi
sono esclusi in quell'ambiente. Non è un risultato CI né una prova POSIX.

```bash
sudo -n env OUF_B1_ISSUANCE_NATIVE=1 /usr/bin/python3 -I -B \
  -m unittest discover -s tests -p test_semantic_provider_b1_acceptance_issuance.py -v
bash -n scripts/deliver-semantic-provider-b1-acceptance-issuance.sh
```

D-018 punto 3: il verificatore valuta il mandato ACTIVE rispetto all'orologio
**al momento della verifica**, anche dopo la firma. Dopo la scadenza del mandato
la verifica fallisce, pur con gli stessi byte e la stessa firma. `issuedAt`
nella finestra non estende il mandato e non consente verifica retrodatata.
Questo è un limite intenzionale del contratto corrente, non un rinnovo o una
promessa di validità archivistica illimitata.
