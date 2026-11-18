# OUF Semantic Provider R3 v16 — configurazione dell’adapter

D-053.1 e D-053.2 collegano l’allowlist dichiarata dall’owner ai byte del file montato, alle ricette B1 v4 e all’acceptance g7. La sequenza conserva i CID, le transazioni A2 e l’evidenza rootfs D-042. Il coordinatore g2 fornisce il flow SPARQL e il profilo d’installazione autorizza i namespace.

## Sequenza VPS

Eseguire dalla consegna approvata dal reviewer, dopo aver compilato il pin `C` dei tre runbook. Usare i pin dell’R3 installato e autenticato (v15 per l’avanzamento a v16). Il file di partenza è `/etc/ouf/deploy-snapshots/semantic-provider-v2-inputs-XE7IwlGm/adapter.json`, bind read-only su `/run/ouf-semantic-provider/adapter.json`, UID/GID `10006:10006` e modo `0600`. L’hash di partenza va ricavato dalla voce `adapter.json` della ricetta B1 v3 autenticata e verificato sul file in custodia.

1. Portare il cohort nello stato fermo e il lease in `QUIESCED`, con `startAuthorized` e `leaseAuthorized` a `false`. Tenere fermi entrambi i provider per tutta la sequenza. I controlli osservano le epoche terminali o assenti, l’head `OPERATE` e il suo legame alla configurazione installata, i restart a `no`, l’inventario Docker e i mount del file e delle directory antenate. La pubblicazione usa i lock dei CID in ordine lessicografico, poi quello della guardia, poi quello dell’issuer.
2. Approvare la lista completa dei prefissi e l’`endpointRef` del flow nel coordinatore g2. Nel profilo viene aggiunto solo `providerNamespaces`, con un elemento `{endpointRef, namespacePrefixes}` per il provider dell’adapter. Ripetere `--namespace-prefix` per ciascun prefisso, nello stesso ordine in plan e apply. Sono ammessi URI HTTP o HTTPS terminanti in `/` o `#`, senza query né userinfo. Il profilo di partenza è quello autenticato da g6.

   ```bash
   namespace_args=(
     --revise-from-sha256 "$PROFILE_OLD"
     --namespace-endpoint-ref "$PROVIDER_ENDPOINT_REF"
   )
   for prefix in "${APPROVED_PREFIXES[@]}"; do
     namespace_args+=(--namespace-prefix "$prefix")
   done
   bash ops/vps/config-publish.sh profile plan "${namespace_args[@]}"
   bash ops/vps/config-publish.sh profile apply --plan-sha256 "$PROFILE_PLAN" "${namespace_args[@]}"
   ```

   Usare lo SHA-256 `profileSha256` della revisione applicata come `PROFILE_NEW`.
3. Pianificare e pubblicare `adapter.json`. I pin R3 provengono dalla ricevuta dell’installazione attiva e dall’head autenticato. Per `RUNTIME_SHA` usare il digest del sorgente runtime emesso nella versione installata. La ricevuta conserva il delta, il puntatore al profilo e i digest prima/dopo. Il plan rifiuta byte non canonici e il rigeneratore ripristina programmaticamente il solo campo modificato per provare l’identità con l’originale.

   ```bash
   r3_args=(
     --r3-version "$INSTALLED_VERSION"
     --r3-wrapper-sha256 "$WRAPPER_SHA"
     --r3-runtime-sha256 "$RUNTIME_SHA"
     --r3-configuration-sha256 "$RUNTIME_CONFIG_SHA"
     --r3-head-sha256 "$OPERATE_HEAD_SHA"
   )
   config_args=(--old-sha256 "$ADAPTER_OLD" --profile-sha256 "$PROFILE_NEW" "${r3_args[@]}")
   bash ops/vps/config-publish.sh plan adapter.json "${config_args[@]}"
   bash ops/vps/config-publish.sh apply adapter.json --plan-sha256 "$CONFIG_PLAN" "${config_args[@]}"
   ```

   `CONFIG_RESULT` è lo SHA-256 del file `/etc/ouf/deploy-snapshots/semantic-provider-config-d053-adapter/result.json`, incluso il LF. Applicazione e ripristino usano un file di staging nella directory del mount, `fsync`, rename atomico, `fsync` della directory e rilettura sotto lock. Il claim conserva l’originale e il piano.
4. Preparare B1 v4 con lo SHA-256 di `semantic-provider-b1-recipes-20261118-v3/result.json` come `B1_V3`. La preparazione rilegge la pubblicazione e D-052, ricompila le policy e verifica il frame e l’evidenza rootfs per entrambi i ruoli. Il nuovo risultato è in `/etc/ouf/deploy-snapshots/semantic-provider-b1-recipes-v4/result.json`. Usare il digest dei byte del risultato come `B1_V4`.

   ```bash
   b1_args=(--previous-recipes-sha256 "$B1_V3" --publication-sha256 "$CONFIG_RESULT"
            --profile-sha256 "$PROFILE_NEW" "${r3_args[@]}")
   bash ops/vps/b1-recipes-v4.sh plan "${b1_args[@]}"
   bash ops/vps/b1-recipes-v4.sh apply --plan-sha256 "$B1_PLAN" "${b1_args[@]}"
   ```

5. Emettere l’acceptance g7 con lo stesso D-042 di g6 e con `PROFILE_NEW`. La consegna è in `/etc/ouf/deploy-snapshots/semantic-provider-acceptance-v51-g7`. Conservare il digest di `manifest.json` e la ricevuta con firma `ARTIFACT_ACCEPTANCE`.

   ```bash
   bash ops/vps/acceptance-v51-g7.sh plan "$B1_V4" "$PROFILE_NEW"
   bash ops/vps/acceptance-v51-g7.sh apply "$G7_PLAN" "$B1_V4" "$PROFILE_NEW"
   ```

6. Generare e usare i runbook R3 issue e upgrade v16 a partire dai contratti v15 e dalle indicazioni sotto. Dopo l’upgrade, verificare wrapper, head, frame policy, broker, lease e stato dei CID. Nel successivo avvio autorizzato ripetere P1 e P2 e verificare che P3 restituisca RDF per l’IRI atteso.

## Input e pin per i runbook R3 v16

| Input o pin | Provenienza |
| --- | --- |
| `installationProfile` | File `/etc/ouf/installations/ouf-lab-netcup-01/semantic-provider.json`. Pin `PROFILE_NEW`, uguale al binding `profile` di g7. |
| `adapter/configProjection` | Output canonico + LF del lettore qui sotto. Salvare nel delivery root:root `0600` e fissare lo SHA-256 dei byte. Il suo `sha256` interno è invece quello del file montato. |
| `adapter/launch`, `adapter/policy` | File della directory B1 v4. Pin dal risultato B1 v4 e dagli stessi binding nel manifest g7. |
| `adapter/template`, `adapter/context`, quattro artefatti `southbound/*` | File della directory B1 v4, con i pin B1 v4 corrispondenti ai byte già accettati in v3 e confermati da g7. |
| `acceptance` | `manifest.json` di g7, con il pin del manifest emesso e riferimenti alla firma conservati con la ricevuta. |
| Input D-052 e g2 | Conservare i pin indipendenti v15, inclusi route APISIX, coordinatore, migrazione e boot. Rigenerare la proiezione delle route usando B1 v4 e il nuovo pin di `adapter/launch` per leggere il certificato. |
| `SOURCE_INPUTS_V16` | Aggiungere `tools/semantic_provider_r3/adapter_v16.py`, `tools/semantic_provider_config/contract.py` e `tools/semantic_provider_r3/read_adapter_v16.py`. Fissare i digest Git dei tre file e di `tools/semantic_provider_r3/compose.py` dalla consegna integrata con task-73. |
| Catena operativa | L’issue succede al pin dell’head `OPERATE` v15. L’upgrade usa lo stesso `inputs.json` e il suo SHA-256, il nuovo head v16 e il pin del wrapper v15 effettivo. |

```bash
set -o pipefail
sudo install -o root -g root -m 0600 /dev/null "$DELIVERY/adapter-config-projection.json"
sudo /usr/bin/python3.13 -I -B "$DELIVERY/tools/semantic_provider_r3/read_adapter_v16.py" \
  --adapter-launch "$B1_ROOT/adapter/launch.json" --adapter-launch-sha256 "$ADAPTER_LAUNCH_SHA" \
  --adapter-policy "$B1_ROOT/adapter/policy.json" --adapter-policy-sha256 "$ADAPTER_POLICY_SHA" \
  | sudo tee "$DELIVERY/adapter-config-projection.json" >/dev/null
```

Per la generazione R3, `adapter/configProjection` identifica un’osservazione pubblica del file e `installationProfile` identifica i byte del profilo firmato via g7. Verificare proiezione, pin del profilo e artefatti all’issue e all’upgrade. Il matching del flow considera tutti i `providerFlows` con sorgente IP della NIC `adapter-egress` e richiede unicità prima di confrontare l’`endpointRef`. L’endpoint HTTPS è confrontato per host, porta effettiva e path esatto. Il profilo attuale ammette `[]` per entrambe le liste CIDR/IP. Una futura lista non vuota richiede una decisione sulla differenza tra filtro DNS dell’adapter ed eccezioni del lease.

Pin dei nuovi sorgenti task-72 in formato Git LF

| Sorgente | SHA-256 |
| --- | --- |
| `tools/semantic_provider_r3/adapter_v16.py` | `1af794ea243bfa1d2caa8cfa702017bd5a378c49d27e6c753f52ab4f1890825a` |
| `tools/semantic_provider_config/contract.py` | `056a97bd7d9f4e506c9200f232fa95a44b766ee7fa628444bb3816018b676e15` |
| `tools/semantic_provider_r3/read_adapter_v16.py` | `66b1dd83d4543e4454036489ff64433d16a9a30bb63127b4310431271064de77` |

| Controllo di composizione | Diniego |
| --- | --- |
| Forma della proiezione | `R3_ADAPTER_PROJECTION_INVALID` |
| Sorgente, digest e limite in launch e policy | `R3_ADAPTER_CONFIG_SOURCE_MISMATCH` |
| Profilo in custodia e binding g7 | `R3_ADAPTER_INSTALLATION_PROFILE_MISMATCH` |
| Corrispondenza con il flow g2 | `R3_ADAPTER_PROVIDER_FLOW_MISSING`, `R3_ADAPTER_PROVIDER_FLOW_AMBIGUOUS` |
| Tupla HTTPS del provider | `R3_ADAPTER_PROVIDER_ENDPOINT_MISMATCH` |
| Liste CIDR/IP | `R3_ADAPTER_PROVIDER_CIDRS_MISMATCH` |
| Dichiarazione e prefissi | `R3_ADAPTER_PROVIDER_NAMESPACES_MISMATCH` |

## Ripristino

Ripristinare prima il file montato, poi il profilo. Usare il pin del piano di pubblicazione applicato e i pin dell’R3 autenticato al momento del ripristino. Per il profilo, fissare entrambi i digest. La copia superseded conserva i byte originali e la revisione inversa verifica il delta prima del rename.

```bash
bash ops/vps/config-publish.sh restore adapter.json --plan-sha256 "$CONFIG_PLAN" "${config_args[@]}"
bash ops/vps/config-publish.sh profile restore \
  --revise-from-sha256 "$PROFILE_NEW" --original-profile-sha256 "$PROFILE_OLD"
```

Se l’issue ha già pubblicato un head che punta a un wrapper ancora da installare, riconciliare la catena prima del ripristino. Dopo l’emissione di g7 o l’upgrade, mantenere i provider fermi fino al riallineamento governato di ricette, acceptance, head e chiusura R3 ai byte ripristinati. Conservare claim e ricevute, anche in caso di esito parziale.
