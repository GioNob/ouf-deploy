# Preflight di attivazione

Per ogni capability dichiarata nel rilascio, il comando confronta i sorgenti candidati, il bundle Gateway da pubblicare, il profilo dell’esecutore e il catalogo attivo dei ruoli. Produce sei righe di evidenza per capability prima del rilascio. La registrazione al rilascio e la conferma umana THS seguono il flusso D-071. Il preflight legge file locali. D-065: nessun nuovo archivio della piattaforma.

## Preparare gli input

In Bash, impostare le variabili `*_REPO` sulle copie locali dei repository e `*_COMMIT` sugli SHA completi fissati per il rilascio. Usare una directory privata temporanea esterna al repository.

```bash
set -euo pipefail
umask 077
INPUT=$(mktemp -d)
extract_source() {
  local module=$1 repo=$2 commit=$3
  test "$commit" = "$(git -C "$repo" rev-parse --verify "$commit^{commit}")"
  mkdir "$INPUT/$module"
  git -C "$repo" archive --format=tar "$commit" | tar -xf - -C "$INPUT/$module"
}
extract_source onboarding "$ONBOARDING_REPO" "$ONBOARDING_COMMIT"
extract_source semantic "$SEMANTIC_REPO" "$SEMANTIC_COMMIT"
extract_source mcp "$MCP_REPO" "$MCP_COMMIT"
extract_source gateway "$GATEWAY_REPO" "$GATEWAY_COMMIT"
unzip -p "$GATEWAY_RELEASE_ZIP" bundle.json > "$INPUT/bundle.json"
cp "$RELEASE_REQUEST" "$INPUT/request.json"
cp "$EXECUTOR_PROFILE" "$INPUT/profile.json"
```

Per il controllo dei grant, l’operatore esegue la seguente chiamata nel client MCP autorizzato.

```json
{"method":"tools/call","params":{"name":"authorization.permissions.read","arguments":{"view":"ROLES"}}}
```

Salvare in `$INPUT/roles.json` il risultato della chiamata riuscita (oggetto con `structuredContent`) oppure il suo contenuto strutturato con `roles` e `assignments`. Profilo e ruoli restano file privati dell’operatore.

## Eseguire offline

Dalla radice di `ouf-deploy`, con immagine `python:3.13-slim` già disponibile e `WHEELS` impostata sulla directory assoluta della wheel locale PyYAML 6.0.2 per Python 3.13/Linux. Il parser sicuro di PyYAML, già usato nei test del repository, gestisce anche documenti YAML multipli e mappe in linea.

```bash
docker run --rm --pull=never --network none \
  -v "$PWD:/repo:ro" -v "$INPUT:/in:ro" -v "$WHEELS:/wheels:ro" \
  -w /repo python:3.13-slim sh -ec '
    python -I -m pip install --disable-pip-version-check --no-index --find-links=/wheels PyYAML==6.0.2 >&2
    exec python -I -B scripts/activation-preflight.py \
      --request /in/request.json --profile /in/profile.json --gateway-bundle /in/bundle.json \
      --source onboarding=/in/onboarding --source semantic=/in/semantic \
      --source mcp=/in/mcp --source gateway=/in/gateway \
      --role-catalogue /in/roles.json --require-runtime'
```

Per il controllo statico si possono omettere le due opzioni finali. Senza vista ROLES il controllo del grant dà `UNVERIFIABLE`. Con `--require-runtime` diventa `FAIL`. Un file ruoli fornito ma illeggibile dà sempre `FAIL`.

## Richiesta versionata

La [richiesta sintetica completa](../tests/fixtures/activation_preflight/request.json) mostra il contratto chiuso `ouf.activation-request.v1`. Il documento contiene `contract` e una lista non vuota `capabilities`, con ID univoci. Chiavi duplicate o sconosciute sono errori d’uso. Ogni campo è obbligatorio salvo dove indicato.

| Campo della capability | Condizione verificata |
|---|---|
| `capabilityId`, `owner` | Identità nei cataloghi, owner registrato da Onboarding e nome dell’albero sorgente dell’owner. |
| `operation`, `requiredScope`, `allowedActors` | Operazione, scope e insieme di attori nel descrittore registrato. Il Gateway deve concordare su identità, scope e operazione. |
| `ownerConfig.file` | File di configurazione predefinito dell’immagine. Documenti con attivazione condizionale e file fratelli `application-<profilo>.yml` o `.yaml` permettono di diagnosticare proprietà disponibili solo sotto profilo. |
| `ownerConfig.flags` | Lista di oggetti con `property` e `expected` booleano. Il valore predefinito può essere letterale o nella forma `${VAR:default}`. Tra documenti incondizionati prevale l’ultimo valore. |
| `ownerConfig.limits` | Lista di proprietà con default intero positivo. Tra flag e limiti serve almeno una proprietà, senza ripetizioni. |
| `ownerResourceAttributes`, `roles` | Attributi che l’owner valorizza e ID dei ruoli richiesti. Serve almeno un ruolo. La presenza degli attributi rende valutabili i selettori di etichetta e livello. I valori concreti, il soggetto e l’assegnazione entrano nella decisione SDK a runtime. |
| `gateway.capabilityFile`, `gateway.routeIds` | File YAML del descrittore Gateway e almeno un ID di risorsa `routes` del bundle. |
| `mcp.tool` | Nome esatto nel manifest. Serve `publicationState: ACTIVE`, anche per i tool interni. |
| `mcp.requiredAuthorizationCapability` | Opzionale. Il binding di autorizzazione atteso usa `requiredScope` per default. Specificarlo quando il tool richiede un ID diverso dallo scope. |

I percorsi dei file sorgente sono relativi alla radice del rispettivo modulo, con separatore `/`. Fornire un solo `--source` per nome. Gli identificatori e i componenti dei percorsi ammettono lettere e cifre ASCII, punto, trattino e underscore, iniziano con una lettera o cifra e hanno al massimo 128 caratteri. Le liste di identificatori hanno elementi distinti.

## Esiti e codici

Lo stdout contiene un JSON con `contract: "ouf.activation-preflight-report.v1"`, `status` complessivo e array `checks`. Ogni riga contiene `capabilityId`, `check`, `status`, `code` e `detail`. Il primo problema del singolo controllo produce la sua riga. Gli altri controlli e capability proseguono. L’esito complessivo segue la precedenza `FAIL`, `UNVERIFIABLE`, `PASS`. L’uscita vale 1 in presenza di `FAIL`, altrimenti 0. Argomento obbligatorio assente, richiesta non valida o sorgente non associata producono errore d’uso 2 su stderr, senza report.

| Controllo | Codice | Significato |
|---|---|---|
| Tutti | `OK` | Condizione verificata. |
| Tutti | `INPUT_INVALID` | Un input del controllo è assente, illeggibile o di forma non riconosciuta. |
| OWNER_CONFIG | `OWNER_FLAG_PROFILE_ONLY` | Proprietà disponibile solo sotto profilo o file specifico di profilo. |
| OWNER_CONFIG | `OWNER_PROPERTY_MISSING` | Proprietà assente. |
| OWNER_CONFIG | `OWNER_DEFAULT_INVALID` | Placeholder senza default valido, flag diverso dall’atteso o limite non positivo/intero. |
| DESCRIPTOR_REGISTERED | `DESCRIPTOR_NOT_REGISTERED` | Capability assente dai cataloghi elencati in `ReleaseCapabilityRegistration.CATALOGUES`. |
| DESCRIPTOR_REGISTERED | `DESCRIPTOR_MISMATCH` | Voce duplicata o discordanza su owner, operazione, scope o attori. |
| GRANT_APPLICABLE | `ROLE_CATALOGUE_REQUIRED` | Opzione `--role-catalogue` omessa. |
| GRANT_APPLICABLE | `ROLE_NOT_FOUND` | Ruolo assente o ambiguo. |
| GRANT_APPLICABLE | `GRANT_MISSING` | Al ruolo manca un permesso sulla capability. |
| GRANT_APPLICABLE | `GRANT_DENIED` | Permesso con effetto DENY. |
| GRANT_APPLICABLE | `GRANT_ATTRIBUTES_MISSING` | Nessun permesso del ruolo soddisfa i requisiti di presenza degli attributi di etichetta e livello. |
| GATEWAY_INSTALLATION | `GATEWAY_CAPABILITY_MISMATCH` | Descrittore Gateway diverso dalla richiesta. |
| GATEWAY_INSTALLATION | `GATEWAY_ROUTE_MISSING` | Rotta richiesta assente dalle risorse del bundle. |
| GATEWAY_INSTALLATION | `GATEWAY_VALUES_MISSING` | Al profilo mancano valori. Il dettaglio elenca nomi e tipi. |
| GATEWAY_INSTALLATION | `GATEWAY_VALUE_INVALID` | La sostituzione dell’esecutore rifiuta un valore. Il dettaglio riporta nome e tipo. |
| GATEWAY_INSTALLATION | `GATEWAY_VALUES_UNUSED` | Valore del profilo non dichiarato o placeholder dichiarato e mai usato. |
| GATEWAY_INSTALLATION | `GATEWAY_PLACEHOLDER_INVALID` | Riferimento a placeholder malformato o sconosciuto nel corpo di una risorsa. |
| MCP_TOOL | `MCP_TOOL_NOT_FOUND` | Tool assente o ambiguo. |
| MCP_TOOL | `MCP_TOOL_BINDING` | ID capability o riferimento di autorizzazione discordante. |
| MCP_TOOL | `MCP_TOOL_INACTIVE` | Stato di pubblicazione diverso da ACTIVE o assente. |
| PROFILE_VALID | `PROFILE_INVALID` | La sezione indicata del profilo fallisce la validazione. |

`PROFILE_VALID` controlla i due insiemi di coordinate CI, ogni modulo, il database Semantic se presente, il profilo Gateway e la continuità dei ruoli runbook tra le versioni ricavate dal profilo. `GATEWAY_INSTALLATION` invoca `gateway_bundle.substitute` sui corpi del bundle con i valori di quel profilo. Entrambe le righe sono obbligatorie. Il report omette valori del profilo, corpi sostituiti e testo delle eccezioni.

## Evidenza D-082

Eseguire `python -I -B -m pytest tests/test_activation_preflight.py` dalla radice del repository. La suite esercita la CLI usando sorgenti e dati sintetici. La CI esegue lo stesso comando in `python:3.13-slim`.

Il riferimento di rilascio è il [Blueprint del PET v1.7, §9](baseline/v1.7/text/OUF_System_Integration_Development_Blueprint_v0_3.txt). La prova contribuisce alla coerenza delle proiezioni in [OUF-E2E-022](baseline/v1.7/package/implementation/ouf-e2e-integration-spec-v0.3/spec/e2e-scenario-catalog.yaml). L’esecuzione end-to-end e la conferma THS hanno evidenze proprie.
