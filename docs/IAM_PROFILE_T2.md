# Profilo IAM T2 e qualifica del mandato

Il custode IAM prepara il profilo privato dell’installazione. Il custode Gateway fornisce l’audience e lo scope richiesto da ciascuna delle quattro azioni del mandato. Il custode dei pool fornisce le misure 55g. La pipeline umana conserva gli input e le ricevute insieme alla revisione applicata. Il comando Python lavora su file locali. Solo il sottocomando esplicito `qualify` effettua letture HTTPS.

## Preparare il profilo

Usare Python 3.10 o successivo. Lo schema chiuso `ouf.iam-profile.v1` vale per `keycloak-ouf` ed `existing-iam`. Sostituire ciascun segnaposto del template con il corrispondente valore JSON completo in un file di parametri privato. Per esempio, uno slot è un intero JSON. Il validatore verifica il **risultato** della sostituzione, compresi i vincoli tra campi. Tutti i comandi accettano anche il profilo già materializzato, omettendo `--parameters`. [Schema](../config/iam-profile/profile.schema.json) · [Template](../config/iam-profile/profile.template.json)

| Parte | Come proiettarla |
|---|---|
| Trust | Configurare issuer, JWKS, introspezione RFC 7662, decisioni e origine Gateway con URL HTTPS espliciti. Usare il riferimento alla CA approvata e l’audience del Gateway. Il probe usa CA e certificato client specifici del destinatario. |
| Client e mapper | Distinguere workload SERVICE MCP e sessione HUMAN THS di Onboarding. Per entrambi proiettare gli effetti dei mapper nel token e nell’introspezione. Derivare `client_id` dal client autenticato, `sub` dal principal, `tenant_id` dal tenant verificato, `acr` dal contesto di autenticazione, `ouf_actor_type` dal tipo di attore e `aud` dal Gateway. Registrare il client secret solo come `ref:…`. |
| Scope | Acquisire dal binding Gateway revisionato la mappa `issue, dispatch, revoke, status`. Il client MCP deve avere l’unione esatta di questi scope e `ouf.analysis.mandate.renewal-check`. Il client THS deve avere `ouf.analysis.renewal.read` e `ouf.analysis.renewal.decide`. Il Gateway verifica lo scope della singola rotta. Gli scope estranei alla gestione T2 vanno nell’inventario esterno. |
| Incarico | All’issue, la delega HUMAN verificata autorizza la creazione o la selezione di una risorsa di autorizzazione IAM del tipo configurato. Conservare come `grantRef` il suo ID stabile. La permission lega issuer, tenant, HUMAN, principal della credenziale d’incarico, risorsa e azione. Il 55h dovrà interrogare questa permission corrente a ogni status e dispatch. Ritirarla e invalidare la credenziale specifica rende osservabile la revoca entro `revocationTtlSeconds`. Qualificare la capacità effettiva dell’IAM di ottenere entrambi gli effetti. |
| Decisioni e THS | L’adapter serve `ouf.analysis.authority-check.v1`. La decisione vincola nonce e byte della richiesta con `requestHash`. Per `renew-budget` verifica anche titolare, grant, mandato, generazione, incidente, versione e hash della proposta e comando THS. Il Gateway restituisce al MCP `requestHash, decisionRef, grantRef, validUntil`. MCP ricontrolla validità, fence e stato al commit. |
| Capacità | Identificatori logici di installazione e provider comuni alle repliche. D-091 fissa rispettivamente 1, 1, 4, 1, 2 per `ActivePlans, ProviderSlots, InstallationActivePlans, InstallationProviderInFlight, ControlReservedSlots`. Il profilo comprende anche i tetti di sessione C.3. Per i rate IAM (richieste/minuto sull’installazione), il TTL di revoca (secondi) e gli slot dati di ciascun pool specificare `value, default, maximum` positivi, con default e valore entro il massimo. I valori operativi vengono approvati sul profilo misurato. |

I riferimenti disponibili nominano le quattro azioni senza specificarne le quattro stringhe OAuth. I nomi `fixture.*` servono esclusivamente ai test. Il confronto usa `gatewayBindings` proveniente dal bundle approvato indipendentemente dal desiderato.

## Esportare uno snapshot

`ouf.iam-profile-observation.v1` è una proiezione in sola lettura. I client sono selezionati tramite il binding di proprietà del custode. Il custode raccoglie dall’IAM client, scope assegnati, mapper effettivi, trust e configurazione dell’incarico, e dai rispettivi owner i binding Gateway e le quote dei servizi. Le proprietà dei mapper descrivono gli effetti osservati. Un export nativo del realm può contenere segreti e deve essere proiettato prima dell’uso. [Osservazione sintetica iniziale](../tools/iam_profile/fixtures/before.json) · [Osservazione sintetica effettiva](../tools/iam_profile/fixtures/effective.json)

| Campo | Origine e significato |
|---|---|
| `contract, kind, installationId, complete` | Identità dell’osservazione. `complete=true` attesta copertura integrale del perimetro gestito. Un campo omesso in tale export è confermato assente. Lettura negata, tronca o ignota richiede `complete=false` e ferma il plan. |
| `gatewayBindings` | Audience e mappa degli scope delle quattro azioni da una revisione Gateway in custodia. |
| `managed` | Dizionario piatto. Ogni chiave è un percorso di foglia dello schema separato da punti. Le liste di scope sono appartenenze gestite. L’export include anche gli scope T2 inattesi per poterli riconciliare. I campi di contratto e i parametri condivisi provengono dal registro di configurazione effettivo. |
| `foreign` | Elenco di `idSha256, stateSha256`. Per un client estraneo, calcolare l’ID con il digest canonico di `["client", clientId]`. Per altri oggetti o binding usare l’identità qualificata dal tipo e dal proprietario. Il secondo digest copre la proiezione senza segreti. Il proprietario include qui anche i binding estranei di un client gestito. Una collisione con un client da gestire ferma il plan. |
| `controlProof` | `null` prima della misura. Dopo 55g, registrare il digest del profilo, `pet="55g"`, SHA-256 della traccia conservata e il campione di ciascun pool Gateway, MCP, DB e Semantic. A dati saturi, contare le richieste di controllo **servite contemporaneamente**. Per il Gateway il campione include anche le due richieste annidate del relay di rinnovo. Usare misure dello stesso intervallo e conservare tempi, attese e occupazione nella traccia. |

## Plan, ricevuta e ritorno

Dalla radice del checkout, la prova senza rete si esegue con questi comandi.

```sh
python -B -m tools.iam_profile plan config/iam-profile/profile.template.json tools/iam_profile/fixtures/before.json --parameters tools/iam_profile/fixtures/parameters.json
python -m unittest discover -s tests -p 'test_iam_profile_*.py' -v
```

Per i file privati, il seguente esempio usa una shell POSIX e JSON UTF-8.

```sh
python -B -m tools.iam_profile validate "$PROFILE" "$BEFORE"
python -B -m tools.iam_profile plan "$PROFILE" "$BEFORE" > "$PLAN"
# Dopo apply umano e nuova cattura degli owner
python -B -m tools.iam_profile receipt "$PROFILE" "$AFTER" > "$RECEIPT"
python -B -m tools.iam_profile gate "$PROFILE" "$AFTER" "$RECEIPT"
```

Un codice di uscita 0 indica successo, 2 indica `HELD` per i controlli applicativi. Conservare come ricevuta durevole solo l’output riuscito. Ogni riga di `diff` e `returnDiff` contiene percorso, azione, digest precedente e successivo. `null` indica assenza. Le differenze di ordine degli scope preservano l’ordine osservato. I byte per l’apply si ricavano dal profilo approvato, quelli per il ritorno dallo snapshot iniziale. L’inverso elimina esclusivamente le foglie create dal plan. L’azione `foreign` conserva il digest in entrambe le direzioni. Per applicare i diff a un IAM nativo la pipeline dovrà lavorare sui soli binding gestiti e verificare preimmagine, identità, proprietà e assenza di drift prima di scrivere.

Per le prove 55g e 55h, `sourceTraceSha256` identifica i byte della traccia originale conservata. `traceSha256` vincola le misure proiettate e la loro fonte con il digest canonico dell’intero record di prova escluso questo campo.

I digest si calcolano sul JSON UTF-8 compatto, con chiavi ordinate, array nell’ordine fornito e Unicode preservato. `planSha256` copre l’intero documento escluso il campo stesso. L’identità del profilo e dello snapshot include tutti i loro campi. La ricevuta `ouf.iam-profile-receipt.v1` lega questi digest a issuer, tipo IAM, client, scope, digest della prova 55g e stato `VERIFIED`.

**Aggancio per il rilascio.** Prima di abilitare l’esecuzione autonoma T2, il futuro chiamante invoca `tools.iam_profile.plan.gate(profile, snapshot, receipt)` con input recuperati dalla custodia del rilascio. Deve esigere `status == "VERIFIED"`. La funzione ricalcola la ricevuta e confronta l’intero documento. Codici tipici sono `RECEIPT_MISSING`, `RECEIPT_MISMATCH`, `PROFILE_DRIFT` e `CONTROL_UNPROVEN`. La provenienza e l’attualità dei tre documenti e della traccia dipendono dalla pipeline umana. Il rilascio verifica separatamente la qualifica IAM 55h e gli altri gate D-091. L’integrazione con module release segue la PR #182.

## PET dopo l’apply umano

| ID | Prova e fonte |
|---|---|
| IAM-55M-01 | Due HUMAN nello stesso tenant, due incarichi e lo stesso client SERVICE. Entrambi osservano il proprio mandato. A riceve 404 su B. La fixture tenta davvero il dispatch A→B e conta gli invii all’owner. Nella qualifica in sola lettura questo ultimo fatto proviene dal tentativo controllato 55h e dal conteggio owner sullo stesso profilo. |
| IAM-55M-02 | Introspezione attiva di A e B. Dopo il segnale dell’operatore, A diventa inattivo entro il TTL, prima della scadenza naturale del bearer. B resta attivo. La fixture usa un orologio controllato. |
| IAM-55M-03 | Il gate restituisce `HELD` per ricevuta mancante o divergente, drift e riserva non dimostrata. Ripetere il comando `gate` sui file privati e conservare l’esito. |
| IAM-55M-04 | La fixture applica il diff con confronto delle preimmagini, genera la ricevuta dalla nuova lettura e applica l’inverso fino allo snapshot iniziale. La verifica del ritorno reale appartiene alla pipeline governata. |

Per il PET reale predisporre su Keycloak OUF i due incarichi di prova con credenziali distinte per il medesimo client e due mandati attivi. Usare la stessa procedura per un IAM preesistente. Compilare il file privato del probe con le identità verificate all’issue, i riferimenti a file protetti dei due bearer già emessi, le CA e le credenziali mTLS di lettura. Il timeout di connessione è il parametro Gateway da 1 a 30 secondi. Usare un TTL e un rate che consentano campionamenti durante la finestra. Il record `deniedForward` si ricava dall’audit 55h e dal conteggio owner correlato al tentativo. Conservare la traccia per digest. [Struttura completa degli input del probe](../tools/iam_profile/fixtures/probe.example.json)

```sh
python -B -m tools.iam_profile qualify "$PROFILE" "$AFTER" "$PRIVATE_PROBE"
```

Il comando in sola lettura esegue esclusivamente POST di introspezione RFC 7662 e di `mandates/status`. Premere Invio **immediatamente prima** che il custode revochi l’incarico A attraverso il canale governato. Il tempo include l’azione umana e la risposta IAM osservata. Il probe mantiene la stessa credenziale in memoria fino al termine. Per un nuovo giro fornire una nuova coppia di incarichi e una traccia corrispondente. Associare gli esiti, il profilo e la revisione alle prove `PET-semantic-306` e `PET-authorization-126` nel fascicolo D-082.

