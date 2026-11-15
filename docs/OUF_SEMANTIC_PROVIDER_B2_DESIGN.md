# Nota di progetto B2 — armatura v5.1 e primo avvio governato del provider

Sprint-01, task-34 (D-032). Scritta da Claude (D-026). Solo analisi: nessun codice, nessuna modifica sul VPS.
Brief: `_handoff/sprint-01/brief-b2.md`. I path sono relativi a `ouf-deploy`. Abbreviazioni usate:
- **CD** = `tools/semantic_cohort_admission/cohort-draft/`;
- **TP** = `tools/semantic_transaction_profiles/`;
- **V51** = `tools/semantic_runtime_v51/semantic_provider_docker_runtime_v51.py`;
- **TR** = `tools/semantic_target_review/`.

## 0. Esito in breve
1. **Tutta la catena deve stare in meno di 300 secondi.** Intent e approvazione durano al massimo 300 s (CD`tools/semantic_provider_deployment_protocol.py:50-54`). Il broker riverifica l'intent a `cohort-ready` (CD`scripts/semantic_provider_deployment_broker.py:220,258`) e il driver riverifica tutto, firme comprese, allo `start` (CD`tools/semantic_provider_deployment_reauthorization.py:37-103`). L'armatura v5.1 contiene `intentRef`, cioè l'hash dei byte dell'intent (V51`:291-295`), quindi si firma solo **dopo** l'intent. Ne segue che record di ruolo, armatura, staging e `docker start` sono **un'unica cerimonia atomica**. I task 35-38 del brief non possono essere passi separati sul VPS: diventano moduli separati, ma un solo apply.
2. **`transactionId` di 64 hex.** Mandato root e intent richiedono `[0-9a-f]{64}` (TP`issue_provider_transaction_authority.py:59`; CD`tools/semantic_provider_deployment_protocol.py:84-86`). Le «transazioni» A2 `7ff12b95…` e `864a28db…` sono invece l'etichetta Docker `ouf.semantic.provider.successor.creation`, di 32 hex (`scripts/prepare-semantic-provider-a2-20261113.py:32,222,443`), e il cohort-draft non legge etichette. Serve un `transactionId` di protocollo nuovo per ruolo (§4).
3. **Gli orchestratori v4 non si riusano.**
   - Bloccano i CID storici: `TARGETS` (TP`authenticate_provider_transaction.py:19-29`), l'intake fissato alla policy originale (TP`provider_transaction_intake.py:18-26,134,148,255`) e `activate` (TP`docker_cohort_activation.py`), che verifica il wrapper v4 e il journal v4.
   - Broker, preparer, driver e librerie del cohort-draft sono invece parametrici, attraverso la configurazione e i binding, e si riusano invariati.
4. **Orologi.** Ogni firma della catena di ammissione si verifica con `DetachedAuthenticator`, che applica `notBefore <= now < expiresAt` dalla policy che gli si passa (CD`tools/semantic_provider_deployment_authentication.py:329-337`) e non conosce il registro dei mandati. La base versionata (D-030) ha lo stesso schema e gli stessi ruoli (`tools/semantic_authority_mandates/mandates.py:25,28,190-197`; `tools/semantic_mandate_renewal/renewal.py:291-301`), quindi B2 la passa come `policyBinding`. **Dopo lo start nessun controllo legge più la policy** (§3), quindi un provider avviato non decade con la scadenza.
5. **Nessuna ripartenza.** Ogni journal va solo avanti e ogni file di prova è creato con `O_EXCL` (§5). Un provider fermato richiede un ciclo completo nuovo, e la RestartPolicy dei successor è `no` (letta sul VPS, §8).

## 1. La catena, anello per anello

| # | Anello | Codice | Scrive | Firma (ruolo, chiave) |
|---|---|---|---|---|
| 1 | Mandato root per ruolo (approvazione umana) | schema `ouf.semantic-provider-transaction-role-mandate.v1`, chiavi esatte in TP`issue_provider_transaction_authority.py:51-59` | `<role>-mandate.json` (root 0600) | nessuna: lega un `approvalRef` |
| 2 | Record di ruolo | `issue_role_authority`, TP`issue_provider_transaction_authority.py:27-141` (preflight `validate_only` `:98-104`) | `review.json`, `intent.json`, `live-authorization.json`, `final-mandate.json`, firme `<sha>.<ROLE>.json` | review e final: `FINAL_DEPLOYMENT_APPROVAL` (installer); intent: `DEPLOYMENT_INTENT` (installer); live: `CREATION_ATTESTATION` (attestor) |
| 3 | Configurazione del broker | schema chiuso `ouf.semantic-deployment-broker.v1` (CD`scripts/semantic_provider_deployment_broker.py:105-107`); scritta storicamente da TP`assemble_provider_profiles.py:139-151` (v2: `assemble_provider_profiles_v2.py:11-27`) | `broker.json`, `broker-state.json` (STAGED), `deployment.json` (STAGED) | — |
| 4 | Armatura `RUNTIME_ARMING` | payload `ouf.semantic-docker-runtime-arming.v1` (V51`:274-305`); verificatore `tools/semantic_runtime_v51/arming_verifier_v51.py` | `<n>.json`, `<n>.RUNTIME_ARMING.json` in `arming/` | `RUNTIME_ARMING` (installer), verificata con `MandateAuthenticator` e il registro b1b2 |
| 5 | Staging v5.1 | contratto `docs/OUF_SEMANTIC_RUNTIME_V5_ARMING_20261112.md` §«API di binding»; `binding_v51` V51`:306` | `<registryRoot>/<cid>/` 0700, `operation.lock`, `adapter.json` `STAGED` | — |
| 6 | `create` (runtime) | V51`:491-537`: seleziona e verifica l'armatura, la consuma, poi `authorize-create`, runc create, `record-created` | marker `.consumed`; journal v5.1 CREATED | — |
| 7 | `authorize-create` / `record-created` | broker `:375-388`; consumazione CD`tools/semantic_provider_deployment_consumption.py:67-84` | broker-state e deployment CREATING → CREATED | verifica l'intent |
| 8 | `cohort-ready` | broker `:214-258`: attende il fratello, raccoglie la rete viva | niente | riverifica l'intent (×2) |
| 9 | `prepare` | broker `:287-363`: i producer locali emettono `CREATION_ATTESTATION` e `FINAL_DEPLOYMENT_APPROVAL` monouso (producer `:218-240`); il preparer scrive `driver.json` v5/v6 e crea le tabelle nft del candidato | `attestation.json`, `approval.json`, `creation.json`, `preparer.json`, `admission.json`, `driver.json`, `preexec.json`; deployment READY | attestor e installer, tramite i producer |
| 10 | hook e `start` del driver | CD`scripts/semantic_provider_preexec_hook.py:160-203`; `consume_locked` (consumazione `:114-131`) | deployment STARTING → STARTED; journal v5.1 STARTED | riverifica completa almeno 4 volte |
| 11 | `docker start` concorrente e readback | modello TP`docker_cohort_activation.py:76-111` (v4) | ricevuta | — |

**Producer (anello 9).** Il producer locale chiama un servizio di firma configurato in `producers` e controlla da sé la finestra del mandato nelle chiavi della propria configurazione (CD`tools/semantic_provider_deployment_producer.py:58-72,129-132`). Non ho visto la configurazione installata sul VPS, né se le sue `keys` derivano dalla policy originale: lo verifica il lettore del task-35 (§9, D1).

## 2. Cerimonia atomica (contratto proposto)

**Plan, in sola lettura e senza chiavi.** Osserva lo stato di partenza: wrapper `e5080250…`, configurazione v5.1 `de1e6dd7…`, successor `created` mai avviati, `arming_absence` vuota, journal assenti, lock vuoto. Poi:
- compone offline per ruolo gli 8 input (§4), la configurazione del broker e i journal;
- esegue `issue_role_authority(validate_only=True)` per entrambi i ruoli;
- produce un digest riproducibile.

Il plan **non** fissa intent, firme o tempi, che nascono solo all'apply.

**Apply, con `--plan-sha256` e un `approvalRef` dato dall'umano.** Il cronometro parte alla prima firma e tutto si ferma se si supera il budget (proposta: 200 s di 300).
1. Claim della cerimonia, quindi `doNotRerunApply`.
2. Mandato root per ruolo: `expiresAt = issuedAt + 270`.
3. Record di ruolo (4 firme per ruolo), verificati con la base versionata.
4. Configurazioni del broker con `intentBinding` = intent appena firmato, `policyBinding` = base versionata; `broker-state.json` e `deployment.json` STAGED.
5. Payload dell'armatura, generazione 1: due candidati con `intentRef` = sha dell'intent e configurazione del broker con il suo hash. Firma `RUNTIME_ARMING` e verifica con il verificatore v5.1 installato.
6. Staging v5.1: directory, lock e journal STAGED con `binding_v51`.
7. Riosservazione completa sotto il guard lock, poi rilascio del lock (come in `activate`: il runtime lo riprende da sé).
8. `docker start` dei due CID insieme, con timeout.
9. Readback: Docker `running` con PID > 0 e runtime `ouf-semantic-admitted-v2`; journal v5.1 `STARTED` con `armingGeneration` 1; deployment STARTED; marker `.consumed` presenti; tabelle nft del candidato come da footprint.
10. Ricevuta finale. Contatori dichiarati: firme 8 + 2 (+ 4 dai producer), zero nft scritte dal controller (le scrive il driver), lease non attivato.

Nessun nuovo tentativo e nessun rollback automatico: un errore lascia una diagnosi e il claim (§5).

## 3. Tabella degli orologi

| Verifica | Dove | Cosa legge | Dopo il 2027-01-02 con la policy originale | Con la base versionata |
|---|---|---|---|---|
| Firma dei record di ruolo (signer e verifica post-firma) | CD`tools/semantic_provider_deployment_signing.py:45-48,66-67`; TP`issue_provider_transaction_authority.py:133` | `policyBinding` passato | fallisce | valida fino all'`expiresAt` della generazione (oggi 2027-02-12), poi si rinnova |
| Intent ad `authorize-create` e `cohort-ready` | consumazione `:67-77`; broker `:220,258` | `policyBinding` del broker | fallisce | come sopra |
| Producer (attestazione e approvazione) | producer `:129-132` | `keys` della configurazione del producer | **non determinato** (D1) | **non determinato** (D1) |
| Riautorizzazione allo start | reauthorization `:37-103` | `policyBinding` del driver (`authenticationBinding`) | fallisce | come sopra |
| Armatura `RUNTIME_ARMING` | verificatore v5.1 | ancora b1b2 + registro dei mandati | non dipende | — |
| Accettazione gen 3 | 29b, solo all'installazione | registro dei mandati | non dipende | — |
| Container in esecuzione | — | nessun controllo dopo `STARTED` | continua a girare | continua a girare |
| `kill` / `delete` / rollback del driver | V51`:548-560`; hook `:160` (rollback senza autorizzatore) | nessuna firma | funzionano | — |

Il versionamento della base cambia path e hash a ogni rinnovo. B2 lega la generazione corrente al momento dell'apply (versione 1 `c135861b…` o successive), e la ricevuta registra quale.

## 4. Input per ruolo e `transactionId`

**Gli 8 input** (TP`issue_provider_transaction_authority.py:21-22`):
- **template, launch e context**: dalle ricette v2 (`semantic-provider-b1-recipes-20261114-v2`); `compile_policy` deve dare byte uguali a `framePolicy`, e la ricetta v2 è già accettata nella gen 3.
- **preparerTemplate** (`ouf.semantic-admission-preparer-template.v1`, campi in TP`authenticate_provider_transaction.py:74-108`): `candidate` con `containerId`, `transactionId`, `networkBindings`, `transport`, `tableName` e `runtimeBinding`. Il trasporto southbound include l'ingresso `BRIDGE_PORT` proposto in A2 (`scripts/prepare-semantic-provider-a2-20261113.py:370-372`).
- **deploymentConstraints** e **provenanceEvidence**: qui sono solo hashati; l'origine storica va recuperata da TR`prepare_private_transaction_*.py` (**non determinato** nel dettaglio).
- **dependencyEvidence** (`ouf.semantic-provider-dependency-evidence.v1`, TP`authenticate_provider_transaction.py:111-149`): legata all'`imageConfigDigest` e con freschezza di 48 h rispetto a `expiresAt` (`:138`). **Va prodotta fresca prima di ogni cerimonia.**

**`transactionId` di protocollo, proposta:** `sha256` del JSON canonico di `{schema:"ouf.semantic-provider-b2-transaction.v1", installationRef, entityRef, containerId, creationLabel, ceremony}`. Qui `creationLabel` è l'etichetta A2 di 32 hex e `ceremony` il numero della cerimonia (1, poi N+1). L'ID è deterministico e rivedibile nel plan, distinto per ogni ciclo e legato all'identità A2. Non va riusato su più cicli, perché commenti nft e journal di ammissione lo portano dentro (CD`tools/semantic_provider_preexec.py:23-28`).

## 5. Errori, generazioni e ciclo N+1

| Momento dell'errore | Che cosa resta | Per riprovare |
|---|---|---|
| Prima della prima firma | claim e diagnosi | nuova cerimonia, stesso numero |
| Dopo i record, prima dell'armatura | record firmati e scaduti entro 300 s | cerimonia N+1 (nuovo `transactionId`, nuovi record) |
| Dopo l'armatura, prima del `create` | generazione 1 non consumata | **bloccante:** due generazioni disponibili darebbero `ARMING_GENERATION_AMBIGUOUS` (`docs/OUF_SEMANTIC_RUNTIME_V5_ARMING_20261112.md` §Selezione). Serve un ritiro governato della generazione orfana: aperto (D3) |
| Dopo il consumo (`.consumed`) | journal v5.1 PREPARING/CREATING, broker in stato intermedio | generazione N+1 e journal nuovi; i container vanno ricreati (A3) perché runc e Docker conservano il tentativo |
| Dopo lo start di uno solo | un container `running`, l'altro fallito | stop compensativo (§6), poi come la riga precedente |

Un `create` riuscito lascia journal non riavvolgibili: broker STAGED → … → PROTECTED → CLEANED (broker `:176-189`), deployment fino a STARTED (consumazione `:26-58`), file di prova con `O_EXCL` (broker `:91-96`; preparer `:260`). Quindi **«N+1» significa in pratica: nuovi container**, cioè una nuova preparazione A, ricette e accettazione, oppure una regola esplicita che consenta journal nuovi sugli stessi CID dopo `delete` (V51`:552-560` arriva a DELETED). Va deciso prima della cerimonia (D3).

## 6. Stop compensativo e ripartenza

**Che cosa consente il v5.1 dopo lo start:**
- `kill` passa a runc (V51`:548-550`);
- `delete` porta il journal a DELETING, esegue `runc delete`, poi il rollback del driver (rimuove le tabelle nft del candidato, CD`tools/semantic_provider_preexec_native.py:80-81`) e il `cleanup` del broker, infine DELETED.

Da Docker significa `docker stop` (kill), poi `docker rm` (delete).

**Stop compensativo governato** (strumento separato, plan/apply, pronto e provato con il plan **prima** della cerimonia, analogo a D-025):
- `docker stop` dei CID indicati;
- readback: `exited`, nessun processo, journal invariato o DELETED secondo la variante.

Non rimuove i container: la rimozione distruggerebbe l'identità A2.

**Ripartenza, due alternative per D-032 punto 3:**
- **(R1) Regola esplicita: ogni ripartenza è una cerimonia nuova.** Dopo un crash o un riavvio del VPS, il provider resta fermo finché l'umano non esegue una cerimonia (nuovi container, o journal nuovi se D3 lo consente). Zero codice nuovo nel runtime, ma ogni riavvio del VPS ferma il provider.
- **(R2) Armatura di ripartenza governata.** Un nuovo runtime (v5.2) e una nuova versione del consumo ammettono, per gli stessi CID, un ciclo «restart» con armatura e intent nuovi. Così i journal non vanno ricreati: si aggiunge un'epoca per CID, che resta a senso unico. Costo: nuovo runtime, nuova accettazione e modifiche alle librerie del cohort-draft fissate per hash, quindi copie versionate. Un'automazione senza umano richiederebbe inoltre una firma automatica, cioè un ruolo nuovo.

**Raccomandazione: R1 per il primo avvio.** Rivalutare R2 dopo C, insieme a D-010.

## 7. Rete
- **Tabelle del candidato** `inet` e `bridge` `<tableName>`, con commento `ouf-preexec:<txn>`: le crea il driver nell'`apply` del preparer, durante `prepare` (CD`tools/semantic_provider_preexec_native.py:76-78`), con regole sigillate nel `driver.json`. Contengono l'ingresso dichiarato nel trasporto del `preparerTemplate`. **Il controller B2 non scrive nft.** Il task 38 del brief confluisce quindi nella cerimonia, come readback.
- **Lease:** lo start richiede il lease **quiescente**: journal di coordinamento `QUIESCED`, `leaseAuthorized=False`, set `provider_N` vuoti (CD`tools/semantic_provider_preexec.py:102-109`; `tools/semantic_provider_lease_nft.py:46-79`). Il driver non attiva mai il lease (`leaseActivated` è sempre False, preexec `:217`). **Aperto (D2):** che cosa del traffico il lease abilita dopo lo start, se l'ingresso 172.18.0.6 → 172.18.0.14:10443 funziona senza lease o se serve un'attivazione in C.
- **Porte (da verificare con le ricette v2 nel lettore).** Il southbound espone 9080 e 9443 (`docker inspect`, §8), mentre l'ingresso proposto è su 10443 e l'URL del peer è `https://ouf-semantic-southbound-v2:10443` (`scripts/cutover-semantic-provider-20261111.py:308`).

## 8. Inventario sul VPS (2026-11-15)

**Letture già fatte da Claude** (sudo diagnostico):
- `docker inspect` dei successor:
  - stato `created`, `StartedAt` zero, runtime `ouf-semantic-admitted-v2`, RestartPolicy `no`;
  - adapter su `ouf-semantic-provider-internal` 172.21.0.3 ed `-egress` 172.22.0.3;
  - southbound su `ouf-backend` 172.18.0.14, `internal` 172.21.0.2 ed `egress` 172.22.0.2, con porte esposte 9080 e 9443.
- `docker inspect` delle reti: `ouf-backend` internal, `ouf-semantic-provider-internal` internal (bridge `oufsp-int`), `ouf-semantic-provider-egress` non internal (`oufsp-egress`).
- Peer Semantic `ouf-semantic-cutover-c0a8…` `running` a 172.18.0.6.
- `systemctl show ouf-authority-mandate-renewal.service`: primo run automatico del 2026-11-15 00:19:20 CET, `Result=success`, exit 0.

**Non leggibili senza root:** `/etc/ouf/deploy-snapshots` e `/var/lib/ouf-authority-mandates` sono 0700. Serve quindi un **lettore B2 in sola lettura eseguito dall'umano** (task-35), che restituisca solo hash, schemi, stati e chiavi pubbliche, mai segreti. Deve leggere:
- configurazione v5.1 installata: `registryRoot`, `runtimeStateRoot`, `candidates`, `admission*` e `driver*` (path e hash);
- base versionata corrente: numero, hash e finestre di installer e attestor;
- configurazioni dei producer: schema, `keys` (origine e finestre) e servizio di firma;
- coordinamento del lease e tabelle nft (`nft -j list tables`, solo nomi e commenti);
- sorgente del broker installato o storico: hash dei 19 file fissati (broker `:20-28`);
- ricette v2: porte e trasporto;
- presenza di journal o directory per i nuovi CID sotto `registryRoot`, che deve essere nulla.

## 9. Decisioni e domande aperte
- **D1 — Producer:** da dove vengono le `keys` della configurazione dei producer, e se scadono con la policy originale. Se sì, serve una configurazione dei producer sulla base versionata, nuova e versionata. Lo risolve il lettore.
- **D2 — Lease dopo lo start:** se il lease resta quiescente per tutto B2 (raccomandato: l'attivazione va a C, con la prova JWT/TLS) e che cosa questo significa per l'ingresso.
- **D3 — Generazione orfana e journal dopo `delete`:** come si ritira un'armatura emessa ma non consumata, e se dopo DELETED si consentono journal nuovi sugli stessi CID (altrimenti ogni N+1 richiede container nuovi).
- **D4 — Ripartenza:** R1 (raccomandata) o R2 (§6).
- **D5 — `transactionId`:** derivazione proposta al §4.
- **Rischio di tempo:** prepare con due producer, ricorsione `cohort-ready` e due start devono stare nei 300 s dell'intent. Il budget del broker (18 s) e del driver (≤ 5 s) lo rende plausibile, ma va misurato in CI con la fixture nativa.

## 10. Scomposizione aggiornata (tutto in `ouf-deploy`)

| Task | Contenuto | Effetti sul VPS | `HELD` principali |
|---|---|---|---|
| 35 | **Lettore B2** (§8), runbook-launcher come i precedenti | nessuno (lettura root dell'umano) | custodia, hash, presenza di journal o armature |
| 36 | **Compositore puro** dei documenti per ruolo: 8 input, `preparerTemplate` con trasporto, configurazione del broker, journal STAGED, payload dell'armatura e staging v5.1. Test CI con fixture: `compile_policy` = `framePolicy`, `binding_v51`, preflight `validate_only` | nessuno | drift delle ricette, ID, trasporto |
| 37 | **Stop compensativo governato** (plan/apply) e relativi test | nessuno finché non serve | stato non `running`/`created`, CID estranei |
| 38 | **Controller della cerimonia B2** (§2): plan senza chiavi, apply atomico con budget di tempo, readback e ricevuta. Fixture nativa CI: catena reale broker, preparer e driver su runc finto e nft simulato, come nel task-25 | firme, start, tabelle nft (dal driver) | ogni drift del §2; budget superato; generazione ambigua |

**Ordine:** 35 → (review con l'umano di D1-D3) → 36 → 37 → 38 → plan di 37 e plan di 38 → apply di 38 entro metà dicembre (D-032).
