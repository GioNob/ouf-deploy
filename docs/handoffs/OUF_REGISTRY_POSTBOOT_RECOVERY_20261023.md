# Handoff — recovery finito Registry dopo riavvio, 23 ottobre 2026

Aggiornamento loader del 23 ottobre: il primo tentativo VPS si è fermato prima dell'entry applicativa su `INTERPRETER_STDLIB_SYSCONFIG_ORIGIN_REQUIRED`. La correzione riconosce modulo/pacchetto sysconfig soltanto nella stdlib esatta dell'interprete. Sorgente `47899a153f1e2c84f778b67564a8c952d8323c35`, capsule `05caff5cf8b75617b2d407a8f2eefdcf116a664f`, SHA256 `75162f0e9f1e3848392b23c1754751b18a45c529ce139e0550c347de0c67b17a`; i 105 moduli applicativi restano identici. CI loader 20 PASS su Python 3.12 e 20 PASS su 3.13, incluso preload completo senza entry. Per i pin attuali usare `docs/handoffs/OUF_REGISTRY_POSTBOOT_PREPARE_REVIEW_OPERATOR_20261023.md`; le consegne precedenti riportate sotto sono storiche. Nessun ripristino VPS o rinnovo continuativo attestato; sessione proposta sempre ≤900 secondi. La CI del commit di consegna è da osservare separatamente, non inferita dalla prova sorgente.


## Stato e obiettivo

Il percorso sorgente copre preparazione privata, review completa, emissione dell'autorità corrente, ledger, bootstrap del gate, successore token owner e prosecuzione fino al GET originale. **Composizione nativa JVM qualificata; nessuna esecuzione di riparazione VPS o risoluzione del 502 attestata. Consegna qualificata prepare/review pubblicata e riletta esattamente.** Commit/hash della consegna e risultati devono essere registrati prima di presentare il pacchetto operatore come qualificato. Il numero di test superati non equivale a riparazione.

Il criterio funzionale è `GET /api/semantic/v1/references:resolve`, attraverso il Gateway configurato e con il SERVICE Ingestion esistente, per tutti i binding congelati: HTTP 200 e corrispondenza esatta di `semantic_id`, `semantic_version`, `revision_id`, `publication_set_id`, `status=ACTIVE`. Health del MCP, health del Registry o JVM avviata non provano questo risultato. Release acceptance resta distinta. Supervisor ed E2E completi non sono prerequisiti della verifica mirata del 502.

## Lineage target già riconciliato

La [ricevuta](../../evidence/semantic-registry-bound-owner-lineage-target-20261023.json) proviene dall'upload operatore `Testo incollato(20261023-072425).txt`, SHA-256 `46fe0f2abf1c98b8b70a325f20044f05368f357c9b84d9258f8d2eb0073dcb35`; non è una lettura indipendente corrente dei file privati. Log target: `/home/oufadmin/ouf-registry-bound-lineage.nRKey7gD/operator.log`. La catena pubblica unica, aciclica e non ramificata è `15 → 16 → 0 → 1 → 14 → 17 → 3 → 2 → 4 → 10 → 13 → 12 → 9 → 8 → 5 → 7 → 11 → 6`.

| Binding | Valore |
| --- | --- |
| Anchor | Ordinale 4, `postgrant-worker` |
| Terminale | Ordinale 6, `semantic-functional-worker-4d73f23481b322c6fc046734f9a50a7251ddafe5d6d3d794129d9728305e8ad6` |
| Cumulativo controllato | **319**: predecessore 318 + 1 tentativo terminale; non sommare i cumulativi |
| Hash recovery terminale | `aed77a73d69ea8d865df1097a9d9e5c3e230445ae8a7fd95857575318fb473ab` |
| Hash sessione terminale | `386d52ccc5847aa17c08d879df4f58e52902bf3c8423712e85a14c377d3aa468` |
| Hash binding output credenziali | `b98834371be7688cf0085a6a52dc695b96820e9871d702526255f00a8aad5032` |
| Hash scope logico owner | `7cb59501000058b5dc5030adf8624c5b38567de0c8bfeb21dd49435644ea3da2` |

Parent esatto: `/etc/ouf/deploy-snapshots/chatbot-file-intake-9f754dbcf7caf450d1d1eef50c0288f2102cfac191a65cfc60a5c1fcbf60ba5e/attempt-f8d38137fc4cca9d36910c19/`. Tutti i 18 record sono `CANCELLED/BLOCKED` e di boot precedente. Nessun owner corrente è selezionato/ammesso. La contabilità legacy non riconciliata resta `null`, non zero; il budget HUMAN storico esaurito è distinto dal SERVICE 319. Nessun grant o nuovo budget deriva dal solo conteggio. **Non rilanciare discovery o reader conclusi.**

## Input e consegna

Entry: `postboot_entry.execute(case, manifest, sources, argv)`. Il case esterno contiene soltanto `schema: ouf.semantic-registry-postboot-recovery-case.v1` e `preparation`. Quest'ultimo usa `ouf.semantic-registry-postboot-preparation-case.v1` con `privateParent`, `retainedInputs`, `historicalReview`, `patchContext`, `lineageReceipt`, `predecessorJournalPath`, `frozenReference`, `proposedOwnerBudget`, `originalRequestTls`. Parent, path/hash conservati, receipt completa e terminale ordinale 6 devono essere esatti. Il budget proposto ammette **massimo 1 nuovo tentativo SERVICE**, owner per **1–900 s**, timeout 1–30 s entro la durata e intervallo esplicito. HTTPS richiede origin/CA/pin indipendenti; HTTP interno deve corrispondere all'IP osservato del Gateway.

`delivery.generate(root, case, source_commit, source_pins)` crea offline capsule e dichiarazione; `runtime.py` verifica byte/hash/path/Git blob/import dell'intera chiusura prima dell'entry, senza fallback a moduli installati. La capsule richiede root e Python `-I -B -S`. Questo handoff documenta l'interfaccia, non contiene un comando target con hash inventati: il pacchetto definitivo deve legare una sola capsule al commit qualificato e al case verificato.

La preparazione è deterministica per case/chiusura/boot; crea il claim privato prima delle richieste e conserva anche gli esiti incompleti. Limiti: massimo 12 Engine GET, 1 Admin GET, 1 GET della configurazione congelata. Usa il bearer Ingestion e la credenziale Admin senza stamparli; per il client secret dell'owner verifica solo metadati/custodia. Nessuna richiesta DB/OAuth o effetto runtime. Conserva nuovi input e copie sorgente privati senza riscrivere i record precedenti.

## Sequenza concreta

| Ordine | Argomenti capsule | Ricevuta o arresto atteso |
| --- | --- | --- |
| 1 | `prepare` | `CURRENT_POSTBOOT_INPUTS_PREPARED`, path/hash preparazione e chiusura; nessuna autorità |
| 2 | `review` | `COMPLETE_PRIVATE_POSTBOOT_REVIEW_PREPARED`, path review, `reviewHash`, proposta budget; nessuna firma |
| 3 | `issue REVIEW_SHA256` | `ouf.semantic-registry-postboot-issued-authority.v1`; decisione fresca e due firme dei ruoli esistenti |
| 4 | `install REVIEW_SHA256` | `CURRENT_BOOT_RECOVERY_LEDGERS_INSTALLED`; solo nuovi ledger, nessun runtime/OAuth |
| 5 | `bootstrap REVIEW_SHA256` | Checkpoint 4, `freshPausedGateObserved: true`, `javaReleased: false`; start/prova/pause del gate |
| 6 | `owner REVIEW_SHA256` | `ouf.semantic-registry-postboot-owner-installed-result.v1`; successore corrente, precedente 319, nessun OAuth |
| 7 | `continue REVIEW_SHA256` | Worker finito, ammissioni native, eventuale GET positivo nella finestra, poi fine sessione |
| Facoltativo | `status` | `PREPARATION_PRESENT_NO_RUNTIME_OBSERVATION`; solo artefatti, nessuna prova di salute |

Hash obbligatorio per **issue, install, bootstrap, owner, continue**, esattamente quello pubblicato da `review`; non l'hash di un JSON editato, del solo case o di una review storica. `prepare`, `review`, `status` non lo accettano. Attendere la ricevuta attesa di ogni passo prima del successivo.

`postboot_authority.terminal_decision` richiede, dopo review pronta, la riga `APPROVO <hash-esatto>` sul `/dev/tty` di controllo. È una decisione corrente vincolata a review e chiusura, non un consenso generico alla diagnosi. Un claim canonico viene consumato prima delle due firme; una firma parziale non rende il claim riutilizzabile. Restano profili di fiducia e ruoli esistenti, senza chiavi aperte dal cloud. Gli 11 scope sono ricompilati dagli input reali e il mandato lega anche la review esatta; i dati per compilarne gli hash non sono owner permissivi o prove runtime.

## Bootstrap, ammissione e concorrenza

Il prefisso ammette solo verifica, start della shell in attesa, prova della prima nuova generazione catturata durabilmente e pause; si ferma al checkpoint 4. Non pretende un owner ACTIVE prima dello start e non concede grant o SIGUSR1. Il successore owner è poi vincolato a questa generazione, boot corrente e terminale storico; mantiene prima ricevuta grant, accounting e predecessore. Il fence successore deriva dal fence esatto precedente ed esclude writer concorrenti. Mai riscrivere boot/orologi/stati storici o adottare un processo trovato ACTIVE.

`continue` parte da checkpoint 4, esegue il worker reale con lock d'invocazione e coordina i passi nativi nello stesso processo. Proposta: precedente 319, massimo cumulativo 320 se il singolo nuovo tentativo viene autorizzato e consumato; non è un budget già concesso. Timeout/esito incerto non creano un altro tentativo. Owner ≤900 s, subordinato a autorità, clock e token. Prima del rilascio restano obbligatori rootfs OCI indipendente completo, frame/mount, processo/namespace, PostgreSQL/Flyway readonly, owner corrente ammesso, attestazione fresca, route complete ed endpoint. Poi unpause, prova dello stesso gate, unico SIGUSR1, readiness e GET originale. Un vecchio attestato non ammette un PID nuovo.

## Startup lento e HTTP 403

Dopo SIGUSR1 con risposta Docker 204 registrata, il controller può osservare ai checkpoint 9–11 la transizione shell/JVM, readiness e richiesta finale: **una finestra condivisa di 90 s per iniziare al massimo 12 osservazioni aggiuntive**, normalmente ogni 5 s. I trasporti in corso mantengono i propri timeout. Non si estendono autorità o contatori durabili. Il lock di coordinamento è rilasciato tra osservazioni, mentre il worker mantiene quello d'invocazione; ogni passo ricontrolla owner, autorità, clock, generazione e prerequisiti.

**403 non distingue policy assente da diniego effettivo della capability.** Resta non riuscito e può soltanto essere osservato nuovamente entro il limite con lo stesso SERVICE. Non si presume transitorio e non si cambiano identità, scope, policy, freshness o budget. Anche 429/502/503/504 non passano. Solo il 200 esatto con tutti i binding ACTIVE completa la verifica; 401, redirect e mismatch non sono accettati. ACK mancante, eccezione, PID cambiato, movimento concorrente del journal, scadenza o budget esaurito richiedono arresto/riconciliazione, senza ridispatchare effetti.

## Risultati e arresto

`ORIGINAL_SERVICE_GET_200_WITH_FINITE_OWNER` è una ricevuta intermedia: prova il GET durante la finestra indicata da `ownerWindowEndsNoLaterThanUnix`. Il processo mantiene poi il worker per il residuo consentito. La receipt finale `ouf.semantic-registry-postboot-finite-session-result.v1` distingue `originalSemanticGetSucceededDuringWindow` da `ownerSessionEnded: true`, `currentOwnerAdmissionProven: false`, `continuousServiceRenewalEstablished: false`, `releaseAcceptance: false`. La fine della sessione non prova continuità durevole o resilienza al prossimo reboot. Le sole scadenze finali provate sono `FINITE_PUBLISHED_TOKEN_WINDOW_ENDED`, `FINITE_OWNER_OPERATION_WINDOW_ENDED` o `FINITE_OWNER_AUTHORITY_WINDOW_ENDED`; un'eccezione o terminazione non giustificata produce `UNEXPECTED_OWNER_TERMINATION` e `POSTBOOT_OWNER_TERMINATION_REQUIRES_RECONCILIATION`, anche dopo un GET positivo.

Su `STOP_RECONCILE` fermare la sequenza e conservare capsule, contesti, review, receipt, journal, claim, fence e log. `runtimeEffectsMayBePartial` non autorizza ripetizione dei cinque modi firmati. `status` inventaria soltanto gli artefatti. Nessuna pulizia, nuova directory, modifica in-place o budget reset può aggirare un claim consumato. La continuità oltre la sessione è un lavoro successivo esplicito; questa patch non installa un daemon e non trasferisce responsabilità Kubernetes al Supervisor.

## Riferimenti e qualificazione

**Aggiornamento delle ripetizioni CI:** il PASS sorgente `2d860631` (157 test) resta acquisito. Sul commit artefatto `03b995`, run [39930134921](https://github.com/GioNob/ouf-deploy/actions/runs/39930134921) PASS ma [39930140686](https://github.com/GioNob/ouf-deploy/actions/runs/39930140686) JVM FAIL; sul wrapper `5508e26`, [39930802948](https://github.com/GioNob/ouf-deploy/actions/runs/39930802948) e [39930808509](https://github.com/GioNob/ouf-deploy/actions/runs/39930808509) hanno 158 componenti + 8 native PASS e JVM FAIL. I tre errori sono `BlockingIOError(11)` nella lettura finale del journal del worker, riga 677 della fixture, mentre il worker è ancora attivo. Il lock non bloccante di produzione resta obbligatorio; è in verifica una correzione della coordinazione della sola fixture. **Alla generazione di questo documento, la qualificazione della correzione della fixture è pendente; un PASS del final head non viene inferito.** Il controller di produzione legge già il journal sotto RLock e, dopo la scadenza, dopo il join: non è dimostrato lo stesso difetto in produzione. Pubblicazione/readback e perimetro qualificato prepare/review restano validi; questa attesa CI non aggiunge un gate runtime. Il risultato successivo sarà registrato separatamente.

Qualificazione sorgente `2d860631ffaf837e15de0f8d5e285fe415fe0486`, [CI39929330813](https://github.com/GioNob/ouf-deploy/actions/runs/39929330813): **148 componenti + 8 native prefix/owner + 1 JVM PASS, zero skip**. Log verificati; la JVM impiega 157,064 s. La fixture prova 502 iniziale → stesso GET SERVICE congelato 200/ACTIVE, un grant 319→320 e i quattro effetti esatti start/pause/unpause/SIGUSR1, con rootfs OCI indipendente completo. Usa direttamente bootstrap/owner/factory/runner: non tutta la capsule CLI né il controller fino a fine finestra. Docker/containerd, JVM, PostgreSQL17, Ed25519/TLS/RS256 e policy sono reali; HUMAN/IAM/fence e dati sono fixture, il proxy Python riproduce il canale APISIX e l'immagine contiene una CA disposable. Nessuna prova di salute VPS o rinnovo durevole. Tutti i fallimenti precedenti restano nella [evidence CI](../../evidence/semantic-registry-postboot-ci-20261023.json).

La correzione di produzione limitata al recovery legge `/proc/PID/mountinfo` fino a EOF, mantenendo limite 131072 byte, guardie e quattro predicati mount originali; l'osservatore condiviso è invariato. Il probe nativo mostra prima lettura 3946 byte, tabella completa 5739 e tutti i predicati completi validi: una lettura corta non era EOF. Il fix separato del controller conserva il GET storico ma segnala STOP se l'owner termina inaspettatamente dopo il 200; non maschera il crash come scadenza normale.

Capsule della sorgente qualificata: SHA-256 `6c76312c07e6eaffdafe22d885a10dce5f34cf93d7866153f0097619293decf5`. [Artefatto pubblicato](https://github.com/GioNob/ouf-deploy/blob/03b995cf0da3ab93a30f82f5c1ee6080ab739ab7/releases/semantic-registry-postboot-20261023.py) nel commit `03b995cf0da3ab93a30f82f5c1ee6080ab739ab7`: quattro file riletti dal repository e identici. Il [wrapper prepare/review](../../releases/semantic-registry-postboot-prepare-review-20261023.sh) è fissato a questo artefatto, alla sorgente e allo SHA-256 sopra; **9 test shell locali PASS**, wrapper SHA-256 `c36a48dba432e6befa4e3d7ff986f93532fedb99637cc8f68ca195e539620022`. Il [wrapper pubblicato](https://github.com/GioNob/ouf-deploy/blob/5508e26cdbd9400679e7e75b0ab2459866de7a74/releases/semantic-registry-postboot-prepare-review-20261023.sh) è al commit `5508e26cdbd9400679e7e75b0ab2459866de7a74`, SHA-256 `c36a48dba432e6befa4e3d7ff986f93532fedb99637cc8f68ca195e539620022`: tutti e tre i file della consegna riletti identici, 9 test shell locali PASS. Il prossimo passo operatore qualificato è **solo prepare/review**; non emette autorità né esegue recovery. Il wrapper ammette soltanto `prepare-review` oppure `review`, in interpreti separati: nessuna autorità o effetto di recovery. Sorgente, readback e test shell non equivalgono a qualificazione nativa di tutta la CLI.

Fonti: [README](../../tools/semantic_registry_recovery_execution/README.md), moduli `postboot_entry`, `postboot_prepare`, `postboot_authority`, `postboot_scopes`, `bootstrap`, `postboot_factory`, `postboot_controller`, `semantic_request`, `runtime`, `delivery` e `tools/semantic_registry_postboot_owner/`. [Dossier incidente](../OUF_SEMANTIC_502_EVIDENCE_AND_REPAIR_20261023.md), [reinvestigation](../../evidence/semantic-502-reinvestigation-20261023.json), [reader lineage concluso](OUF_REGISTRY_BOUND_OWNER_LINEAGE_READMESPEC_20261023.md).

La [qualificazione precedente native path](OUF_SEMANTIC_REGISTRY_NATIVE_PATH_20261023.md) a `f5937486fcfe1e461caed65abf45ca49887ca33f` include gate Alpine e owner sintetici dichiarati; non qualifica nuova capsule, JVM AUTHZ o VPS. Il [perimetro controller](../../tools/semantic_registry_recovery_execution/tests/CONTROLLER_QUALIFICATION.md) distingue test locali e collaboratori simulati. Nuovi risultati devono distinguere sostituti, Docker/DB/TLS/JVM reali e target. Il PASS riguarda la composizione nativa e i componenti indicati, non la CLI completa o il target.

Contratti preservati: Matrix 1.7 §1; Registry PET 1.3 §§150.1–150.2, 160.6–160.7, 160.15; caller Ingestion `PublicationGatewayClient`/`FrozenConfigurationProbe`/`PublishedActivation` verificato a `4165b9e149be467d5d7c6bed35e4e1af4e249db1`. Nessuna activation, provider recovery, migrazione DB, modifica Gateway o deroga AUTHZ. Per chiudere il 502 servono ricevute target e GET SERVICE esatto; per dichiarare disponibilità continuativa serve ulteriore evidenza.

I flag `operatorWrapperProvided: false` e `wholeNativeRecoveryQualified: false` nell'audit pubblicato delle sorgenti descrivono il momento della generazione e il suo perimetro source-only. Restano conservati; CI nativa e wrapper successivi hanno evidenze separate e non costituiscono una qualificazione dell'intera CLI.

La [pagina operatore prepare/review](OUF_REGISTRY_POSTBOOT_PREPARE_REVIEW_OPERATOR_20261023.md) contiene la consegna ristretta con i pin e la verifica hash. Non duplicare tale wrapper né usarlo come launcher dei modi di autorità/runtime.
