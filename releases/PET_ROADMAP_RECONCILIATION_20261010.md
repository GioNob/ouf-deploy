# Punto PET e roadmap — 10 ottobre 2026, 08:34 CEST

Il percorso corrente è coerente con l'ownership e i confini della baseline v1.7, nel perimetro verificato. **La conformità completa dei sette PET e l'accettazione della piattaforma non sono ancora dimostrate.** Il residuo comprende codice, integrazione, superfici umane e prove operative: non è soltanto configurazione IAM.

Fonte normativa: Blueprint L0 v0.3, Matrix v1.7 e Supersession Notice v1.1, quindi PET Onboarding/THS1.6, Authorization1.5, Gateway1.5, Ingestion1.3, UDP/Lake1.3, Semantic1.3, MCP1.4. Sono stati consultati tutti i sette PET per ownership, sicurezza, activation/startup, recovery e acceptance, confrontati con gli alberi main, roadmap, registri e CI nominati. Questa riconciliazione non è una riesecuzione di ogni acceptance test. I323 checksum della baseline erano già verificati; quella decisione non viene riaperta.

[Snapshot di commit, CI, stati e rilievi](../evidence/pet-roadmap-reconciliation-20261010.json). La roadmap del16 settembre è uno snapshot storico: le sezioni successive del registro centrale e le prove nominate la superano nel rispettivo perimetro.

## Stato per PET

| PET | Risultato disponibile | Residuo che impedisce la chiusura |
|---|---|---|
| Authorization1.5 | R1a/SDK e AUT-01/02 chiusi nel registro; amministrazione governata, valutazione locale e enforcement owner; IAM reale provato sul gate Onboarding nominato | AUT-03/04 parziali: tutti i domini/canali, rotazione/revoca, assurance e accettazione IAM completa |
| Onboarding/THS1.6 | ACTIVE/versioni, review umana, managed formats, browser review e permessi; R2f ha una prova di deployment circoscritta | Discovery sorgenti, superfici cross-module/protected operations/log store, gate di scala/restore e tutti i formati nel downstream |
| Ingestion1.3 | Admission automatica R2a; CSV/REST R2b, pubblicazione/replay R2c e GIS R2d/e tra owner reali con fixture dichiarate | ING-01/02/03 parziali/aperti; raw replay completo, OA persistente/catch-up, profili GIS; latest module CI presenta errori reali del test worker |
| UDP/Lake1.3 | Identity/resolution, serving e lineage autorizzati, riferimenti storici e fondazioni CRS/GeoPackage | 69 righe dichiarate:48 VERIFIED,16 PARTIAL,3 VERIFIED-LAB,2 EXTERNAL-OPEN; capacity, concurrency, cold history, traversal/budget e scenari completi restano da chiudere; alcune prove MinIO/DR non riproducibili |
| Semantic1.3 | Discovery/adoption/publication governate e R2c; candidato firmato remediato; V1–V9 identiche e V10 additiva; Flyway effettivamente installato e candidato, backup/restore corrente di fixture PASS | Closure del nuovo peer, backup fresco e recupero governato target, provider reale, job/limits/upstream lifecycle e capacity/DR completi |
| Gateway1.5 | Mediation/control plane, route IAM/MCP e confini north/south; native packet/DNS/lease tests; due flussi R9 attivati sul VPS | APISIX/etcd HA/LKG/quorum/restore/carico rappresentativi; route discovery additive e nuova autorità transport/profile; nessuna accettazione ricavabile dalla sola lease |
| MCP1.4 | SDK/authorization/owner API channel-neutral e OA; permessi/proposte; candidato con search/file/Semantic e tre descriptor discovery INACTIVE | Catalogo completo dietro owner/Gateway/grant/readiness; OA di tutti i moduli e client disconnected catch-up; interoperabilità/HA/DR e percorso umano finale |

Gli stati UDP sono classificazioni del repository, non69 recertificazioni di questo controllo. Il registro centrale conserva AUT-01/02 CLOSED; AUT-03/04 e i gruppi cross-module sono PARTIAL/OPEN. Le parti già consegnate non vengono riaperte in assenza di nuova evidenza.

## Roadmap riconciliata

| Tranche | Stato corretto oggi | Criterio ancora necessario |
|---|---|---|
| R0 | CHIUSO nel perimetro originario | Conservare il pairwise autenticato e le prove pinned; il vecchio403 non è il blocco corrente |
| R1a | CHIUSO nel perimetro SDK/adapter/conformance | Conservare default deny e backend deny |
| R1b | Implementato con gap owner/ambiente | Tutti i domini/canali, IAM lifecycle e acceptance completi |
| R2a–R2f | Verticali implementate e verificate nel perimetro dichiarato; R2f include deployment Onboarding | Non estendere prove CSV/REST/GIS a ogni formato, tutte le superfici o intera produzione; riportare rosse latest CI |
| R3 | Aperto, baseline operativa parziale | Fault offline → incidente persistente → retry/dedup/recovery → catch-up autorizzato; retention/misfire/tutti i producer |
| R4a | Parziale; browser review/permessi e tranche catalogo esistono | Discovery nazionale usabile e percorso proposta→decisione THS→owner; map UI e protected operations cross-module |
| R4b | Aperto sui residui di dominio/GIS | Profili/formati, job/limits, cold/history/capacity e criteri puntuali |
| R5 | Parziale; supply chain e guard/native gates avanzati | Applicatore N/N+1, recupero, conformance e package operativo per combinazione candidata |
| R6 | Aperto |25 E2E canonici, OA/OA-CN, suite locali PET, ambiente/HA/fault/load/restore/RPO/RTO e verifica umana nominata |

L'attività attuale è una verticale R2c/R4a sostenuta dai gate R5 e dall'ambiente R3a. Non è uno sprint che sostituisce la roadmap generale. Cinema e l'asset Teatri già acquisito rimangono la base da conservare; nessun reupload o nuovo mapping implicito.

## Verifica di coerenza

1. **Ownership preservata:** Semantic possiede semantica/pubblicazioni; Onboarding possiede mapping e bundle; Ingestion acquisisce con riferimenti pinned; UDP risolve/materializza; Authorization valuta e gli owner applicano il controllo fine; Gateway media; MCP proietta capability. Nessun servizio Authorization sincrono, incident hub o Agent interno è stato introdotto.
2. **Human authority preservata:** MCP può proporre e restituire riferimenti opachi; approve/activate/publish e protected log operations restano THS→Gateway→owner (MCP§122, Onboarding§109.8, Matrix§1/7). Il consenso operativo R9 in chat non sostituisce una decisione di pubblicazione semantica o un grant applicativo.
3. **Rete fail-closed:** Semantic§160.6 e GatewayT11/T33 richiedono Gateway southbound e allowlist. R9 ha aperto soltanto i due flussi approvati con lease finita, niente lifecycle o boot enablement. La ricevuta non dimostra connettività/provider health continuativi. Claim consumate: nessun replay.
4. **Compatibilità e storico:** V10 è expand-compatible; library-level Flyway e current-snapshot restore PASS soddisfano una parte di Semantic§160.2/5/12. Non certificano full Spring startup, snapshot/reference reconciliation, WAL/PITR/RPO/RTO o target restore. Dopo nuove scritture il backup pre-V10 non può essere ripristinato ciecamente.
5. **Peer e recovery:** un vecchio ifindex non è un'autorità permanente. Il compilatore dell'inversa verifica digest, footprint e generazioni; il vecchio veth assente o ricreato richiede nuova closure. È un'applicazione dei binding e del default deny, non una nuova prescrizione arbitraria dei PET.
6. **Capability/readiness:** i descriptor discovery del candidato rimangono INACTIVE fino a route, identità/grant owner e readiness; nessun fallback locale per rendere la demo verde. Vale Semantic§160.15, UDP§109.7 e Onboarding§109.17.
7. **OA ancora incompleta:** lo status PUBLIC_OPERATIONAL corrente di MCP descrive MCP; non basta a certificare lo snapshot di tutti i moduli richiesto da MCP§33/Matrix§6. Ingestion§46 richiede stesso incidentId nella recovery, misfire distinguibile e retention almeno30 giorni: i documenti attuali lasciano queste prove aperte.

## Rilievi nuovi e tracciabilità

- Ingestion main a8ba969…: [run36423996284](https://github.com/GioNob/ouf-ingestion-runtime/actions/runs/36423996284), job108933344141,92 test con3 failure e1 error in RunExecutionWorkerRuntimeTest. Il log mostra attese PAUSED/SUCCEEDED e mismatch ingestionRunId. La causa non è ancora determinata; non la classifico come semplice flakiness. Le precedenti prove verdi restano storiche.
- R2b/c/e Ingestion e module/DR UDP: pull di quay.io/minio/minio:RELEASE.2025-09-07T16-13-09Z fallisce unauthorized. Latest esiti non riproducibili: [Ingestion R2b](https://github.com/GioNob/ouf-ingestion-runtime/actions/runs/36423996047), [UDP](https://github.com/GioNob/ouf-udp-object-resolution/actions/runs/36334165297). Va ripristinata una fixture storage governata, con pin/provenance; nessuna sostituzione permissiva o waiver.
- Semantic main d188e5… ha una latest module run cancelled, con precedenti success sullo stesso SHA e pairwise success. Il candidato firmato403531… resta distinto da main e ha proprie evidenze: non si confondono le combinazioni.
- Alcune intestazioni di tracciabilità citano versioni PET precedenti: Onboarding1.5, Ingestion1.2, Gateway1.3 e Matrix1.6 in note storiche. Questa riconciliazione fissa le versioni applicabili; non rinomina l'evidenza storica.
- La vecchia assenza totale di browser THS è superata dai file ths/r2f e ths/permissions e dalla loro CI. L'intera THS comune resta aperta.
- Main MCP oggi dichiara dieci descriptor tool/proposal eligible, non i sette del primo audit. Il candidato3ba1d4… ne dichiara21 totali:17 eligible ACTIVE,3 eligible INACTIVE discovery e1 TRUSTED_HUMAN_ONLY non eligible. Il manifest dichiarato non è una prova di pubblicazione sul VPS.

## Sequenza confermata per l'attività corrente

Incremento iniziale autorizzato, completato nel seguito delle08:50: avvio **completo Spring** del Semantic candidato sull'ambiente isolato con V1–V9, upgrade V10 e database corrente ripristinato, senza disabilitare IAM o trasformare un provider mancante in salute inventata. Anche la compatibilità dell'applicazione precedente sullo schema aggiornato è ora verificata nella fixture. Proseguono custodia/fencing/backup fresco, closure firmata del peer e coordinazione lease, applicatore concreto e revisionabile.

Prima del cutover target restano necessari readiness, nuove autorità operative nel perimetro concreto, credenziali private e binding reali. Dopo il cutover: nuova policy/grant HUMAN ove richiesto, route additive che preservano Cinema, attivazione dei descriptor e prova reale CLASS/teatro/it,en → stato/candidati → adozione/pubblicazione governata → mapping ACTIVE → ingestione/serving. La lease R9 non viene riapplicata.

Gli errori Ingestion/storage sono registrati nella roadmap di rilascio e vanno risolti prima di dichiarare il percorso completo accettato; non impediscono la preparazione isolata del cutover Semantic/MCP già autorizzata.


## Seguito 10 ottobre, 08:50 CEST

Il gate isolato di avvio completo ora è PASS: [CI38032196847](https://github.com/GioNob/ouf-deploy/actions/runs/38032196847), [evidenza](../evidence/discovery-full-spring-startup-qualification-20261010.json). Quattro avvii dei JAR effettivi precedente/candidato su baseline V1–V9 e V10 corrente ripristinato; IAM/JWT/policy attivi, quattro ricerche consentite e24 rifiuti verificati. Storico e scritture successive preservati. Provider/worker disabilitati nella fixture: nessuna nuova accettazione di provider, target o intero PET. Il prossimo lavoro è applicatore con backup fresco/custodia/fencing e closure autenticata del peer, coordinato al worker R9. Gli altri gap e i blocchi Ingestion/storage rimangono aperti.


## Seguito 10 ottobre, 09:55 CEST — database e accesso R9

La verifica dei writer ha individuato dieci connessioni del vecchio `ouf-semantic-r4a-smoke` oltre alle dieci del Semantic principale. Lo smoke è stato fermato e conservato, senza rimozione o riavvio e senza modificare Semantic principale o R9. La rilettura indipendente conta ora dieci connessioni, tutte del principale. Non riavviare lo smoke prima della revisione della compatibilità dello schema.

Sono PASS sei prove native di fencing e quattro di backup su PostgreSQL 17 isolato, con vero dump e restore su database nuovo: [run38035267718](https://github.com/GioNob/ouf-deploy/actions/runs/38035267718), [evidenza](../evidence/discovery-database-fence-backup-qualification-20261010.json). La chiusura delle nuove connessioni precede il fencing completo e non basta da sola; un backup non viene accettato durante il solo stato parziale. Le prove comprendono guasti/SIGKILL, transazioni preparate, archivio corrotto, preservazione di righe e sequenza e divieto di sovrascrivere scritture successive. Nessun fencing, backup nuovo, migrazione o restore è stato eseguito sul database target.

La lettura fresca di R9 è pronta e supera quattro prove di scope. Il tentativo sul runner [38035986086](https://github.com/GioNob/ouf-deploy/actions/runs/38035986086) restituisce `OPERATOR_SUDO_REQUIRED`: non è una prova di worker corrente attivo. Serve solo l'esecuzione locale del launcher [current-r9-transition-read-20261010.sh](current-r9-transition-read-20261010.sh) con password sudo dell'operatore; nessuna nuova autorizzazione di apply viene richiesta. Il programma legge stato e custodia di R9 e ingress condiviso senza lock, DNS, chiavi, firme, restart o replay.

Coerenza PET confermata nel perimetro di preparazione: owner/auth e approvazione HUMAN restano separati dalla delega operativa; custodia, provenance e fail-closed conservati; Cinema e asset/profilo Teatri preservati. Nessun gap PET viene chiuso da questi test e l'applicatore di produzione completo resta da comporre dopo la lettura target.


## 10 October — R9 read completed and private runtime input preparation

The operator's 10:50 CEST read captured the unchanged existing peer/profile/source bindings and R9 LEASE_ACTIVE at refresh643. The 15ms minimum TTL is an observation, not continuous liveness. R9 remains sealed and consumed; observers acquire no lease lock. [Target evidence](../evidence/current-r9-transition-active-target-20261010.json).

The replacement configuration delta takes JVM defaults from the signed candidate, discards legacy JAVA_VERSION metadata and retains application overrides plus the two existing read-only consultation/auth mounts. No unreviewed explicit override remains; imported Spring configuration is still uninspected. [Configuration evidence](../evidence/semantic-replacement-configuration-target-20261010.json).

Read-only IAM queries confirmed the existing confidential service-account client ouf-semantic and gateway.southbound.invoke scope. Its unchanged client secret was copied to a new private user-owned snapshot, not installed or rotated. Main Gateway process metadata identifies OpenResty UID/GID636. [Custody evidence](../evidence/semantic-workload-custody-stage-target-20261010.json). The earlier alias-parser denial remains retained with its actual partial-read scope; it was not a reason to alter the IAM client.

The next [immutable launcher](application-runtime-input-preparation-20261010.sh) needs operator sudo only to prepare new root-protected runtime inputs. It freshly validates the exact IAM profile/credential and source generations, verifies the existing public provider CA/leaf/hostname, then uses an exclusive one-use claim. It copies the existing OAuth credential for Semantic UID10001 and generates one distinct discovery MAC with two role-owned copies for Semantic10001/Gateway636, all secret copies0400. No authority key, TLS private key or consultation key is opened; no credential rotation, IAM grant change, mount, restart, image import, database change, firewall change or R9 operation occurs. A claimed preparation must never be replayed or reset. [Native custody qualification](../evidence/application-runtime-input-preparation-qualification-20261010.json).

The production applicator, Java truststore, replacement complete OCI/reciprocal peer, new signed transport/profile/source closure, additive routes and governed HUMAN/readiness remain open. No descriptor activation, national flow, full PET acceptance or production health is claimed. Original roadmap gap states, Cinema and managed Teatri assets are preserved.


## 10 October, 13:15 CEST — runtime custody mount correction

The operator's first preparation was blocked before output directory creation or claim consumption: EXACT_READ_ONLY_SOUTHBOUND_CERTIFICATE_REQUIRED. Three administrative IAM GET/logins ran; no existing configuration, key, service, grant, database, firewall or R9 change occurred. [Retained target denial](../evidence/application-runtime-input-preparation-blocked-target-20261010.json).

The previous preparer incorrectly expected a separately mounted server.crt. The admitted southbound embeds TLS into its read-only APISIX config.yaml. The corrected preparer requires the exact OCI bind mount, policy source hash/UID/mode, live Docker read-only mount and original startup/trust receipt chain before selecting the public CA and leaf certificate. It never opens that APISIX configuration, which contains private TLS material. The exact live mount was independently reread by the self-hosted runner without root or file access; native ownership and four public-trust binding/denial tests pass. This is input custody, not a live TLS handshake or application health proof. The new immutable launcher can be run because the rejected attempt consumed no claim; no consumed R9 apply is repeated. Full cutover and PET acceptance remain open.


## 10 October, 13:22 CEST — OCI read-only predicate aligned with the admitted compiler

A second operator attempt rejected the OCI configuration mount before output/claim creation. Three IAM administrative reads/logins ran; no existing configuration, grants, services, database, firewall or R9 change occurred. [Retained denial](../evidence/application-runtime-input-preparation-oci-blocked-target-20261010.json).

The admitted creation-frame compiler accepts ro or recursive read-only rro. The runtime-input preparer incorrectly required ro alone. It now uses the same read-only predicate while rejecting rw and missing read-only options, and still requires exact source, live read-only Docker mount and original startup/trust bindings. Source custody is read from the immutable original creation frame (hashf49155…), separately from the network policy; its expectedOci must equal the already hash-bound complete OCI. No fallback to unbound source metadata is permitted. Nine native custody/binding tests and three delivery tests qualify the corrected preparation; full target root preparation and application health remain unproven. Neither rejected attempt consumed a claim. Original PET gap states are preserved.


## 10 October, 14:03 CEST — protected runtime inputs prepared; Java trust next

The operator's one-use preparation succeeded. Root snapshot semantic-discovery-runtime-inputs-682nr5ky holds the unchanged existing workload credential for UID10001, one distinct discovery MAC in role-owned0400 copies for Semantic10001/Gateway636 and the verified public provider CA. Manifest hash732a633e… is bound in [target evidence](../evidence/application-runtime-inputs-prepared-target-20261010.json). The claim is consumed: never rerun/reset the runtime input apply. No mount, application lifecycle, import, database/firewall/grant/signature or R9 operation occurred; application health remains unproven.

The exact signed Semantic archive was then rehashed and its image configuration bound to b1a7956a…. Four archive/whiteout/link tests pass; the self-hosted reader captured candidate public cacerts hash98d34a90… without importing or running images. This preserves the candidate's own public roots rather than substituting the installed JVM defaults.

Native Java21 keytool/PKCS12 and trust-manager qualification accepts baseline plus provider roots and rejects an unknown CA. Actual disposable Docker qualification verifies network none, readonly rootfs, cap-drop ALL, no-new-privileges, bounded memory/PIDs, role UID10001, no overwrite and removal of only the temporary tool container. [Evidence](../evidence/application-java-trust-preparation-qualification-20261010.json).

The next [immutable Java trust launcher](application-java-trust-preparation-20261010.sh) needs operator sudo to read the already prepared public CA and write a new protected truststore. It creates/removes one offline keytool container from the exact already installed Java21 image; imports no images and changes no application, database, firewall, IAM grant, consumed discovery-input claim or R9 state. Candidate baseline/public CA hashes and the primary generation are reread. It assigns the merged public-only PKCS12 to UID10001 mode0400 and consumes its own separate one-use claim. It mounts nothing into an application. Full replacement configuration/OCI, signed peer/transport/source closure, coordinated migration/applicator, routes/HUMAN/readiness and national end-to-end acceptance remain open; original PET gaps, Cinema and Teatri preserved.


## 10 October, 14:27 CEST — public Java trust prepared on target

The operator completed the separate one-use Java trust preparation: [target evidence](../evidence/application-java-trust-prepared-target-20261010.json). All118 candidate public roots are preserved and the provider CA adds one entry; public-only PKCS12 has119 entries, UID10001 mode0400 and hashdcfb221c…. The offline tool container was removed. This claim and the runtime-input claim are consumed and must never be replayed/reset. No application mount, application lifecycle, image import, database, firewall, IAM grant, deployment signature or R9 operation occurred.

Private replacement configuration composition now derives existing IAM issuer/audience and caller workload from stable current service metadata, preserving the signed candidate JVM defaults and existing consultation mounts. Provider routes remain subject to the frozen binding read; private credential/MAC hashes require protected manifest intake. This draft is not complete OCI, an authority grant or application readiness. Production applicator, signed reciprocal peer closure, migration/recovery, additive Gateway routes and governed HUMAN/end-to-end acceptance remain open. Original PET gap states, Cinema and Teatri are preserved.


## Verticale file → semantica → ingestion → UDP → search, 10 ottobre15:42

La [roadmap dettagliata F0–F11](https://github.com/GioNob/ouf-semantic-registry/blob/a315de5b33a6d9074a04bcbbbca224efd0c4c135/docs/FILE_TO_SEARCH_ROADMAP_20261010.md) esplicita owner, dipendenze e gate del giro richiesto dall'owner. L'identità richiede natura semantica compatibile e evidenze sufficienti; relazioni tra nature diverse, target tardivi e navigazione inversa sono gestiti separatamente. La prima prova file-to-search e la prova multi-fonte precedono l'accettazione su host pulito, mentre il disegno dell'installer procede insieme all'applicatore. I claim consumati, i23 gap PET e Cinema/Teatri sono preservati. La presenza di filtri/riconciliazione nel codice non è accettazione del target; CI Ingestion/UDP rosse e cutover incompleto restano gate espliciti.
