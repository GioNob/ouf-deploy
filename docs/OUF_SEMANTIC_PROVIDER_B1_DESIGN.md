# Nota di progetto B1 — provider Semantic

Task `sprint-01/task-02a`, 11 novembre 2026. Base letta: branch
`sprint-01/task-02a-b1-design`, HEAD `fd3f6b45176385bc03961473f99aafdbe5cac8b6`.
Solo analisi locale e proposta: nessuna osservazione VPS, esecuzione di test,
lettura di segreti o autorizzazione operativa. Il brief `sprint-01/brief.md`
non è presente in questa working tree; il mandato è la sintesi fornita nel task.
Le informazioni live e il profilo P riportati nel task sono input dell'owner,
non risultati di questa analisi. Prevale il perimetro del task: non aggiornare
STATE, registro funzionale o log.

Le frasi marcate **Requisito B1** o **Proposta** descrivono lavoro futuro;
le altre affermazioni tecniche hanno riferimenti alla versione locale del codice.
Gli intervalli indicano righe incluse. I percorsi relativi di packaging
`scripts/...` e `tools/...` non sono percorsi d'installazione.

## 1. Inventario

Il percorso `scripts/semantic_provider_docker_runtime.py` indicato nel mandato
non esiste alla radice del checkout. La copia analizzata e da includere nella
chiusura dei sorgenti è
`tools/semantic_cohort_admission/cohort-draft/scripts/semantic_provider_docker_runtime.py`.
I riferimenti runtime nella tabella seguente puntano a questa copia, senza
attestare che coincida con i byte installati sul VPS.

| Modulo / punto verificabile | Funzione attuale | Impiego B1 proposto |
| --- | --- | --- |
| `tools/semantic_transaction_profiles/README.md:8-57`, `tools/semantic_transaction_profiles/README.md:132-145` | Distingue assemblaggio, autorità, pubblicazione e switch; avverte che ricevute e callback sintetici non conferiscono autorità. | Riferimento, non contratto sufficiente di B1. |
| `scripts/prepare-semantic-provider-installation.py:78-137` | `Reader`: custodia, hash, binari, letture limitate e ricontrollo. | Riutilizzare i controlli; aggiungere controllo finale del contenuto, non solo degli attributi. Non invocare `main` di P. |
| `scripts/prepare-semantic-provider-installation.py:180-278` | `Docker`: socket/peer, daemon o attivazione systemd, GET API 1.44. | Riutilizzare con argomenti ricavati da P; nessuna chiamata mutante. |
| `scripts/prepare-semantic-provider-installation.py:280-346` | `receipt_a`, `frame`, `read_roles`, `verify_peer`: caricano A e confrontano frame, processo, boot, namespace e veth. | Riutilizzare ed estendere: ruoli selezionati esplicitamente da P, namespace pinned e link reciproco, verifiche ripetute sotto lock. |
| `scripts/prepare-semantic-provider-installation.py:404-479` | Legge autorità senza aprire le chiavi; risolve guard successor e wrapper corrente. | Riutilizzare la lettura con pin CLI e confronto con P; separare osservazione e aspettativa. |
| `scripts/prepare-semantic-provider-installation.py:559-574`, `scripts/prepare-semantic-provider-installation.py:673-702` | P pubblica solo un file assente; piano e apply sono legati per digest. | Modello di interfaccia, non ripetere pubblicazione P. |
| `scripts/prepare-semantic-provider-a-20261111.py:101-165`, `scripts/prepare-semantic-provider-a-20261111.py:208-222`, `scripts/prepare-semantic-provider-a-20261111.py:270-291`, `scripts/prepare-semantic-provider-a-20261111.py:305-321` | Produce peer, frame dei successor, ingresso proposto e quattro JSON privati. | Consumare gli artefatti già prodotti. Non rieseguire il preparatore; estrarre soltanto controlli parametrizzati se necessari. |
| `tools/semantic_cohort_admission/compose_successor_cohort.py:39-46`, `tools/semantic_cohort_admission/compose_successor_cohort.py:50-167` | `compile_successor_pair`: ricompila ricette indipendenti, cambia CID/transazioni e peer; restituisce proposta non firmata, senza rootfs o runtime. | Estendere per P e A; non usare il compilatore attuale senza parametrizzazione e aggiornamento del peer Semantic. |
| `tools/semantic_frame_compiler/compile_creation_frame_policy.py:49-82`, `tools/semantic_frame_compiler/compile_creation_frame_policy.py:114-116`, `tools/semantic_frame_compiler/compile_creation_frame_policy.py:177` | `docker_context`, `compile_policy`, `compilation_receipt`: contesto Docker e policy OCI da template/launch indipendenti, non dall'OCI osservata. | Riutilizzare; contesti e ricette sono input vincolati, non scoperti come aspettative dal candidato. |
| `tools/semantic_image_rootfs/prepare_provider_image_rootfs.py:119-152`, `tools/semantic_image_rootfs/prepare_provider_image_rootfs.py:161-229` | `verify_layout`, `prepare`, `apply_docker_init`: verifica archivio/layer, unpack offline e init Docker, sigilla rootfs e produce ricevute. | Supporto alle evidenze rootfs. Non lanciarlo implicitamente in `--plan`; la sua integrazione concreta in B1 resta da qualificare (§4, §11). |
| `tools/semantic_stopped_rootfs/stopped_rootfs_comparison.py:26-57`, `tools/semantic_stopped_rootfs/stopped_rootfs_comparison.py:60-100` | `expected_overlay` e `stopped_export_view`: vista indipendente e vista effettiva di container fermo; mount/export con cleanup verificato, nessun task start. | Primitive riusabili solo nell'apply qualificato, se necessario. Non equivalgono a pura lettura senza effetti filesystem/mount. |
| `tools/semantic_stopped_rootfs/rootfs_image_equivalence.py:16-69` | Policy del modo radice e confronto delle entry di immagine. | Riutilizzare con evidenze complete, senza inventare normalizzazioni. |
| `tools/semantic_stopped_rootfs/compare_provider_v2_stopped_rootfs.py:17-38`, `tools/semantic_stopped_rootfs/compare_provider_v2_stopped_rootfs.py:84-134` | Orchestratore storico con CID/path/digest fissi; distingue sigillo offline, overlay, effettivo ed equivalenza. | Non eseguire; riferimento per un nuovo orchestratore parametrizzato. |
| `tools/semantic_transaction_profiles/assemble_provider_profiles.py:26-49`, `tools/semantic_transaction_profiles/assemble_provider_profiles.py:52-72`, `tools/semantic_transaction_profiles/assemble_provider_profiles.py:75-152` | Canonicalizzazione, chiusure, selezione del sigillo effettivo e profili node/installer/broker. Non autentica gli input. | Riutilizzare funzioni pure dove compatibili; non chiamare l'assemblaggio completo B2 con intent fittizi. |
| `tools/semantic_transaction_profiles/assemble_provider_profiles_v2.py:11-27` | Estende l'assembler con parent runtime esplicito e ricalcola entrambi i journal. | Preferire a quello legacy per il parent; richiede comunque un intent e un mandato finale (§4). |
| `tools/semantic_transaction_profiles/authenticate_provider_transaction.py:19-37`, `tools/semantic_transaction_profiles/authenticate_provider_transaction.py:152-242`, `tools/semantic_transaction_profiles/authenticate_provider_transaction.py:245-356` | Target storici; autentica quattro record temporanei, compila coppia e configurazione v4 con `intentRef`. | Non usare `build_install_plan` direttamente in B1. Estrarre/estendere i controlli puri e il modello di manifest; autenticazione completa in B2. |
| `tools/semantic_transaction_profiles/publish_provider_transaction.py:17-47`, `tools/semantic_transaction_profiles/publish_provider_transaction.py:50-130` | `directory`, `publish_once`, `sync`; `publish_plan` pubblica una transazione autenticata nuova, file 0600, directory 0700, claim e diagnosi durabili. | Primitive di pubblicazione riusabili; estendere/versionare `publish_plan` per materiale B1. Non falsificare lo status autenticato richiesto a riga 63. |
| `tools/semantic_transaction_profiles/guarded_runtime_switch.py:18-44`, `tools/semantic_transaction_profiles/guarded_runtime_switch.py:47-79`, `tools/semantic_transaction_profiles/guarded_runtime_switch.py:82-162` | Custodia, render del wrapper, controllo profili autenticati, CAS sotto lock con backup e tre checkpoint. | `custody`, `wrapper_bytes`, `switch_existing_wrapper` riusabili; verificatore specifico B1 da implementare. `verify_installed_plan` richiede un piano autenticato B2 e non è già un verificatore B1. |
| `tools/semantic_transaction_profiles/transaction_guard_observation.py:21-177` | Lettura nativa sotto descriptor preso in prestito: guard storico, journal vuoti, unità caricate, runtime e due candidati created. | Estendere per P, ricevuta successor, API omogenea e Semantic di A. Nessuna scrittura nft. |
| `tools/semantic_transaction_profiles/authenticated_runtime_switch.py:15-60` | `make_locked_switch_verifier`: ricostruisce piano autenticato e ricontrolla finestre a ogni checkpoint. | Non usare così com'è: richiede già B2. Nuovo verificatore B1 di custodia e inattività; conservare l'obbligo B2 di autenticazione fresca. |
| `tools/semantic_transaction_profiles/provider_transaction_intake.py:19-26`, `tools/semantic_transaction_profiles/provider_transaction_intake.py:56-104`, `tools/semantic_transaction_profiles/provider_transaction_intake.py:227-323` | Loader vincolato a installazione storica; la transazione integrata firma, pubblica, cambia wrapper e attiva Docker. | Riutilizzare il principio di source seal, non invocare `execute_transaction` né il suo CLI in B1. |
| `tools/semantic_transaction_profiles/issue_provider_transaction_authority.py:27-141` | Emette review, intent, live authorization e final mandate solo da mandato root esplicito; claim prima delle chiavi. | Escluso da B1; B2, dopo parametrizzazione e nuova verifica di A. |
| `tools/semantic_transaction_profiles/docker_cohort_activation.py:24-129` | Claim e due `docker start` concorrenti, readback, diagnosi di esito incerto. | Escluso da B1. Non implementa da solo lo stop compensativo richiesto a B2. |
| `tools/semantic_cohort_admission/cohort-draft/scripts/semantic_provider_docker_runtime.py:170-221`, `tools/semantic_cohort_admission/cohort-draft/scripts/semantic_provider_docker_runtime.py:280-348` | Runtime v4: allowlist, journal per CID, broker prima di create/start, nessun CID generico. | Consegnare sorgente vincolato; estensione per fase B1 inattiva da definire (§4). Non invocare operazioni runtime in B1. |
| `tools/semantic_cohort_admission/cohort-draft/scripts/semantic_provider_deployment_broker.py:103-122`, `tools/semantic_cohort_admission/cohort-draft/scripts/semantic_provider_deployment_broker.py:124-180`, `tools/semantic_cohort_admission/cohort-draft/scripts/semantic_provider_deployment_broker.py:270-350` | Loader chiuso; broker e profili di ammissione legati a intent, template e journal. | Pubblicare sorgenti verificati per B2; non eseguire il broker in B1. |
| `tools/semantic_cohort_admission/cohort-draft/scripts/semantic_provider_preexec_hook.py:52-91`, `tools/semantic_cohort_admission/cohort-draft/scripts/semantic_provider_preexec_hook.py:134-205` | Loader verificato, gate/driver e controlli peer prima dell'esecuzione. | Chiusura sorgenti da conservare; non eseguire hook/start/rollback runtime in B1. |
| `tools/semantic_cohort_admission/cohort-draft/scripts/semantic_provider_admission_preparer.py:86-118`, `tools/semantic_cohort_admission/cohort-draft/scripts/semantic_provider_admission_preparer.py:134-350` | Carica preparer, osserva e costruisce ammissione/driver. | Materiale per B2; non invocare il preparer operativo. |
| `tools/semantic_cohort_admission/cohort-draft/scripts/semantic_provider_node_attestor.py:15-22`, `tools/semantic_cohort_admission/cohort-draft/scripts/semantic_provider_node_attestor.py:81-106`; `tools/semantic_cohort_admission/cohort-draft/scripts/semantic_provider_installer_approval.py:15-22`, `tools/semantic_cohort_admission/cohort-draft/scripts/semantic_provider_installer_approval.py:81-106` | Entrypoint con chiusura dei moduli e configurazione dei producer. | Consegnare closure, non produrre attestazioni/approval in B1. |
| `tools/semantic_cohort_admission/cohort-draft/tools/semantic_provider_deployment_authentication.py:176-210`, `tools/semantic_cohort_admission/cohort-draft/tools/semantic_provider_deployment_authentication.py:232-352`; `tools/semantic_cohort_admission/cohort-draft/tools/semantic_provider_deployment_signing.py:21-68` | Policy, envelope Ed25519, verifier e signer delle chiavi esistenti. | Verifier riusabile per documenti compatibili già firmati; signer escluso fino a decisione sulle firme B1 (§4). |
| `tools/semantic_cohort_admission/cohort-draft/tools/semantic_provider_node_observation.py:24-95`; `tools/semantic_cohort_admission/cohort-draft/tools/semantic_provider_peer_bindings.py:55-151` | Sigillo completo filesystem; dichiarazioni e raccolta peer. | Riutilizzare strutture/algoritmi, separando aspettativa indipendente e raccolta effettiva. |
| `scripts/deliver-semantic-provider-installation.sh:5-25` | Download da commit fissato, verifica SHA-256 prima di sudo e ricontrollo prima di esecuzione. | Modello di consegna, non launcher B1. Nuovo launcher/closure da fissare in futuro. |

La primitiva citata nell'handoff è riconciliata **per contenuto Git**:
SHA-256 del blob HEAD di `tools/semantic_transaction_profiles/guarded_runtime_switch.py`
`1492237e1c1ce85da5c9220ea3f6f024b24dc4d217ff5bf6e5b43c14fff225bd`.
Il checkout Windows ha terminatori CRLF e SHA-256 diverso
`316881f80a598d2201928bbfe022dd022071a169032f7ce822cdcccb8c520d00`;
non consegnare questi byte come se fossero il blob LF. Nessun file è stato
normalizzato. Per il futuro launcher fissare il commit effettivamente revisionato
e i byte LF di **tutta** la closure, non soltanto questa primitiva.

## 2. Costanti da parametrizzare

**Requisito B1.** Nessun valore storico qui elencato è un default di progetto.
Le stringhe letterali sono riportate solo come inventario del codice attuale.
P fornisce path e aspettative stabili; A fornisce identità/generazioni volatili.
Hash dei nuovi artefatti e scelte della transazione devono essere in un manifest
CLI root-only fissato per hash, non ricavati dall'osservazione per autoapprovarla.

### 2.1 Chiamate che B1 riuserebbe o deve adattare

| File:riga, valore attuale | Fonte richiesta / modifica |
| --- | --- |
| `tools/semantic_transaction_profiles/authenticated_runtime_switch.py:28`, `ouf-semantic-admitted-v2` | `runtime.name`. Il verificatore B1 non eredita il target storico di riga 27. |
| `tools/semantic_transaction_profiles/transaction_guard_observation.py:21-22`, `/etc/systemd/system/ouf-semantic-boot-guard.service`, `/etc/systemd/system/docker.service.d/90-ouf-semantic-boot-guard.conf` | **Nuovi campi proposti** `paths.guard.unitFiles.guardService` e `paths.guard.unitFiles.dockerDropIn`, verificati contro ricevuta e unità caricate. P attuale non li contiene. |
| `tools/semantic_transaction_profiles/transaction_guard_observation.py:137`, `ouf-semantic-boot-guard.service`, `docker.service` | **Nuovo campo proposto** `guardServiceUnit`; il secondo è già `dockerServiceUnit`. Non dedurre il nome dell'unità dal solo basename del file. |
| `tools/semantic_transaction_profiles/transaction_guard_observation.py:141`, `ouf-semantic-admitted-v2`, `/usr/local/sbin/ouf-semantic-admitted-v2` | `runtime.name`, `runtime.wrapper`. |
| `tools/semantic_transaction_profiles/transaction_guard_observation.py:130`, directory temporanea `/root` | Eliminare il Docker CLI con config temporanea dal lettore B1; usare il client GET di P. Nessun nuovo campo necessario con questa proposta. Se si conserva il CLI, serve un root temporaneo esplicito e `--plan` non può creare quella directory. |
| `tools/semantic_transaction_profiles/transaction_guard_observation.py:133`, `unix:///var/run/docker.sock` | URI costruito da `paths.dockerSocket`, verificato con `dockerSocketOwnership`, `dockerSocketActivation`, `dockerSocketUnit`, `dockerServiceUnit`, `dockerdExecutable.path`. |
| `tools/semantic_transaction_profiles/assemble_provider_profiles.py:143`, `/run` | `runtime.runtimeStateRoot`, tramite `assemble_provider_profiles_v2.assemble_profiles(..., broker_runtime_root_parent=...)`; non cambiare solo il broker senza i journal (`tools/semantic_transaction_profiles/assemble_provider_profiles_v2.py:24-26`). |
| `tools/semantic_cohort_admission/compose_successor_cohort.py:43-46`, suffisso `/rootfs/overlayfs/` più CID | Layout oggi presupposto dal compilatore: il nuovo `context.rootfsPath` deve essere un input indipendente del manifest B1, sotto `runtime.dockerDataRoot`/parent approvati e coerente col backend Engine. Non derivarlo sempre da quel suffisso. Nessun nuovo campo P se il contesto resta dato di transazione. |
| `tools/semantic_image_rootfs/prepare_provider_image_rootfs.py:211`, engine commit `464cd50c3d9e92877d56940ea160de6fca7bea23` | Binding indipendente della ricetta init nel manifest B1, confrontato con l'Engine corrente. L'helper non è generico solo perché riceve `engine_commit`: il suo controllo è ancora fisso. Estendere il controllo e qualificare il tool costruito dal sorgente Engine approvato; niente sostituzione automatica del commit. |
| `tools/semantic_cohort_admission/compose_successor_cohort.py:124`, `172.18.0.6`, `br-113b5f0a3c53` | IP dalla NIC Semantic in `roles.semantic.networks`; bridge da `networks[rete].bridge`, con ruolo/rete selezionati esplicitamente e confermati da A. |
| `tools/semantic_cohort_admission/compose_successor_cohort.py:145`, binding `<altro ruolo>-internal`; `tools/semantic_cohort_admission/compose_successor_cohort.py:146-147`, `172.21.0.2`, `172.21.0.3`, `9443` | BindingRef dalle ricette indipendenti; IP dai binding dei due ruoli su rete comune interna, porta `ports.adapter`. Non concatenare nomi di reti o scegliere la prima rete comune. |
| `tools/semantic_cohort_admission/compose_successor_cohort.py:150`, `1377`; `tools/semantic_cohort_admission/compose_successor_cohort.py:151-152`, `172.18.0.6`, `172.18.0.14`, `10443` | `1377` resta solo un dato storico della ricetta originale vincolata, mai ingresso corrente. Usare dichiarazione del Semantic corrente coerente con A; ingresso A `semanticPeer.proposedIngress`, indirizzi P e `ports.southbound`. |
| `scripts/prepare-semantic-provider-a-20261111.py:120-133`, `eth0`, `ouf-semantic-registry`, `semantic-backend` | Non chiamare direttamente `reciprocal_link` come funzione generale B1. Interface/bindingRef/workloadRef vengono dalla dichiarazione/ricetta peer indipendente vincolata nel manifest B1 e sono confrontati con `A.semanticPeer.binding`. A non sostituisce l'aspettativa indipendente. |
| `scripts/prepare-semantic-provider-a-20261111.py:21-25`, CID Semantic, hash piano D, directory A, SNI, eseguibili IP/NSENTER; `scripts/prepare-semantic-provider-a-20261111.py:216`, runtime fisso; `scripts/prepare-semantic-provider-a-20261111.py:239-240`, `29.8.1`, `overlayfs`, `systemd`, `/var/lib/docker`; `scripts/prepare-semantic-provider-a-20261111.py:272-273`, destinazione/porta | Il preparatore A **non viene rieseguito/importato come orchestratore**. Per eventuali controlli estratti: CID/hash/D/root da A e CLI; SNI da alias dichiarato e A, eseguibili `paths.binaries`, runtime da P, backend Engine dal manifest di transazione e `runtime.dockerDataRoot`, ingresso da A/P. Nessun valore ereditato implicitamente da D. |

Per le due reti comuni, P non assegna nomi logici «backend/internal/egress» alle
chiavi dinamiche. **Proposta:** nel manifest CLI B1 dichiarare esplicitamente
quali chiavi P svolgono tali ruoli per questa transazione e verificarne
internal/subnet/bridge, membership e ricette. È una selezione di riferimenti P,
non una seconda fonte di IP/MAC. Se si vuole rendere stabile questa selezione,
servirebbe invece il **nuovo campo di profilo** `networkRoles`; non è presente
né implicitamente approvato.

### 2.2 Target storici da eliminare se si estraggono controlli dall'autenticatore

`TARGETS` e `AUTHORITIES` sono letti dall'autenticazione e dalla closure di coppia
(`tools/semantic_transaction_profiles/authenticate_provider_transaction.py:164`,
`tools/semantic_transaction_profiles/authenticate_provider_transaction.py:245-275`, `tools/semantic_transaction_profiles/authenticate_provider_transaction.py:321`). Per B1 tutti i valori seguenti diventano argomenti espliciti,
mai nuove costanti; il percorso B2 dovrà fare la stessa migrazione.

| File:riga e valore storico | Fonte sostitutiva |
| --- | --- |
| `tools/semantic_transaction_profiles/authenticate_provider_transaction.py:21`, CID `f3d59af93fc90162681cee3a7562bdff3bf2af8c05cbdb7e270d1508fff18f67` | CID adapter da A, confermato da nome/ruolo P e proprietà della creazione. |
| `tools/semantic_transaction_profiles/authenticate_provider_transaction.py:22`, manifest `sha256:277dcefd4744c244f4f6f23f8969f3d0acd64369e2ff1bd67594955c4ca7fbbc` | Binding immagine adapter indipendente nel manifest B1; A contiene `Image` osservato, non prova provenance. |
| `tools/semantic_transaction_profiles/authenticate_provider_transaction.py:23`, config `sha256:62e066bd021f386291f5de21ce0e1f9e67904a74b4146326070c7784493ad320` | Digest config indipendente, distinto dal manifest, nel manifest B1. |
| `tools/semantic_transaction_profiles/authenticate_provider_transaction.py:24`, seal hash `8744724088d02145b86b433058a4336fcb9c873a4a92e7009753209c284d3d73`, entries `3390`, bytes `46079786` | Nuova evidenza completa rootfs del CID adapter di A (§4), non copia dei tre valori storici. |
| `tools/semantic_transaction_profiles/authenticate_provider_transaction.py:26`, CID `1fc5ae6a0db4600e0124bb1f9d2998780d533fd2b4de7cb086d8675b6afb5916` | CID southbound da A e proprietà della creazione. |
| `tools/semantic_transaction_profiles/authenticate_provider_transaction.py:27`, manifest `sha256:c15541037a08276e36715a3c3798c2d07fe6faabf5547d3885a66cd10575e366` | Binding immagine southbound indipendente nel manifest B1. |
| `tools/semantic_transaction_profiles/authenticate_provider_transaction.py:28`, config `sha256:d4c47bbeca75d94e2231e17ca14552885b7b339a5f33dbace411e275c79ded04` | Binding config southbound indipendente nel manifest B1. |
| `tools/semantic_transaction_profiles/authenticate_provider_transaction.py:29`, seal hash `52e06f47e1da5a107525e2260b9d375329997181dd13de7023654278aeaf3f39`, entries `7458`, bytes `255900260` | Nuova evidenza completa rootfs del CID southbound di A. |
| `tools/semantic_transaction_profiles/authenticate_provider_transaction.py:31`, `ouf-lab-netcup-01`, `ouf-lab` | `installationRef`, `entityRef` di P, uguali all'authority profile fissato. |
| `tools/semantic_transaction_profiles/authenticate_provider_transaction.py:32-34`, `ouf-lab-infrastructure-installer` (intent e approval), `ouf-lab-node-attestor` | `authorities.intentIssuerRef`, `approvalIssuerRef`, `attestorRef` dentro `paths.authorityProfile`, vincolato separatamente per hash. Non nuovi campi P. |

`State.created`, PID zero, `restart=no`, schemi versionati, nomi dei ruoli,
Ed25519, SHA-256, limiti di lettura e budget sono controlli di protocollo, non
identificatori d'installazione. Il runtime legge path, CID e binari dalla propria
configurazione (`tools/semantic_cohort_admission/cohort-draft/scripts/semantic_provider_docker_runtime.py:170-215`);
il compilatore ha slot standard del filesystem container, non path host di P
(`tools/semantic_frame_compiler/compile_creation_frame_policy.py:114-116`).
I PATH sanitizzati dei subprocess non devono diventare un meccanismo di ricerca
di eseguibili alternativi: usare binari assoluti vincolati; esempi attuali in
`tools/semantic_transaction_profiles/transaction_guard_observation.py:131-133` e
`tools/semantic_cohort_admission/cohort-draft/scripts/semantic_provider_docker_runtime.py:213-220`.

### 2.3 Moduli esclusi: non trascinare i loro pin nella nuova consegna

Non sono sorgenti di default B1: `AUTHORITY/POLICY/EMPTY_ADAPTER/PYTHON/OPENSSL`
con path e SHA in `tools/semantic_transaction_profiles/provider_transaction_intake.py:19-26`;
snapshotRoot/prefisso in `tools/semantic_transaction_profiles/provider_transaction_intake.py:140`, `tools/semantic_transaction_profiles/provider_transaction_intake.py:159`, `tools/semantic_transaction_profiles/provider_transaction_intake.py:198`, `tools/semantic_transaction_profiles/provider_transaction_intake.py:258`, `tools/semantic_transaction_profiles/provider_transaction_intake.py:266`;
pointer/root/owner hash in `tools/semantic_transaction_profiles/provider_transaction_intake.py:269-280`; Docker/systemctl pin in `tools/semantic_transaction_profiles/provider_transaction_intake.py:282-284`;
wrapper e hash originale in `tools/semantic_transaction_profiles/provider_transaction_intake.py:286-288`, `tools/semantic_transaction_profiles/provider_transaction_intake.py:318`. Se ne riusa logica, i path
vengono rispettivamente da `paths.authorityProfile`, `paths.trustPolicy`,
`runtime.pythonExecutable`, `paths.binaries.openssl`, `paths.snapshotRoot`,
`paths.guard.*`, `paths.binaries.*`, `runtime.wrapper`; gli hash vengono dai
binding CLI revisionati e dal piano corrente, **non dai pin di ottobre**.
`EMPTY_ADAPTER` non ha equivalente stabile P: B1 deve costruire una configurazione
nuova; non azzerare i journal/config storici per ottenerla.

Analogamente, B1 non usa il wrapper di default, runtime e socket di
`tools/semantic_transaction_profiles/docker_cohort_activation.py:26`, `tools/semantic_transaction_profiles/docker_cohort_activation.py:72`, `tools/semantic_transaction_profiles/docker_cohort_activation.py:102`,
né il lettore attestazioni con ROOT/TARGET storici
(`tools/semantic_transaction_profiles/read_existing_image_attestations.py:16-29`).
L'orchestratore rootfs storico fissa OFFLINE, DATA_ROOT, SNAPSHOT_PARENT, SOCKET,
SOURCE_MANIFEST, DOCKER/MOUNT/UMOUNT e ROLES con CID/nome/archivio/manifest/config/seal
(`tools/semantic_stopped_rootfs/compare_provider_v2_stopped_rootfs.py:17-35`):
nessuna chiamata a quel `main`. Riutilizzare le primitive parametrizzate;
archivi/receipt/seal sono binding CLI per ruolo, dataRoot/socket/binari sono P.
Lo staging generico dei producer con binari fissi
(`tools/semantic_cohort_admission/cohort-draft/scripts/stage_semantic_local_producers_package.py:62-64`)
non fa parte della consegna B1. I pin commit/SHA del launcher P
(`scripts/deliver-semantic-provider-installation.sh:5-7`) sono versionamento
del software, da sostituire con quelli B1, non dati installativi da mettere in P.

**Evento P da segnalare.** I tre campi proposti per file/unità guard non esistono
nel P fornito. La loro introduzione richiede una revisione/pubblicazione governata
del profilo e un nuovo hash; l'installer P attuale rifiuta il file esistente
(`scripts/prepare-semantic-provider-installation.py:559-574`). B1 non deve
sovrascriverlo. Finché la fonte stabile non è concordata, il controller non è
consegnabile. Tutti gli altri elementi mancanti qui proposti sono binding del
manifest CLI di transazione, senza modifica del profilo P esistente.

## 3. Input di B1

**Proposta di CLI**, non implementata: modalità esclusive `--plan` oppure
`--apply --plan-sha256 <hash>`, più `--installation-profile`,
`--installation-profile-sha256`, `--a-root`, `--a-plan-sha256`, `--b1-inputs`,
`--b1-inputs-sha256`. Il manifest B1 elenca **ogni** binding seguito: nessuna
scansione ricorsiva di snapshot, scelta «latest» o lettura dei mount applicativi.
`planSha256` lega l'intero grafo degli input e le scritture previste.

| Categoria e file letto | Custodia attesa e legame |
| --- | --- |
| Stabile: file P passato via CLI | root:root 0600, regolare, nlink=1, no symlink, antenati root non scrivibili da gruppo/altri. Hash byte esatti dal mandato: `b956466521ca1f1cc887eeeaa321d66414a26f8c76e2d96eabc7fd4d84a74d5f`, finché P non cambia. Non hash di JSON riformattato. Modello di reader in `scripts/prepare-semantic-provider-installation.py:88-113`. |
| Transazione: `<a-root>/manifest.json`, `result.json`, `semantic-peer.json`, `successors.json` | directory root:root 0700, file 0600. Piano A fornito dall'owner e via CLI; manifest/result devono coincidere; i due payload sono legati ai `filesCreated[].sha256`. Modello esistente `scripts/prepare-semantic-provider-installation.py:280-298`; writer `scripts/prepare-semantic-provider-a-20261111.py:294-321`. Il piano A lega anche `cutoverInputHashes`, non soltanto il manifest (`scripts/prepare-semantic-provider-a-20261111.py:291`); non tentare di ricostruirlo da quattro file senza questi hash. Registrare i quattro hash raw in B1. |
| Transazione: manifest B1 via CLI | **Nuovo** JSON 0600 root:root, hash approvato separatamente. Contiene destinazione deterministica sotto `paths.snapshotRoot`, selezione delle reti P, binding ricette/immagini/rootfs, proprietà della creazione successor, peer Semantic indipendente aggiornato a D, closure software e output. Non contiene chiavi né payload di ammissione inventati. Schema finale non determinato (§11). |
| Transazione: ricevuta della creazione successor, manifest e richiesta pre-CREATE per ciascun ruolo, completion/prove di proprietà | Path/hash espliciti nel manifest B1, 0600 root:root. Devono legare i CID di A alla creazione autorizzata, immagine e ricetta effettiva. A conserva transaction e frame ma non la richiesta intera (`scripts/prepare-semantic-provider-a-20261111.py:274-291`). Nomi/path esatti e sufficienza della catena per B1: **non determinato**; non attribuirli ad A per deduzione. |
| Transazione: ricevuta input di generazione e i due `<ruolo>-inputs.private.json`, ricette `template`, `launch`, `context`, `policy` di entrambi i ruoli | Path/hash dal manifest B1 e ricevute conservate; root:root 0600. La lettura P segue i primi binding (`scripts/prepare-semantic-provider-installation.py:444-457`); il compilatore richiede le quattro parti della ricetta (`tools/semantic_cohort_admission/compose_successor_cohort.py:59-76`). Nessuna nuova preparazione degli input già conclusi. |
| Transazione: ricetta/dichiarazione Semantic indipendente corrente | Binding espliciti nel manifest B1, root:root 0600. Confrontare CID, applicationHash, NIC e generazione con A. Il solo peer A non contiene l'OCI completa: payload a `scripts/prepare-semantic-provider-a-20261111.py:162-165`, `scripts/prepare-semantic-provider-a-20261111.py:270-273`. La vecchia dichiarazione pre-D non è automaticamente valida. |
| Rootfs: archivi/receipt offline, digest manifest/config separati, ricetta init Docker e comparison per ruolo | JSON e archivi root:root 0600, regolari/nlink=1/no symlink; archivio entro il limite 512 MiB del reader, hash raw nel manifest B1. Rootfs conserva metadata completi dell'immagine, non viene reso ricorsivamente 0600/0700. Output privato vuoto 0700 e contratto archivio a `tools/semantic_image_rootfs/prepare_provider_image_rootfs.py:180-194`; receipt legano archivio, digest, diffIds e seal (`tools/semantic_image_rootfs/prepare_provider_image_rootfs.py:202-229`); la comparison distingue il seal effettivo (`tools/semantic_stopped_rootfs/compare_provider_v2_stopped_rootfs.py:108-134`). Path/hash dei successor correnti **non determinati**. Nessun fallback ai seal storici. |
| Autorità: `paths.authorityProfile`, `paths.trustPolicy` | root:root 0600 e hash indipendenti nel manifest B1. P ne conserva i percorsi, non gli hash (`scripts/prepare-semantic-provider-installation.py:619-625`). Authority profile può contenere metadata delle chiavi: non seguire `keyBindings[].path`; confrontarli con `keyPaths` P senza aprire le chiavi (`scripts/prepare-semantic-provider-installation.py:404-412`). |
| Guard: `paths.guard.pointer`, ricevuta, profile, ownerConfiguration, bootConfiguration, coordinationJournal, bootJournal, lock | root:root 0600; lock vuoto, identità inode vincolata nel piano. Catena pointer→receiptHash→profile/owner/boot da verificare come `scripts/prepare-semantic-provider-installation.py:415-440`. Hash raw anche dei journal/pointer nel piano, nessuna loro scrittura. |
| Guard: observer/compiler/source closure e unità/drop-in referenziati dalla ricevuta/profile | Binding per hash e custodia dal produttore; nessuna esecuzione automatica dei sorgenti installati. Il lettore storico assume 0600 per questi file (`tools/semantic_transaction_profiles/transaction_guard_observation.py:118-124`), ma modi esatti della nuova closure successor **non determinati** qui: verificare il contratto del produttore, non convertire 0644/0755 in 0600 per farlo passare. |
| Runtime: wrapper `runtime.wrapper`, configurazione e sorgente a cui punta oggi | Wrapper 0755 root:root, hash/identità esatti nel piano. Config 0600; sorgente con modo esplicito accettato dal reader e hash della config (`scripts/prepare-semantic-provider-installation.py:460-479`). Leggere solo i riferimenti necessari alla prova dello stato corrente; nessuna riscrittura dei vecchi registri. |
| Software: pacchetto/manifest di closure B1, runtime, frame compiler/observer e dipendenze; binari P | Commit e SHA-256 di ciascun file revisionato; byte verificati **prima** di import/exec. Binari root non scrivibili, mode esplicito e SHA nel piano; non imporre 0600 agli eseguibili. OpenSSL richiede anche versione esatta nel binding (`tools/semantic_cohort_admission/cohort-draft/tools/semantic_provider_deployment_authentication.py:233-239`); umoci/init, se usati, sono binding CLI di ricetta aggiuntivi, assenti da P, non eseguibili cercati nel PATH (`tools/semantic_image_rootfs/prepare_provider_image_rootfs.py:180-184`, `tools/semantic_image_rootfs/prepare_provider_image_rootfs.py:208-217`). Modelli: `tools/semantic_transaction_profiles/provider_transaction_intake.py:87-104`, `scripts/prepare-semantic-provider-installation.py:118-123`. |
| Osservazioni kernel/processo/socket: `/proc/<pid>/stat`, `ns/net`, boot_id, GET Docker, letture ip/systemd/nft | Non normali file root 0600: verificare descriptor, credenziali del peer, identità/generazione e letture limitate. Dati attesi da A/P, non creati come nuove aspettative dal readback (`scripts/prepare-semantic-provider-installation.py:180-278`, `scripts/prepare-semantic-provider-installation.py:326-346`). |
| Materiale firmato eventualmente preesistente: payload e `<payloadHash>.<ROLE>.json` | Binding payload/firma/policy nel manifest B1; root:root 0600, directory firme privata. Risoluzione esistente in `tools/semantic_cohort_admission/cohort-draft/tools/semantic_provider_deployment_authentication.py:343-350`. Non consumare record B2 scaduti o creare nuove firme implicitamente. Per le firme durature B1 il contratto non esiste ancora (§4). |

**Requisito B1.** `keyPaths.installer` e `keyPaths.attestor` sono esclusi dal
reader degli input; root non autorizza da solo una lettura. Non seguire ricorsivamente
path dentro documenti non ancora validati. Il manifest di lettura deve distinguere
file di metadata e file credenziale, rifiutando qualsiasi alias verso questi ultimi.

## 4. Che cosa significano concretamente «ricette OCI/rootfs» e «firme non a scadenza»

**OCI esistente.** Una ricetta comprende template completo, launch indipendente,
contesto `ouf.semantic-docker-frame-context.v1` e policy ricompilata con `expectedOci`;
non basta una lista di IP. Il compilatore deriva parent, rootfs, namespace, cgroup
e hostname dal contesto indipendente
(`tools/semantic_frame_compiler/compile_creation_frame_policy.py:49-82`). La coppia
successor produce `ouf.discovery-successor-cohort-proposal.v1`, policy, template,
application/artifact/transport hash per ruolo; dichiara esplicitamente false
proprietà creazione, custodia, rootfs, autorità e runtime
(`tools/semantic_cohort_admission/compose_successor_cohort.py:159-167`).

**Rootfs esistente.** `prepare` produce `ouf.semantic-offline-image-rootfs.v1`;
`apply_docker_init` produce `ouf.semantic-offline-docker-rootfs.v1` collegato al
precedente receipt e all'engine commit
(`tools/semantic_image_rootfs/prepare_provider_image_rootfs.py:180-229`). Il sigillo
di nodo `ouf.semantic-rootfs-seal.v1` comprende `sha256`, `entries`, `bytes` e viene
calcolato sull'albero completo con limiti, metadata e contenuti
(`tools/semantic_cohort_admission/cohort-draft/tools/semantic_provider_node_observation.py:24-95`).
La comparison conserva seal originale offline, atteso overlay ed effettivo,
non intercambiabili; equivalenza immagine non significa uguaglianza arbitraria
dei seal (`tools/semantic_stopped_rootfs/compare_provider_v2_stopped_rootfs.py:108-134`).
`approved_runtime_seal` richiede proprio l'`actualSeal` v1 e il suo binding al
frame completo nell'autorizzazione live
(`tools/semantic_transaction_profiles/assemble_provider_profiles.py:52-72`).

**Requisito B1 / limite.** Preparare le ricette dei **nuovi** CID e le aspettative
rootfs indipendenti; provare il sigillo effettivo dei candidati fermi prima di
riutilizzarlo in B2. Non dedurre il nuovo seal da immagine/CID o da quello storico.
La produzione rootfs può richiedere unpack, init, export e mount, pur senza start
(`tools/semantic_image_rootfs/prepare_provider_image_rootfs.py:180-229`,
`tools/semantic_stopped_rootfs/stopped_rootfs_comparison.py:26-100`).
**Proposta:** B1 consuma evidenze già vincolate quando sufficienti; altrimenti
espone nel piano una sottosequenza rootfs offline finita e qualificata, solo in
apply. L'integrazione per i successor correnti, incluso tool umoci/init e relativo
hash, non è determinata. Non inserire export/mount in `--plan` né dichiarare
«read-only» quell'operazione. Se mancano prove e integrazione, HELD prima dello switch.

**Firme esistenti: tre livelli diversi.**

1. L'envelope `ouf.semantic-deployment-detached-signature.v1` Ed25519 non include
   `issuedAt`/`expiresAt`; lega payloadHash, ruolo, issuer, installation, entity e
   keyRef ai byte esatti
   (`tools/semantic_cohort_admission/cohort-draft/tools/semantic_provider_deployment_authentication.py:199-210`, `tools/semantic_cohort_admission/cohort-draft/tools/semantic_provider_deployment_authentication.py:312-328`).
2. La verifica richiede comunque una chiave ACTIVE nella propria finestra
   `notBefore/expiresAt` e policy invariata fino alla fine; una firma senza campo
   scadenza non è quindi un'autorità perpetua
   (`tools/semantic_cohort_admission/cohort-draft/tools/semantic_provider_deployment_authentication.py:329-339`).
3. Review, intent, live authorization e final mandate hanno finestre proprie;
   `window` ammette al massimo 300 s e l'autenticatore li ricontrolla tutti
   (`tools/semantic_cohort_admission/cohort-draft/tools/semantic_provider_deployment_protocol.py:50-54`,
   `tools/semantic_transaction_profiles/authenticate_provider_transaction.py:171-226`).
   Il requisito B2 di 240 s è più stretto, non già il limite implementato qui.

Chi firma attualmente: installer per review (`FINAL_DEPLOYMENT_APPROVAL`), intent
(`DEPLOYMENT_INTENT`) e final mandate (`FINAL_DEPLOYMENT_APPROVAL`); attestor per
live authorization (`CREATION_ATTESTATION`). `ExistingEd25519Signer` legge le due
chiavi esistenti attraverso `authority.keyBindings/keyRefs`, firma e ricontrolla
chiave/policy; i record sono salvati nella directory di emissione e le firme nella
signatureDirectory, con claim precedente alla lettura chiave
(`tools/semantic_transaction_profiles/issue_provider_transaction_authority.py:105-140`,
`tools/semantic_cohort_admission/cohort-draft/tools/semantic_provider_deployment_signing.py:21-68`).

**Manca nel codice analizzato:** documento di accettazione durevole B1 delle
ricette/rootfs, schema, ruolo autorizzato, issuer, modalità di emissione e regola
di revoca/riuso che non autorizzi start. Non chiamare review/final mandate
«non a scadenza» togliendo i timestamp: campi esatti e window lo rifiutano
(`tools/semantic_transaction_profiles/authenticate_provider_transaction.py:176-179`, `tools/semantic_transaction_profiles/authenticate_provider_transaction.py:212-225`).
**Proposta da revisionare:** un distinto manifest di accettazione degli artefatti
B1, legato a P/A/closure/ricette/CID/seal, con `startAuthorized=false` e nessuna
lease, salvato sotto la nuova root B1 insieme alle firme. Schema e firmatario sono
**non determinati**: non assegnare autonomamente un nuovo ruolo alle chiavi.
Se B1 deve emetterlo, servono letture delle chiavi strettamente necessarie e un
mandato concreto separato; la variante B1 senza chiavi deve riceverlo già emesso.
Il piano non può prevedere i byte di una firma futura come se esistessero.

**Altro contratto mancante, bloccante.** La configurazione v4 richiede per ogni
CID `intentRef` e hash del broker; broker e journal sono a loro volta legati
all'intent e al mandato finale
(`tools/semantic_transaction_profiles/authenticate_provider_transaction.py:328-350`,
`tools/semantic_transaction_profiles/assemble_provider_profiles.py:90-108`, `tools/semantic_transaction_profiles/assemble_provider_profiles.py:123-151`,
`tools/semantic_cohort_admission/cohort-draft/scripts/semantic_provider_docker_runtime.py:186-209`).
Un intent B2 emesso dopo B1 cambia quegli hash. Non esiste quindi già un piano v4
definitivo B1 senza record B2. **Proposta:** fase runtime B1 esplicitamente inattiva,
con i soli due CID e manifest artefatti, che neghi create/start prima di ogni
producer; B2 pubblica un'armatura firmata immutabile distinta e verificata.
Formato/aggancio/compatibilità non determinati, richiedono modifica runtime e test.
Non usare hash fittizi, intent vuoti, callback permissive o journal storici azzerati.
Fino a questa decisione, B1 deve fermarsi HELD prima di installare il wrapper:
il CAS disponibile non risolve questo contratto.

## 5. Sequenza `--plan` / `--apply`

**Requisito B1.** I passi sotto specificano il controller futuro. Lo stato finale
non implica readiness provider, ammissione, TLS o discovery. Gli elementi mancanti
del §4 sono gate di implementazione, non controlli da saltare in apply.

### `--plan`: nessuna scrittura

1. Verificare launcher/closure prima di eseguire moduli; richiedere root isolato,
   CLI esclusiva e hash completi. Leggere P e manifest B1 con custodia. Verificare
   schema/insieme campi e selezioni di rete; elencare ogni input e suo hash.
   Modelli esistenti: consegna `scripts/deliver-semantic-provider-installation.sh:11-25`,
   CLI `scripts/prepare-semantic-provider-installation.py:673-700`.
2. Leggere A con il piano A atteso e hash dei quattro file. Confrontare Semantic:
   CID/nome/immagine/frame completo API 1.44, running, StartedAt, PID/startTicks,
   boot_id, device/inode netns, endpoint/network ID e veth reciproco. Ripetere
   i controlli di A/P senza ricreare gli input. Legare anche la ricetta indipendente
   Semantic aggiornata a D. Modelli: `scripts/prepare-semantic-provider-installation.py:280-346`,
   `scripts/prepare-semantic-provider-a-20261111.py:136-165`.
3. Verificare esattamente i due successor di A, distinti e diversi da Semantic,
   con ruoli/nome da P, frame identico ad A, stato `created`, PID0, mai avviati,
   restart=no, runtime P, transaction/label della creazione autorizzata, reti e
   prenotazioni IP/MAC/alias P senza endpoint attivi. **HELD qui, prima di ogni
   possibile firma o lettura chiave**, se differiscono identità/generazione/stato.
   Il controllo attuale di A copre questi campi ma ha pin storici
   (`scripts/prepare-semantic-provider-a-20261111.py:208-222`); P confronta frame
   e ruolo a `scripts/prepare-semantic-provider-installation.py:305-323`.
4. Verificare daemon/socket/binari P, registrazione `runtime.name→runtime.wrapper`,
   custodia/hash del wrapper attuale, pointer e catena guard successor. Sotto lock
   nativo esistente leggere journal QUIESCED/RUNTIME_EMPTY, comandi caricati,
   struttura nft e set vuoti. Rilasciare il descriptor al termine del piano.
   Il modello storico `observe_locked` non accetta direttamente la ricevuta
   successor: schema/directory differiscono
   (`tools/semantic_transaction_profiles/transaction_guard_observation.py:102-124`,
   `scripts/prepare-semantic-provider-installation.py:415-440`).
5. Ricompilare ricette e closure in memoria, verificare peer reciproci e coerenza
   P/A. Leggere le evidenze rootfs disponibili; pianificare separatamente eventuale
   produzione offline. Verificare firme durature solo se contratto e input esistono.
   Nessun unpack, export, mount, directory temporanea o claim in questa modalità.
6. Selezionare una root B1 **deterministica e assente** sotto `paths.snapshotRoot`,
   passata nel manifest: non generare un nuovo nome casuale tra plan/apply.
   Renderizzare il wrapper in memoria da `runtime.pythonExecutable`,
   `<rootB1>/source` e `<rootB1>/runtime-configuration-proposal.json`.
   Il renderer esistente restituisce esattamente
   `#!/bin/sh\nexec <python> -I -B <source>/scripts/semantic_provider_docker_runtime.py --configuration <config> "$@"\n`
   (`tools/semantic_transaction_profiles/guarded_runtime_switch.py:39-44`).
   **Il piano reale deve includere la stringa UTF-8 completa con i path risolti,
   l'encoding/base64 dei byte esatti, byteLength e SHA-256.** Questa formula con
   placeholder non è un wrapper revisionabile né autorizzabile.
7. Stampare piano e `planSha256` ottenuto dal payload canonico senza il proprio
   hash, senza tempo corrente variabile. Includere commit/closure, P/A/manifest hash,
   input raw hash e identità, stato/generazione osservati, root/output e hash attesi,
   wrapper precedente hash/identità, wrapper proposto esatto, lock path/identità,
   guard binding, due CID, ricette/rootfs, eventuali firme richieste e contatori
   previsti. `PLAN_READY` solo se tutti i contratti bloccanti sono definiti;
   altrimenti `HELD` con motivi. Nessun receipt su disco in `--plan`.

### `--apply --plan-sha256 <hash>`: solo dopo il sì umano separato

1. Ripetere i passi di lettura e ricostruire il medesimo piano; confrontare hash
   prima di scrivere o aprire chiavi. Stesso P/A/closure/destinazioni/wrapper/lock.
   Modello di confronto `scripts/prepare-semantic-provider-installation.py:695-701`.
   Non fidarsi di un JSON di piano deserializzato come autorità, come già richiede
   `tools/semantic_transaction_profiles/guarded_runtime_switch.py:47-58`.
2. Prima del primo claim e di ogni eventuale emissione, riverificare entrambi i
   successor e Semantic contro A. Se serve produrre rootfs, eseguire solo la ricetta
   offline prevista, confinata e qualificata; conservare claim, log sanitizzati,
   cleanup/readback e risultati nuovi. Prima dello switch ripetere i frame di A.
   Una nuova prova mancante non può essere inventata nel piano né riutilizzare
   claim consumati; un esito diverso dalle aspettative è HELD.
3. Pubblicare un nuovo snapshot privato: source closure, ricette, evidenze rootfs,
   eventuali firme/accettazione B1, configurazione inattiva per due CID, manifest
   input/output, journal B1 e ricevuta di preparazione. File 0600 e directory 0700
   con O_EXCL/fsync. Riutilizzare le primitive di
   `tools/semantic_transaction_profiles/publish_provider_transaction.py:17-37`,
   estendendo il contratto di `publish_plan`, non il suo status per simulazione.
4. Creare il **verificatore B1** descritto al §6, aprire tramite la primitiva il
   lock P e fare CAS del solo wrapper. Ogni checkpoint rilegge P/A/input/closure,
   stato dei tre container, guard e inattività pubblicata. Nessuna ammissione.
5. Leggere il wrapper installato, verificare i byte proposti e la configurazione
   con allowlist esatta, ripetere frame/guard e conservare ricevuta finale B1.
   Nessun avvio per «provare» il wrapper. Se readback/receipt falliscono conservare
   lo stato incerto e i claim: non dichiarare rollback avvenuto.

**Proposta di ricevuta B1:** schema versionato da definire, stato distinto da
quello della primitiva, `planSha256`, P/A/manifest/closure hash, input/output hash,
root evidenza, due CID/transaction, generazione Semantic, wrapper prima/dopo,
claim/backup/lock binding, verifiche ai tre checkpoint, prove rootfs e firme,
`privateKeysRead`, `signaturesIssued` effettivi, `containerLifecycleOperations=0`,
`dockerStartRequests=0`, `nftWrites=0`, `daemonRestarted=false`,
`startAuthorized=false`, `leaseAuthorized=false`, `notReleaseAcceptance=true`.
In errore: stage/reason/cause sanitizzata, scritture tentate, switchOutcome,
renameAttempted/wrapperReplaced, doNotRerunApply e percorsi di evidenza.
La ricevuta della primitiva offre solo un sottoinsieme di questi campi
(`tools/semantic_transaction_profiles/guarded_runtime_switch.py:141-159`).

## 6. Switch del wrapper e allowlist dei 2 CID

`switch_existing_wrapper` non sceglie da sola wrapper, autorità o verificatore:
riceve tutti gli argomenti. Controlla wrapper root:root 0755 e lock root:root 0600
vuoto, identità attesa del lock, flock esclusivo non bloccante, root evidenza 0700
e assenza del claim; confronta l'hash dei byte correnti
(`tools/semantic_transaction_profiles/guarded_runtime_switch.py:82-116`).

**Origine degli argomenti proposta:**

- `wrapper`: `P.runtime.wrapper`, anche registrazione Docker verificata.
- `expected_wrapper_hash`: hash dei byte del wrapper corrente, osservato nel piano
  approvato, fissato da `planSha256`, ricontrollato in apply. Non il vecchio hash
  costante dell'intake, né il nuovo hash del wrapper proposto.
- `expected_lock_identity`: tupla di `custody(P.paths.guard.lock, 0600)` nel piano,
  contenente dev/ino/uid/gid/mode/nlink/size/mtime_ns/ctime_ns; stesso valore
  ricontrollato in apply, non una nuova identità accettata dopo sostituzione
  (`tools/semantic_transaction_profiles/guarded_runtime_switch.py:18-35`, `tools/semantic_transaction_profiles/guarded_runtime_switch.py:104-112`).
- `claim_root`: root B1 pubblicata nuova, non directory storica o root A.
- `proposed_bytes`: gli stessi byte esatti già mostrati nel piano.
- `verify_locked(fd, phase)`: nuova composizione B1 di custodia delle pubblicazioni,
  confronto A/P e osservazione nativa del guard successor. Non un booleano del
  chiamante: deve restituire `None` solo dopo i controlli e sollevare al diniego
  (`tools/semantic_transaction_profiles/guarded_runtime_switch.py:113-115`).

La primitiva pubblica prima `runtime-switch-claim.json`, poi
`prior-runtime-wrapper.sh` con i byte originali (0600 tramite `publish_once`),
prepara file adiacente al wrapper, chmod 0755/fsync, esegue rename atomico e fsync
directory. Checkpoint: `BEFORE_CLAIM`, `BEFORE_RENAME`, `AFTER_RENAME`;
verifica stabilità lock e byte originali anche tra callback e rename
(`tools/semantic_transaction_profiles/guarded_runtime_switch.py:115-144`).
Il verificatore usa il **descriptor già detenuto**; non chiama un helper che
riacquisisca un altro lock. Modello borrowed descriptor:
`tools/semantic_transaction_profiles/transaction_guard_observation.py:75-84`.

`make_locked_switch_verifier` non è questo verificatore B1: ricrea un piano
autenticato e scarta autorità scadute a ogni checkpoint
(`tools/semantic_transaction_profiles/authenticated_runtime_switch.py:29-59`).
L'implementazione B1 deve verificarne l'equivalente per **custodia/inattività**,
senza fingere che questa equivalga all'ammissione firmata B2.

**Allowlist esistente:** è il mapping `candidates` nel JSON della configurazione
adapter v4, non una lista nella shell. L'assembler inserisce esattamente un entry
per CID e il runtime rifiuta un CID assente con `UNSTAGED_DOCKER_CANDIDATE`
(`tools/semantic_transaction_profiles/authenticate_provider_transaction.py:340-350`,
`tools/semantic_cohort_admission/cohort-draft/scripts/semantic_provider_docker_runtime.py:186-209`).
I campi entry v4 sono `intentRef`, `bundleParents`, `admissionConfiguration`,
`admissionConfigurationHash`; i journal adapter legano hash della configurazione
comune più l'entry per CID
(`tools/semantic_cohort_admission/cohort-draft/scripts/semantic_provider_docker_runtime.py:138-139`, `tools/semantic_cohort_admission/cohort-draft/scripts/semantic_provider_docker_runtime.py:188-209`).
**Requisito B1:** l'allowlist della fase inattiva deve vivere nella nuova
configurazione puntata dal wrapper e contenere solo i due CID di A, mai Semantic
o vecchi provider; nessuna wildcard/ricerca per nome all'invocazione runtime.
Il contratto inattivo e il passaggio ai campi v4 B2 restano il gate del §4.

## 7. Annullamento

Non esiste una funzione di annullamento in `guarded_runtime_switch.py`:
la primitiva conserva diagnosi e non ripristina automaticamente
(`tools/semantic_transaction_profiles/guarded_runtime_switch.py:145-162`).
`wrapperReplaced`, `renameAttempted` e `switchOutcome` distinguono `REPLACED`,
`UNPROVEN`, `UNCHANGED`; `doNotRerunApply` resta true dopo claim
(`tools/semantic_transaction_profiles/guarded_runtime_switch.py:151-158`).

**Proposta: annullamento come controller/modalità separata, con piano e sì
specifici, mai retry di apply B1.**

1. Leggere claim, ricevuta/denial, piano B1 e backup `prior-runtime-wrapper.sh`
   con custodia e hash: SHA backup uguale a `priorWrapperHash` del claim e del
   piano; wrapper corrente uguale ai byte proposti installati. Verificare che i
   path/sorgenti/config del wrapper precedente esistano ancora e siano invariati.
2. Ammesso soltanto prima che B2 abbia emesso/consumato autorità o avviato task:
   stessa generazione A, entrambi created/mai avviati, nessuna progressione dei
   journal, guard QUIESCED e set vuoti; nessun effetto esterno da compensare.
   La prova della non-progressione deve includere claim B2 e journal, non la sola
   assenza di una ricevuta di successo. Se cambia Semantic o parte un candidato,
   HELD e riconciliazione B2: B1 non ferma container.
3. Sotto lo stesso lock guard invariato, nuovo claim di ripristino in root distinta,
   file temporaneo adiacente con byte del backup e mode 0755; fsync, CAS contro
   hash wrapper installato, rename/fsync e rilettura hash uguale al prior.
   Conservare anche copia dei byte rimossi, ricevuta e tutti i claim originali.
4. Si può riusare `switch_existing_wrapper` con byte proposti uguali al backup,
   hash atteso uguale al wrapper B1 e **nuova** claim_root solo dopo la qualifica
   di questa procedura. Non passare la root originale: il claim già esistente
   viene correttamente rifiutato
   (`tools/semantic_transaction_profiles/guarded_runtime_switch.py:98-103`, `tools/semantic_transaction_profiles/guarded_runtime_switch.py:118-144`).

Claim già presente: nessuna cancellazione/riscrittura e nessun secondo switch
nella stessa root. Se l'esito è `UNPROVEN`, prima sola riconciliazione sotto lock:
confrontare byte correnti con prior/proposed, file staging, backup e journal.
Se coincide prior, registrare «nessuna sostituzione attuale provata» senza
cancellare il tentativo; se coincide proposed, pianificare ripristino solo con
prove complete; se non coincide nessuno o manca prova, **HELD**, nessuna scrittura.
Un errore dopo rename non implica che il vecchio wrapper sia già ripristinato.

## 8. Cosa B1 non fa e cosa resta a B2

**Requisito B1.** Zero CREATE/start/stop/restart/exec di container, zero restart
Docker/daemon-reload, zero nft add/delete/replace/flush e zero aggiornamenti al
coordinatore/pointer/journal storici. Nessun accesso al provider, IAM o credenziali
applicative. Nessun worker, JWT/TLS probe, grant MCP, readiness o E2E.
Rootfs offline va distinto da start e descritto esplicitamente come effetto
filesystem/mount nel solo apply, se qualificato (§4).

Nessuna chiave privata in B1 nella variante raccomandata che consuma accettazioni
già firmate: `privateKeysRead=0`, `signaturesIssued=0`. Se l'owner vuole emissione
B1 delle firme durature, sono strettamente necessarie chiavi/mandato di emissione,
ma schema/ruolo/firmatario non sono determinati; finché non risolti, HELD.
Il signer esistente apre davvero la chiave e usa OpenSSL con `-inkey`
(`tools/semantic_cohort_admission/cohort-draft/tools/semantic_provider_deployment_signing.py:28-30`, `tools/semantic_cohort_admission/cohort-draft/tools/semantic_provider_deployment_signing.py:50-67`),
quindi non va descritto come sola lettura di metadata.

**B2:** nuova verifica P/A e generazioni prima delle chiavi; review/intent/live
authorization/final mandate con finestra richiesta 240 s, emissione root e ruoli
distinti; armatura della configurazione B1; ingresso nft, start concorrenti,
readback e stop compensativo governato. L'issuer esistente emette quattro record
con scadenza (`tools/semantic_transaction_profiles/issue_provider_transaction_authority.py:71-140`);
`activate` esegue start concorrenti e conserva parziali ma non stop compensativo
(`tools/semantic_transaction_profiles/docker_cohort_activation.py:64-129`).
Questi componenti richiedono integrazione B2, non chiamate nascoste dentro B1.
C rimane la prova JWT/TLS successiva secondo il mandato.

## 9. Condizioni di `HELD`

Gli helper transaction usano attualmente `status=BLOCKED`, non `HELD`
(`tools/semantic_transaction_profiles/authenticate_provider_transaction.py:40-45`).
**Proposta:** controller B1 espone `HELD` e conserva stage/reason originali;
mai convertire il rifiuto in successo. I codici con prefisso `B1_` sotto sono
**proposti, non implementati**. Le famiglie elencano codici già esistenti o nuovi
controlli del controller; exception inattese vanno sanitizzate e conservate.

| Motivo previsto | Codice/i e provenienza |
| --- | --- |
| Profilo errato, hash/custodia drift o sintassi JSON non valida | `B1_INSTALLATION_PROFILE_UNPROVEN` (nuovo); preservare `FILE_CUSTODY_UNPROVEN`, `BOUND_INPUT_HASH_CHANGED`, `FILE_CHANGED_DURING_PROFILE_READ` (`scripts/prepare-semantic-provider-installation.py:88-109`). |
| Modifica stabile P necessaria ma non pubblicata/revisionata | `B1_PROFILE_REVISION_REQUIRED` (nuovo). |
| A assente, status/piano/hash dei payload incoerenti | `PREPARATION_A_RECEIPT_UNPROVEN`, `PREPARATION_A_SCOPE_CHANGED`, `PREPARATION_A_PIN_UNPROVEN`, `PREPARATION_A_ARTIFACT_CHANGED` (`scripts/prepare-semantic-provider-installation.py:280-298`). |
| Semantic differisce da A o namespace/processo/veth cambiato | `SEMANTIC_FRAME_DIFFERS_FROM_A`, `PROCESS_GENERATION_UNPROVEN`, `SEMANTIC_GENERATION_DIFFERS_FROM_A` (`scripts/prepare-semantic-provider-installation.py:305-346`); `B1_RECIPROCAL_PEER_UNPROVEN` per estensione reciproca (nuovo). |
| Successor non esatti/created/mai avviati o ruoli/proprietà incoerenti | `SUCCESSOR_FRAME_DIFFERS_FROM_A`, `SUCCESSOR_ROLE_UNPROVEN` (`scripts/prepare-semantic-provider-installation.py:314-322`); `B1_SUCCESSOR_CREATION_OWNERSHIP_UNPROVEN` (nuovo). |
| CID storici, transazioni riusate, dichiarazioni peer o frame incompleti | `HISTORICAL_OR_PEER_IDENTITY_REUSE_FORBIDDEN`, `FRESH_DISTINCT_ROLE_TRANSACTIONS_REQUIRED`, `INDEPENDENT_INSTALLED_FRAME_REQUIRED` (`tools/semantic_cohort_admission/compose_successor_cohort.py:68-76`, `tools/semantic_cohort_admission/compose_successor_cohort.py:98-115`); `B1_PROFILE_RECIPE_SCOPE_DRIFT` (nuovo). |
| Immagine/config indipendenti, rootfs o accettazione durevole mancanti/non verificati | `B1_INDEPENDENT_IMAGE_BINDING_UNPROVEN`, `B1_ROOTFS_EXPECTATION_UNPROVEN`, `B1_DURABLE_ACCEPTANCE_UNDEFINED`, `B1_DURABLE_ACCEPTANCE_UNPROVEN` (nuovi). Non riusare successi storici per completarli. |
| Runtime inattivo/aggancio B2 non definito o allowlist diversa dai soli due CID | `B1_INACTIVE_RUNTIME_CONTRACT_UNDEFINED`, `B1_EXACT_TWO_CID_ALLOWLIST_REQUIRED`, `B1_RUNTIME_NOT_INACTIVE` (nuovi). |
| Piano apply diverso, path di destinazione non nuovo, source/import drift | `PLAN_DIGEST_CHANGED` (modello `scripts/prepare-semantic-provider-installation.py:700`); `B1_SOURCE_CLOSURE_DRIFT` (nuovo); `EXISTING_TRANSACTION_EVIDENCE_PRESERVED`, `SOURCE_PATH_ESCAPE_DENIED`, `AUTHENTICATED_SOURCE_BYTES_CHANGED` per il publisher attuale (`tools/semantic_transaction_profiles/publish_provider_transaction.py:62-83`). |
| Guard/pointer/ricevuta successor non coerenti | `GUARD_POINTER_UNPROVEN`, `INSTALLED_GUARD_UNPROVEN`, `GUARD_OWNER_BINDING_UNPROVEN`, `QUIESCED_COORDINATION_JOURNAL_REQUIRED` (`scripts/prepare-semantic-provider-installation.py:415-436`); `B1_SUCCESSOR_GUARD_RECEIPT_UNPROVEN` (nuovo). |
| Guard nativo non vuoto, journal/comandi/runtime cambiati o lettura fuori budget | `PROVIDER_KERNEL_MEMBERSHIP_NOT_EMPTY`, `EMPTY_KERNEL_READBACK_DRIFT`, `EMPTY_COORDINATED_JOURNAL_DRIFT`, `EMPTY_BOOT_JOURNAL_DRIFT`, `LOADED_GUARD_COMMAND_DRIFT`, `NAMED_DOCKER_RUNTIME_BINDING_DRIFT`, `GUARD_OBSERVATION_BUDGET_EXCEEDED`, `NATIVE_GUARD_OBSERVATION_COMMAND_FAILED` (`tools/semantic_transaction_profiles/transaction_guard_observation.py:128-173`). |
| Custodia/pin guard o binari alterati | `INSTALLED_GUARD_FILE_HASH_DRIFT`, `INSTALLED_GUARD_EXECUTABLE_DRIFT`, `GUARD_INPUT_CUSTODY_CHANGED`, `NATIVE_COMMAND_CUSTODY_CHANGED`, `GUARD_LOCK_CUSTODY_CHANGED` (`tools/semantic_transaction_profiles/transaction_guard_observation.py:38-72`, `tools/semantic_transaction_profiles/transaction_guard_observation.py:168-172`). |
| Switch non esplicito, percorso unsafe, file/lock o wrapper cambiati | `EXPLICIT_VERIFIED_RUNTIME_SWITCH_REQUIRED`, `ABSOLUTE_SWITCH_PATH_REQUIRED`, `CLOSED_WRAPPER_PATH_REQUIRED`, `ROOT_SWITCH_FILE_REQUIRED`, `RUNTIME_SWITCH_CUSTODY_CHANGED`, `PRIVATE_SWITCH_EVIDENCE_REQUIRED`, `INSTALLED_WRAPPER_HASH_DRIFT`, `EXISTING_NATIVE_GUARD_LOCK_DRIFT`, `NATIVE_GUARD_LOCK_REPLACED`, `WRAPPER_CHANGED_BEFORE_CLAIM`, `WRAPPER_CHANGED_BEFORE_RENAME`, `SWITCHED_WRAPPER_READBACK_DRIFT` (`tools/semantic_transaction_profiles/guarded_runtime_switch.py:18-44`, `tools/semantic_transaction_profiles/guarded_runtime_switch.py:95-140`). |
| Claim esistente, lock occupato, falso callback, esito incerto | `EXISTING_RUNTIME_SWITCH_CLAIM_PRESERVED`, `LOCKED_VERIFIER_MUST_RAISE_ON_DENIAL`; eccezione flock/OS→`GUARDED_RUNTIME_SWITCH_UNPROVEN` con errorType/errno e switchOutcome (`tools/semantic_transaction_profiles/guarded_runtime_switch.py:101-114`, `tools/semantic_transaction_profiles/guarded_runtime_switch.py:145-159`). `B1_NATIVE_STATE_CHANGED` per confronto con A a tutti i checkpoint (nuovo). |
| Pubblicazione parziale o ricevuta non durevole | `DURABLE_PRIVATE_PUBLICATION_UNPROVEN` (`tools/semantic_transaction_profiles/publish_provider_transaction.py:120-130`); `B1_RESULT_READBACK_UNPROVEN` (nuovo), conservare claim e `doNotRerunApply`. |
| Annullamento senza backup/hash/prova di inattività o con UNPROVEN irrisolto | `B1_RESTORE_BACKUP_UNPROVEN`, `B1_RESTORE_NOT_ADMISSIBLE`, `B1_RESTORE_RECONCILIATION_REQUIRED` (nuovi). |

Per altre eccezioni bounded reader, Engine, ip, nft, systemd o decoder: proposta
`B1_OBSERVATION_UNPROVEN` con stage e tipo, senza valori privati/raw stderr.
Nessun retry automatico, rimozione claim o apertura chiavi dopo un HELD.

## 10. Piano di test

Questa task non esegue test. Le indicazioni seguenti sono requisiti per la futura
implementazione, non risultati CI o VPS. Le prove esistenti sono basi da riusare,
senza rieseguire preparazioni sui dati reali.

| Test da riusare / estendere | Casi richiesti per B1 |
| --- | --- |
| `tools/semantic_transaction_profiles/test_guarded_runtime_switch.py:39-110` | CAS/backup byte esatti, hash errato senza claim, lock occupato o sostituito, errore prima/dopo rename, replay, callback false, path injection; aggiungere crash tra rename/fsync/ricevuta e outcome UNPROVEN. |
| `tools/semantic_transaction_profiles/test_transaction_guard_observation.py:21-40` | Borrowed descriptor mantiene esclusiva; fd estraneo/inode cambiato rifiutati. Estendere alle tre osservazioni B1 e Semantic di A. |
| `tools/semantic_transaction_profiles/test_assemble_provider_profiles_v2.py:11-33` | Parent runtime esplicito in node/broker/entrambi i journal; multiparent ambiguo/outside rifiutati. Non far passare il legacy `/run` come parent installativo. |
| `tools/semantic_transaction_profiles/test_authenticated_transaction.py:194-255`, `tools/semantic_transaction_profiles/test_authenticated_transaction.py:319-357` | Pubblicazione durabile, directory producer private/vuote, parziali, path escape, drift profili/source prima dell'exec. Separare nuove fixture B1 inattive da fixture con autorità B2. |
| `tests/test_semantic_provider_installation.py:28-132`, `tests/test_semantic_provider_installation.py:135-253`, `tests/test_semantic_provider_installation.py:324-370` | Custodia/binari, profilo canonico, P già esistente, socket systemd/daemon. Aggiungere P hash raw con LF/CRLF, file symlink/hardlink, UID/GID/mode errati e rifiuto modifiche P da B1. |
| `tests/test_semantic_provider_preparation_a.py:35-113` | Peer reciproco e staging esatto; nuove fixture A per ogni delta CID/Name/Image/StartedAt/PID/startTicks/netns/boot/veth/endpoint, created→exited/running, restart policy, labels e frame. Stesso API1.44 senza ignorare Config.MacAddress. |
| `tools/semantic_transaction_profiles/test_authenticated_transaction.py:383-545` | Tenere test firme, tamper, scadenza, root mandate/hash, dependency freshness e sigillo non sostituibile nel percorso B2. Aggiungere test del nuovo documento durevole solo dopo schema/ruolo approvati; rifiuto riuso come start authority, revoca e key expiry. |

**Nuovi unitari indispensabili:**

- Fixture di **due installazioni differenti**: cambiare tutti i nomi/IP/MAC/porte,
  reti/bridge/runtime/path P e lasciare identica la logica; entrambi i piani devono
  derivare solo dai rispettivi P e input. Campi extra/mancanti, rete comune ambigua,
  CID duplicato/storico/terzo CID e digest manifest scambiato con config rifiutati.
- Determinismo plan/apply e destinazione; ogni byte input/output previsto e del
  wrapper cambia `planSha256`. Stringa wrapper/base64/digest coerenti, quote/LF e
  terminatore finale esatti. Il piano non crea file temporanei/claim/snapshot,
  non apre chiavi, non emette firme e non esegue export/mount/start/nft mutante.
- Apply con A cambiata va HELD **prima** di accesso al signer; spy dei file aperti
  per provare esclusione chiavi, non solo contatori auto-dichiarati.
- Allowlist inattiva esattamente due CID; runtime rifiuta create/start prima di
  producer/chiavi/nft anche per quei due CID finché manca l'armatura B2. Nessun
  intent dummy, journal READY simulato o fallback alla configurazione storica.
- Ogni checkpoint rifiuta drift P/A/closure/guard/profili/wrapper; il verificatore
  dopo rename riconosce correttamente la fase e non pretende ancora i byte prior.
- Annullamento: backup alterato/mancante, wrapper terzo, claim esistente, B2 claim
  o journal progredito, task avviato e UNPROVEN; nessuna sovrascrittura in tutti i
  casi incerti. Positivo con nuovo claim e hash prior letto dopo restore.

**Nativi CI Linux isolati da qualificare:**

1. Filesystem root reale, flock, O_EXCL, nofollow, rename e fsync, fault injection
   ai punti di durabilità; controllo hash/custodia effettivi, non solo mock.
2. Namespace di rete isolato: nft reale solo per preparare la fixture, osservatore
   B1 esclusivamente read-only; set non vuoti/struttura diversa/lock sostituito
   negati. Base `tools/semantic_transaction_profiles/test_transaction_guard_observation_native.py:24-86`
   usa nft reale ma Docker/systemd fixture: non presentarla come prova Docker reale.
3. Engine della versione pertinente, backend classic e containerd quando pertinenti
   ai contesti/rootfs: due candidati reali created/mai avviati con reti multiple,
   processo/namespace/veth peer sintetico reale; snapshot prima/dopo B1 invariati,
   zero start e journal storici identici. Config.MacAddress presente/assente con
   endpoint per rete osservati alla stessa API; nessuna normalizzazione globale.
   Non serve un ciclo stop/detach/rename di container per B1: se l'implementazione
   lo introducesse uscirebbe da questo perimetro.
4. Ricette rootfs: offline unpack/init e confronto effettivo dei due CID CI, limiti,
   xattr/mode/ownership, export/mount cleanup anche in errore; nessun segreto o
   archivio VPS. Verificare che seal offline/overlay/effettivo rimangano distinti.
5. Consegna da commit/SHA simulati localmente: sorgente modificato rifiutato prima
   di import/exec, nessuna dipendenza fuori closure. Nessuna nuova rete esterna
   richiesta dalla logica del controller.

## 11. Rischi e domande aperte

Questa nota completa l'analisi documentale; **non qualifica un controller B1
pronto per il VPS**. I seguenti punti sono esplicitamente non determinati e
devono restare visibili alla review.

1. **Firme durature:** non determinati schema del documento B1, issuer/ruolo,
   firmatario, luogo e mandato di emissione, revoca e validità dopo key expiry.
   L'envelope senza scadenza non risolve questi punti (§4). La review deve scegliere
   emissione precedente con B1 senza chiavi, oppure autorizzazione concreta alla
   firma B1. Non riutilizzare un final mandate di start come accettazione durevole.
2. **Configurazione inattiva:** non determinato il contratto che consenta switch
   B1 oggi e intent B2 domani senza alterare hash approvati o usare intent fittizi.
   Serve una fase inattiva esplicita con due CID e armatura B2 distinta, o altra
   soluzione revisionata equivalente. La v4 attuale lega già `intentRef`/broker
   (`tools/semantic_transaction_profiles/authenticate_provider_transaction.py:328-350`).
   Questo è un blocco d'implementazione prima dello switch, non permesso di
   anticipare review/intent/mandati B2 dentro B1.
3. **Aggiornamento P:** i path delle unità e il nome dell'unità guard non sono in P.
   Proposti tre campi nuovi (§2), quindi evento di modifica P e nuovo hash.
   Il writer P attuale non sovrascrive (`scripts/prepare-semantic-provider-installation.py:573`).
   Non determinata procedura di revisione del profilo: non eseguirla qui.
4. **Ricevuta guard successor:** non determinati tutti i mode/binding della closure
   installata e l'adattamento completo del lettore borrowed-lock alla nuova receipt.
   La differenza di schema è dimostrata da
   `tools/semantic_transaction_profiles/transaction_guard_observation.py:104-108`
   rispetto a `scripts/prepare-semantic-provider-installation.py:419-440`.
   Non cambiare il check in «qualunque receipt INSTALLED» né riscrivere la ricevuta.
5. **Catena di proprietà e ricette nuove:** non determinati path/hash completi delle
   richieste autorizzate dei successor, delle ricette che incorporano le modifiche
   effettive alla creazione, della ricetta indipendente Semantic post-D e delle
   nuove prove rootfs. A lega frame/generazione, ma non contiene tutti questi
   documenti (`scripts/prepare-semantic-provider-a-20261111.py:270-291`).
   Non copiare la ricetta storica né usare l'inspect come sua approvazione.
6. **Seal osservato vs atteso:** non determinato se esistano già evidenze sufficienti
   per entrambi i nuovi CID. Nessun accesso VPS è stato fatto. Se servono nuove
   prove, l'integrazione export/mount e i suoi limiti vanno qualificati e mostrati
   nel piano; `--plan` rimane senza tali effetti. Non attestare rootfs in base a CI
   o alla sola immagine uguale (§4).
7. **Binding P incompleti per hash:** P conserva percorsi di autorità/trust/binari,
   non tutti gli hash (`scripts/prepare-semantic-provider-installation.py:619-636`).
   La proposta usa un manifest CLI revisionato; non determinati i byte/hash di
   tale manifest. Un hash osservato per la prima volta non diventa indipendentemente
   approvato fino alla review del piano.
8. **Annullamento prima di B2:** non esiste ancora il controller descritto al §7;
   non determinata la prova completa di assenza di emissione/progressione B2 finché
   il contratto B1→B2 non è fissato. UNPROVEN richiede riconciliazione, non retry.
9. **Sorgenti e packaging:** il runtime è nella copia `cohort-draft`, non nel path
   root indicato nel task. Non determinata qui l'uguaglianza con il VPS; futura
   consegna deve fissare commit/SHA dell'intera closure e non usare hash CRLF (§1).
   Il launcher B1 non esiste in questa task e non viene consegnato un comando sudo.
10. **Semantica digest Docker:** il lettore storico confronta `.Image` con il campo
    chiamato `imageManifestDigest` (`tools/semantic_transaction_profiles/transaction_guard_observation.py:157-164`).
    Non determinata la corretta corrispondenza dei binding dei successor con i
    digest manifest/config indipendenti: preservare entrambi e qualificare il
    confronto, senza rinominare un digest osservato per far coincidere il check.
11. **Brief assente e runbook storici:** `sprint-01/brief.md` manca; STATE e i
    documenti successor sono contesto storico, mentre P completato e stato live
    derivano dal mandato attuale. Non determinati eventuali dettagli aggiuntivi
    del brief non incluso. Nessuna domanda viene risolta con rete, segreti,
    ripristini già conclusi o modifica dei registri vietati dal perimetro.

Le decisioni di schema/autorità sopra richieste appartengono alla review prima
dell'implementazione. In loro assenza il futuro controller deve restituire HELD
con il motivo specifico; questa task non costruisce workaround o nuovi stati live.
