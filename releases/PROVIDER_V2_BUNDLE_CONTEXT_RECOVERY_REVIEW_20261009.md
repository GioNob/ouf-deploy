# R4 approved — one pinned operator execution pending

Human approval received on 9 October 2026 at 10:22:23 Europe/Rome (epoch 1791534143), ref `OUF_PROVIDER_V2_BUNDLE_CONTEXT_RECOVERY_HUMAN_APPROVAL_20261009_102223`. Witness and the helper's only two authorization edits are recorded in commit `796e23f6e3f6e4c8c6ac64bace2230e9bfbf7abe`, `evidence/provider-v2-bundle-context-recovery-human-approval-20261009.json`. The five recovery tests pass with that exact approval. Prior review/CI remain the reviewed implementation; do not request the same acceptance again.

Execute only `releases/provider-v2-bundle-context-recovery-20261009.sh` pinned by commit and SHA256 `ea1ab4e7970ffd61e85b0ec6429a16a3526a4698fa7d8ec66ddc9b073868ecc2`. It verifies and reuses the existing R2 and R3 downloads, downloads only approved R4 helper from 796e23f6… (SHA256 `262f03825cc8beb4c8823c5882d9549d4220a8ffeb90e4601d8fc5671e610fce`), verifies bytes again as root and invokes the exact approved reference. Failures before root emit the launch phase; transaction failures preserve native evidence/claims and never automatically retry. Local fault injection proves failed downloads/digests never reach sudo. No R4 target execution has been observed yet. Await operator output, not another approval. Never repeat R3, image/SBOM/guard preparation or the completed context review.

Earlier checkpoint text below is historical and superseded by this approved execution checkpoint.

# Provider v2: recupero dei due contesti bundle — R4, 9 ottobre 2026

Stato: proposta concreta, non autorità. Nessun comando target da eseguire prima dell'accettazione umana di questo R4.

Il tentativo R3 ha richiesto due avvii Docker, entrambi negati dal runtime a `ADAPTER_BINDING_UNPROVEN_L283`; i due journal riportano STAGED. I contatori storici incerti restano incerti. Il wrapper è stato sostituito e il suo hash osservato è `3234529d94e84c70ed66f6e54a2d86f156e875fc73c9f8e15844b61edbb8ae20`. Le evidenze R3 e tutte le firme già emesse devono restare conservate.

La lettura kernel riportata dall'operatore osserva 13 shim Docker non target sotto `/run/containerd/io.containerd.runtime.v2.task/moby`, correlati al socket `/run/containerd/containerd.sock`. Nessuna invocazione storica dei due CID è stata acquisita. La revisione successiva sul VPS, commit `95fcec2b39bb510dbadd84ab729db279bc40b4fc`, calcola i due contesti proposti cambiando esclusivamente `bundleParent`; entrambi i profili OCI completi rimangono byte-identici a quelli accettati. Queste sono ricevute dell'operatore, non acquisizioni indipendenti in cloud.

| Ruolo | CID | Nuovo context SHA256 |
|---|---|---|
| adapter | f3d59af93fc90162681cee3a7562bdff3bf2af8c05cbdb7e270d1508fff18f67 | cfc1bfc12855dc49bfe0bf3eef22d0b2fb1f376d017a5cf68a4e77822dc9dfc6 |
| southbound | 1fc5ae6a0db4600e0124bb1f9d2998780d533fd2b4de7cb086d8675b6afb5916 | ce46668d3652eeb1fbf45ebba78c6fdc15aefa9af62801b536b616635a0f4246 |

Per entrambi, `bundleParent` passa da `/run/docker/containerd/daemon/io.containerd.runtime.v2.task/moby` a `/run/containerd/io.containerd.runtime.v2.task/moby`. I quattordici altri input si riusano agli hash già accettati. Image/rootfs, application hash, frame policy, trasporti, NIC/peer, sorgenti runtime e guard non cambiano. Non estendere l'allowlist a due percorsi: la nuova allowlist per ciascun CID contiene soltanto il nuovo percorso.

## Implementazione proposta

`tools/semantic_target_review/execute_bundle_context_recovery.py`, sorgente `56f2b541370258b498cb52c8ad92635af54b39a3`, è inerte: approvalRef PENDING e APPROVED_AT None negano prima di qualsiasi lettura. Dopo un'accettazione esplicita, i soli due campi di autorizzazione vengono sostituiti con riferimento e timestamp effettivi della risposta; non si usa il timestamp della CI o della revisione come approvazione.

Riusa le due copie già trasferite: bridge R2 `/home/oufadmin/ouf-reviewed-recovery.qGpE9is0/execute.py` (SHA256 e3253513c4220a0a506c117e0a535145d14f76fcba3f58fe292ee894c46bfcd4) e recupero R3 `/home/oufadmin/ouf-r3-recovery.3ssUuaKX/execute.py` (SHA256 5ff0a5ac9de85132371026584124f26ad57301601d16882c06974a9c21356328). Legge solo le definizioni dopo verifica hash, senza eseguire i relativi main. Riusa il pacchetto sorgente originale ff13uh3n, le quattordici binding private e le chiavi già installate sul VPS. Nessuna rigenerazione o esportazione chiavi, trasferimento SBOM o reinstallazione.

Prima di qualunque lettura chiavi controlla il caso R3 esatto: claim originale, due rifiuti L283, due hash di stato/journal riportati, otto record di ruolo, pubblicazione originale di 81 file, wrapper corrente 3234529…, nessun risultato di successo confliggente. Ricompila entrambi i contesti e pretende esattamente i nuovi hash e l'identità dell'intera policy OCI. Sotto il lock esistente osserva entrambi i CID ancora created, Running false, Pid zero, mai avviati, hash di stato uguali al R3 e set provider vuoti. Qualsiasi deriva nega prima delle chiavi.

Materializza un nuovo contesto privato con esattamente due nuovi file context, due mandati di ruolo e la configurazione. Una claim esclusiva `bundle-context-recovery-claim.json` nel pacchetto impedisce il replay. Emette otto nuovi record firmati con le chiavi esistenti, entro una finestra di 240 secondi coperta dal database dipendenze valido fino al 10 ottobre 2026 alle 08:33:47 Europe/Rome. Pubblica nuovi profili/journal STAGED e sostituisce il wrapper con CAS dal preciso hash R3. Il predecessore viene conservato.

Le due riparazioni già approvate nel R3 (budget autenticazione 18 secondi e diagnosi simbolica) vengono caricate in memoria dal recupero R3 verificato. Il bridge R2 viene adattato soltanto nei due confronti del wrapper: dall'hash del wrapper empty storico all'hash R3 corrente. Il runtime e l'observer della chiusura dc87593c… non vengono modificati.

Segue una sola coppia di richieste Docker, tramite il runtime nominato, dopo i controlli firmati e nativi; restano obbligatori OCI completo, rootfs, NIC, peer, generazione e guard. Si conserva l'esito di entrambi e una diagnosi con fase, motivo, evidenze e contatori incerti. Nessun retry o rollback automatico; nessun riavvio daemon, Docker start diretto, sudo generale, lease provider, chiamata provider autorizzata dall'orchestratore, discovery Teatri o accettazione di rilascio.

## Validazione e confini

Cinque test locali passano: gate prima dell'approvazione/clock, rifiuti R3 precisi, adattamento dei soli due confronti wrapper, trasformazione dei contesti con policy completa invariata, otto firme Ed25519 reali con chiavi CI nuove e nuova allowlist esatta. Il primo test di issuance usava erroneamente la directory delle firme iniziali del fixture e veniva correttamente negato per duplicazione; corretto usando una directory fresca, come nel recupero proposto. Nessuna modifica ai verificatori di produzione.

CI [37903901943](https://github.com/GioNob/ouf-deploy/actions/runs/37903901943), job connected-locked-switch 113732624093: SUCCESS. CI [37903901869](https://github.com/GioNob/ouf-deploy/actions/runs/37903901869), quattro job: SUCCESS. Docker reale 29.8.1 riproduce due rifiuti L283 con i due container CI ancora created/STAGED e nessuna applicazione rilasciata; corretto il percorso nella pubblicazione CI, i due container raggiungono l'ammissione completa e due marker applicativi. È prova CI con chiavi isolate, non autorizzazione o prova dei CID VPS. Il recupero root R4 non è stato eseguito sul VPS.

PET Authorization v1.5 AUTH-05/06/07/08/09/12 e regole operative OUF consultati. Il vincolo già accettato nel [review sign/start](PROVIDER_V2_SIGN_START_REVIEW_20261009.md) dice: «Il recupero, se necessario, richiede un intervento umano esplicitamente limitato al risultato osservato.» R3 è stato consumato e questo R4 cambia due input autorizzati. L'accettazione richiesta riguarda insieme i due nuovi hash context e questo singolo recupero controllato; non ripete le accettazioni già valide degli altri quattordici input, delle immagini o delle rootfs.
