# Provider v2 admission: next target step — 8 October 2026

## Regole operative

Seguire [OUF_WORKING_RULES.md](OUF_WORKING_RULES.md): diagnosi degli errori inclusa in ogni procedura, nessuna verifica ridondante e nessuna ripetizione di passi completati.

## Prossimo passo operativo — transazione e avvio controllato

**Migrazione delle protezioni di rete completata sul VPS l'8 ottobre 2026. Non ripetere il bootstrap.** L'operatore ha riportato `EMPTY_GUARD_EXTENDED`; ricevuta in [provider-v2-network-guard-target-20261008.json](../evidence/provider-v2-network-guard-target-20261008.json). Fonte installata: `/etc/ouf/deploy-snapshots/semantic-network-guard-source-ib5rco84`; snapshot: `/etc/ouf/deploy-snapshots/semantic-coordinated-boot-install-v2-e4repg0a`.

Il runtime riporta `RUNTIME_PROVIDER_OIDC_EMPTY`, due flussi provider, destinazioni vuote, custodia verificata e due candidati mai avviati. Gli handle originali sono preservati; zero operazioni sul ciclo di vita, nessun riavvio del daemon, nessuna lettura di chiavi private e nessuna chiamata al provider. I resolver restano quelli dell'installazione: `46.38.225.230`, `46.38.252.230`. Configuration SHA256: `656c23f18e3f3eb4c1ce630f5056be87f7883eab7b048065092dafbd018284a8`.

Questa è evidenza dell'operatore, non una ricevuta acquisita indipendentemente. `stableAcrossReads:false`, `realRebootProven:false`, `startupReady:false`, `startAuthorized:false` e `leaseAuthorized:false` restano riportati esattamente. Nessuna accettazione del rilascio deriva dalla migrazione. Il tentativo corretto è riuscito, ma l'endpoint effettivo del primo errore non era stato catturato: non attribuire retroattivamente la causa target alla porta 443 come fatto provato.

Il prossimo lavoro è completare l'orchestratore target della transazione: verificare gli input completi autorizzati e i sigilli rootfs, installare la chiusura di sorgenti/profili, emettere i mandati di ruolo limitati, configurare l'allowlist runtime e coordinare l'ammissione/avvio con diagnosi conservata. **Nessun comando di avvio target è ancora pronto.** Riprendere dagli snapshot esistenti; non ripetere immagini, rootfs, TLS, input, handover o migrazione di rete.

Il bootstrap completato era fissato al commit `2c3dc6ff917cc05327abd420985fcc6faab544de`, pacchetto `f7740ce1cbe03c16f5069398985c8795ef1f68b9`, SHA256 `0c3aa73309fbdb851e63a597caf40aa46c2be42d3c3aa384d9d8304e58e1bcd4`. La [CI 37826181070](https://github.com/GioNob/ouf-deploy/actions/runs/37826181070) resta prova isolata; il nuovo output è la distinta evidenza target.

## Previous completed target steps

**Target image equivalence completed successfully on 2026-10-08. Do not rerun the comparison.** Operator snapshot: `/etc/ouf/deploy-snapshots/semantic-provider-v2-rootfs-compare-ox08k7hb`; source: `/etc/ouf/deploy-snapshots/semantic-v2-image-equivalence-source-GH4jyznf`. Both roles report zero image differences, `imageEquivalent:true` and `IMAGE_EQUIVALENCE_PASS`. Selected operator-reported facts are retained in `evidence/provider-v2-image-equivalence-target-20261008.json`.

The earlier strict-seal mismatch came from directory link counters and root-directory mode representation. Both actual roots are 0755; neither image has an explicit root-mode tar header, so the independently defined Engine default is 0755. The corrected comparator excludes only directory link counters from image equivalence and continues to compare regular-file links and all other fields. Original full v1 seals remain unchanged; `strictSealsMatch:false` is retained honestly.

The actual full v1 runtime seal to bind for Adapter is `8744724088d02145b86b433058a4336fcb9c873a4a92e7009753209c284d3d73` (3390 entries, 46079786 bytes); Southbound is `52e06f47e1da5a107525e2260b9d375329997181dd13de7023654278aeaf3f39` (7458 entries, 255900260 bytes). Portable image seals must never replace these node-attestation seals.

The next implementation is the target transaction assembler: complete OCI/context authorization, creation-intent issuer, node-attestor v4 and installer approval profiles, broker/preparer configuration and durable journals. Runtime allowlist installation and controlled activation follow only when these inputs are complete. No startup or release acceptance follows from image equivalence alone. Both containers remain never started; no further imports, reconstruction, creation, source listings or rootfs comparisons are needed.

Focused CI [37796294095](https://github.com/GioNob/ouf-deploy/actions/runs/37796294095) already passed four unit tests and a native Engine 29.8.1 fixture, including modified-content rejection with concrete diagnosis. No repeat of this CI is needed for recording target evidence.

## Target state

The operator completed stopped creation in `/etc/ouf/deploy-snapshots/semantic-provider-v2-stopped-resume-k5mmsudx`, source SHA256 `2a9fc3d2861faa2e15370c70979b171cb63b2e09a2dfef1e2895ca27fa663861`. The full receipt is `evidence/discovery-provider-v2-stopped-creation-target-20261008.json`.

- Adapter CID: `f3d59af93fc90162681cee3a7562bdff3bf2af8c05cbdb7e270d1508fff18f67`; Docker manifest/image ID `sha256:277dcefd4744c244f4f6f23f8969f3d0acd64369e2ff1bd67594955c4ca7fbbc`; verified config `sha256:62e066bd021f386291f5de21ce0e1f9e67904a74b4146326070c7784493ad320`.
- Southbound CID: `1fc5ae6a0db4600e0124bb1f9d2998780d533fd2b4de7cb086d8675b6afb5916`; Docker manifest/image ID `sha256:c15541037a08276e36715a3c3798c2d07fe6faabf5547d3885a66cd10575e366`; verified config `sha256:d4c47bbeca75d94e2231e17ca14552885b7b339a5f33dbace411e275c79ded04`.

Both candidates were never started. Mounts, startup and configured addresses were verified. All 96 pre-existing container states were preserved. One image was imported during recovery. No daemon restart, firewall write, provider call, authority-key read or runtime-allowlist update occurred. Configured address metadata does not prove live namespace allocation. No start or release acceptance was granted.

Do not repeat stopped creation or run Docker start. The runtime allowlist is still empty.

## Required implementation

Creation-only intent issuance and the runtime broker already exist in reviewed Gateway source `ace683b1019f79adaace86796b67e463b93ec12e`. The existing authority profile is `/etc/ouf/deploy-snapshots/semantic-creation-issuer-install-USjonf22/installation-authority-profile.json`, hash `7fb7880d58e43ab40f9f53dac07a5dbad462d12e3a96f3b1287c6763b1d7ce18`.

The target transaction-specific installation/signing orchestrator remains unimplemented. Its pure profile assembler is now implemented at `tools/semantic_transaction_profiles/assemble_provider_profiles.py`. It derives CLI source closures from the actual source declarations, creates node v4/installer/broker profiles and STAGED journals, and binds the broker to exact generated producer bytes. It performs no file writes, key reads, signing, target installation or activation. Its caller must first authenticate external intent/mandates and separately validate complete target inputs; the assembly helper cannot supply authority. Focused tests cover seal substitution, complete OCI scope drift, signed transport drift with diagnosis and generated producer/source bindings. The four local tests pass; hosted CI is triggered by this implementation. It must assemble per-CID creation mandate, verified frame policy, node-attestor v4 observer binding, final-approval producer, broker/preparer profiles and durable journals, then complete reviewed actual-OCI and namespace/guard/lease admission. It must preserve independent image/config digest bindings and existing source/authority custody. CI or locally generated booleans cannot replace signed complete authorization.

The operator has now installed and verified the source package at `/etc/ouf/deploy-snapshots/semantic-provider-v2-producers-Vj1CmjRH`. Apply and verify both returned PASS. This package contains the 26 reviewed Gateway sources and the reviewed frame observer. The raw operator output is retained at `evidence/discovery-provider-v2-producers-target-20261008.txt`; it is operator evidence, not an independently fetched target receipt. Some printed source hashes have missing characters, so do not reconstruct an authoritative root receipt from that pasted output. Use the sealed package manifest for canonical source hashes.

The source-only receipt explicitly leaves broker, preparer, node attestor, installer approval, runtime adapter, trust-policy consumption and startup authorization uninstalled/unconfigured. The previously registered runtime remains separate and has an empty candidate allowlist. No further filename listing or repeated source installation is required.

### Compiler and current integration boundary

The pure compiler at `tools/semantic_frame_compiler/compile_creation_frame_policy.py` now resolves seven closed Docker path/identity slots from separate template, launch and context inputs. It does not consume observed OCI. All other fields stay exact, and the owner full-document comparison remains unchanged.

CI [37741307729](https://github.com/GioNob/ouf-deploy/actions/runs/37741307729) passed 12 unit tests and one real isolated Docker test per backend (classic vfs and containerd overlayfs). A second fixture policy was sealed before its OCI existed and subsequently matched the complete generated document. The runtime refused create before runc; no candidate application ran. The fixture template is synthetic, not an independently approved target template. This proves path compilation in those fixtures, not deployment acceptance or the full controlled runtime create/start path. Evidence: `evidence/discovery-provider-v2-frame-compiler-ci-20261008.json`.

The self-hosted read at [37734793698](https://github.com/GioNob/ouf-deploy/actions/runs/37734793698) independently confirms both exact target candidates remain never started, Docker data root is `/var/lib/docker`, and storage driver is `overlayfs`. It did not read private configuration/environment, authenticate a complete context, or prove rootfs admission. Evidence: `evidence/discovery-provider-v2-frame-context-target-20261008.json`.

The operator has completed private launch preparation, frame-policy compilation and the bounded admission-manifest read. The manifest is retained in `evidence/provider-v2-admission-input-manifest-target-20261008.json`. It reports hash-bound inputs, not authenticated context, rootfs acceptance, signed transaction configuration or startup authorization. No repeat of these operator steps is needed.

The stopped-network handover is complete: only five endpoint declarations moved from the two never-started legacy candidates to the exact v2 candidates. Existing container states were preserved. This is metadata preparation, not live kernel address allocation; do not repeat the handover.

### Sibling peer coordination: CI proof complete, target integration pending

The southbound-to-adapter flow requires the actual sibling host-veth index. The draft at `tools/semantic_cohort_admission/cohort-draft` embeds each peer's independently expected complete OCI hash and all approved NIC identities in immutable transport declarations. It resolves numeric kernel indices only after real runc state, process generation and reciprocal links are observed, then repeats those checks before guarded start. Signed transport hashes remain unchanged.

The broker's bounded read-only `cohort-ready` phase waits only for missing created peers or incomplete NIC/address assignment; OCI or identity drift is denied. Concurrent admission initially failed at the existing nonblocking common guard lock. The adapter now serializes admission and guarded start on the already sealed root-private registry directory inode, after peer readiness. This scheduling lock is distinct from the existing guard/lease lock; no guard-lock failure is ignored, no lock inode is created or replaced, and create/readiness can proceed concurrently.

Hosted CI [37768123080](https://github.com/GioNob/ouf-deploy/actions/runs/37768123080), source `ff1a50205c147295517fb7a4c5259d1d17298129`, passed both jobs. It verifies all 29 source hashes, 15 integration unit tests, six resolver unit tests and the native peer recheck. The frozen Gateway authenticated Docker regression passes its real Ed25519/broker/node/installer path and signature, lease and rootfs rejection cases. The new controlled fixture also proves two real runc-created candidates, complete expected OCI documents fixed before create, no early application release while a peer is absent, and two authenticated v6 guarded starts. The successful final repetition uses the original broker and attestor CLI sources without diagnostic instrumentation. Evidence: `evidence/provider-v2-cohort-authenticated-two-candidate-ci-20261008.json`.

The two-candidate fixture invokes the production draft runtime adapter against controlled real runc candidates; it does not prove concurrent two-candidate lifecycle allocation through the Docker engine. The separate single-candidate regression exercises real Docker. All signing keys, images/rootfs acceptance and authorities in these fixtures are disposable CI-only inputs. They neither authenticate target context nor accept the target provider images.

Existing installed target sources, private profiles, empty runtime allowlist and stopped candidates remain untouched. The transaction-specific target provisioner/orchestrator is still missing. Required target work is independent complete OCI/context approval, image/rootfs acceptance, target-bound creation intent and live signed approval profiles, installation of the reviewed source closures and actual namespace/guard/lease admission. No target start command is ready. Completed source installation, network handover, launch/frame preparation and manifest reads must not be repeated.

## Completed offline expected Docker filesystems

Hosted [37770703203](https://github.com/GioNob/ouf-deploy/actions/runs/37770703203), source `e5bead716d02527e937be83e1cb22cad74affcbb`, passes seven archive/provenance tests and both native filesystem comparisons. It builds umoci at `1c44d6f2f9e4b50f5d2a99463f540acf9915dd47` and a tiny caller of the actual Moby initlayer implementation at the independently read target engine commit `464cd50c3d9e92877d56940ea160de6fca7bea23`. The runner read confirms Docker 29.8.1 / Linux amd64 / GitCommit 464cd50 with no container/configuration operations. The source commit's daemon umask is zero; the initlayer caller reproduces that setting.

`tools/semantic_image_rootfs/prepare_provider_image_rootfs.py` verifies the private frozen archive SHA256, original manifest/config digests, all layer blob hashes and uncompressed diff IDs, reconstructs the image via pinned umoci, and seals it with the reviewed node rootfs sealer. It then applies that exact engine's initlayer code to the offline copy, retains the original image seal, and records the derived expected Docker filesystem seal. Docker schema2 descriptor-only conversion preserves original manifest/config/layer bytes and digests. The native tests compare separately authored expected filesystems, including whiteouts, opaque deletions, hardlinks, symlinks, numeric owners, modes, extended attributes and Docker additions.

Evidence is `evidence/provider-v2-offline-rootfs-ci-20261008.json`. Artifact `ouf-pinned-umoci` in that exact successful run includes both verified binaries. Umoci SHA256 is `b21ac9b656fa76035db6ac4793facfd26982165d96f730bae9606d6f0929932e`; initlayer caller SHA256 is `be8b8804a0d63990d02cc4b44008c22397778b4fecf16077397103fe8a64cb22`. The same hashes were obtained in the preceding successful build.

The single operator bootstrap is `releases/provider-v2-offline-rootfs.sh`. **It completed on the VPS on 2026-10-08.** The operator reported both expected seals and `OUF_OFFLINE_EXPECTED_DOCKER_ROOTFS=PASS`; snapshot is `/etc/ouf/deploy-snapshots/semantic-provider-v2-offline-rootfs-s3BU0nDX`. Retained evidence is `evidence/provider-v2-offline-rootfs-target-20261008.json` (operator-reported selected facts, not an independently fetched root receipt). Adapter derived seal is `8a67afc590854316165176c39fbc0d393bb9b38ab6662430d2a36d3313858cf8`; Southbound derived seal is `ec013e0317560153aece8e08a393442c95aaa13f64e3df274c61987953e546d8`. **Do not repeat the bootstrap or offline reconstruction.** It uses existing authenticated gh, fetches exact source/binary versions, creates one new root-private `semantic-provider-v2-offline-rootfs-*` snapshot and processes the two frozen archives already held in `semantic-provider-v2-stopped-create-a2kbzv6l/images`. It installs no packages, replaces no existing source/configuration or runtime, and performs no container, network, firewall, provider or signing operation. The copies of the 29 reviewed sources are used only for the exact offline node sealer closure; previous source snapshots are retained.

The received outputs were two `OUF_OFFLINE_IMAGE_ROOTFS` JSON reports, `OUF_OFFLINE_EXPECTED_DOCKER_ROOTFS=PASS`, and `OUF_OFFLINE_ROOTFS_SNAPSHOT=...`. Full receipts remain root-private in each role directory as `expected-rootfs.json` and `expected-docker-rootfs.json`. A failed or partial run must be diagnosed from the retained new snapshot, not blindly repeated.

This step creates independent expected seals; it does not compare a live target rootfs, accept publisher/dependency trust, authenticate full target OCI/context, provision transaction mandates/profiles, grant startup or prove the seven infrastructure/runtime gates. Those remain required before target startup. Filesystem metadata differences between an unpacked image and the target snapshotter must be resolved explicitly before comparing/authorizing the live rootfs; no digest mismatch may be ignored.

The completed offline preparation needed operator intervention because the runner has Docker access and the fixed read helper, but no general sudo or access to the private archive directory. No SSH credential or private key upload is requested. After the reports return, continue transaction-specific target integration and then the MCP-only product path.

## Completion goal

After provider admission, activate the reviewed Semantic/MCP configuration and necessary discovery grants. Use the existing Teatri asset (`6609b245-86ed-4315-8ce0-73f2a8555bf3`) for national discovery, chatbot semantic mapping/review, human approval, onboarding, ingestion and UDP readback. Product operations must use the MCP-compatible chatbot, not SSH. No Teatri reupload, local fallback or repeat of completed tests. Continue beyond milestones and update the user at least once per minute; stop only for genuinely required user intervention. Infrastructure sudo remains operator-only.


## 8 October: node-v4 profile integration and next operator input

The pure assembler is now exercised by [37810226113](https://github.com/GioNob/ouf-deploy/actions/runs/37810226113), source `845158944210759b83f791c199f62e9d05ae359d`. Both jobs pass: four profile/seal-scope tests, four partial-creation classification tests, and the real two-runc node-v4/broker/installer/v6 path. A source-pinned CI facade deterministically exposes a sibling as stopped/pid=0 while its source-owned journal is CREATING. The barrier waits within its existing budget and subsequently requires actual created/running state and all full OCI/NIC/generation checks. Failed/completed/foreign journals never satisfy that wait. All keys and acceptance remain CI-only. Existing authenticated single-Docker regression [37810226138](https://github.com/GioNob/ouf-deploy/actions/runs/37810226138) also passes. Evidence: `evidence/provider-v2-frame-profiles-integration-ci-20261008.json`.

The available MCP channel returned HEALTHY and a published semantic search for teatro returned an empty list. No national discovery operation was executed and no onboarding was created.

The operator completed the network input reader successfully. Its retained report is `/tmp/ouf-transaction-network-979dcbgd`; selected fields are retained in `evidence/provider-v2-network-integration-progress-20261008.json`. Do not repeat the reader or any completed image comparison.

## Network integration progress, 8 October

The captured global kernel contains provider HTTPS only for adapter source `172.22.0.3` to `https://schema.gov.it/sparql`. Southbound OIDC requires a distinct expiring HTTPS flow from `172.22.0.2` to `https://auth.ouf-lab.it/realms/ouf`. No broad destination range or guessed DNS address is proposed.

Draft source `5e8b907d41b53690b4531f4b92c185eee5eb0551` composes the existing port identity guard with the independently verified global expiring destination guard on dedicated bridges only. The exact kernel hash and table name are part of the signed NIC transport declaration. Shared bridges retain static exact flows. The preexec guard revalidates the global binding under the existing coordination lock. Both the two-runc assembled-profile integration [37815886571](https://github.com/GioNob/ouf-deploy/actions/runs/37815886571) and the existing authenticated Docker regression [37815886350](https://github.com/GioNob/ouf-deploy/actions/runs/37815886350) passed. These sources have not been installed on the target.

The isolated packet test [37817136572](https://github.com/GioNob/ouf-deploy/actions/runs/37817136572), source `cbb15efdb5b38ff7bae7bec26434c5b0c275e034`, passes provider and identity separation, wrong source/MAC/destination/port rejection, empty and expired lease denial, and denial of an already-established connection after the full lease duration. Two earlier fixture failures are retained: the strict production set reader rejects retained zero-TTL elements, and a probe based on the displayed expiry alone ran before a guaranteed full duration. The fixture now observes both monotonic duration and set readback; production TTL enforcement was not weakened. This proves isolated Linux packet behavior, not target TLS/OIDC, reboot, startup or release acceptance.

Read-only self-hosted [37816365408](https://github.com/GioNob/ouf-deploy/actions/runs/37816365408) captured existing Semantic backend address `172.18.0.6`, MAC `b2:96:a1:e2:c1:8d`, and host uplink `eth0` index 2. All southbound declared network gateway priorities are zero. No gateway-priority mutation is needed: exact Moby source [sandbox.go](https://github.com/moby/moby/blob/464cd50c3d9e92877d56940ea160de6fca7bea23/daemon/libnetwork/sandbox.go) orders non-internal networks before internal ones at equal priority. Both backend and provider-internal networks are internal, while provider-egress is non-internal.

The additional read-only peer job [37817578661](https://github.com/GioNob/ouf-deploy/actions/runs/37817578661) captured Semantic child `eth0` and host peer `vethca2111d`, index `1377`, on `br-113b5f0a3c53`. It read only NIC metadata through a bounded exec in the existing Semantic container and host link metadata; no private files or lifecycle/configuration changes occurred. This permits an exact static ingress proposal `172.18.0.6 -> 172.18.0.14 TCP10443`. Port identity must remain bound at actual admission; a stale index must not be guessed or silently adopted.

`tools/semantic_transaction_network/build_target_network_policy.py` now assembles the two provider-purpose flows, all five exact target NIC declarations, dedicated guard bindings and static Semantic ingress from captured inputs. It consumes the actual authenticated original kernel rather than hashing its projection, clears new leases until fresh authorization, preserves existing static infrastructure flows, and never delegates the shared backend bridge. Three local tests passed for separate role scopes/empty leases, exact kernel binding and issuer/peer drift diagnosis.

### Remaining concrete implementation

The target transaction-specific provisioner/orchestrator is still incomplete. The reviewed guard migration has completed on the target with operator-reported EMPTY_GUARD_EXTENDED; its receipt is evidence/provider-v2-network-guard-target-20261008.json. Do not repeat it. The remaining orchestrator must install the reviewed source/profile closure, authenticate the complete target frame and actual rootfs seals, issue the short-lived role-scoped mandates and configure the runtime allowlist, then perform controlled admission/start with retained stage-specific diagnosis. None of that target operation was performed by these CI or read jobs. Do not issue a direct Docker start, broad sudo grant or another preparation-only operator command.

The following product phase remains the original goal: existing Teatri asset -> national discovery -> chatbot semantic review -> human approval -> onboarding -> ingestion/duplicate checks -> UDP readback. Product operations remain MCP-only. No product write, national discovery or ingestion execution has occurred in this network integration work.


## Cloud continuation — authenticated transaction boundary

The attached OUF_Reality_Baseline_Package_v1_7.zip was read in this cloud session. All 321 manifest entries match their SHA256 and byte counts; all 323 SHA256SUMS rows also match (the checksum list additionally covers the package control documents). Matrix v1.7 and Gateway/Authorization v1.5 were consulted directly, not inferred from this handoff.

`tools/semantic_transaction_profiles/authenticate_provider_transaction.py` now authenticates externally signed complete template/launch/context, image acceptance review, creation intent, node live authorization and final mandate before producing a two-CID installation plan. It independently recompiles the complete frame, binds original v1 seals and separate manifest/config digests, checks signed source bytes, cross-checks sibling declarations and computes exact adapter/journal bindings. Ten local tests pass with actual OpenSSL Ed25519 verification and disposable CI-only keys; four existing profile tests also pass. See the directory README for the exact input contract and limitations. The new target-review schema is not yet issued by a target producer; do not infer that such a mandate exists on the VPS.

This is the authenticated compilation boundary, not the finished target orchestrator. Root-private intake/source-sealed loader, durable publication, existing wrapper/allowlist compare-and-swap, fresh guard custody and Docker cohort activation remain to implement. Full private target input documents and actual authorized image/provenance/dependency acceptance plus role-specific mandates are still required. Target policy custody must be pinned to the existing policy binding; synthetic keys with the same identity strings cannot replace it. No target write, source installation, signing, allowlist update, lifecycle operation or Teatri job occurred. No new operator command is ready; do not run another preparation-only bootstrap or direct Docker start.



### Private intake/publication implementation in the cloud continuation

`provider_transaction_intake.py` now source-seals its loader through 34 fixed
hashes and fixes the existing target authority profile, policy, original empty
runtime configuration and actual Python/OpenSSL bindings. It reads complete
explicit private JSON inputs, excludes the authority-key paths, verifies the role
signatures and rechecks source/input custody. `publish_provider_transaction.py`
installs the authenticated proposal into one NEW private snapshot with durable
O_EXCL publication, retained originals/claims and sanitized failure diagnosis.
Neither component switches the live wrapper/allowlist, signs or starts anything.
Fifteen local tests now pass, including isolated loader and durable failure paths.

Initial CI 37830139331: native two-candidate job PASS; profiles job FAIL in fixture
custody because its private records were placed under runner-owned ancestors.
The fixture was corrected to use a root-owned CI directory without weakening any
production custody requirement. Final hosted status must be recorded separately.

Remaining concrete implementation: producer for the newly defined target-review
record and authentic image/provenance/dependency approval; transaction-specific
intent/live/final issuance under explicit existing role mandates; full target
intake integration; guarded live wrapper/allowlist publication; actual Docker
cohort activation with fresh namespace/guard/lease custody. These remain open,
not automatically supplied by the new compiler or its CI. No new operator command
is ready. The existing target network guard and all completed preparations remain
untouched; do not repeat them. Any request for operator involvement must be for
actual target authority/private input access or the complete controlled operation,
not another repeated preparation step.


### Explicit role authority issuer added

The helper `issue_provider_transaction_authority.py` now consumes a separately
operator-authored root-private per-role mandate and its explicitly approved hash.
It binds eight complete documents, image manifest/config separately, original v1
seal, source closure, transaction/approval refs and separate installer/attestor
scopes. It publishes a durable claim before ExistingEd25519Signer reads the
existing key and emits the review, creation-only intent, live node authorization
and final mandate. Actual admission attestation/approval remains with the existing
live producers. The helper does not manufacture root acceptance or change/start
the target. Eighteen local tests pass, including real existing-key signing and
consumer verification, rejection without explicit approved hash and refusal of
input drift before key read. The intake closure now contains 35 files.

The issuer helper still needs the complete target documents and an actual root
acceptance mandate; neither was acquired in the cloud. They cannot be created
from the hash-only operator receipt or CI assertions. The target invocation wiring,
guarded live runtime publication and Docker cohort lifecycle remain incomplete.
No operator bootstrap or target start command is ready. The existing network
migration, candidates, inputs and product asset must not be repeated.


Hosted run 37831986938: 17/18 authentication tests passed; sealed-loader acceptance correctly denied PRIVATE_INTAKE_HASH_DRIFT. Local materialization had appended one trailing newline to 32 pre-existing repository files. Restored exact repository bytes and canonical closure hashes; all 29 runtime hashes agree with cohort-draft/sources.json. Production hash checks unchanged. Eighteen local tests pass after correction. This is CI/source diagnosis, not target observation.


## Verified cloud checkpoint and target authority dependency

Hosted CI [37832278081](https://github.com/GioNob/ouf-deploy/actions/runs/37832278081), source `ee95fba9aa664c2b6e3909d7cc74c2fe81739087`, passed both profiles and native-frame-profiles jobs. This verifies the sealed intake/explicit role-issuance boundary and existing real native regression; it does not inspect or authorize the VPS. The target orchestrator remains incomplete: live guarded wrapper/allowlist switch, complete operator invocation integration and Docker cohort lifecycle are still required. No target command is ready.

Actual complete target input records and independent publisher/dependency acceptance remain unavailable in cloud. Operator intervention is required to supply authorized full-record custody and explicit per-role root mandates bound to the actual two CIDs and reviewed bytes; hash-only receipts and general permission to modify GitHub cannot replace them. Do not transmit private signing keys or secrets to cloud, manufacture acceptance or rerun completed target preparations. Preserve private documents on the VPS. The next integration must consume them there under a complete reviewed operator transaction, not a preparation-only command.


## GitHub authority audit and guarded switch development

The user asked to search GitHub rather than reconstruct approvals from memory. All seven authorized repository default trees and branch inventories were accessible. Read 96 deploy evidence/release/README documents, relevant acceptance/mandate history, Gateway PR #57 and provider/source branches. Historical operator authorizations were found in Semantic source `72310a0f4b0d649854d3abc010509d6724617e4e`: custody and verification-policy preparation plus scoped image/mount/metadata/Env reads. They explicitly exclude signing/start; the verified older images differ from the v2 identities. Evidence: `evidence/provider-v2-authority-github-audit-20261008.json`. No current signed two-CID v2 mandates or complete-frame acceptance were found in inspected sources; private VPS absence is not asserted. Do not repeat historically authorized work.

Continued autonomous implementation with `guarded_runtime_switch.py`: existing-wrapper atomic CAS, preserved prior bytes, native lock inode checks, three locked verification checkpoints and durable uncertain-failure diagnosis. Twenty authentication/publication tests and eight actual filesystem/lock tests pass locally. The helper is sealed as source 36; it has no CLI or default verifier and is not a target authority producer. Actual locked guard/candidate verification, source/authority-bound operator integration and Docker cohort lifecycle remain incomplete. The installed read helper must not be called under this lock without adapting its lock ownership, as it reacquires the common guard lock. No new target command is ready, and no target operation or Teatri job was performed.


Hosted CI [37836024605](https://github.com/GioNob/ouf-deploy/actions/runs/37836024605), source `dbbbce099546472dfb163d598cb32934467edb9e`, passed both jobs: 20 authenticated publication tests, 8 actual private-filesystem/lock tests and the existing native frame-profile regression. Evidence: `evidence/provider-v2-guarded-runtime-switch-ci-20261008.json`. Target records were not acquired or signed. This is development validation only, not VPS or release evidence. The operator path remains incomplete; no bootstrap is issued. The prior request that the user remember whether approvals existed has been resolved by the GitHub audit: reuse recorded narrow preparation/read authorizations, while specific v2 image/frame acceptance and transaction mandates are not registered in the inspected sources.


## Borrowed-lock guard integration development

Added read-only `transaction_guard_observation.py` and the fresh-authentication checkpoint verifier `authenticated_runtime_switch.py`. They use the existing guard descriptor without reacquiring another inode, verify installed receipt/source/journal/unit/command custody, read actual nft structure and empty memberships, inspect only approved stopped candidate metadata, and bind signed NIC guard references to the observed kernel. No installed observer code is imported; registry credentials are excluded with an empty Docker CLI configuration. Three local lock-custody tests pass; real nft validation is in the new isolated hosted test, whose Docker/systemd responses are fixtures. Source-sealed intake now contains 38 files. Actual target receipt/command pins, complete authorized records, cohort activation and operator invocation remain required. No target command or operation is issued by this commit.


## Approved transaction orchestration development

The sealed root entrypoint now has an explicit approved-transaction mode connecting both independent root-mandate preflights, existing-key issuance, fresh signed profile assembly, guarded atomic wrapper switch and concurrent exact-CID Docker activation through the admitted runtime. Default intake remains inert. Source closure contains 39 files. Preflight emits no signatures and reads no keys; both approvals must pass before issuance. Guard observation also binds the registered Docker runtime path and signed nft table name. Activation releases the common lock before Docker requests so the runtime can acquire it, preserves claims/partial observations, and performs no automatic retry or rollback.

Twenty-five local authenticated-transaction tests pass, including preflight/no-key-read and partial child failure. Eight private-filesystem switch and three descriptor tests passed previously. Broad local discovery could not import the native frame regression because this partial cloud checkout lacks scripts/semantic_provider_docker_runtime.py; native verification remains in the full hosted checkout. The partial activation test uses fixture Docker/guard responses; it is not a real Docker cohort or VPS observation. Prior hosted guard CI 37841884119 passed both jobs, with real isolated nft and fixture Docker/systemd.

The execution mode is implementation under validation, not a ready target command. No complete target input records, independent per-CID provenance/dependency/frame acceptance, fresh explicit root mandates or target transaction configuration have been acquired. No bootstrap is provided; no wrapper, runtime, container or VPS operation occurred. Real Docker cohort integration and complete target review remain required. Do not use CI fixture approvals or keys as target authority.
