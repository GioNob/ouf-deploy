# CSV/chatbot — current handoff, 2026-10-15

## Current diagnostic update: masked timer retains failed state

Operator readback identifies the strict predicate mismatch: `ouf-policy-token@semantic.timer` is permanently masked, `ActiveState=failed`, `SubState=failed`, `Result=resources`, no Job. The service is masked/inactive/MainPID=0/no Job. The delivery unit is inactive/not-found/MainPID=0 (collected transient unit); its retained `Result=success` is not delivery acceptance. `resources` alone does not establish a RAM/disk problem.

No production predicate change or recovery has been deployed. Preserve timer failure evidence and all owner/output/retirement reservations. Do not issue `reset-failed`, repeat mask/stop, restart delivery, or rerun an execution wrapper.

The next operator action is **one read-only diagnostic**:
`scripts/read-chatbot-pregrant-retirement-20261015.py`,
SHA256 **6ce593b40fa6d1959aa34dd2a4827e78e4cdf686da2b45d699219b1e5060e1f9**.
Run with root read access only; no Keycloak login, device code or HUMAN execution approval. It binds exact 95749a8 source/context/authority and sealed prepared bundle, reads seven exact global ledgers, four owner ledgers, source-stage intent/intake/file hashes without executing source, root/output/credential-directory metadata without opening credential/token members, five image journals/native image GETs, and bounded authorization/APISIX/later-stage metadata. Completed APISIX native generation is compared with the final journal binding via two container GETs. It does not initialize/lock/rewrite journals. Nine local privacy/custody/transport/full-flow/source-hash/native-generation scenarios were checked during development; native VPS execution remains pending. This is diagnostic evidence, not recovery authority.

## Latest VPS result: retirement reconciliation required

The qualified 95749a8ef316856e16c44c1d7aa3b6791b408993 execution was run and approved. It progressed beyond all five image imports and APISIX runtime preparation, then paused at `INSTALLING_FINITE_TOKEN_OWNER` with `RETIREMENT_QUIESCENCE_UNPROVEN`. See `evidence/chatbot-legacy-retirement-paused-20261015.json` for the exact new context, authority and plan bindings.

The exact source proves `systemctl mask --now` returned zero and the following bounded unit read parsed, but the strict masked/inactive/no-process predicate failed. The differing property is **not yet known**. First grant, application-container replacement and cohort database migrations are later in the code and were not reached in this attempt. APISIX may already have changed; do not classify this attempt as mutation-free.

**Do not rerun any execution wrapper or restart the consumed finite action.** Owner-installation intent and legacy-retirement command reservation have already been written by this path. The old auth-only/image-only predecessor gates are insufficient for this new partial stage. Do not remove/reset any reservation or replay a command. Next action: read-only current unit properties/mask links, then reconcile durable stage evidence before proposing a recovery. Actual CSV/chatbot end-to-end remains unproven.

## Prior qualified launch preparation (historical; no longer the next action)

### Historical qualification and launch instructions

The containerd image-identity defect is corrected and qualified in **GioNob/ouf-deploy commit 95749a8ef316856e16c44c1d7aa3b6791b408993**, draft PR31, branch codex/retained-inspection-channel-20261015. PR31 still targets PR29's branch codex/chatbot-mcp-migration-role-20261014 at fdc990136592f0353c2824f4de632a052910a2a0. Neither PR is merged.

**The corrected execution has NOT been run on the VPS. Actual CSV/chatbot end-to-end remains unproven.** The next action is the new wrapper `releases/chatbot-file-cohort-native-identity-execute-vps-20261015.sh`, SHA256 **136267249a832148754100de5f741dafd93da5beee231cf160dd6b81a2e0913d**. Fetch it from the same exact evidence commit as this handoff, verify that hash, then run it. Never execute application/deployment code from this evidence branch: the wrapper fetches the qualified source commit above with launcher SHA256 **547790e03093f8c51c3947e09e14d3b9b10b900bbf42363f7fe0047333c12715** and capsule SHA256 **5fb8c5e1ec207594155ac61fbd2b03d821135d28d50c6f00aa7cd86a018f49a5**.

The wrapper preserves existing GitHub authentication, reuses the exact existing ZIP, and waits only if needed for old authority expiry **1792052697 / 2026-10-15 10:24:57 Europe/Rome** before preparation. The bounded clock wait performs no privileged work or runtime authority issuance. Preparation may ask for sudo, the existing Keycloak administrative login and a device-code identity login. Fresh full-action approval is required in the controlling VPS terminal: type APPROVO followed by the new hash displayed by that execution. A new finite one-hour window starts after that approval. Never paste an old approval hash or pipe approval automatically. If roles remain as currently published, no new role proposal should be needed; any mandatory role-review URL is now printed explicitly outside JSON.

Do not rerun the old reconcile-execute wrapper: its gate handles only auth-only predecessors and correctly refuses image-stage history. Do not restart either old unit. After terminal loss or pause, read the newest retained unit/status before further effects. The corrected one-use source cannot automatically replay a consumed later-stage attempt.

## What the VPS actually proved

Old auth-only predecessor:
- Source 6959b1dbaeb30ca3a838c7d6243a55e9cfc5118a.
- Context /etc/ouf/deploy-snapshots/chatbot-file-cohort-signed-b96d2afabbd3275beadb0bbb525608278d5f098af1e14de1f5e4333bff9b488d.
- Unit ouf-file-cohort-b96d2afabbd3275beadb0bbb52560827.service.
- Authority 80b8f8218991d12d3abff0b4760804d86e247de1f4adc76ab446255fe19ec7f6, expired 08:48:03 CEST. Stopped with PlanDenied after HUMAN role publication. Strict Jackson GrantConstraints DTO round-trip issue was subsequently fixed; exact inner old code was not retained.
- Owner roles were published through a separate HUMAN recovery proposal. Do not reopen expired proposal adf95413-92b0-460b-a112-2fd80bd208ac or rerun its recovery driver. Its old draft was EXPIRED, not the newer published confirmation.

Latest attempted execution:
- Source **b64645982655f58a2907bf1425dd86fd6ab0ed9f**.
- Review a7cc6bd53145dc53a4e62b3d25318aff5df6ce1a1401f51f56ff534e4ab5fb44 was explicitly accepted.
- Context **/etc/ouf/deploy-snapshots/chatbot-file-cohort-signed-dd03d434361deb62e1caeaf7958a71c39c095f065e776312779d59dd6a7f4a77**.
- Unit **ouf-file-cohort-dd03d434361deb62e1caeaf7958a71c3.service**, old PID3229846 gone.
- Authority **48c75739575b7d618484ed78184834d2d1961da97fa2870d80d14ce26fe978f4**, expiry1792052697. Status PAUSED_REQUIRES_RECONCILIATION / ValueError.
- AUTHORIZATION_RECONCILED_BEFORE_FIRST_GRANT succeeded, then IMPORTING_QUALIFIED_IMAGES_BEFORE_FIRST_GRANT.
- Semantic journal IN_FLIGHT/version1/effectAttemptCount1. Other four image journals READY/version0/attempt0. No containers/databases/gateway/gatewayRuntime recovery journals. Process inactive/dead/MainPID0. Systemd Result=success after transient-unit collection does not prove delivery success.
- Pure readback validated all five archives exactly against their sealed audits. Native identity readback at09:53 CEST confirmed semantic exists as **sha256:b61bc39c1593c28404a8258962008c024d13689d7e9b132e6a85619580003ca3**, while its published config ID is **sha256:29e32c1487b5ba29d6d29ec04f7daa3baeb1e30f392a46c838eef01493d60489**. Source label, every selected execution-config field and RootFS all match; repository tag count0. All other source-revision image candidate lists were empty.
- Target Docker29.8.1, containerd overlayfs, cgroup systemd, bundle SYSTEM_CONTAINERD, namespace VAR_RUN_ALIAS.

The original tagless archive SHA256s observed on target were semantic9f1961025f0e55d7a12e7f3f6df5c5fe0980ff4cad730086262bedecdaf6a357, udp06407b66e1750a700457a66b023534f4c34e16e71ff2ef9cdd303b31c3e3881a, onboarding759acf9c4475fe5755af53e4328e89a786f9edc9da0e44c867342694abf2a72d, ingestion9637f803b18f41b38b7dd9ef3fb20dcf75165db1d9bf89e5354bb80b447c9f02, mcp9711dae70d52b66cff781a7af4196be7b8f3c0ae0d8029cafb9391be6882708c. See structured evidence for exact sizes and IDs.

## Correction, recovery limits and qualification

The published ID hashes raw image configuration. The containerd ID hashes the manifest. Existing code loaded the image successfully, then got404 when looking up the configuration ID and raised IMPORT_ABSENCE_DOES_NOT_PROVE_NO_EFFECT as a plain ValueError. Original reproducer run38700933784 proved classic PASS / containerd same failure with the exact retained semantic artifact; native target readback confirms the same identity split.

The correction derives and binds an exact Docker schema2 manifest from unchanged config/layer bytes, includes an explicit tagless OCI index/manifest, and uses native IDs in import journals, four replacement plans and semantic registry creation/realized validation. It preserves the original configuration identity and publisher package pins. Explicit index descriptors avoid cache-dependent legacy-importer compression choices. App config/layer bytes are not rebuilt or changed; derived archive metadata/hashes change under the reviewed new profile. Config/rootfs comparisons stay exact; there is no acceptance based only on source labels. Known ImageCustodyDenied codes are visible, arbitrary ValueError bodies remain private.

The successor readback accepts only the known6959 auth-only context and knownb646 first-semantic-image case, with stopped/expired worker, exact review/decision/authority/start-claim bindings, exact archived bytes, deterministic native manifest and current config/rootfs, pristine remaining image journals, and empty later application/DB/token stages. It preserves all old journals and attempt counts; it does not reuse the old authority or reset claims. Any unknown source, missing image, altered bytes/native identity, extra image attempt or later-stage history denies. The child rechecks the predecessor receipts before effects.

At final source95749a8:
- Push38704843732/job116321589250 and PR38704849033/job116321606947 each **PASS234 tests/30 suites/0skips**. Includes real signatures, closed source imports, privileged PostgreSQL17 roles/triggers and privilege revocation, four DB archives, native processes/namespace/Gateway fixtures, and actual owner joins distinguishing ACK/commit/NOOP.
- HUMAN verifier38704849109 PASS.
- Exact retained artifact matrix38704843739: classic job116321589263 and containerd job116321589315 **PASS**. All five original app images; existing legacy semantic reconciliation without reload; fresh explicit-envelope import; native-ID container creation without application start; exact semantic config through full four-mount gated frame; signed five-image owner/store guard on both backends.
- CI Docker28.0.4; exact full deployment on target Docker29.8.1 remains pending. Target readback proves the same semantic manifest identity/config/rootfs.
- Earlier extra synthetic fixture failure38704349009 was a strict execution-config mismatch on minimal docker-import images; all five real images passed. Disposable fixture now declares USER/WORKDIR/ENV/ENTRYPOINT/CMD/STOPSIGNAL explicitly. Production comparison was not relaxed.
- Wrapper Bash syntax and finite clock wait cases passed (already expired,61s simulated wait, clock>1h behind denied). No target mutation/new authority by this work.

## Frozen six-module package and host delivery

Producer **8bff54a52a0ce15daccaf2aee932004f106dd178**, run38584614991 attempt2, artifact11907557440, original ZIP SHA256 **144699ab7756c8312d49783967cfbb64acc02a617015ad89f5adf51e25a10300**. Reuse `$HOME/ouf-chatbot-file-delivery-126e49f3830667934bf8f8d7/cohort/cohort.zip`; do not redownload/rebuild to change a deployment helper. Existing gh is `$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh`; check it first, then PATH; preserve auth and never request/print tokens.

Pins unchanged:
- semantic GioNob/ouf-semantic-registry eccef11a97367f20e278db40b9ed6f45dd980c37.
- onboarding **GioNob/ouf-source-onboarding** 84828f74ac586bae09a78f0fb197b75b1a3d98d1.
- ingestion c48ee4b1873a474e81c6e1be70d393854021e2c1.
- udp b49c0d6f50c574c11684361ce4e8040e9cbddee2.
- mcp f249b3dcc58c2a96742092d90fa09fd90b705bd0; target overlay preserves migrations1–9 and appends10–12; do not merge it globally.
- gateway bf179e96200deb84942ad32507edef52a4284cd0.

Read AGENTS.md and current docs/OUF_RESILIENCE_POLICY.md. Preserve legacy UNKNOWN/R9/R10/R12 history, consumed claims and cumulative attempts. No automatic new budget, DB rollback, authority renewal or shared-service restart. This is finite acceptance, not permanent runtime acceptance. GitHub development work is authorized; a current exact runtime HUMAN decision is still native protocol. User primarily uses a phone, needs concrete copyable commands and meaningful updates within60s; no unsupported “almost done”/ETA promises. No SSH session exists here and no private keys/passwords should be requested in chat. Full98-item VPS inventory remains on VPS at /home/oufadmin/ouf-vps-inventory-v2.sRYFvsMe/inventory-full.json; only selected reports were archived—do not claim the complete file was saved.

## Continue through actual CSV acceptance after COHORT_READY

Delivery order: authorization reconciliation -> exact images -> optional same-image APISIX config replacement -> finite token owner/legacy retirement -> first grant<=300s and distinct worker<=128 attempts/3600s -> registry hold -> quiesced four DB backups/migrations/temp MCP audit-role grants and verified revocation -> other services/routes -> release -> **COHORT_READY_FOR_ACTUAL_CHATBOT_CSV_ACCEPTANCE**. The same finite worker must stay alive. Never relaunch it because SSH was lost. Readback observed before stage claims is not proof later mutations happened.

At readiness, continue actual application work through the MCP **ouf-admin** account (link_6aafef96b4148191b767e9af7b756a07, owner profile b93d8cf6-cd14-4ee6-91d7-84cd76c4f500), not the other giovanni-chatgpt account. Refresh available tool metadata before claiming new capabilities; old MCP catalog had18 tools until upgrade/scopes/client refresh. Required new tools are onboarding.read, onboarding.review.prepare, semantic.proposal.read. Role publication alone does not prove tool availability.

Teatri existing asset6609b245-86ed-4315-8ce0-73f2a8555bf3, profile7984c39c-7396-4248-ab0a-f2efc390b49c v1,13 rows/20 columns/UTF8 semicolon/header1. Historical bytes SHA25608b20658b2b4eadf34d25cd93eead2945096b353ae33b797cf3c41df5319c9e9. No raw CSV bytes are available locally; use owner readback and a governed human file upload/picker for a second source.

Prepared review files remain releases/TEATRI_SEMANTIC_REUSE_REVIEW_20261014.md, teatri-reuse-semantic-proposal-20261014.json and teatri-reuse-20261014.ttl. Proposal hashbe74308e098aa3a65396f3df739dd8f2837e9f8e27b6e49deb0e49d04506cb1a, RDF SHA2566e4668ea42cf1c75b822e17a8ca9cb71fb2c4d8f500eed628282fa6039a6dbaa. Class https://schema.org/PerformingArtsTheater, ontology semantic ID https://api.ouf-lab.it/semantic/teatri#TeatriOntology. Twenty lexical string mappings preserve input/provenance/CAP zeros; source-native key proposed nome_teatro with normalization://managed-file/native-key-v1. This remains PENDING_HUMAN_REVIEW and RESTRICTED classification needs actual HUMAN decision. No semantic proposal or onboarding draft is proved registered yet; never invent approved/published references.

Acceptance sequence: fresh asset/profile/identity read -> register semantic proposal and HUMAN review/publication -> resolve real pins -> onboarding DRAFT and HUMAN approval -> ingestion ACK **then owner-proven commit** -> UDP lineage and fresh chatbot search -> distinct second governed source with same file bytes demonstrating MATCH/NOOP/reuse. Preserve baseline8 ACTIVE Cinema objects at revision1 and ontology/property IRI sets. Expected13 Teatri objects only if uniqueness/commit is actually verified; do not assert total21 or identical property values prematurely. Application HUMAN reviews stay in their THS; infrastructure approval does not replace them.

Owner AcceptanceObserver runs every30s within the same worker. ACTUAL_CSV_OWNER_ACCEPTANCE_OBSERVED is not itself success; inspect nested phase. TWO_SOURCE_COMMIT_AND_REUSE_PROVEN is owner proof; fresh chatbot search/read evidence is additionally required. No CSV end-to-end proof currently exists.
