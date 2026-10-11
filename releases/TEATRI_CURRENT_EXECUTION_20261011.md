# CSV Teatri: current profile and application continuation — 11 October 2026

> **Stato corrente, 11 ottobre 2026, 23:22 CEST:** diagnosi protetta R12 completata, entrambi i flussi `LEASE_READY` e worker1943 rinnovi totali osservati. Piano nativo V11 preparato nel VPS con dichiarazionefc94b491…, richiesta59181588… e4 documenti privati; nessun reimport/cutover. Qualificata in containerd la creazione dell'immagine originale e la riconciliazione dopo crash anche attraverso il controller composto. [Prossima operazione root](NATIVE_V11_ATOMIC_REVIEW_20261011.md): pubblicazione atomica dei documenti di revisione, senza autorità runtime. CSV end-to-end rimane aperto.


[Platform resilience policy v3](../docs/OUF_RESILIENCE_POLICY.md), Reality Baseline v1.7 and [file-first acceptance](FILE_FIRST_EXECUTION_CHECKPOINT_20261010.md) apply. The owner explicitly authorized the existing Teatri asset on 11 October at 16:29 Europe/Rome. No upload/profile replay is needed.

## What is now proved

The operator completed current protected input preparation with exit0: R12 refreshCount120, two approved addresses total, LEASE_READY and native remaining TTL16s in both flows. The new private declaration is bound to SHA256 `096a9bb877da54de35d41725064ebb14a0c456c42cf8b83af409bc1f253172d6`. Database secret projection is readonly UID10001,0500/0400; candidate environment has no DB password; four readonly input additions are declared. [Operator evidence projection](../evidence/semantic-r12-cutover-inputs-target-20261011.json). No application cutover/import/fence/database/firewall/signature or R12 change occurred.

The authenticated [profile observation](../evidence/teatri-authorized-profile-20261011.json) confirms asset6609b245-86ed-4315-8ce0-73f2a8555bf3, profile7984c39c-7396-4248-ab0a-f2efc390b49c, version1: CSV, UTF-8, semicolon, header row1, **13 rows and20 columns**. No raw bytes or redacted samples are published. The prior automatic-review rejection is resolved by the user's exact-file authorization and successful governed preview.

The existing self-hosted runner independently read current host/engine/catalog/admin metadata at [run38147699164](https://github.com/GioNob/ouf-deploy/actions/runs/38147699164), job114494433103 SUCCESS. R12 active/running, same PID2446150, no restarts; original Semantic image f6525f… still runs, DB has V1–V9 and10 sessions. Candidate Semantic/Ingestion/UDP images are NOT imported. About11.2GB memory and466.5GB filesystem are available; these observations are not resource/SLO admission. No application rows, private snapshots, key files or credential files were read by that runner. [Independent observations](../evidence/semantic-r12-host-database-current-20261011.json).

Exact historical Cinema ontology get remains ACTIVE at revision51706bed-81e4-4306-aca1-70119821727d and publicationf92a2e17-30c9-456f-bb12-63afa84f41e6, with17 asserted RDF statements and partial=false. This explains why CLASS-only search can be empty while a class is present inside a containing ONTOLOGY. The broader teatro search also returns empty; no suitable published Teatro reference has been acquired. Do not map Teatri to Cinema merely to bypass that gap.

## Decisions prepared from the profile, not yet approved

| Fields | Treatment to review |
|---|---|
| nome_teatro | Required name;13 distinct values support a proposed source key in this file, not lifetime stability or canonical identity. A rename requires governed continuity/reconciliation. |
| tipologia |9 distinct strings; map to an approved vocabulary or retain raw text until that mapping is approved. |
| toponimo, nome_indirizzo, civico, cap, citta, provincia | Address components, not universal object identity. CAP is profiled LONG but must be reviewed as a lexical postal code; preserve leading zeros where present in raw input. |
| latitudine, longitudine, sistema_riferimento, precisione_coordinate | Nullable coordinate pair, explicit declared CRS and accuracy/provenance. Do not fabricate missing coordinates or interpret a partial pair as a valid point. |
| capienza_posti | Optional capacity; the sample indicates capacity may refer to a room rather than the whole venue. Preserve qualification; do not sum or assign it blindly to the theatre object. |
| spettacoli_stagione, stagione_riferimento | Optional time-scoped measure and period, not permanent attributes without temporal mapping. |
| note | Free text may carry qualifications or sensitive content; preserve raw evidence and require an explicit access decision. |
| fonte_indirizzo, fonte_coordinate, fonte_altri_dati, data_verifica | Field/observation provenance and verification date. Source URLs are evidence, not permission to crawl external sites or authoritative freshness guarantees. |

Every selected field needs a published semantic term, supported transform and owner-approved DataAccessLabel. No OPEN classification is inferred from being in a CSV. The profile's NATIVE_KEY(nome_teatro) is PENDING_HUMAN_REVIEW. Thirteen rows mean13 source observations to account for, not necessarily13 new UrbanObjects: accepted, rejected/quarantined and intentionally excluded records must reconcile to input count; UDP decides MATCH/NEW/REVIEW under the pinned profile. Same address does not merge different theatres or different canonical types.

## Concrete creation-plan implementation

[creation_plan.py](../tools/semantic_application_cutover/creation_plan.py) compiles a PRIVATE Engine creation request from the hash-bound file-secret declaration. It compares the entire retained configuration/mount/network/generation against current native facts, preserves all unrelated host fields, rejects widened privilege/ports/mounts and requires mandatory configtree and exact readonly custody metadata. Proposed explicit profile v1:2GiB memory, equal total memory+swap (no swap allowance),2CPU quota,512 PIDs,2GiB control reserve and10GiB free-disk reserve. These are conservative technical proposals, not measured production SLOs. The exact Semantic candidate still needs resource-bound startup/load qualification.

Endpoint IP/MAC remain explicitly bound; legacy top-level MAC moves to EndpointSettings for modern Engine APIs. Generated aliases containing the retired container ID are not inherited. **The old endpoint must release IP/MAC under a new governed transition before the creation request is used.** No simultaneous same-identity peer is assumed. A stopped/restarted old image has a new process generation and cannot use the original conditional inverse or consumed R12 authority automatically; migration-aware roll-forward/recovery and newly authenticated transport remain required.

The [protected planner](../scripts/compile-semantic-creation-plan-after-r12.py) composes this with the SAME sealed R12 readiness verifier already exercised by the operator. It rechecks native positive leases, full current frame, all four input-file bytes/metadata and existing DB credential binding, then stable-rereads before producing a new private root0700 snapshot. It never signs, imports, creates/starts/stops a container, fences/writes DB, modifies nft or resets budgets. Its receipt is PLAN ONLY, not apply authority or complete OCI.

[CI38148764870](https://github.com/GioNob/ouf-deploy/actions/runs/38148764870), job114497583833 SUCCESS:18 distinct Python tests, actual hosted-root four-input POSIX custody and credential mismatch denials, eight download/tamper positions, four root-bootstrap tamper positions, retained portable gh and failure propagation. Actual Engine API1.44 creates/starts UID10001 on a disposable internal bridge with readonly fake inputs, enforced resource limits and exclusive IP/MAC transfer. Alpine fixture, synthetic declaration/host scope; no target application, provider, complete OCI or target planner acceptance is inferred. The first native run failed on fixture API1.49 vs runner maximum1.48; fixed to1.44, failed evidence retained. [Qualification and limits](../evidence/semantic-current-creation-planner-qualified-20261011.json).

## Target compilation completed

The operator completed the protected planner with exit0: [receipt](../evidence/semantic-current-creation-plan-target-20261011.json). R12 reports302 renewals with unchanged workerPID2446150, exceeding R10's failed refreshCount250. This is a bounded observation, not continuous uptime proof. All four retained inputs were reverified. Private creation plan SHA256 `69cdcb80391b0796af6a4fac4ee845fff65b2322465b20fbfff897c5d64e1a73`; private request SHA256 `339c8949bfd8b23700778225847ef43da2ee943621d6de0ad1b0cc627659b74d`, retained in `/etc/ouf/deploy-snapshots/semantic-current-creation-plan-ik1it73_`. No application, database, image, firewall, lease or budget change occurred. The completed planner command is historical and need not be repeated.

[Resource/recovery CI38150242024](https://github.com/GioNob/ouf-deploy/actions/runs/38150242024) is SUCCESS. The exact candidate image and JAR start asUID10001 with enforced2GiB memory/no additional swap,2CPUs and512PIDs, mandatory readonly configtree and IAM. Candidate appliesV10; both the candidate and exact installed JAR start on a current post-migration snapshot without dropping its writes. Missing secret and unauthorized calls are rejected. Installed JAR runs in the candidate Java runtime: original old OCI/peer recovery is not inferred. Provider and discovery worker remain disabled in this fixture; production load/SLO and complete target OCI/readiness remain open. [Complete qualification and limits](../evidence/semantic-current-resource-recovery-qualified-20261011.json).

[Fresh crypto/security CI38150242010](https://github.com/GioNob/ouf-deploy/actions/runs/38150242010) is SUCCESS for all three unchanged producer ZIPs. Original publisher identity/signatures and all retained byte/migration hashes are freshly verified. Current OS/Java image scans include unfixed vulnerabilities and pass the existing zeroHIGH/CRITICAL/UNKNOWN threshold. Lower severities remain visible: Semantic40MEDIUM/4LOW, UDP1MEDIUM, Ingestion0. No threshold was weakened. A first workflow incorrectly rejected lower severities too; failed run38150088023 is retained with the corrected reporting/gate distinction. Scanner action and transitive setup are SHA-pinned; no new signatures or target installation authority. [Security evidence](../evidence/file-loop-current-security-qualified-20261011.json).

## Gates still required for the end-to-end

1. Fresh target custody, host capacity admission and complete OCI/security inventory at the authenticated transition. Hosted artifact crypto/security and exact-image resource-bound startup qualification are completed; they do not grant target effects.
2. Composed migration-aware applicator: intentional lease coordination retaining incident/budget history, quiesced producers/fresh fenced backup, exact new OCI/reciprocal peer and new signed driver/transport closure. No blind pre-migration restore over later writes.
3. Additive Gateway routes, current IAM/owner readiness and eligible discovery capabilities; preserve existing Cinema routes/data.
4. Adequate published Teatro class/properties; if missing, authorized provider discovery, adoption/publication through HUMAN/THS. No local fallback or guessed ontology.
5. Owned Onboarding DRAFT from this profile, human-reviewed keys/access/mapping, ACTIVE checksum-pinned bundle.
6. Real ingestionRunId, durable UDP ACK, lineage, complete bounded search and negative authorization/replay/recovery tests, with all13 rows accounted for.

A technical development delegation is not a HUMAN domain approval/grant. No Onboarding DRAFT, semantic adoption, ingestion run or new Teatro UrbanObject has been created yet. This is genuine source/fixture/target-preparation progress; CSV end-to-end, reusable installer and full platform acceptance remain open.

## Crash reconciliation and newly identified runtime gap — 11 October 2026

[Qualification](../evidence/semantic-transition-crash-qualified-20261011.json): seven journal tests and a real isolated Docker/PostgreSQL crash fixture pass at [run38156389130](https://github.com/GioNob/ouf-deploy/actions/runs/38156389130). Create, pause and release effects reconcile the same container/process after abrupt death; partial start without pause is denied. Committed migrations and later writes survive reconciliation. No previous snapshot is restored automatically. The predecessor incident/history and consumed intents are retained. The production authorization checkpoints in this fixture are synthetic; this is not a qualified production installer, target cutover or application acceptance.

The exact Semantic candidate source622614b0040cf11be2f6c7e3568733a488ca4ca8 has an additional open policy gap: discovery fails after the first provider failure, publishes candidates before fenced completion, and drains an unbounded worker loop. Neither resource-startup qualification nor current artifact scanning establishes resilience. Deployment of this candidate is held pending durable finite retry budgets, shared dependency incident/circuit handling, safe failure classification, bounded scheduling and stale-worker fencing. Its existing private creation plan remains historical preparation; a replacement source/image must receive fresh provenance, security, compatibility and current target bindings before effects. No rerun of R10/R11/R12 or completed preparation is requested.

## Source correction checkpoint: classification and bounded polling

[Source checkpoint](../evidence/semantic-discovery-resilience-source-checkpoint-20261011.json), immutable Semantic source[e5aabd9d4495](https://github.com/GioNob/ouf-semantic-registry/commit/e5aabd9d4495792d244a792e98798b33aef682ba), branches from the exact candidate rather than the diverged main branch. The actual HTTP adapter passes55 checks covering status classification, Retry-After seconds/date, body deadline and preserved interruption. TLS/unknown classification uses exception fixtures and does not claim a live TLS/IAM provider test. [Native run38157944652](https://github.com/GioNob/ouf-semantic-registry/actions/runs/38157944652).

The worker now yields after at most8 claimed jobs by default, configurable1–32, stops claims on thread interruption, and preserves its local single-invocation fence. Six bounded worker tests pass; the full Java/PostgreSQL module job reports96 tests,0 failures,0 errors,2 skipped. [Module run38157944702](https://github.com/GioNob/ouf-semantic-registry/actions/runs/38157944702), job114524703425. The container/security job of this new source is separate and is not promoted from the historical image's scan.

Durable shared dependency budgets/incidents, fenced atomic candidate publication and authorized new HUMAN budget sessions remain open. The previous image and private creation request do not identify this changed source. No target apply or R12 change occurred. CSV/ingestion/ACK/search acceptance remains open.


## Durable recovery continuation and fresh target observation — 11 October, 19:39 CEST

Qualified Semantic source `8a2e84b32d4ce2bdc3bc529b56afb5663ab133e3` adds persistent job/provider budgets, shared same-subject/provider incidents, bounded admission, cancellation and atomic generation-fenced candidate publication. Module [38160443449](https://github.com/GioNob/ouf-semantic-registry/actions/runs/38160443449) passes109 Java/PostgreSQL tests,13 new recovery tests,0 failures/errors,2 existing skips; actual service late-worker recovery is exercised. Image build/UID10001/current HIGH-CRITICAL-UNKNOWN scan and all four other triggered workflows pass. [Checkpoint and limits](../evidence/semantic-discovery-durable-recovery-checkpoint-20261011.json).

The governed ouf-admin MCP preview freshly confirms the same Teatri asset/profile/version:13 rows,20 columns; no upload or profiling replay. Current published search for teatro still returns no match. No samples/raw bytes are included in repository evidence.

Existing read-only self-hosted target job was refreshed at [38147699164 attempt2](https://github.com/GioNob/ouf-deploy/actions/runs/38147699164/attempts/2), job114532330242 SUCCESS. At17:39Z R12 is active/running, PID2446150 and zero restarts; Semantic still runs the original f6525f… image, DBV1–V9 and10 sessions. Replacement images are absent. This observes service metadata, not private worker state/native positive lease membership or application readiness.

The [new protected read](../scripts/read-current-r12-cutover-custody.py) reuses exactly the retained R12/planner/custody source closure to recheck current lease, generation and four role-owned inputs. It only reads; it does not repeat preparation, generate a plan/claim, sign, write private files or change R12. Nine tests qualify source-tamper, generation/frame/input drift, expired final TTL and safe projection. Its workflow first tries the existing runner's noninteractive sudo; access denial is reported explicitly, without printing private stderr or trying another privilege path.

[Separate offline package producer](https://github.com/GioNob/ouf-semantic-registry/actions/runs/38160893223) binds exact application source8a2e84b, resolves base digests, rescans the actual export and verifies allV1–V11 JAR migration bytes/fixture absence. Publication/cryptographic result is pending until that producer completes; the historical package is not reused for changed source. Target trust of the new producer, HUMAN budget renewal integration, tenant/global capacity/retention, rolling-configuration fencing and complete authenticated migration-aware cutover remain open. No target apply is ready and no source activation/run/ACK/search or new Teatro object has been executed. All13 rows still need end-to-end accounting.


## Offline package qualified; concrete protected-read access boundary

[Producer38160893223](https://github.com/GioNob/ouf-semantic-registry/actions/runs/38160893223) and job114533383998 SUCCESS. Artifact11710556577,212264647 bytes, ZIP digest `sha256:b6ae1051cee4ec9fb1b28f532622ecd39e038ec2e6a384d50565cbf92f2a0def`; image `sha256:83635be46d1fe61dea08597ea4488980b4349e5f6e0ed8bbd3ab6f5e2686370e`. Eight subjects have freshly verified GitHub/Sigstore provenance from producer3ec99277 and embedded application source8a2e84b. Actual image-bound vulnerability gate, source inventory and V1–V11 JAR migration continuity pass. This is a new offline package, not permission to replace the target image or reuse old trust/creation/lease claims.

[Protected-read38161252572](https://github.com/GioNob/ouf-deploy/actions/runs/38161252572), job114534478699 explicitly reports `NOT_EXECUTED_EXISTING_ROOT_PERMISSION_UNPROVEN_OPERATOR_REQUIRED`, root-attempt exit1. Its workflow is green because it successfully reported an access boundary; the protected reader did NOT execute. No sudo policy, access binding or target runtime was changed to bypass this boundary.

The concrete next operator action is [current-r12-custody-read-20261011.sh](current-r12-custody-read-20261011.sh), SHA256 `ba8e8cab5c2b6e5030c5e3f093fc9945f06efd0bbeed5dcfb88441faa187371e`. It verifies five immutable source hashes before sudo and again inside isolated root, then only rechecks current R12 generations/native positive leases and four existing input files. It does not repeat preparation or allocate an intent/claim; no protected-file/container/database/firewall/lease writes. Local13 tests cover9 reader cases plus all10 download/tamper positions, all5 root-bootstrap tamper positions, portable gh selection and exact failure propagation. Hosted delivery qualification is separate. Request only this necessary operator read, preserve its entire safe receipt, and continue source/runtime-policy and authenticated cutover work from it. No CSV end-to-end acceptance or restart permission is inferred from a successful read.


## Current protected custody reverified — 11 October, 20:00 CEST

The operator supplied the successful current read receipt, launcher exit0: [target evidence](../evidence/current-r12-custody-target-20261011.json). All four retained role inputs were reverified; both native flows had one approved address and minimum remaining TTL15seconds. R12 remains PID2446150 with refreshCount1045; authorization/generation/frame/declaration hashes are retained. This is an operator-supplied stable reread, not independent runner root access, continuous liveness or atomic transition authority. No protected write, image import, database query/write, lifecycle, DNS/provider call, signature, new claim or budget reset occurred. The previously requested reader is completed and need not be repeated. Fresh native lease/current-generation verification is still required at any future authenticated transition.

The new source8a2e84b/V11 and image83635be4 need exact-image startup and post-migration compatibility qualification; prior source622614b/V10 evidence does not carry over. A separate hosted qualification reuses the established file-secret/IAM/resource fixture and retained installed JAR, verifies all eight original signed subjects and packaged migration source bytes, then tests V1–V11 startup, persisted exhausted dependency/incident/attempt history across restart and current-state restore. It performs no target effects and grants no installation authority.

## Internal published-search diagnostic

Current owner search finds the ACTIVE Cinema ONTOLOGY; search for MovieTheater/theater returns no artifacts. Exact revision51706bed/publicationf92a2e17 reads all17 asserted statements, including cinema#Cinema rdfs:subClassOf https://schema.org/MovieTheater and local nome/indirizzo properties with domain cinema#Cinema. Publication is present. SemanticReadService searches registered artifact metadata, while contained RDF members and their alignment IRIs are not searched or ranked by actual reuse. SEMANTIC_READ_DELEGATION explicitly documents that boundary. An empty query is not proof of absent RDF semantics or a failed publication. Internal term retrieval/compatibility and usage preference need qualification before claiming the internal-first reuse mechanism is complete. Schema.org distinguishes PerformingArtsTheater from MovieTheater; no equivalence, Theatre publication or reuse of Cinema-domain properties is inferred from a shared name/address structure. The official-site lookup was explanatory, not OUF provider discovery/adoption.


## Exact V11 compatibility and target package delivery completed — 11 October, 20:06 CEST

[Hosted qualification38162226566](https://github.com/GioNob/ouf-deploy/actions/runs/38162226566), job114537359394 SUCCESS: exact source8a2e84b/image83635be4, JAR SHA25623986c7d6ccdc3cae21bedbadeb6db60ac56988ea5b3d49c1f76bf13ba756f01, all original eight signed subjects and V1–V11 source/JAR closure verified. Real Spring boots asUID10001 with2GiB memory/no additional swap,2CPU,512PIDs, mandatory readonly file secret and IAM. V1–V9 request history survives migration. A stored exhausted job/provider budget, incident and attempt history survive a candidate restart and a current post-V11 dump/restore; candidate and exact installed JAR both boot on that current state. Anonymous/ungranted/missing scope/wrong audience/invalid signature and forged/missing discovery receipts are denied; missing secret cannot reach readiness. [Receipt and scope limits](../evidence/durable-v11-configtree-qualified-20261011.json). Provider and worker are disabled in this fixture; no target migration, production load, installed old OCI recreation, actual Cinema/Teatro serving or automatic HUMAN renewal is proved.

[Target stage38162329087](https://github.com/GioNob/ouf-deploy/actions/runs/38162329087), job114537662589 SUCCESS: the self-hosted runner transferred the original exact ZIP to new private directory `/home/oufadmin/ouf-durable-v11-stage.drTnFl4m`, verified all member/migration bytes and freshly checked all eight original producer signatures with exact commit/ref. [Target-stage receipt](../evidence/durable-v11-target-stage-20261011.json). No sudo, protected writes, image import, DB query/write, container/firewall/R12 effect, new claim or budget reset. The existing target image is still installed; new image custody and target installation authority are not inferred from an oufadmin package stage. The old private declaration/request still identify the previous candidate and must be freshly rebound and reviewed against the new package before any composed transition.


## Reused October1 Cinema chain: current serving now proven

The existing approved Cinema fixture now has an actual governed MCP urban.object.search result:8 ACTIVE objects, canonical type `https://api.ouf-lab.it/semantic/cinema#Cinema`, revision1, visible name/address properties, nextCursor=null and partial=false. No new upload/profile/source activation/run/handoff replay was performed. [Chain report and limits](CSV_CINEMA_END_TO_END_EVIDENCE_20261011.md), [safe current result projection](../evidence/cinema-current-authorized-serving-20261011.json).

The historical owner readback already documents8 durable ACKs/lineages/materializations for run86809c17-3354-45ca-a7e6-57e903944b24. Exact current joining of the eight returned object IDs to that run remains open: source-specific MCP ingestion.status/history reads both returned authorization denied, retryable=false. No retries, other account, direct DB bypass or grant/route changes. Required descriptor capability is ingestion.operations.read; current IAM/MCP/Gateway/owner denial layer and producer readiness must be inspected through governed deployment metadata before proposing a bounded correction. Search-specific negative authorization and independent storage byte/hash gates remain separate. Teatri13-row acceptance and new-image cutover are not inferred from this Cinema serving success.


## New source-bound plan delivery qualified — 11 October, 20:33 CEST

[Current preparation and exact operator command](DURABLE_V11_CURRENT_PLAN_20261011.md), [qualification](../evidence/durable-v11-current-plan-qualified-20261011.json): hosted run38164130910/job114543027739 SUCCESS,15 tests and native verification of both exact original archives/configs. Eight immutable sources are sealed twice; final generation/authorization/lease/frame/input/package/creation drift is rejected before new private drafts. Old declaration/request remain historical. New target plan execution is still pending; no image import, migration, lifecycle, firewall, claim, budget or R12 effect. The completed custody-reader command need not be repeated.

The governed current authorization catalog is now observed at policy38:63 grants, admin28 permissions, missing status/history and owner lineage capabilities. [Safe diagnostic](../evidence/cinema-governed-lineage-read-gap-20261011.json). This is configured-grant evidence, not the exact runtime denial reason or effective authorization. Existing status/history cannot join UDP object IDs, and a source-scoped grant alone cannot fix missing MCP resource context. Bounded additive lineage contract/readiness and HUMAN/THS finite read grants remain to be composed. No permission/route mutation or new CSV execution occurred.

## Target preparation blocked at final journal reread — 11 October, 20:55 CEST

The operator executed the pinned launcher. It exited1 in FINAL_STABLE_RECHECK with LEASE_JOURNAL_CHANGED_DURING_READ, protectedFileWrites0 and all target effects/claim/budget flags zero or false. [Safe operator receipt](../evidence/durable-v11-current-plan-blocked-target-20261011.json). No new private declaration or plan is proved; the previous pending target preparation is now an observed blocked attempt.

The retained lease reader uses optimistic before/after journal equality during native reads, without acquiring the common lock. A concurrent journal update invalidates that particular observation. Normal renewal is a possible explanation, not a proved benign target event; revocation/state change cannot be inferred away. The equality, positive native TTL/membership, current authorization/generation and secret/config custody guards remain intact.

A new explicit operator observation may use the SAME pinned launcher and command above: this attempt performed no protected writes or transition effects and consumed no claim. It rereads all facts from the beginning, retains the blocked evidence and does not reuse partially read lease data. This is not permission to replay R10/R11/R12, reset a provider/recovery budget, or automate repeated launches. If the journal collision repeats, retain both results and diagnose the exact read window before another attempt.

A regression reproduces the exact final-read exception and asserts immediate blocking, no internal retry, no draft publication, no claim or budget effect. Local16 tests pass; the hosted checkpoint for this added case is recorded separately. Program and launcher bytes are unchanged; no new executable trust or private authority is introduced.

Hosted regression [CI38166096436](https://github.com/GioNob/ouf-deploy/actions/runs/38166096436), job114548865204 SUCCESS:16 tests, exact journal-collision refusal and original-package compatibility pass. [Qualification](../evidence/durable-v11-journal-collision-denial-qualified-20261011.json). The exception is injected in orchestration; target renewal causality and plan acceptance remain unproved. Launcher/program hashes are unchanged.

## Target V11 plan prepared — 11 October, 21:01 CEST

The operator completed a fresh execution of the unchanged pinned launcher; all eight source checks passed, exit0. [Safe success receipt](../evidence/durable-v11-current-plan-target-20261011.json). This supersedes the pending/blocked status of plan preparation, while retaining the earlier journal-collision observation. No cause for that earlier collision is inferred.

New private directory: `/etc/ouf/deploy-snapshots/semantic-durable-v11-plan-2yliy8_t`.
Declaration SHA256: `ffc02da66a08fb1f1b06c143ef0f2aa18d68a6fb7b2bfaa616a812aa37eabe0f`.
Creation request SHA256: `798de748a4fcc0d8c2b6eb70f3577430d690729a4a03bc00ebbf3adcae765836`.
Public plan SHA256: `749399d19c1fae5ad02b1c97e3d05ee04b6bdade242d107b6ab7004a5f0cf7cd`.
The exact source8a2e84b/image83635be4/ZIPb6ae1051 binding is now prepared on the target. Execution defaults, retained host fields and all four existing input files were preserved/reverified.

R12 reports PID2446150 and refreshCount1332; each native flow had one approved address and minimumTTL16seconds at this read. These are stable-reread observations, not continuous liveness or future transition authority. Exactly four new private draft files were written. No image import, container lifecycle, DB read/write, DNS/provider call, firewall change, signature, common lock, new claim or budget reset occurred. The snapshot is not atomic installation authority. All apply/image-custody/transport/full-realized-OCI flags remain false.

**This preparation is completed. Do not repeat this launcher or the previous custody reader.** Preserve all private artifacts; publish only these safe hashes/receipt. The earlier old-candidate creation request and predecessor declaration remain history, not the new executable intent.

## Next composed transition bindings

The source-bound artifacts to consume are now concrete, but the qualified Engine/journal primitives do not form an authenticated target applicator. The next work must compose the following contracts before any runtime effect:

| Required binding | Current evidence | Remaining proof |
|---|---|---|
| New package and image | Exact original ZIP, eight publisher subjects, source/JAR/migrations and target private plan | Target Engine image/layer custody, exact source-bound import reconciliation and resource/admission inventory |
| Existing authority/history | R12/native custody checks; old consumed claims and finite budgets retained | Distinct authenticated transition authority tied to the new declaration/request; no reuse of R12 activation |
| Old endpoint and DB | Retained host/network frame; candidate/current-JAR V11 compatibility in CI | Quiesced producers, revoked old traffic, fresh fenced backup, migration-aware admission and recovery |
| New OCI/peer | Creation intent and Engine/journal primitives qualified separately | Realized expanded OCI, reciprocal peer/generation and new signed driver/transport closure |
| Release | No target release performed | Authenticated checkpoints, exact paused-generation reconciliation, fresh lease/admission, runtime verification |
| CSV proof | Cinema8 ACTIVE served; Teatri13×20 profile | Bounded authorized lineage join for Cinema; published Teatro terms, approved mapping/bundle, run/ACK/lineage/search and13-row accounting |

Engine creation, pause and unpause helpers explicitly leave authority and full OCI/peer/transport checks to the caller; hash receipts alone supply none. No placeholder/no-op checkpoint may be installed on the target. Preserve post-migration writes and reconcile ambiguous effects rather than replaying or restoring an old snapshot. No target apply command is ready from this receipt.


## Exact image custody/import primitive qualified; target image-only action ready

[New implementation, scope and operator command](V11_OFFLINE_IMAGE_CUSTODY_20261011.md), [qualification](../evidence/v11-offline-image-import-qualified-20261011.json): run38168097869/job114554772062 SUCCESS,28 tests. Original publisher/ZIP and actual10 rootfs layer bytes are verified. A tagless envelope preserves the exact config/layers/image ID; actual Docker import followed by process death leaves IN_FLIGHT and a reopened journal reconciles without reimport. Six-source delivery, all8 publisher-verification failure positions and current root private-plan bindings are qualified separately. Root entry tests/authentication callbacks are fixtures; actual target execution remains pending.

Next required operator action is the image-only launcher, not a repeated plan/custody read and not an application cutover. It may import one exact untagged image and writes a distinct private import journal; no container, database, R12/firewall/provider/signature effects or application transition claim. The existing runner cannot execute the required root path. New OCI/peer/transport and migration-aware composed application installation remain open. No runtime domain grant is inferred from a hash, root image-only invocation or hosted proof.
