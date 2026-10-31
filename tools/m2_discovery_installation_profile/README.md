# Complete discovery installation proposal

`native_profile.py` and `frame.py` compile a distinct, typed discovery launch and
complete OCI proposal. They extend the audit/compiler work in PR53. They are not
an operator launcher, credential owner, native observer or execution authority.

Inputs must come from independently authenticated preparation and owner review:
an immutable image creation request, preserved old environment, explicit provider
and workload references, five independently bound files, the DB-only configtree,
the current renewable policy-token directory, an independent OCI template and
Docker context. No deployment domain, secret path, network or identity defaults
are supplied. A captured private record is provenance, not current admission.

The five file roles are consultation key, proposal receipt key, provider client
credential, discovery receipt key and public PKCS12 CA truststore. Each carries
explicit readonly source/target and byte/metadata identities. The three MAC keys
must also have different content identities; distinct filenames alone are not
sufficient. The DB projection and renewable token directory retain their exact
separate contracts. Secret bytes never appear in compilation receipts. The
truststore password `changeit` is the fixed password of the public CA bundle;
native preparation must still verify that it contains approved CA certificates
and no private keys. It does not substitute for provider/IAM TLS admission.

The launch preserves unrelated environment settings exactly. Provider/worker,
IAM and Gateway authentication are explicitly enabled. Alternate Spring/JVM
channels, inline credentials, shared namespaces, direct published ports,
unbounded resources, writable/shadowing mounts and automatic Docker restart are
rejected. The exact existing application gate prevents Java starting before
native acceptance. Five files and two directories are represented by a new
closed seven-mount proposal schema; the historical seven-mount proposal channel
has different roles and cannot accept it.

The complete 13-phase discovery order is reused from `transition_journal.py`,
including authenticated transport installation and a distinct lease worker.
The 11-phase file-only profile, compiler and executor are unchanged and cannot
accept a DiscoveryProfile. No flag is temporarily disabled to pass old guards.
The unchanged generic file compiler checks all five file declarations, process
identity, arguments, environment, resources and closed Docker slots. Only the
two exact signed argv lists containing the existing gate are projected during
slot checking; no path or environment value receives an exemption.

All outputs retain `nativeExecutorIntegrated=false`,
`externalProviderCallsAllowed=false`, no authority, no start and no apply.
Native observer/adapters, coordinated MCP/Gateway packaging, full current
cohort, effective configuration, key agreement/custody, provider TLS/workload/
network, DB V11/V12 backup/fencing and current signed HUMAN maintenance authority
remain mandatory before target execution. Rotation requires fenced coordinated
replacement; reboot/reentry must reacquire current generation and admission
without resetting retry or incident history. These are declared requirements,
not implemented boot or rotation proof.

`tests/test_m2_discovery_native_profile.py` uses explicit synthetic inputs and
the real unchanged compiler/gate/profile modules. It never reads target secrets,
starts containers or exercises a production provider. Qualification of these
pure proposals is separate from actual native frame acceptance and application
E2E. No command should be delivered for the consumed f759d397 capture scope.

Public CA trust preparation is separate from current admission. `public_truststore.py`
compiles the exact approved IAM CA set and single currently valid provider CA into
certificate-only PKCS12, rejecting ambient trust roots and private keys. Real
Java21/OpenSSL CI verifies both isolated issuer chains, outsider rejection before
application data and tampered integrity. `trust_inputs.py` additionally binds the
exact prepared material role record and deployed IAM owner configuration, matching
issuer/token endpoint and native owner CA digest. `trust_preparation.py` stages a
new root:10001/0440 public store only after exact review/configuration/file custody
and all thirteen current native peers agree, then reobserves peers and source seals.
It reads no application credential or key and has no CLI or operator delivery.
Consumed scope/claims and partial output remain preserved on failure. These
source/fixture checks do not prove target TLS/IAM admission, executable coordinated
installation, distinct lease worker or E2E.


## Create-only worker file publication (29 October continuation)

`lease_file_installation.py` compiles exact installation/coordination/recovery
bytes from the qualified static template and capsule. A separate parent-reviewed
publication journal and the same existing logical lock fence one publication.
The installer requires three **already issued** current CREATION_ATTESTATION
signatures (publication seal, installation receipt, native-generation receipt),
a current typed native two-peer probe, and the parent/child phase checks. It has
no signing, manager, DNS, nft or container mutation entry point.

The durable exclusive claim precedes destination writes. New directories and
files are create-only; an existing ledger is preserved. The signed seal includes
the exact initial recovery clocks/budget and every payload hash. The installed
receipt is the final runtime-visible marker. Read-only reconciliation checks
owned inode records, custody and exact bytes; partial/ambiguous installation
never grants an automatic resume, overwrite, signature reissue or budget reset.
This reconciliation is the **initial installation, before the worker runs**;
it does not adopt or reset a live worker journal.

`LeaseStartAdapter(publication_directory=...)` binds publication and its separate
single-start scope in the same parent review. The old start-only scope remains
available solely for already installed signed files. This does not implement
service-manager unit registration/reload, fresh provider admission, attestation
issuance, a complete installer controller, boot/rotation or target delivery.
The 37-module runtime capsule and its pinned snapshot are unchanged.


## Finite worker attestation issuer and retained provider admission

`provider_admission.py` reuses the existing signed deployment protocol (v2
creation-frame acceptance), the signed creation/rootfs mandate and a STARTED
consumption journal. Independent image/recipe/rootfs/artifact/transport/runtime
bindings and the exact worker peer generation must agree. Missing, expired,
legacy-only or mismatched evidence is rejected. The reader creates no provider,
updates no consumption record and proves no provider readiness.

`lease_attestation.py` composes that reader with the retained Registry owner,
current native two-peer probe and existing Ed25519 signer. A separately reviewed
parent scope explicitly covers the pinned existing key and exactly three payloads:
publication seal, generation and installation receipt. Its private transaction
and each signing dispatch are durable before key use. Partial/ambiguous signing
never re-signs or auto-completes; read-only reconciliation requires the same
current provider proof, exact signatures and owned inodes. Existing byte publisher
then consumes those signatures without a second signing path. The signer and
installation/runtime worker remain separate, and the frozen capsule is unchanged.

This is an initial finite installation component, not a boot/rotation controller
or provider lifecycle implementation. The current source scope's provider slot
covers the retained-admission reader; a future lifecycle controller must compose
its separately reviewed installation scope explicitly, rather than hiding create
or start in this reader. Actual provider child/gate-only integration and complete cohort remain OPEN.
Manager registration and composed initial worker installation are described below.
Protocol tests use real Ed25519/files/fsync/flock and signed deployment records,
but model native observations/previous application admissions synthetically.


## One initial worker installation phase

`lease_registration.py` creates an exclusive root-owned symlink for the exact
installed unit in the explicitly reviewed system-manager unit directory. Its
separate private claim, link inode and reload dispatch precede one daemon-reload;
registration never enables, starts or restarts a service. Reconciliation verifies
the owned link and loaded exact fragment, with no drop-ins or pending reload.
A lost result is observed, never followed by another reload.

`lease_installation_phase.py` composes ATTEST → FILES → REGISTER → START as one
parent-reviewed phase. Every substage has a durable dispatch before execution.
Each commit requires exact readback; dispatch rechecks the retained claim and
the invocation rejects a journal regression before any second effect.
Read-only observation reconciles attempted stages; explicit same-authority
continuation may dispatch only untouched stages. A partial or unknown action
blocks progress and cannot be retried. Start requires all three immutable prefix
proofs. The returned start evidence is exactly the record in NativeEvidenceStore,
including the reviewed sequence and prefix hashes.

Once started, the worker owns its cumulative mutable journals. Completed phase
observation checks signatures, manager registration and current worker evidence,
retaining the initial publication proof without reinitializing or demanding an
initial ledger. Read-only observers verify the logical lock inode without
acquiring the worker's lifetime flock; mutation paths keep the exclusive fence.
The frozen 37-module runtime capsule remains unchanged.

The optional native `--composed-worker` qualification uses the real signer,
publisher, registration, systemd and Docker probe. It retires only an unused CI
seed before installing into fresh destinations. Previous Registry/provider
application admission remains synthetic: this proves worker composition, not
fresh provider admission, target installation, boot/rotation or CSV E2E.


## Provider expectations before creation and one owned Engine create

`provider_installation_template.py` reviews the complete provider request,
independent frame template/launch, package/image/rootfs and explicit native NIC
allocation before new identities exist. Only the Registry peer's CID and full
OCI hash have two closed transport slots. Pure materialization reuses the full
frame compiler, with no observed OCI input or admission flag. A static v2 node
recipe keeps worker expectations stable while concrete artifact/transport hashes
are derived after the owning creation receipts exist. This template alone does
not authenticate those receipts or bind the Registry peer to the gate owner.

`provider_creation.py` shares the typed parent, Engine and Registry gate window.
It checks the current running wait gate, claims one exact new name/request and
dispatches one Engine create. No start, key, broker, old-provider mutation or
automatic retry is available. A lost result is observed by the exact owned name
and created configuration; absence remains UNKNOWN. The same retained creation
can be reconciled after the finally block has safely closed the Registry window.
Stored creation ownership is available later without claiming running admission.

The optional native creation fixture uses real Docker creates and root journal/
signature/gate checks. Its named-runtime alias is never started; application and
rootfs expectations remain synthetic. It qualifies creation only, not actual v4
provider admission or the complete installer. Profile issuance/publication,
reviewed wrapper switch, one start, signed admission and worker composition are
separate remaining owners, not hidden callbacks in the creation primitive.


## Initial provider mandates, profiles and materialized admission

`provider_profiles.py` binds the owned new provider CID and the Registry's
separately signed independent node recipe to the existing full-frame compiler.
It reuses the qualified v4 runtime/Broker/node-attestor/installer format. Three
finite initial mandates use pinned existing role keys with durable dispatches
and owned signature/payload inodes; partial results cannot re-sign. The proposed
runtime configuration adds exactly the new candidate and preserves every prior
candidate and setting. Rootfs acceptance remains independently reviewed.

`provider_profile_publication.py` publishes only fresh per-CID profiles and a
separate configuration proposal. Prior configuration and journals are untouched.
The owned-file commit reconciles a lost acknowledgement. Initial readback checks
all STAGED bytes; completed observation never restores mutable runtime journals.
No switch/start or new signing occurs in this publisher.

`provider_materialized_admission.py` bridges the static v2 recipe to initial
worker expectations. It rederives exact frame/transport/Broker hashes, checks
signed v2 creation plus signed rootfs mandate and both STARTED consumption and
v4 adapter, and binds the same current worker provider generation. It admits no
old provider and performs no native observation or lifecycle operation. The
worker's finite issuer accepts this exact typed reader as well as the retained
v1 reader. Signature/IO tests model previous native admissions explicitly; real
wrapper switch/start/v4 admission and complete provider composition remain OPEN.


## Provider native boundaries and contained initial sequence

`provider_runtime_installation.py` switches only the exact already registered
OUF wrapper, using the existing atomic CAS primitive and one durable claim.
The held common native inode protects a fresh QUIESCED journal, empty inet and
bridge lease families, source/program custody, current gate and Engine runtime
selection. The proposed configuration retains every old candidate and all prior
configuration bytes. Start is a separate single POST for the new owned CID;
the common lock is released before it, so Broker/preparer can acquire it. Neither
daemon reload nor old candidate lifecycle is available. A lost switch or start
acknowledgement is reconciled by owned claims, actual wrapper/runtime generation
and the current signed v4 admission plus both STARTED ledgers, never retransmitted.

`provider_installation_phase.py` requires an explicitly reviewed v2 component
covering CREATE, ISSUE, PUBLISH, SWITCH and START. Each stage is dispatched once
behind durable CAS and exact readback; an in-memory retained row rejects a journal
regression within the invocation. The distinct short maintenance-window policy
permits three cumulative read-only observations per stage, with delays 0/1/3s
and up to20% jitter. Its deadline remains the same original parent/child/gate;
it grants no mutation retry, automatic closed-window reopen or renewed budget.
Permanent failures close the gate immediately. Ambiguous transient effects can
only be observed; exhausted/partial effects block. The original gate's finally
closure pauses the Registry before completion returns. Completed observation
retains initial publication proofs without demanding/resetting live mutable
journals. Provider readiness and full cohort release remain separate checks.

Protocol tests exercise actual wrapper CAS, fsync, flock, private files and
Ed25519. The provider Engine/nft responses and prior node admission in these
fixtures are explicitly synthetic; this is not native provider admission or a
target start. One early concurrent composed run reported a retained-row drift;
the diagnostic full rerun passed without reproduction, so this remains an open
qualification issue pending CI/native investigation. Deferred worker assembly
from new peer generations and complete application/cohort composition remain open.


## Provider v4 evidence and late worker composition (30 October)

Source `33a268fc35bf300ded261b1cb132727d26c11113` passed 342 tests in 40 suites
on push and PR. The separate native provider qualification passed both events:
actual v4 node/Broker/installer admission, independent full OCI/rootfs/NIC,
Ed25519, nft/common lock, wrapper CAS and one runc start with lost-reply
reconciliation and Registry gate closure. Docker provider create/start remains
modeled at that boundary; images/review/predecessors are synthetic. This does
not prove full cohort, target deployment or CSV application E2E. The exact
run/job references and limits are in `evidence/m2-provider-native-qualified-20261030.json`.
The legacy profile assembler/intake closure is unchanged. `assemble_provider_profiles_v2.py`
adds explicit approved runtime-parent selection and updates both initial journal
configuration bindings; no old source manifest or consumed command was repinned.

`lease_materialization.py` captures the actual paused Registry/running provider
only after current admissions. It owns a fresh logical fence and immutable
snapshot/material claim, retains original wall/monotonic clocks, validates the
exact native probe result, and constructs the existing worker sequence. It reads
no key and dispatches no lifecycle operation. An incomplete claim/fence cannot
be recreated; lost completion is reconstructed without writes or new clocks.
Seven protocol cases pass locally, including actual worker signatures and byte
publication up to a modeled manager boundary. Native/application admissions are
modeled in these local cases. The native worker fixture now exercises actual
capture and fresh-fence preparation; its new qualification is pending.

`installation_application.py` composes the existing Registry application,
provider installation and late worker under the same typed owners and signed
parent/child. Provider admission and retained closed gate precede Registry
attestation. Existing sequences are only observed; permanent/unknown outcomes
block dependent phases. Explicit worker continuation uses original stages and
clocks. The existing sealed full-cohort checkpoint remains mandatory before
producer release. Seven order/fault/identity cases pass with modeled native
owners; this is not current full-cohort admission or an executable target CLI.

Full current cohort, TLS/IAM/DB/fencing/trust, boot/rotation and target capability
publication/E2E remain open. The prior local concurrent row-drift/signature
observation remains an unresolved local fixture concern; fresh CI success alone
does not establish its cause. CSV loading ends at UDP materialization and all
row outcomes. Capabilities on loaded UDP objects are qualified separately.


Late-worker sourcec6227103 passed356tests/42suites on both events, no skips;
safe-diagnostic successor eefcfb32 retained that protocol result. Native late
materialization passed push41030898590 and PR41030907680 (logs read): actual
Docker metadata capture, one fresh fence, real signer/publication/manager/start,
lost-start reconciliation and the unchanged runtime sandbox/recovery probes.
Its application admissions remain synthetic. The firstc622push native attempt
returned UNKNOWN at final worker observation despite ACTIVE state; cause remains
unestablished. Safe CI-only diagnostics preserve denial and print only codes and
source frame names. Subsequent success is not cause resolution or stability proof.

The newer source cross-checks materialized-provider and worker Registry recipe,
kernel,DNS,coordination binding,nft command and common-lock inode before
materialization. The worker ledger stays distinct from the preserved provider
journal; sharing the path would conflict with create-only publication. New boot
cannot reconstruct/rearm retained material. Nine late
materialization cases and seven composition cases pass locally; these newer
binding/boot changes await CI. Actual v4 provider and late worker native proofs
remain separate; their complete common cohort is still open.


Source92121207 passed358tests/42suites push41033242607/PR41033252084, zero
skips; native late worker also passed both events at that source. Reports read.
The successor adds known provider/Registry signing-key exclusion and one common
parent v2 protocol case: worker owner constructed before future CID allocation,
one provider sequence/current materialized admission, real worker signatures and
create-only files, preserved provider journal and a distinct new worker ledger.
All10 worker cases plus7 composition cases pass locally; the last before-CID
variant passes separately. Engine/kernel/application admission remain modeled
in that protocol case and manager dispatch stops at an explicit modeled boundary.
Successor CI is pending. A local full-suite attempt reported row drift at
`effects/2,state,version`; strict equality blocked, later diagnostic10-case run
passed, cause unestablished. Neither that rerun nor native success establishes
why the earlier observation changed. No target, full cohort or stability claim.


## Selected images, bounded parent component (source qualification)

`cohort_images.py` reuses the existing archive/native identity and one-use Import
owner for only the selected Registry/MCP images. The reviewed plan binds Docker
binary and both distinct private journal paths, native image store, exact Registry
request and the MCP replacement image. An O_EXCL dispatch precedes each CLI load;
uncertain loads are read-reconciled, never retransmitted. Tagless archive bytes
are revalidated; the CLI receives an explicit local socket, private empty config
root and minimal environment. No old five-image intake, source closure or action
is repinned/replayed. Remaining cohort sections have their own owners and do not
become admitted by this import receipt. Six cases pass with real crypto,
archives and journals plus modeled Engine/CLI. Sourcec62d0b21 passed365tests/43suites
on push and PR, no skips, final reports read. Native CLI qualification at
source9c93274f passed push41090657018 and PR41090667765: actual Docker29.8.1,
two real loads, one lost load reply read-reconciled, unchanged second-apply
journals and revocation denial. Parent/application/package context is synthetic;
no application container runs and full current cohort remains open. Initial CI
import-path and writable-/opt custody failures were corrected in fixture setup
only; production guards are unchanged.

Owner decision2026-10-30 approves the current stable supported Go release under
exact version/checksum and all existing gates. Central controlled addendum on PR50:
`docs/decisions/OUF_MCP_GO_BASELINE_ALIGNMENT_DECISION_20261030.md`.
Initial resolved version1.27.3; MCP9539cbb4 full CI passed on push and PR,
including exact official distribution checksum, Staticcheck/nilness/current
official pinned govulncheck. Corrected package12993233270 has independent
262blob/10payload/modes/config/layer/binary/ELF readback, SBOM36components and
all-severity scan0; details on PR50. SDK1.7.0/contracts/original DOCX
unchanged. No renewed approval needed for routine Go-only updates. Old1.26.10
package remains historical. New source/build/package are acquired in their
stated scope; current private review/admission and full cohort remain required. This decision grants no runtime authority or M2 acceptance.

The sixth selected-image case deliberately regresses only a disposable mutable
journal: the separate O_EXCL dispatch still blocks another CLI load. This proves
that fence; it does not establish the cause of earlier observed row drift.


## Existing Gateway runtime under the current discovery parent

`gateway_runtime.py` composes the existing APISIX owner with an actual
`AggregateAction` over the same current thirteen-phase child, and checks the
current discovery parent in every internal owner guard. The reviewed component
binds the exact legacy runtime scope and a distinct journal directory; the child
also signs that exact runtime scope. No surrogate authority or additional issuer
is introduced. Historical post-grant recovery adoption is rejected. The existing
same-image/config/mount/network, one-use effect and finite readiness logic stays
unchanged in its original module.

Eight local cases pass with real parent/child Ed25519 and durable journals:
normal repeated application, parent revocation while the child remains valid,
child revocation, unreviewed fresh journal, historical-adoption rejection,
unknown connect without retransmission, stale Gateway generation and actual
transport construction. The old namespace constructor deliberately accepts only
its exact legacy runtime-owner type. A new typed readonly channel composes its
supported observed I/O path with current parent/journal/generation checks; no
legacy type or runtime-owner flag is impersonated. Route PUT requires a separate
current capability-publication owner and is denied here. Docker and
Admin HTTP responses are modeled; this is not native APISIX/current full-cohort
admission or an installation CLI. Source5b5be6ed passed373tests/44suites on push41098250616 and PR41098262269, no skips; final reports read. Registry+MCP
image imports, the current MCP package and complete cohort/publication owners
retain separate scopes and gates.


## Selected archive preparation before review

`selected_image_preparation.py` creates exactly two tagless archives from the
selected Registry/MCP packages and an explicit native Engine profile. Each source
is independently rehashed/audited against its pinned source/image identity and
module runtime user. An exclusive preparation claim precedes create-only archive
and receipt publication. Completed preparation can be read-reconciled only after
both original and derived bytes/config/native identity are revalidated; partial
preparation cannot be overwritten, automatically finished or rearmed. No image
load, signing, publisher-trust acceptance or runtime authority is issued.

Five local cases pass with real archives/custody/files and modeled Engine profile
GET: complete readback/no overwrite, interrupted second write, original/derived
tamper, profile/package drift and wrong user. The disposable native qualifier now
uses this production preparer before real Engine/CLI imports of inert fixtures.
Native and extended45suite protocol qualification are pending. This library is
not yet a concrete current-target private profile compiler or operator command.


## Only the selected MCP replacement

`mcp_runtime.py` compiles the current standalone offline MCP package record,
including its actual artifact/scan vocabulary, through the existing pure
replacement planner. The raw package-record hash is retained; no historical
six-module source lock or four replacement action is fabricated. Offline
compilation against the actual Go1.27.3 package12993233270 passed using a
synthetic old-container observation, with no load or lifecycle operation.

The owner uses the actual current parent/child AggregateAction and checks the
exact same signed Registry transition at its verified, producers-held barrier.
It reuses only the existing native process/config/mount/network comparisons.
Rename/create/start/restart-policy changes each have an independent exclusive
dispatch marker before effect; an ambiguous outcome is observed without resend.
A distinct, reviewed readiness journal uses the existing Recovery protocol,
128attempts/3600seconds maximum, backoff/jitter/Retry-After, the original parent
and child expiry, and persisted wall/monotonic/boot checks. Readiness publishes
only a local proof; it does not publish routes, traffic or capabilities. The old
MCP container is retained and no other application is replaced here.

Thirteen cases cover ordinary completion and repeat, lost create/start replies,
unproven creation, preserved recovery wait across reconstruction, parent/child
revocation, changed boot/monotonic deadline, unreviewed journal, historical
adoption, stale process, unknown health failure, exact signed Registry history,
mutable-record regression against exclusive dispatch, exhaustion and the empty
HTTP204 contract. Signatures/archives/files are actual; Docker/health responses
are modeled. Final local qualification and extended46suite CI are pending.
Earlier local image-journal/state and detached-verification denials remain
unresolved observations; guards were not relaxed. This is not native MCP owner,
full cohort, target E2E, boot/rotation or coordinated publication acceptance.
The ordinary MCP's three discovery descriptors remain INACTIVE; source/package
qualification alone cannot make them production-visible.


## Native qualification of the single MCP replacement

`tests/qualify_m2_discovery_mcp_native.py` exercises `DiscoveryMcpRuntime` with
Docker 29.8.1, native Engine create/start/update, the original production HTTP
readiness method, real Ed25519 and private journals. A deliberately lost start
reply is reconciled after constructing a new owner; another apply leaves both
journals and the effect count unchanged. Mount content and restart policy are
preserved; parent revocation prevents further work.

This is a disposable CI fixture, never a target entrypoint. The executable is a
small static HTTP server with the MCP empty-204 readiness contract. Parent/HUMAN
scope, package provenance and the Registry held-release transition are explicitly
synthetic. The fixture does not qualify the real MCP binary, complete cohort,
capability publication, semantic discovery or CSV-to-UDP. Native initial proof passes on both push and PR at `d4410db9`;
real 503/Retry-After/backoff/reconstruction proof passes on push and PR at
`dc16fa46`, with both final reports read. See
`evidence/m2-discovery-mcp-native-qualified-20261030.json` for exact scopes. The earlier intermittent
local `MCP_INVOKING_RECORD_DRIFT` remains unresolved; an isolated passing rerun
is not a causal fix. The lost-reply protocol test now requires the exact transport
error and proves the expected dispatch happened before it accepts reconciliation.

## Selected runtime composition and Gateway dispatch custody

`selected_runtime.py` composes the existing image, Registry/provider/worker,
Gateway and single-MCP owners under the same parent, child, Engine, transition
and reviewed component. It imports the two images, invokes Registry verification
up to its release barrier, then installs Gateway and MCP. The Registry history
must remain identical while those owners run. Completed imports and both runtime
proofs are rechecked with read-only verifiers before the selected-owner receipt.
No new journal, initialization, retry loop, clock/budget, authority, admission
flag or producer-release method is introduced. Owner pauses propagate. The
receipt deliberately does not assert full-cohort admission, physical quiescence,
capability publication, target installation or application E2E.

The discovery Gateway component is v2: each of its seven lifecycle dispatches
requires an exclusive fsynced marker independently of the mutable owner journal,
bound to the component and both authority hashes. Completed markers are read
back on every record read. A claimed unknown effect only reconciles; deliberate
journal regression cannot send another POST. The original GatewayRuntime source
and historical scope/journals remain unchanged. Old v1 review values do not match
this new component; it never silently adopts or repairs them.

The controlled local pre-fix regression fails because a second connect is not
blocked after a deliberate journal rewind. The successor covers retained marker
bytes/inodes, lost start and owner reconstruction, changed marker denial,
unclaimed writes and invocation fencing. These component tests use actual
Ed25519/files/journals with modeled Docker/Admin HTTP. The selected composition
suite models owner leaves and proves only ordering/binding/failure propagation.
Combined native composition, the complete current cohort and target delivery
remain separate mandatory qualifications.

The selected owners' signed child carries `gatewayRuntimeInstallation` and
`discoveryMcpInstallation`. The original Executor correctly rejects these extra
fields; a parent-bound assembly must supply `discovery_parent` to
DiscoveryApplication. Its dedicated `DiscoveryExecutor` authenticates the current
parent/child and exact Gateway v2/MCP v1 sections before extending only that
closed field set. It reuses all original phase/checkpoint/fencing logic. The
shared Executor bytes and file-only profile remain unchanged. Discovery specializes
only the v1/13-phase validation branch locally; ordered dispatch/CAS/fencing and
reconciliation are inherited. No flag or temporary projection bypasses validation. Unknown signed
fields, mismatching sections, changed parent and revocation fail before a claim.
The complete sealed private compiler/CLI and native cohort qualification remain
mandatory; constructor support and synthetic phase tests do not supply them.

The selected dependent-owner phase holds the existing Registry transition invocation
fence, excluding concurrent producer release. No shared lease/network lock or DB
transaction spans the phase; a paused owner raises immediately and releases the fence.

## Docker peer OCI custody and joint worker qualifier (31 October)

The native Docker qualifier exposed a boundary hidden by the manually staged
runc fixture: containerd owns the Registry peer's `config.json` as root `0644`,
while the provider's private readers require `0600`. The new pure revision in
`semantic_transaction_profiles/repair_peer_bundle_sources.py` changes only peer
OCI collection. It accepts exactly `config.json` below the runtime-reported
peer CID, with root-owned nonwritable ancestry, regular root:root `0644`, one
link, bounded length, stable descriptor/path metadata and the signed expected
full OCI hash. Both native peer observations still match the same generation,
OCI and reciprocal NICs. Unknown errors are not retried/reclassified. Private
keys, policies, authority records, journals and the candidate shadow bundle keep
their original readers. The original draft and earlier repairs are byte exact.
The selected discovery profile now requires the exact revised peer source hash;
new source maps must explicitly apply the pure revision before hashing/review.
No runtime source substitution or old installation adoption is authorized.

`qualify_m2_provider_docker_worker_native.py` uses actual Docker29/Engine and
v4 broker/node/installer/driver admission, a separately qualified control-peer
rootfs seal, and independent committed expected OCI. Its finite process-worker
mode reuses the earlier handoff assertions. `--sealed-worker` instead composes
late WorkerMaterialization, three signatures, create-only file publication,
unit registration and one systemd start with that same provider admission.
The Registry complete-admission predecessor, images and parent review remain
explicit CI fixtures; target/cohort/TLS/IAM/DB and application E2E are separate.
The worker's shared kernel inode has a dedicated directory so its readonly
sandbox never mounts the issuer's private signing directory. Candidate results,
initial native denials and qualification status are recorded in
`evidence/m2-provider-docker-worker-20261031.json`; source presence is not PASS.

The daemon qualifier has a feature-only, lifecycle-denying runtime bootstrap
before Docker discovers the named runtime. That bootstrap is authenticated and
replaced during disposable CI setup before parent review; the production owner
still performs its one guarded wrapper CAS. Registering an absent wrapper made
Docker cache different recursive-readonly mount capabilities and caused the full
OCI comparison to deny the candidate. Expected mount flags are not projected
from actual OCI. The two worker modes run on independent disposable runners;
failed/consumed fixtures are never reused. The admitted adapter intentionally
does not implement pause/resume; the Docker fault case uses its supported kill
operation and proves the worker cannot restart/rearm the terminated provider.
The earlier native runc pause/resume proof remains a separate retained scope.


## Safe diagnostics for an unproven installed-worker read (31 October)

An installed-worker read can remain UNKNOWN after an already consumed manager
start. Previously its exact observation denial was discarded by the start owner,
and the installation sequence also discarded the pending owner's evidence.
The start owner now retains a finite allowlist of observation reason codes and
a coarse read-failure category. Unknown messages, paths, errno, command arguments,
stdout/stderr and arbitrary exception formatting are excluded. The sequence
returns that structured pending-stage observation while keeping its original
claim and history unchanged. Neither reader gains a retry, manager dispatch,
positive receipt, new authority, budget or continuation permission.

Controlled protocol cases cover known denials, custom exception text, private
process/IO errors and the full consumed START sequence. A later separately
requested read may reconcile the original claim; it cannot start again. This
closes a diagnostic information loss, not the cause of the historical native
UNKNOWN or the full stability/cohort/target requirements.

## Concrete Registry node, token and transport before the sealed worker

The Docker qualifier's third independent mode, `--registry-worker`, replaces the
modeled Registry-admission predecessor with the actual DiscoveryNodeOwner and
TransportInstallationAdapter. An independent Registry control-peer rootfs seal
precedes review; the real five files, DB configtree, token, complete OCI/rootfs
and reciprocal NICs are read natively. InstalledTokenOwner retains actual source
custody, Ed25519, journals, pinned TLS and the masked legacy-unit fence on the
disposable host. Later reads cannot renew its one initial token grant; final IAM
revocation must deny Registry readback.

`engine_transport_backend.py` reads the exact signed Engine OCI as a bounded,
stable root-owned public file. It authenticates the current matching paused
Engine SandboxKey and the same admitted PID/startTicks/inode before and after,
then uses that canonical Docker namespace for native access. Expected OCI and
reviewed paths stay unchanged, including OCI_CREATED proc paths. An AST parity
test retains all original namespace/NIC/peer/generation guards except these two
reader call sites. Original backend, private readers and frozen pins stay exact.

The complete composition reached worker ATTEST but exhausted the original
90-second provider profile. A separate v2 profile explicitly reviews a complete
Registry/transport/sealed-worker window of at most 300 seconds, within the
existing protocol hard ceiling. V1 retains its 90-second limit. The new scope
requires new exact parent review before candidates; three exclusive signature
claims still clip expiry to the original parent/child/gate. It cannot extend live
authority or renew/adopt consumed claims.

Native qualification and causal failures are recorded in
`evidence/m2-registry-node-worker-native-20261031.json`. HUMAN/IAM realm,
images/packages, earlier transition phases and host transport remain fixtures.
Java stays paused. Real Gateway, full cohort, publication, target authority and
Farmacie-to-UDP require separate qualification.


The host-side worker observer no longer takes the nonblocking exclusive kernel
writer lock. Controlled real-flock tests show that its former exclusive read can
block both renewal and safe revocation, producing SAFE_PAUSE_UNPROVEN in the
actual recovery protocol. The reader authenticates the same approved inode
before/after without flock and retains the complete stable journal, ownership,
positive equal two-family membership and receipt subset checks. An incomplete or
changing publication is unproven; no retry/effect/reset budget is added. Process,
manager, signed generation and nonregressing accounting checks remain required.
The worker's frozen37pins and writer semantics are unchanged. This proves a
concrete interference mechanism, not the cause of every historical UNKNOWN;
current native and complete-protocol qualification must be read separately.


At production/test/workflow source `bc82ccef0fadcdc4d669a1743f3d38cb6a288693`,
PR41165277183 passes all three native modes; PR41165277205/job124431387665
passes457tests/54suites/0fail/0skip, and IAM41165277274/job124431388446
passes251tests/33suites/0skip plus actual disposable Keycloak. All those final
logs/reports are read. The Registry/token/transport final report also proves IAM
revocation denial with unchanged token/journals and one initial grant. These are
the named qualified scopes; full target/cohort/product acceptance remains open.
