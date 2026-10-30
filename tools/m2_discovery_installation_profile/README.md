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
