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
