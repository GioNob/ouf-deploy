# QUIESCED / ACTIVE recovery-reader interference — 31 October 2026

The external installed-worker reader reused `lease_service.build_installed`,
which constructs a runnable worker. Its factory and later recovery reads use
`Journal.read()`, an **exclusive nonblocking** recovery/CAS transaction. An
outside reader can therefore make the actual worker's own read or CAS fail.

The worker then correctly revokes its kernel leases. If the external reader
still holds the recovery lock, the worker also cannot persist its blocked
checkpoint. Its parked-alive fallback retains an old ACTIVE record while
coordination is QUIESCED and both lease families are empty. This is a separate
lock from the kernel common lock addressed by the earlier host-observer fix.

A controlled reproduction uses the production worker failure path, actual
private journal files and flock, with a modeled kernel. It reproduces ACTIVE,
16publications,1attempt, QUIESCED/unauthorized, unchanged recovery bytes and
parked-alive/unavailable reporting under the exclusive outside reader. It
establishes a concrete defect compatible with the source41f935 snapshot; the
old incident did not capture its flock owner, so its exact historical trigger
is not independently proven by this reproduction.

The host entrypoints now use `lease_observation_inputs.build_observed`, which
constructs read-only observation inputs rather than a runnable supervisor.
`RecoverySnapshot` opens only the existing private recovery record and never
opens/acquires the recovery lock or writes a ledger. It verifies protected
ancestry/root identity, root:root0600/one-link regular bounded canonical bytes,
stable fd/path identity, exact context/generation/policy/scope/accounting and
valid state/counters. A concurrent valid atomic replacement is read contention,
reusing only the observer's original three attempts, single deadline and
0.02/0.04s waits. Bad custody and malformed or foreign records deny immediately.

Signed installation/configuration/source/recipe bindings, kernel/DNS/coordination
hashes, policy bounds and native generation verification remain required. The
start reader validates a NEW zero-attempt ledger before dispatch. Operational
recovery validation occurs when the observation reads its snapshot; static
composition itself performs no recovery transaction. Revoked QUIESCED leases
remain an immediate denial, never retryable publication or positive evidence.

The production worker, its original37pins and464208byte capsule SHA
`3b88cd8f329ea5f143bed61906270070341a6cda9ebc534a2268d82eeada3262`, its writer,
runtime budgets and the original108module compiler remain byte-for-byte unchanged.
The independent infrastructure compiler source closure now contains128modules
and has source-map anchor
`649322a5fa52193ca1b12efdf03901c0f30485a3051216465ebee299b40f778b`.
Its capsule is a new exact compiler binding, not adoption of a previous assembly.

Local checks:8recovery-reader tests PASS1.752s,16start/read tests PASS4.281s,
13signed-file tests PASS18.420s and15infrastructure compiler tests PASS8.472s.
The worker capsule and original108module compiler pins were rebuilt unchanged.

Native CI now adds a separate, fresh Registry/worker negative-control mode. It
deliberately holds the **old** exclusive recovery-reader transaction, requires
actual kernel revocation with the stale ACTIVE record, and verifies that the
current observer still denies the revoked publication. That mode must not claim
installation acceptance or restart/rearm the consumed worker. The normal
Registry/worker mode instead holds an unlocked snapshot fd across an actual
renewal and requires publication progress with the original clocks/attempts.
Both controls are bounded CI fixtures; no production authority or budget changes.
Their final reports are required before claiming native qualification.

No target apply, merge, runtime authority/grant, reset or consumed replay.
M2/current full cohort/complete parent/child/HUMAN/publication/Farmacie→UDP,
boot/rotation/two real clients and general acceptance remain OPEN. Historical
UNKNOWN/MCP/worker cases retain their separate evidence and unresolved causes.
