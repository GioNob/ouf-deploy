# Registry running policy repair — implementation handoff

The target incident remains open. No command in this document authorizes an
installation or another token grant.

## Target evidence

The historical gateway route pointed to the reviewed stopped Registry without
a live network endpoint. Docker/host shutdown was corroborated in its stop
window; the stopping actor was not established. No Kubernetes ownership of this
container was proven.

After recovery, current observations show the same running Registry generation
with one network endpoint. Two diagnostic original-caller HTTPS GETs returned
403. TLS chain, name and peer pin passed; body/header correlation identifies a
Registry-shaped `SEM_CAPABILITY_REQUIRED` response forwarded through APISIX.
This does not distinguish unavailable/stale policy from a real capability deny.

The controlled Registry credential owner is cancelled, total attempts 321. Its
last recorded lease expired. The configured policy refresher uses this owner's
output. This is evidence for a renewal problem, not proof of the current policy
cache or the precise cause of the 403. The current caller token also rotated;
its reviewed historical byte binding is stale. Do not restore that old bearer,
silently rebind its signature, grant permissions or disable authorization.

The native journal remains at checkpoint 11: eleven effects APPLIED and final
effect CLAIMED; DB/Admin/Semantic read counts 18/18/0. Existing application 200,
continuous target renewal and release acceptance remain unproven.

The latest target capture is complete:

- Input SHA256: `1ab900e9818543788df36f5bc7f101da99507dd01933bd10a8194137b5de42de`.
- Input file: `/etc/ouf/deploy-snapshots/semantic-registry-running-policy-inputs-47eb283d194f9a9b81f22852c278e1f9b24d0c72c63e60e968cf8ce67d876f89/inputs.json`.
- Receipt: `RUNNING_REGISTRY_POLICY_REPAIR_INPUTS_PREPARED`.
- Four Engine GETs, two bounded credential reads, no HTTP/OAuth/runtime effect.
- Rotated caller candidate captured; no signed rebinding or new budget.

Do not repeat completed captures, either diagnostic GET, old owner/apply,
checkpoint handoff or the six-directory JVM cleanup.

## Implemented components

`tools/semantic_registry_operational_owner` implements a separate normal
credential worker. This is not the deferred Supervisor and performs no
orchestration, gateway routing, database change or IAM permission provisioning.

It uses the existing confidential client, SERVICE identity, online IAM
admission, output and publication fence. Its ledger inherits 321 and reserves a
new distinct counted attempt before every grant. Unknown grant/publication
outcomes block; a crash cannot redispatch the same attempt. Proven pre-submission
failure uses capped backoff under a rolling hourly rate limit without resetting
the failure streak or cumulative accounting.

The actual store uses root-owned no-follow FD traversal, lifetime flock and
versioned atomic fsync/CAS writes. Process restart checks current token hash and
readmits it online without extending its authenticated expiry. The runtime
requires a real current scoped Ed25519 installation receipt, protected source
and configuration, the current global fence and the shared logical-owner lock.
It never signs or reads private signing keys.

IAM CA trust is independent of the caller API CA. Preparation must freeze the
exact previously admitted IAM certificate set into a public PEM bundle; its
roundtrip fingerprint must equal the retained owner trust hash. Runtime binds
that file's bytes and uses no additional ambient roots. No service address,
IP, URL, port or credential location is invented.

## Qualified installation and delivery

At source commit `4b4c1c7ed2084d4419cf88f3664d1ab23253fbe7`, native CI
[40037200420, job 120699485359](https://github.com/GioNob/ouf-deploy/actions/runs/40037200420/job/120699485359)
passed 34 component tests and all 10 native cases (141.007 seconds).
Direct logs were inspected. These include actual dual Ed25519 authorization,
exclusive installation claims, unchanged old journals, a late generation-change
refusal leaving the public fence inactive, real systemd RootDirectory execution,
TLS grant/admission/publication, process restart, a second renewal after a real
60-second wait, atomic fence revocation and absence of signing keys, Docker
socket and host `/proc/1/root` inside the worker.

The installer fixtures declare synthetic historical inputs and an Engine API
representation. Unix HTTP, current host PID/start ticks/network namespace,
filesystem, locks, signatures, systemd isolation and IAM transport are real.
This does not establish a full Docker installation or target readiness.

The source-only capsule contains the eight exact qualified operational modules
and the unchanged 142 legacy dependencies. All eight local Git blob hashes
were compared with the qualified Git tree. Capsule SHA256:
`c33b6467d424489aeec7406c65fafc37534badc08e909bf7c2d78bb1f122d378`.
The legacy F7 capsule remains unchanged.

One `deploy` invocation prepares the complete private review, requests exact
`APPROVO <review hash>` on the controlling terminal, signs with the existing
installation authorities, installs once, enables the specific systemd unit and
waits up to 45 seconds for its first actual publication. The new signed mandate
authorizes normal scheduled credential renewal, with distinct attempts at most
60/hour and prior cumulative count 321 retained. Its finite 900-second window
covers installation; it is not reuse or extension of the old cutover window.
No IAM permissions, container lifecycle, gateway routes, database or old native
journal are changed. The operator does not automatically replay failed phases.

The worker runs in its own private filesystem root with CAP_CHOWN only. It
binds exact public runtime/configuration material, existing credential and
public trust directories, shared owner lock, and an atomically replaceable
public fence directory. Only the separate operational ledger and existing token
output are writable. Boot identity is bound separately; `InaccessiblePaths`
and `ReadWritePaths` use the explicit root-relative `+` prefix. The signing
keys are outside every runtime bind. systemd owns process restart and boot
activation; this is not the deferred Supervisor and makes no Kubernetes claim.

The launcher must use the existing authenticated GitHub client, first the
retained portable executable then PATH, before sudo. It checks immutable
source checksums both before and after copying to a newly created root-owned
private directory. It preserves operator exit status and logs, and refuses a
second invocation of an existing private launch. Delivery fixture tests check
these boundaries separately from native installer qualification.

## Next target evidence and remaining limits

No new target effects or token grants have occurred during this implementation.
After the one installation command, inspect its actual output. Expected success
is an ACTIVE worker, an active manager/PID and at least one publication with
cumulative attempts at least 322. A positive recorded token window alone is not
current IAM admission proof, application readiness or permanent renewal proof.

Then perform a separately bounded original-caller GET using its current
configured rotating credential, existing TLS identity and reviewed resolver
view. Do not replay either completed diagnostic GET or the old final CLAIMED
native stage. The new install does not rebind that stale caller snapshot.
The response must establish the exact active reference; a continued 403 needs
policy/capability investigation without granting permissions or disabling IAM.
Only actual original-request 200 and observed continued target renewal can
support closing this repair. Then proceed to E2E and the Supervisor.

Full Registry reboot recovery and durable production caller DNS correction
remain unproven. Do not change RestartPolicy=no blindly: the historical gated
bootstrap requires coordinated release. No full platform resilience or release
acceptance is claimed. Technical phases remain 8/8, functional milestones 4/6,
G3 OPEN.

## Immutable delivery artifacts

- Capsule artifact commit: `ca9815fc3505085360c5601fc1f3c6672c21b660`.
- Capsule path: `releases/semantic-registry-operational-owner-20261024.py`.
- Capsule SHA256: `c33b6467d424489aeec7406c65fafc37534badc08e909bf7c2d78bb1f122d378`.
- Launcher path: `releases/semantic-registry-operational-owner-20261024.sh`.
- Launcher SHA256: `198a129219f11cabc8333197f88ed1a17e3ce9615a1fbd3ed6bde55dcff1ab91`.

Download the launcher through the existing authenticated `gh api` raw Contents
endpoint at its published immutable commit, verify its checksum, then run it
once as oufadmin. It downloads and independently verifies the capsule, copies
it into an exclusive root-owned directory, checks that protected copy again,
and invokes the one-pass `deploy` mode. Never inject the TTY approval. Never
relaunch after a STOP; preserve the public receipts and operator log.

The final delivery fixtures and unchanged operational modules passed at
`5cbeb5804b2beb45ad9c8c63b12dc1811bc463ba`, CI
[40038873138/job120704938504](https://github.com/GioNob/ouf-deploy/actions/runs/40038873138/job/120704938504):
40 component tests and all 10 native cases (141.021 seconds), direct logs
inspected. All six launcher shell cases pass, including portable-client absence
with a real fixture fallback, and complete client absence with an isolated PATH.
The generated launcher also passes `bash -n`. Target execution is pending.

## Target installation result: first publication absent at initial observation

The operator reported complete installation for review
`b67488693c49241d8b6bdf1691216847bd07d7057895a26aa35946442ee450fe`,
configuration `0b72275fcc2c51be0929ca0ba454de932ae4863af1b2410dd67bef61bf81e91a`.
The manager then reported active with a running process and boot enablement,
but the initial 45-second observation saw DISPATCHING, three new attempts,
cumulative 324, zero publications and no positive recorded token window.
The deploy operator stopped with
`INITIAL_ACTUAL_OPERATIONAL_PUBLICATION_AND_PROCESS_REQUIRED`.
The independently running worker was not stopped by that operator failure.
Preserve `/home/oufadmin/ouf-registry-normal-launch.CP13rdcp/operator.log`.
Do not replay installation/start or reset its claims/counters.

If no process restart occurred, the initial two attempts returned through the
proven-no-submission branch to allow a third distinct reservation with zero
publications. A restart can also abandon an undispatched RESERVED attempt
without refunding it. Restart count, third outcome and current state need observation. Attempt counts do not establish
issued tokens. The precise unavailable dependency remains unproven.

The new observer checks this exact review/configuration, takes two bounded
atomic FD ledger snapshots and performs one read-only manager show. It never
reads credentials or runs the capsule. One separately claimed unauthenticated
TLS connection from the host uses the configured IAM peer, issuer SNI and exact
CA file, with an eight-second deadline and no HTTP or bearer. Its result is
explicitly not proof of worker-cgroup connectivity. No operational ledger,
manager, network configuration, container or IAM mutation is performed.
Seven focused tests pass, including real loopback TLS identity verification,
certificate rejection, refusal, protected-file and claim boundaries, redaction,
and an explicitly synthetic manager/transport full-observation fixture.
The eight operational modules and installed capsule are unchanged.

## Host TLS observation and next network comparison

User result qvEOuMzE reports RETRY_WAIT/version12, four consecutive proven
no-submission failures, cumulative325, zero publications and zero process
restarts. The manager is active, private root/unit hash match, and NNP is set.
A single TLS connection from outside the worker cgroup verified the configured
IAM peer, chain and hostname. No credentials, HTTP or OAuth were used.
The observer claim is consumed. Do not replay it or restart the worker.

The network comparison candidate creates exactly one temporary probe process,
moves only that child into the already identified worker cgroup, joins the
worker's pinned mount namespace and enters that worker's private root. It drops capabilities, sets NNP and closes inherited
host descriptors before creating sockets. A fresh host TLS comparison and the
child TLS/public discovery GET use the exact configured peer/SNI/CA. No bearer,
credential, grant, redirect or alternate endpoint is used. The child is reaped;
the unit, original PID, policy and ledger are not edited. This explicitly has
one transient cgroup-membership effect and does not claim readOnlyRuntime.
PID start ticks, root/network namespace and cgroup identity must match before
and after, and the actual manager generation must remain unchanged. The probe
does not reproduce the worker's pre-existing seccomp/environment restrictions.

The comparison has its own fixed fsynced one-use claim and does not reset any
prior scope. It allows at most two TLS connections and one public discovery
GET, with bounded child/parent deadlines and redacted phase/errno/status/equality
output. Four real loopback TLS/HTTP tests pass. An actual native cgroup/root
allow-versus-deny test is being qualified before target delivery; fixture-only
units must not be confused with editing a production worker unit.

## Network comparator qualification and delivery

Source `e972b718bc9ee0b08df59a065be43547cc8405d6` passed CI
[40041485859/job120713481609](https://github.com/GioNob/ouf-deploy/actions/runs/40041485859/job/120713481609):
51 component tests and all 11 native cases (155.166 seconds), direct logs
inspected. The real temporary child joins the actual cgroup and mount
namespace, enters the pinned private root, closes inherited descriptors and
drops capabilities before creating its socket. An allowed fixture worker yields
TLS/public discovery200 with unchanged worker PID, ledger and token POST count.
A separate disposable deny-all fixture actually blocks TCP with no HTTP GET.
The first negative fixture needed an exact-frame readiness wait because
Type=simple start can return before root setup; the guard was not relaxed.
Issuer/history/Engine API inputs remain synthetic; target success is not proven.

Immutable script: `scripts/probe-registry-operational-network-20261024.py` at
`e972b718bc9ee0b08df59a065be43547cc8405d6`, SHA256
`96f9f2da571e8b2f56dbfd27f66fa7db40d60bb2a4e904a7e18d64895f8b6cc1`.
Published bytes were read back exactly. Deliver through existing authenticated
gh, checksum before privilege and protected-copy execution, one new exclusive
root launch. Its fixed probe claim prevents re-execution even from a new launch
or changed source. At most two TLS connections, one public discovery GET,
one temporary child cgroup-membership write and one child mount-namespace join.
No credentials, grant POSTs, manager/worker/config/ledger writes or worker
signals. The child is reaped. readOnlyRuntime is explicitly false for its
transient child-membership effects. The original worker continues independently.
This does not reproduce its existing seccomp/environment. Await actual target
JSON before deciding a repair. Do not rerun prior observation or deployment.
