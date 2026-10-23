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

`installation.py` currently only compiles configuration and public CA bytes.
`entry.py` only runs an already installed worker and redacts untrusted errors.
Neither is a privileged installer. A proposal grants no authority.

## Validation and limits

At commit `cb355dbc764377ac46f568e95930f3c027a34191`, CI run
`40031446707`, job `120680405205` passed 22 core/store tests and five native
tests in 64.503 seconds; direct logs were inspected. Native tests use actual
TLS, Ed25519, IAM admission, root/gid10001 atomic publication, both locks and a
separate isolated Python process restart. A real 60-second wait precedes a
second grant with distinct token/attempt and cumulative accounting 321→322→323.
Revocation, bad signature/trust and changed fence are refused.

Those are disposable issuer/installation fixtures, not production permission or
Registry policy acceptance evidence. Subsequent changes add six pure contract
tests, an independent CA roundtrip case and safe-outage backoff semantics. These
passed at `8119f9f9e350621f35cedfd7166dcbf02cb141bb`, CI `40031891184`,
job `120681881745`: 28 component tests and six native cases, 65.918 seconds;
direct logs inspected. The final public error-boundary changes passed at
`a1388bf3c17f060e3f96d0b88e027d889b50f35b`, CI `40032178372`, job
`120682855310`: 30 component tests and six native cases, 65.178 seconds; direct
logs inspected. Local component tests deliberately skip
native gid10001 publication because this sandbox cannot perform that CHOWN.

Still required before a target installation command: complete source capsule,
concrete signed installation review and issuer integration, privileged
single-use installer/fence transition, qualified process-manager sandbox, and a
rotation-aware final original-caller acceptance check. Keep Kubernetes duties
with Kubernetes and retain the existing native journal as historical evidence.
Only actual original-request 200 plus observed continued renewal on the target
can support closing this repair; then proceed to E2E and the Supervisor.
