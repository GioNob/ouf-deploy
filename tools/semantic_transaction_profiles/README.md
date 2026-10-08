# Authenticated provider transaction boundary

`assemble_provider_profiles.py` remains pure assembly. The new
`authenticate_provider_transaction.py` verifies externally issued Ed25519
records before compiling a two-CID installation plan. Neither module installs
an allowlist, signs evidence, reads private keys, grants leases or invokes Docker.

## Inputs that confer authority

For each exact v2 CID, the caller supplies the full template, launch, context,
compiled frame policy, deployment constraints, preparer template, publisher
evidence and dependency evidence. Existing hash-only operator reports cannot
replace those documents. A new `ouf.semantic-provider-target-review.v1` record
must carry the installed infrastructure installer's detached
`FINAL_DEPLOYMENT_APPROVAL` signature and bind the exact bytes of all eight
documents, the full reviewed source closure including frame observer, separate
image manifest/config digests, and the actual full v1 runtime seal. Its exact
decision is `ACCEPT_PROVIDER_IMAGE_AND_COMPLETE_FRAME`; its ACTIVE window is at
most 300 seconds. The signature is an explicit installer acceptance, not a
replacement for publisher/dependency verification: the issuer must verify the
two evidence documents before accepting them. This compiler does not implement
an image-provenance verifier or manufacture that acceptance.

The caller also supplies the existing production schemas: signed creation-only
intent, signed node live acceptance authorization and signed final-approval
mandate. Node authority is separate from installer authority. Both role mandates
bind the exact intent hash, CID, transaction, runtime executable, constraints,
transport and complete policy; live acceptance also binds complete OCI and the
original full v1 seal. Portable image seals are never substituted. The verifier
must be the production `DetachedAuthenticator`, with the same policy,
signature directory and OpenSSL bindings as the resulting profiles. The target
caller must pin the existing installed trust policy; a test policy is not target
authority merely because it uses the same identity strings.

## Result and remaining installation responsibilities

Only after both roles authenticate does `build_install_plan` return exact node
v4, installer, broker, preparer and STAGED journal bytes, two adapter entries,
and per-CID adapter journal hashes computed from the complete resulting adapter
configuration. The complete frame is independently recompiled; sibling OCI/NIC
declarations are checked across roles. Every result remains a proposal in memory
with `startAuthorized:false` and `leaseAuthorized:false`.

The target provisioner still must source-seal its own loader, pin the existing
authority/policy custody, read bounded private documents and signatures, recheck
their custody after verification, durably retain all signed inputs and failure
diagnoses, verify actual stopped candidates and the empty installed guard, then
publish sources/profiles and perform a guarded compare-and-swap of the runtime
configuration. The installed wrapper still targets the old runtime source; a
profile plan alone cannot change that. Target lifecycle coordination through
Docker remains a separate integration obligation, with no direct `docker start`
recipe. Uncertain signing/admission must preserve claims and must not be replayed.

Missing signatures produce `SIGNED_TARGET_RECORD_MISSING` plus the document
name and role. Scope differences list field names without printing private
values. The future installer must attach its retained snapshot path to that
diagnosis; this pure module has no filesystem evidence location to invent.

## Normative traceability and validation

Consulted in the attached v1.7 package: Matrix v1.7 sections 1, 4, 6 and 7;
Gateway v1.5 T16/T17 and GW-A13/A15; Authorization v1.5 AUTH-06/07/09/12.
Ownership, representative target bindings, durable faults, default deny and
separate actor authority remain unchanged. The selected product path is still
the existing Teatri asset via MCP, national discovery, semantic review and human
approval, onboarding, ingestion/duplicate checks and UDP readback.

`test_authenticated_transaction.py` uses disposable keys and synthetic complete
documents. Eighteen tests exercise real OpenSSL signatures, missing/tampered/expired
authority, context and source drift, publisher-evidence drift, independent config
digest, seal substitution and all-or-nothing two-role assembly. It proves this
boundary only; it does not issue target acceptance, inspect the VPS or prove the
full Docker activation transaction.

## Source-sealed private intake and publication

`provider_transaction_intake.py` pins 35 source files through
`intake-source-closure.json` before any module execution. It fixes the existing
v1 target authority profile, trust policy, empty adapter configuration and actual
Python/OpenSSL byte bindings; callers cannot select a disposable CI policy.
Its configuration names all complete private JSON input bindings for both roles.
The installed authority-key paths are metadata only and are explicitly excluded
from the input reader. The loader verifies signatures, rechecks input/source
custody under the bounded operation and invokes `publish_provider_transaction.py`
only after complete authentication.

Publication uses O_EXCL, mode 0600, root-owned 0700 directories and file/directory
fsyncs in one new snapshot. Original signed payloads and input hashes are retained;
uncertain attempts retain installation claims and sanitized stage diagnosis.
Replaying into an existing snapshot is denied. The runtime configuration remains
an inert proposal: the installed wrapper, live allowlist, guard, services and
containers are untouched. The target CLI has not been exercised against the
private VPS documents. The isolated loader acceptance/modified-source rejection
and durable publication success/failure/replay/path-escape tests passed locally.

The first hosted run 37830139331 passed its native two-candidate job but failed
private-input tests because their files were beneath the runner-owned checkout.
The fixture now uses a separate `/root/ouf-transaction-ci` directory on hosted CI;
the production ancestor check is unchanged. This does not grant the VPS runner
any additional sudo or filesystem access.

No operator bootstrap is issued for these components until actual complete target
acceptance/mandate inputs and the remaining live switch/activation transaction are
ready. Do not install this as another preparation-only step.

## Explicit role authority issuance

`issue_provider_transaction_authority.py` now emits target review, creation-only
intent, live node acceptance authorization and final-approval mandate from one
root-private, operator-authored per-role issuance mandate. The mandate binds all
eight complete input hashes, the reviewed source closure, separate manifest/config
digests, original full v1 runtime seal, explicit transaction/approval references
and exact installer/attestor signing scopes. Root must explicitly pass the exact
approved mandate hash. An input mismatch or omitted approval hash is rejected
before a signing key is read. No mandate is manufactured by this helper; its
author must independently accept publisher/dependency evidence and the complete
frame. A successful image-equivalence report alone is insufficient.

The helper uses only the installed keys through ExistingEd25519Signer. It preserves
a durable ISSUING claim before signing, publishes signatures before records,
verifies issued signatures and denies replay. Four bounded records are emitted;
actual live-generation attestation and final approval still belong to the existing
node/broker producers at admission. No key is generated, target runtime changed,
lease granted or application started. The helper is not yet wired to an operator
bootstrap or tested on the private target inputs. Its real signing/consumer test
uses disposable CI keys and confers no target authority.


Hosted run 37831986938: 17/18 authentication tests passed; sealed-loader acceptance correctly denied PRIVATE_INTAKE_HASH_DRIFT. Local materialization had appended one trailing newline to 32 pre-existing repository files. Restored exact repository bytes and canonical closure hashes; all 29 runtime hashes agree with cohort-draft/sources.json. Production hash checks unchanged. Eighteen local tests pass after correction. This is CI/source diagnosis, not target observation.
