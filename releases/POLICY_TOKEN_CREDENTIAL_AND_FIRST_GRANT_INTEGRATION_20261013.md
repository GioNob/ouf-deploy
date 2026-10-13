# New credential and first controlled grant — integration state

The target migration host receipt `93fa9bc8fe4d90fe445bb310363f11966f9ed89df74d169ad925cda0a157acc4` remains the historical input. Its ABSENT directory observation has been superseded by the [successful root-custody receipt](../evidence/policy-token-root-custody-target-20261013.json): three roots are CUSTODIED/0700. Do not repeat root creation or prior host/consumer observations. The latest reported legacy service state was inactive with its timer active/enabled; this development has made no target service change.

## Implemented path

1. `legacy_retirement.py` requires current explicit native HUMAN/dual-role authority, exact host/executable/boot bindings and one durable reservation before masking/stopping the selected units. Ambiguous or partial outcomes cannot replay the command.
2. `credential_reestablishment.py` accepts a direct new issuer-generated secret only when authenticated readback agrees, it differs from the previous owner-read secret, and the confidential SERVICE registration remains unchanged except for the secret and a valid creation timestamp. Known rotation/overlap attributes require separate review. It never copies the weak legacy secret file.
3. `credential_transaction.py` requires durable governed legacy retirement, current unit quiescence, a previously prepared root:root0700 destination with bound device/inode, matching docker executable, and a separate signed credential scope. It durably consumes one IAM mutation attempt before `kcadm create clients/<selected-uuid>/client-secret -o`. The new secret is published exclusively as root:root0400, single-link, without replacing any existing file. The complete operation is bounded to90seconds and each CLI call to15seconds; stdout is an anonymous private file with an RLIMIT_FSIZE bound. No credential/token output enters public diagnostics. Crash, timeout, mismatched readback or failed publication leaves the reservation; subsequent invocations do not automatically adopt a later secret or repeat the regeneration.
4. `first_controlled_grant.py` composes the concrete governed credential receipt, first-gap session, TLS peer/CA/hostname binding, online issuer admission and protected token publication. The separate signed grant scope binds the client/profile, source closure, credential operation, trust set and output directory identity. It consumes the sole first-session slot before the grant. It performs actual online introspection before publication and again at the publication guard. A pre-existing output is not replaced by this first migration. The result is `TOKEN_PUBLISHED_NOT_RUNTIME_ACCEPTED`, never a periodic-worker activation or a traffic lease. Historical totals remain null/UNKNOWN and the historical gap remains OPEN.
5. `migration_runtime.py` closes all29 component/dependency modules (28 at the first qualified checkpoint below), loader bytes and source commit. `-I -B -S` import happens from verified memory, with no disk-source fallback; missing, extra, foreign, tampered and preloaded namespaces deny. Loading components creates no roots, session, credential, signature or grant.

## Native protocol evidence and limits

The exact retained Keycloak repository digest is used in disposable hosted CI. Dedicated secret regeneration and authenticated readback preserve the client registration; the old credential is rejected, and the new credential supports a real grant/introspection. The exact administrative CLI `create .../client-secret -o` is exercised. These fixtures do not establish target client policy, target running bytecode, target credential custody, or production authorization.

Local credential guards and transaction tests pass with native signatures, private persistence and actual fork/crash. The local namespace cannot assign GID10001 (`EINVAL`), so actual protected token publication is qualified on the hosted root runner; the group requirement is not weakened or skipped. The composed first-grant tests use real TLS and native crypto with a synthetic issuer and HUMAN. The separate actual-Keycloak test proves protocol behavior; it is not claimed to be an end-to-end execution of the entire migration installer.

Dedicated endpoint source reviewed: Keycloak26.7.4 `services/src/main/java/org/keycloak/services/resources/admin/ClientResource.java`, `services/src/main/java/org/keycloak/protocol/oidc/OIDCClientSecretConfigWrapper.java`, and `server-spi-private/src/main/java/org/keycloak/models/ClientSecretConstants.java`. Generic client PUT is not selected because its update path also processes unrelated client configuration. Client policies may retain rotated secrets; no target policy is inferred from the default fixture. Changing a client secret is not evidence that all previously issued bearer tokens have been revoked, nor does it reconstruct historical accounting.

## Still required before target credential or service effects

The full installer must bind current selected IAM baseline (including the already-applied audience mapper), prove the credential policy/consumer scope and current TLS/generation, prepare the separately scoped output, integrate the executing source closure with the existing signer and exact fresh HUMAN execution review, and provide durable phase reconciliation and worker installation. Root creation/signing/delivery is completed. `completed_roots()` now reads the completed ledger and current directory identities without renewing its old creation window; `from_completed_custody()` binds those identities to the existing migration. This still is not an installable replacement. Do not start the old worker on an empty/zero history journal.

The17:05:55 design approval remains recorded and is not requested again. It does not authorize a production credential rotation, service mutation, new budget or grant. The later root-only execution produced two signatures and six directory creations under its own consumed HUMAN claim. That authority cannot be reused for migration. The final execution package must be complete and reviewable before asking for its execution approval.

## Qualified source checkpoint

Source commit `1775975d9d5577175692a981b1c4dccba6bd5d89` passed hosted run38433049140, job115419906102: **203 tests, zero skipped**, plus the actual disposable Keycloak protocol check. [Structured qualification receipt](../evidence/policy-token-credential-first-grant-components-qualified-20261013.json) pins the four new module hashes and records the actual protocol flags and remaining installer gates. This includes the exact CLI route, safe diagnostics, guard-duration budget enforcement, weaker prior-credential comparison without weakening new-secret validation, first-grant consumption/publication and the28-module memory loader. It does not authorize execution on the VPS.

## Minimal composed execution path

`FirstControlledGrant.migrate()` composes existing retirement, credential and
first-grant operations, without another journal, retry scheduler or service.
It checks all four signed scopes, an unconsumed/current retained session and
prepared empty output before changing units or IAM. A completed credential
transaction is reused only through the existing custody/hash guards. Ambiguous
credential outcomes and consumed grants stop before service/IAM/issuer calls.
Failures retain the existing evidence names and expose a safe phase/reason.

The caller must still provide the independently reviewed current client policy,
consumer scope, prepared directories, TLS bindings and execution authority.
Keycloak 26.7.4 `ClientPoliciesResource` requires the explicit
`include-global-policies=true` query to include global policies; client metadata
alone cannot establish that secret-rotation policies are absent. The retained
target observation `3aef37971d405e0a84c60e0e110f7ababdba8e5c62cbda815e44e9ea5077d060`
already includes global policy metadata and reports zero realm/global policies.
It remains an observation rather than runtime applicability or consumer proof;
any required current comparison belongs in the complete execution flow.
