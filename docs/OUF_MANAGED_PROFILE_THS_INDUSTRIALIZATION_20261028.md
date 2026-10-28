# THS recovery: persistent installation contract and IAM binding verification

The managed-file recovery surface has three distinct gates: the OAuth request in the installed owner, IAM client-scope bindings/eligibility, and the scopes in a newly emitted browser token. A published OUF authorization policy does not substitute for these gates.

## Reusable production path

1. The owner catalogue `managed-profile-ths-oauth-request-v1.json` declares the recovery contract (Onboarding a9c8310d284a118787fff63b700b964a2fe3027e). Capability identities are protocol contracts; domains, client IDs, transport endpoints and placement remain explicit installation inputs.
2. `tools/managed_profile_ths_scopes/client.py` resolves the actual literal registration/provider from a previously classified and sealed owner overlay, with higher-priority JSON applied. It does not equate registrationId with clientId or expose other properties.
3. `bindings.py` verifies scope definition UUIDs, default/optional assignments, inclusion in the token and role-scope restrictions. Keycloak26 assignment responses contain only ID/name; definition attributes come from the separately read full definition of that UUID. Missing, restricted or ambiguous proof blocks profile compilation.
4. `contract.py` and `configuration_profile` preserve every existing requested scope and unrelated property, and propose only the missing request scopes on the same image. The private output carries installation/client/issuer/current-owner/hash bindings and requires a new execution review and fresh runtime/job fences.
5. The existing native installation verifier `tools/source_revision_update/configuration.py:verify`, sealed into owner-update preflights, now rejects a JAR containing `ManagedProfileRecoveryThs.class` unless its explicit JSON request includes preview, file.profile and quarantine.release exactly once. Legacy artifacts without that surface retain their own contract. This gate does not silently patch or authorize effects.
6. After actual installation and IAM verification, normal USER authentication and a fresh native card must prove effective scopes and exact-job access. E2E continues through original/hash/parser/preview, human decisions and UDP.

The installation guard closes the missing-request regression for future owner updates using this verifier. It is not proof that all independent bootstrap/deployment paths use it. A separate reviewed configuration update must still install the corrected request on the current owner. No merge or release acceptance is implied by a draft PR.

## Resilience and custody

The API reader accepts only the selected IAM namespace and fixed read operations. Its sole POST is one separately consented administrative password grant. Protected provider identity must be verified before client metadata reads. No CLI credential cache, automatic login, refresh or IAM mutation is allowed.

One new operation has an exclusive root journal. Authentication and GET attempts are reserved with fsync before dispatch. GET retries require explicit transient transport/429/502/503/504 classification, same stage/token/deadline, 5/15seconds with up to20% jitter, maximum3 attempts/stage and4 global retry reservations. Retry-After is respected within the original deadline/token margin. Permanent/unknown errors and ambiguous authentication stop; they do not open another budget. Reinitializing the ledger or rerunning the consumed scope is denied.

Limits:2 metadata,5 Engine GET,1 administrative authentication,16 normal Admin GET/20 maximum including retries,24MiB. Review/password each have90second TTY input limits; maximum210seconds after consent, narrowed to at most120seconds after password, never extended. Total invocation600seconds. These finite diagnostic limits reflect the short administrative token; they do not relax the distinct production >930second authority guard.

The password and freshly returned access/ID material stay in process memory and bounded pipes; returned refresh material is dropped in the child. No token/password or their hashes enter argv, environment or journals. Current IAM Engine observations are persisted as binding hashes, without copying its environment. Existing Onboarding environment may contain retained installation credentials and is necessary in the private conditional profile; it remains root0600 and is never public. Do not claim that every private installation artifact is secret-free.

Consumed predecessors and their counts/files remain unchanged. Runtime update authority, profiling budget and resume remain separate from this administrative read.

## Qualification boundaries

Pure contract tests cover two installation parameter sets with distinct clients/issuers/images/mounts and exact property preservation. Native package tests exercise the actual verifier definitions sealed by owner update Context against temporary ZIP package contracts; they are not a Java application E2E test.

The physical qualifier uses disposable Docker, real process roots/mounts/network namespace, actual Keycloak26.2.5 and a controlling PTY, with fixture-only consent and credentials. It verifies protected identity, read-only IAM configuration before/after, no credential persistence and replay denial. Immutable source/wrapper delivery has its own nonroot/sudo/root400/private600 qualification.

None of these tests proves the current VPS binding state, a fresh application browser token, two real external MCP clients or full M2 acceptance.

Primary sources consulted: [Keycloak26.2.5 ClientResource](https://github.com/keycloak/keycloak/blob/26.2.5/services/src/main/java/org/keycloak/services/resources/admin/ClientResource.java), [ClientScopeModel](https://github.com/keycloak/keycloak/blob/26.2.5/server-spi/src/main/java/org/keycloak/models/ClientScopeModel.java), [client scopes guide](https://www.keycloak.org/docs/latest/server_admin/#_client_scopes). Exact helper reuse: the separately qualified21October explicit API terminal/access-identity functions at3b205c44e983184e90baf31230b7f5ec1affb6b7; no historical main/session is invoked.
