## Protected target comparison COMPLETE — one retained DNS representation difference

Technical8/8; functional4/6. The operator diagnostic completed with zero writes/mutations and no incident pointer. In legacy API1.44 all3 apps retain exactly the same Id/Image/Name/Config/Mounts; only HostConfig.Dns differs (old null, current list). The list contents/length were not printed, so empty is NOT yet assumed. Current-server inspect additionally omits deprecated Config.MacAddress; the corrective owner continues using1.44 and does not waive this field. Native provider is confirmed BLOCKED with empty kernel sets, revoked authority, reconciliation still required and start disallowed.

A narrow preboot-only profile is being qualified: explicit HostConfig.Dns null to an actually empty list, with all other immutable fields strict. Nonempty lists, missing keys, other types and all unrelated differences remain rejected. Neither original c23 inputs nor live DNS configuration is rewritten; the correction plan freezes the actual current bytes after this proof. Post-plan runtime comparison remains exact. The existing finite host scope, pointer,13write/300second budget and no-provider-start rule are unchanged.

Docker's native InitDNSHostConfig initializes nil DNS arrays on metadata load; primary-source context: https://github.com/moby/moby/blob/v28.5.1/container/container.go#L222-L245 and #L560-L581. This source is not presented as the current daemon version; a new isolated Docker29.8.1 cold-load fixture will verify the actual supported runtime before delivery. The failed v29.8.1 GitHub source URL was not treated as evidence.

## Previous checkpoint and history

## Current checkpoint — protected application comparison qualified; target read pending

Technical **8/8**, functional **4/6**. The operator's second STOP, PREBOOT_APPLICATION_CONFIGURATION_CHANGED, occurred after the native provider proof passed but before creating a plan/incident or changing any endpoint/container. [Exact boundary](../evidence/host-network-application-comparison-stop-20261018.json). The former corrective launcher is retired; it must not be rerun.

The cause of the application mismatch is **not yet observed**: the STOP did not print the failing role or changed fields. No change is normalized or accepted as harmless. A single bounded diagnostic is now fully prepared: source [5091b02579123ba1232b53bb1debecfb5133679e](https://github.com/GioNob/ouf-deploy/commit/5091b02579123ba1232b53bb1debecfb5133679e), immutable delivery [4eb0ea7f2c5afaaf3a3e15034b362d1a91806eac](https://github.com/GioNob/ouf-deploy/commit/4eb0ea7f2c5afaaf3a3e15034b362d1a91806eac). [CI39151634206](https://github.com/GioNob/ouf-deploy/actions/runs/39151634206) passes **10 tests**, including redaction, exact boolean/integer distinction, mount-order classification, stable reads of all three roles, existing-incident fencing, all9 payload hashes, shell/Python syntax, rejected corrupt/nonisolated payloads and isolated-root fail-before-effect probes. [Qualification receipt](../evidence/preboot-application-difference-qualified-20261018.json).

The diagnostic reuses the sealed native empty-provider proof and original c23 prepared inputs. It compares UDP, MCP and Onboarding against both current legacy1.44 and current-server Docker projections; emits only standard field paths/types and equality/order classifications; checks all3 configurations remain stable after9 container reads. Installation-controlled keys, environment values, paths, labels and credentials are not copied into output. No baseline adoption, journal mutation, incident creation, Docker write, source publication, migration, provider/application start or job retry occurs. Maximum120seconds; original lock held only for bounded reads, no retry sleeps.

**Target diagnostic execution is pending.** The protected credential-bearing c23 reference cannot be read through the chat/runner's available administrative surface, so one existing physical sudo read is necessary. No new repository/MCP permission or OUF login is required. Local operator artifact: outputs/OUF_Diagnosi_Configurazioni_Preboot_VPS.txt. Launcher SHA256 c86b306703e0e38cc3bb345f9be2dd922ed607efc8f1e52238559d9dafa68ca9. The direct MCP status is HEALTHY for module MCP only; platform readiness and stages5/6 remain unproven.

## Historical record before diagnostic qualification

## Target STOP at sealed application comparison — no host writes

Technical8/8; functional4/6. Operator execution of delivery2c597b8c passed the strengthened native provider gate, then stopped with PREBOOT_APPLICATION_CONFIGURATION_CHANGED at bootstrap run line107. The exact delivered flow reaches this comparison after acquiring the common lock and constructing the read-only Engine, but before configuration scanning, plan/context/incident creation or any Engine write. The first provider diagnosis is resolved; no host network mutation or UDP start was reached. The current launcher is retired pending evidence, not replayed.

The failing role and changed fields were not printed, so neither configuration corruption nor a harmless Docker projection/order change is asserted. A single protected read of all3 applications is being qualified: immutable preboot c23 reference versus both current legacy1.44 and server-native inspect, field/type differences only, array order classification, final configuration stability check, original native empty-provider proof, incident absence check. No configuration values, dynamic keys, labels, credentials, new baseline, private incident or mutation are emitted/created. It preserves the old sealed inputs and never normalizes unknown differences to pass.

The chat and runner cannot read the protected credential-bearing c23 inputs through their available administrative surfaces. One physical sudo read will be required once exact immutable diagnostic delivery is qualified. No new OUF login or repository/MCP permission is required. Application readiness, source-revision release and functional stages5/6 remain pending.

## Previous qualified successor and historical record

## Current checkpoint — pre-effect STOP reconciled; successor qualified

Technical **8/8**, functional **4/6**. The previous operator execution stopped at the first provider_guard with PROVIDER_MUST_REMAIN_QUIESCED, before lock acquisition, Engine construction, private incident creation or network/container effects. [Exact reported boundary](../evidence/host-network-pre-effect-stop-20261018.json). Delivery8bed is retired, not replayed.

The original native boot coordinator intentionally leaves **BLOCKED**, with authority revoked, when restoring missing tables or encountering changed lease handles. The submitted STOP did not print the current journal state, so BLOCKED is a source-proven explanation covered by the successor, not an asserted fresh target observation. Successful Docker structural admission never grants provider restart.

Corrected source [15ccf48affe567218b66beeb6a4179e2db1f5c39](https://github.com/GioNob/ouf-deploy/commit/15ccf48affe567218b66beeb6a4179e2db1f5c39) and immutable delivery [2c597b8c8252e18f6948d2968923eb5d20fa13a6](https://github.com/GioNob/ouf-deploy/commit/2c597b8c8252e18f6948d2968923eb5d20fa13a6) pass **23 tests** in [CI39151236254](https://github.com/GioNob/ouf-deploy/actions/runs/39151236254):13 root/journal,5 native-provider regressions,4 immutable-delivery probes and1 real Docker29.8.1 integration. The provider tests execute the original pinned native boot transition to BLOCKED and its empty-set/footprint functions. Seals/custody remain checked by the existing qualified reader. The source-only intermediate run rejected the intentionally stale delivery hashes; the final bound delivery passes all checks.

The successor accepts QUIESCED or BLOCKED only with explicit false lease/start authority, original bound journals, empty per-flow lease receipts, validated paired native configurations, actual inet/bridge table membership, original empty structural footprint and empty kernel sets. It calls native read functions only: no restore/revoke/publish, journal rewrite, handle adoption or provider start. It rechecks under the original common lock before effects and after effects. Unknown/active/malformed states remain blocked.

The same installation scope and durable budget apply: six fixed endpoint declarations, at most13 Docker writes/300seconds, then one retained UDP start. The same persistent pointer prevents replay if an incident exists. Existing requests can be interrupted and workers may resume; no explicit job retry, source publication, migration, identity decision or OUF authority is issued. Native provider reconciliation and full application readiness remain pending.

**Successor target execution is pending.** One existing sudo operation is required because protected profiles and host mutations are unavailable to the chat/runner. No new repository/MCP permission or OUF login is needed. Local operator artifact: outputs/OUF_Ripresa_Rete_Provider_VPS.txt. Exact launcher SHA256: 239f290981a38ee443f25ccf435bae9e585f71d52f197f804843e3730c18993e. [Qualification receipt](../evidence/host-network-provider-successor-qualified-20261018.json). A direct MCP system-status call reports HEALTHY for module MCP only; it is not platform or CSV acceptance.

## Historical checkpoint before the reported STOP

# Postboot host network correction — explicit installation scope

Technical8/8, functional4/6. The protected preboot contract read is complete; its receipt is evidence/preboot-network-contract-target-receipt-20261018.json. The current dependency read39147714237 confirms DNS-based references to APISIX and MinIO in the observed live environment. No credential values were printed. Mounted configuration and the retained UDP configuration still require preflight checks by the corrective program.

## Concrete proposed delta

| Existing service | Current backend IPv4 | Proposed fixed backend IPv4 |
|---|---|---|
| APISIX |172.18.0.5 dynamic|172.18.0.15|
| MinIO |172.18.0.6 dynamic|172.18.0.16|
| Keycloak |172.18.0.2 dynamic|172.18.0.2|
| PostgreSQL |172.18.0.3 dynamic|172.18.0.3|
| Caddy |172.18.0.4 dynamic|172.18.0.4|
| Gateway operational owner |172.18.0.8 dynamic|172.18.0.8|

These are new explicit installation declarations, not a claim that APISIX/MinIO previously had these addresses. Destinations15/16 are outside every retained reservation found in the bounded125-container inventory; preflight rechecks all current/stopped declarations and rejects any occupancy/drift. Every current dynamic backend endpoint must be included in the exact profile. Four addresses stay unchanged; two move away from UDP5 and the retained Semantic6. The installation profile also retains Onboarding7, Ingestion10, MCP11 and southbound14. No new network/subnet/host default is invented by the generic owner.

## Effects and safeguards

At most13 Docker writes: disconnect/connect each of six existing backend endpoints, then start the exact retained UDP once. Same container IDs, images, application configuration, host configuration, mount/data references, process PIDs/start times, endpoint MACs and aliases are preserved for the six live services. Docker's legacy inspect representation can add only the exact retained primary-endpoint MAC to Config.MacAddress under the named narrow derived-metadata profile; arbitrary configuration changes remain blocked. APISIX's independent control-network endpoint and Caddy's independent public-ingress network are unchanged. No container replacement/removal, daemon restart, database migration, source publication, identity decision, job API or explicit historical retry is implemented. Ordinary workers may resume when UDP starts.

This creates brief network interruptions, including PostgreSQL, IAM and ingress requests. Application retry/transaction/dedup contracts remain responsible for outstanding work; no assertion of zero affected requests is made. Application/provider readiness and the whole CSV E2E are not established by a successful endpoint readback.

Before effects, the root bootstrap verifies original native boot sources/profiles and quiesced journals, holds the existing common lock without sleeping, verifies the immutable c23 prepared snapshot and unchanged application configuration, freezes a new current-generation private plan, inspects affected consumer bindings/configurations, and rejects literal dependencies on either moving service. Read-only configuration files retain their approved owner UID constraints; no values/credentials are changed. Native provider authority stays quiesced. No old authority or consumed action is reused.

Each write is claimed in a persistent root-private incident before dispatch. A lost response is reconciled against exact endpoint/process/configuration readback; proven completed effects advance without resending the write. Unproven effects, integrity drift, permanent errors or unknown failures stop. The incident pointer blocks another launch and retains all claims. No automatic rollback or budget reset is allowed. The full finite action is capped at300 seconds, including reads and calls. No shared lock is held during retry sleeps; this procedure has no sleep-based retry loop.

The fixed addresses prevent competing allocations among the current retained approved backend fleet on daemon restart. They do not authorize unmanaged new containers or prove global IPAM admission/HA. Existing native APISIX replacement code explicitly rejects retained static endpoints; a future APISIX replacement must qualify preservation under its native reviewed endpoint contract before proceeding. Do not remove that guard merely to pass a rollout.

## Qualification / remaining boundary

The implementation and immutable delivery are qualified by run39149585487:13 real private-journal tests,4 delivery/security probes and1 integration case using an isolated official Docker29.8.1 daemon on GitHub-hosted runners. The case includes real response-loss reconciliation, initially working public HTTP, DNS, retained data and a daemon restart; it rejects the old socket generation afterward. Tests use synthetic HTTP services and do not stand in for actual APISIX, MinIO, PostgreSQL transaction recovery or target application acceptance. No corrective target operation has run. The immutable one-command host-administrator delivery is ready; target execution remains pending. Existing repository/MCP authorization is already granted; the interactive sudo password is the remaining protected host execution boundary.
