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

At most13 Docker writes: disconnect/connect each of six existing backend endpoints, then start the exact retained UDP once. Same container IDs, images, configurations, mount/data references, process PIDs/start times, endpoint MACs and aliases are preserved for the six live services. APISIX's independent control-network endpoint is unchanged. No container replacement/removal, daemon restart, database migration, source publication, identity decision, job API or explicit historical retry is implemented. Ordinary workers may resume when UDP starts.

This creates brief network interruptions, including PostgreSQL, IAM and ingress requests. Application retry/transaction/dedup contracts remain responsible for outstanding work; no assertion of zero affected requests is made. Application/provider readiness and the whole CSV E2E are not established by a successful endpoint readback.

Before effects, the root bootstrap verifies original native boot sources/profiles and quiesced journals, holds the existing common lock without sleeping, verifies the immutable c23 prepared snapshot and unchanged application configuration, freezes a new current-generation private plan, inspects affected consumer bindings/configurations, and rejects literal dependencies on either moving service. Read-only configuration files retain their approved owner UID constraints; no values/credentials are changed. Native provider authority stays quiesced. No old authority or consumed action is reused.

Each write is claimed in a persistent root-private incident before dispatch. A lost response is reconciled against exact endpoint/process/configuration readback; proven completed effects advance without resending the write. Unproven effects, integrity drift, permanent errors or unknown failures stop. The incident pointer blocks another launch and retains all claims. No automatic rollback or budget reset is allowed. The full finite action is capped at300 seconds, including reads and calls. No shared lock is held during retry sleeps; this procedure has no sleep-based retry loop.

The fixed addresses prevent competing allocations among the current retained approved backend fleet on daemon restart. They do not authorize unmanaged new containers or prove global IPAM admission/HA. Existing native APISIX replacement code explicitly rejects retained static endpoints; a future APISIX replacement must qualify preservation under its native reviewed endpoint contract before proceeding. Do not remove that guard merely to pass a rollout.

## Qualification / remaining boundary

Candidate implementation is being qualified with real private journals and an isolated official Docker29.8.1 daemon on GitHub-hosted runners. Tests use synthetic HTTP services and do not stand in for actual APISIX, MinIO, PostgreSQL transaction recovery or target application acceptance. No corrective target operation has run. Only after the complete qualification succeeds should an immutable one-command host-administrator delivery be used. Existing repository/MCP authorization is already granted; the interactive sudo password is the remaining protected host execution boundary.
