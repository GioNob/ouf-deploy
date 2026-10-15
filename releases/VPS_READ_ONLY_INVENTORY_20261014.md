# Current operator step

The next read-only action is [inventory v2](VPS_READ_ONLY_INVENTORY_V2_20261014.md),
qualified at source `8dd4c06b26c2c3a0e0545e8f733b8d58a20275de`.
The v1 operator report is archived at commit `a3a7c8bfab7711d05a0b668e362e093c559c771b`;
the assessment is in `VPS_INVENTORY_ASSESSMENT_20261014.md`. Do not rerun the
cohort delivery until the stable CLI/API comparison and remaining coverage are reconciled.
The following section records the original v1 collector and its limits.

# VPS inventory: exact qualified operator action, 14 October 2026

This is resource-read-only diagnostic collection, not a rollout.
The six application pins, package, PR29 and its executable source are unchanged.
The supplementary source is commit `671cbef1f16fec195f8b0095efdf561479a117ed`.
Collector SHA256: `7e61c2477b82411ba7cc97a4b9f5ee1556ad8453d537c51e8abb3c221fa4ec8a`.

[Run38638294650](https://github.com/GioNob/ouf-deploy/actions/runs/38638294650),
job116107009766: PASS; 16 redaction/comparison/aggregation tests and one
actual Docker/PostgreSQL test of five history reads. Native test ran, unskipped,
and preserved fixture rows and roles. This does not prove execution on the VPS.

The single command in `vps-read-only-inventory-20261014.sh` downloads the exact
collector using the existing authenticated portable gh, verifies its hash, invokes
isolated root Python once, and retains the redacted JSON under a new private
operator directory. It neither downloads/extracts the 1.7GB package nor changes
application resources. Temporary/audit files and native read processes are
expected; no image import, restart, migration, grant, application approval, budget
reset or mutative replay occurs.

Coverage: all OUF containers/images/networks, exact selected historical Registry
inputs and all eight binding differences, mounted configuration key names/hashes,
five database histories, administration metadata, runc state, cached-session
Keycloak catalogue/scopes, live APISIX routes, active policy projection, existing
Teatri asset/profile, and retained recovery history. Independent failures are
collected together. Limits: 240seconds and128 native calls, short read-only DB
transactions, no automatic retry. kcadm GET can refresh the existing administrative
session; there is no interactive IAM login and no client-secret API.

Current-authority ledger selection and fresh conversational MCP read are explicit
gaps. Other missing/unsupported/denied observations remain UNAVAILABLE rather
than PASS. `completeEnvironmentInventory=false` is intentional until the remaining
coverage is reconciled. The old configuration is never silently replaced with
current observations, and hashes/readiness are never E2E acceptance.

After the operator returns the inventory, classify every difference and unavailable
area against baselinev1 before changing code or reattempting rollout. Preserve
the archived report and the original historical evidence. Do not paste passwords,
bearers, raw environment, or APISIX plugin configuration.
