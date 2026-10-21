> **Aggiornamento corrente:** preparazione target riuscita (R12 refresh120 e TTL16s); CSV Teatri esplicitamente autorizzato e profilo letto (13 righe/20 colonne). Il comando di input qui sotto è storico e completato. Usare la [continuazione Teatri e nuovo piano privato di creazione](TEATRI_CURRENT_EXECUTION_20261011.md). [Receipt input](../evidence/semantic-r12-cutover-inputs-target-20261011.json). Nessun nuovo apply applicativo o CSV end-to-end dichiarato.

# CSV end-to-end: continuation after active R12 — 11 October 2026

[Platform resilience policy v3](../docs/OUF_RESILIENCE_POLICY.md) and the attached Reality Baseline v1.7 apply. The operator-confirmed [R12 receipt](../evidence/resilient-r12-active-target-20261011.json) establishes existing two-flow lease readiness at activation; application readiness and CSV acceptance remain open.

## Concrete progress and observations

The old protected Semantic input preparation required the consumed failed R10 worker to be active. Replaying it cannot progress after R12. A distinct [post-R12 compiler](../scripts/prepare-semantic-inputs-after-r12.py) now validates the exact R12 snapshot, source hashes, authorization capsule, consumed claim, invocation, preclaim proof, current boot and running service/worker before reusing the qualified application-frame and private input checks. The retired R10 reader is byte-verified and used only as an existing read-only native inventory implementation; no retired worker must become active.

It verifies fresh native two-flow membership and positive TTL, current reciprocal Semantic peer, unchanged full application creation frame and the three retained role input files. It creates a NEW private snapshot and a readonly UID10001 database-password file projection, removes the password from the proposed candidate environment, and declares restart=no. It does not mount files, import images, change applications/firewall/database, sign, grant, renew leases or reset recovery state. Credential/key material is read only in memory for custody checks and is not printed. Preparation is not cutover authority or apply readiness.

[Qualified delivery](semantic-r12-cutover-inputs-20261011.sh), source `1dcf79829e2f051dcaf10f4bafed003e1d3d8afe`, delivery `32a5143cace5cf166b3a7a48e02ec60c7b3f9bb6`. [CI38146862484](https://github.com/GioNob/ouf-deploy/actions/runs/38146862484), job114491948561 SUCCESS: 19 ordinary tests plus the actual hosted-root UID10001 POSIX test; four download/tamper positions, root in-memory rehash, retained portable gh without gh in PATH, and sudo failure propagation through tee. These tests qualify boundaries, not full target R12/native/application execution. [Evidence](../evidence/csv-continuation-after-r12-20261011.json).

Current authenticated OUF reads through the retained giovanni-chatgpt connection:
- MCP HEALTHY, actionRequired=false, partial=false (MCP scope only).
- Semantic CLASS searches for teatro and cinema return empty; this does not prove the historical published references are absent.
- Ingestion status is authorization-denied; do not infer ingestion health or bypass with another account.
- Existing canonical Cinema search returns two pages of three ACTIVE objects each. Third page is refused with non-retryable ORCHESTRATION_BUDGET_EXHAUSTED. Pagination is INCOMPLETE; historical eight-object evidence is not reattested by this read. No budget reset, alternative account or automatic retry was used.
- Automatic approval review rejected the historical Teatri asset preview because the current request does not explicitly identify/authorize that private file. No file bytes/profile were acquired. Request explicit confirmation before using that asset; do not access it through an alternate path.

## Historical input-preparation command — completed by operator

The protected files require operator sudo; previous runner evidence showed password-required before execution. No sudo permission expansion or credential collection is proposed. The old R10 preparation command remains suspended. Run the following distinct qualified preparation as oufadmin and return its full receipt through OUF_CURRENT_CUTOVER_INPUTS_EXIT:

```bash
(
  set -euo pipefail
  umask 077
  OUF_GH="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
  if [ ! -x "$OUF_GH" ]; then OUF_GH="$(command -v gh || true)"; fi
  if [ -z "$OUF_GH" ] || [ ! -x "$OUF_GH" ]; then echo "OUF_EXISTING_GITHUB_CLIENT_REQUIRED" >&2; exit 1; fi
  OUF_LAUNCH="$(mktemp "$HOME/ouf-semantic-r12-inputs-launch.XXXXXXXX")"
  "$OUF_GH" api -H 'Accept: application/vnd.github.raw' 'repos/GioNob/ouf-deploy/contents/releases/semantic-r12-cutover-inputs-20261011.sh?ref=32a5143cace5cf166b3a7a48e02ec60c7b3f9bb6' > "$OUF_LAUNCH"
  printf '%s  %s\n' '3f7b9b2d26e5e43d1f0e0efde26b3ab13ed0d0aaebf240a885211032ab60e662' "$OUF_LAUNCH" | sha256sum -c -
  /usr/bin/bash "$OUF_LAUNCH"
)
```

Expected successful preparation: CURRENT_INPUTS_AND_FILE_SECRET_DECLARED_NOT_APPLY_READY, exit0. A BLOCKED receipt is not readiness. Do not rerun R10/R11/R12 activation. The R12 startup window does not invalidate a running generation-bound worker by itself; this preparation still rechecks live boot/service/claims/scope.

## Observable acceptance for the new file

| Step | Evidence required |
|---|---|
| Exact file | User identifies the authorized existing managed asset, or selects a new CSV through the governed picker. Preserve existing upload/profile; no unnecessary reupload. |
| Profile | Bounded format/row/column profile from Onboarding, asset ownership and version pinned. |
| Semantics and mapping | Exact published class/property revisions, explicit gaps and provenance; DRAFT may be proposed by MCP, required HUMAN adoption/publication/activation goes through THS to the owner. |
| Ingestion | Same approved configuration bundle, ingestionRunId and source identity; finite persisted retries/quarantine, no scheduler budget reset. |
| UDP materialization | Durable owner ACK, expected object/revision counts and lineage, justified duplicate/merge decisions rather than shared-address equivalence. |
| Authorized search | Complete bounded pagination and comparison with input/ACK counts; negative scope/property tests and explicit partial/budget failures. |
| Recovery | Replay/idempotency and transient pause/fresh recovery evidence, preserving checkpoints and incident identity. |

Remaining application gates include current private custody, exact qualified artifacts, complete new OCI/reciprocal peer and coordinated transport closure, writer fence/fresh backup/migration-aware recovery, host/resource admission, IAM/owner readiness and governed semantic decisions. The existing Cinema results remain acquired and are preserved. Teatri discovery and full application rollout are not silently treated as prerequisites already complete. No new CSV end-to-end, clean-host installation or whole-platform acceptance is claimed.

PET references: Onboarding/THS1.6 INTERNAL_MANAGED and human-only activation; Semantic1.3 published reference/approval ownership; Ingestion1.3 durable ACK, checkpoints and recovery; UDP1.3 canonical identity/materialization and authorized serving; Authorization1.5 and Gateway1.5 channel-neutral owner enforcement. See [file-first checkpoint](FILE_FIRST_EXECUTION_CHECKPOINT_20261010.md).
