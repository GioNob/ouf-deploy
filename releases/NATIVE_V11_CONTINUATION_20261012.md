# Current V11 cutover continuation — 12 October 2026

The operator's policy preflight is successful. Development continued with seven native core phase adapters rather than treating CI success as target completion. The target remains on old Semantic f652…, with no deployment/migration/lease mutation by this work.

## Completed composition and current evidence

ProducerAdapter binds exact reviewed generations and complete initial host/network hashes; the intent explicitly authorizes only restartPolicy no. Legacy unless-stopped is disabled before stop. Update/stop or multi-producer partial outcomes remain IN_FLIGHT, without retransmission. EndpointAdapter consumes journal-bound initial network evidence and the stopped generation; it supports both explicit static and observed dynamic legacy addresses, preserves the old container/network and blocks foreign IP/MAC ownership. Replacement creation remains tied to its exact request; pause/release consume private prior native payloads and preserve generation.

MigrationAdmissionAdapter connects actual fenced-backup evidence to the same database container/OID/user and exact still-paused workload. Executor durably marks databaseMayHaveChanged before ALTER DATABASE admission. Reconciliation never repeats admission and blocks foreign sessions, changed database or changed/unpaused generation. No restore/automatic reopen is implemented. [Qualification](../evidence/native-v11-migration-admission-qualified-20261012.json), [CI38207193350](https://github.com/GioNob/ouf-deploy/actions/runs/38207193350):3 boundary and2 actual PostgreSQL/paused-process integration tests.

[Dynamic/static endpoint qualification](../evidence/native-v11-endpoint-executor-qualified-20261012.json), [CI38210242728](https://github.com/GioNob/ouf-deploy/actions/runs/38210242728):3 boundary and3 native bridge/controller-death tests. Inventoried producer quiescence, independent scope preservation and the legacy restart-policy gap are qualified separately. Fixtures' authority, lease/attestation/transport and target inventory are synthetic; no complete target-installer claim is made.

CoreAdapterFactory binds all seven actual core adapters and rejects missing owner phases, mismatched database/OID/user, mismatched creation/stage/release references or replacement bridge/IP/MAC. It does not turn six owner callbacks into qualified target implementations or issue any authority.

## Fresh actual VPS observations

Existing qualified self-hosted readers ran successfully, without protected snapshots, keys, domain rows or mutations. R12 unit active/running, PID2446150, no restarts and restart no; private worker status/native lease membership remain unproven by this runner surface. Original Semantic PID3789123/generation2 October and PostgreSQL CID50b36d…/OID21558 remain bound. The exact native V11 manifest image bd48… is present. All10 observed application DB sessions map to Semantic;23 relations, V1–V9 plus baseline, zero prepared transactions, large objects, foreign relations/subscriptions. Existing administrator visibility is outside the application DB with fsync/synchronous commit on; no grant/fence is issued.

The refreshed host projection confirms two important retained-host differences: old Semantic restart policy unless-stopped, and configuredIpamIpv4 null (observed dynamic address172.18.0.6/MACb2:96:a1:e2:c1:8d). The new adapters explicitly handle those facts. [Initial complete target read receipt](../evidence/current-v11-cutover-host-target-20261012.json), [latest host observation](../evidence/current-v11-host-binding-refresh-20261012.json). Generation rereads are observations, not runtime authority.

## Necessary protected coordination input

The runner cannot open the selected root-private coordinator configuration, R12 cumulative retry history or installed authority profile. Their actual field contracts and private path bindings are required to connect the remaining stop/revoke, OCI attestation, authenticated transport/distinct worker and final acceptance owner phases. Public service metadata cannot substitute for those contracts. No unfinished cutover approval is requested.

The completed [capture program](../scripts/capture-native-v11-coordination-inputs.py), sourcee28587cf2a68980337c8f0364aece10416d7a7c1, SHA2568bf34d1dd1239bd62c6fe6c9407820fd742191b2035a7bcfde7f89696f327b40, reads ten specifically selected inputs: original9ec review manifest, existing7fb authority profile, exact656 coordinator, retained HUMAN/execution context, exact973 R12 authorization/consumed claim/invocation/status/cumulative history. It verifies all15 retained program hashes, current boot/context and stable rereads. It never follows key paths, executes configuration/code from inputs or invokes native commands, services, Docker, SQL, DNS/provider/nft. Private scalar values stay hidden; only bounded field/type contract shapes, hashes/counters/PID are projected.

Copies are atomically published root-private with the existing no-replace primitive: ten input copies plus manifest, at most11 protected writes, no overwrite. Historical HUMAN records, declarations and observation copies are not reused as current runtime authority. R12 files/journal/claims/budgets are untouched; no reset, new recovery authority, signature or activation claim. Partial writes/publication ambiguity retain private evidence and honest attempted/confirmed counts. If inputs change, the observation is unproven and no runtime progression occurs.

[Launcher](native-v11-coordination-inputs-20261012.sh), sourcea5b2b209abee548c0de514adc2cf9dcc80c24ff2, SHA2569dcaa61a1d505b1018072b04aaf37b854f040b7edfb514b5e6f3efe82f6dfbf4: all four downloaded source hashes precede sudo, and root verifies them again before executing any source. The existing portable gh client is preferred. [CI38211080512](https://github.com/GioNob/ouf-deploy/actions/runs/38211080512), job114685157076 SUCCESS:3 core consistency tests,4 delivery tests covering each download/hash failure and root tamper,4 actual private POSIX/root-custody entry tests including key non-read, safe projection, context/history drift and partial-write accounting. [Receipt](../evidence/native-v11-coordination-capture-qualified-20261012.json).

```bash
(
  set -euo pipefail
  umask 077
  OUF_GH="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
  if [ ! -x "$OUF_GH" ]; then OUF_GH="$(command -v gh)"; fi
  OUF_LAUNCH="$(mktemp "$HOME/ouf-v11-coordination-launch.XXXXXXXX")"
  "$OUF_GH" api -H 'Accept: application/vnd.github.raw' 'repos/GioNob/ouf-deploy/contents/releases/native-v11-coordination-inputs-20261012.sh?ref=a5b2b209abee548c0de514adc2cf9dcc80c24ff2' > "$OUF_LAUNCH"
  printf '%s  %s\n' '9dcaa61a1d505b1018072b04aaf37b854f040b7edfb514b5e6f3efe82f6dfbf4' "$OUF_LAUNCH" | sha256sum -c -
  bash "$OUF_LAUNCH"
)
```

Return only OUF_NATIVE_V11_COORDINATION_INPUTS and OUF_NATIVE_V11_COORDINATION_INPUTS_LAUNCHER_EXIT. This is a concrete protected input capture, not runtime approval or apply. CSV→ACK→object search and the complete sealed target installer remain OPEN.
