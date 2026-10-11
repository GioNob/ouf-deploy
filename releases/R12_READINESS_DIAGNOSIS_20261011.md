# R12 readiness and retained budget diagnosis — 11 October 2026

The operator's native V11 preparation stopped at CURRENT_R12_PRIVATE_WORKER_UNPROVEN in CURRENT_R12_APPLICATION_AND_INPUT_CUSTODY. No private plan was published and all protected writes, image imports and application effects were zero. [Blocked receipt](../evidence/native-v11-plan-worker-blocked-target-20261011.json).

A direct, unprivileged read from the VPS runner at20:48:08 UTC confirms the original R12 service is active/running, MainPID2446150, Restart=no and NRestarts=0. [Native service receipt](../evidence/r12-public-service-current-20261011.json), [runner execution](https://github.com/GioNob/ouf-deploy/actions/runs/38173718656). This does not establish readiness, valid leases, or the protected reason. The existing nine-predicate readiness check remains unchanged; paused workers are never promoted to ready.

The root diagnostic reads worker-status.json, optional worker-denial.json and the existing retry/recovery.json, authenticates the retained capsule hash9730f8006a4257cbd2bf7576e6d0e49e41258360e0ca367f3e37852d57826e2b and all15 retained R12 program hashes before and after reading. It compares current boot/invocation/service bindings, projects safe state/reason/error codes and finite budget counters, and attempts native readonly lease collection using the retained sealed reader. Native lease collection failure is reported separately so the protected worker reason is still observable.

Worker and journal may change during diagnosis: before/after values and change flags are evidence only, not atomic transition authority. The startup authorization deadline is explicitly distinguished from worker lifetime. No journal initialization/write, claim creation, restart, import, DNS/provider call, firewall change or budget reset is performed. Only launcher downloads and result files in the operator's fresh home directory are written. This diagnostic grants no recovery, cutover or release acceptance authority.

## Qualified delivery

Source commit de3ca98607a933a1dc68b6a9b3be09978c88f21c; program SHA256 a9d8bfcf5b3d5592835fb6cff89ecaeb06d87c11990cb7cb3b38321208225556.
Launcher commit b7d9710b6decdb2284dffe85dc546390582ee8c5; SHA256 afc17132c3a88bfdc1be8560347a60047da9e996534bd993bbe842d92c9726a5.
Three immutable source files are hashed before sudo and again before any root execution; both module hashes are checked before module execution.

[CI run38174333532](https://github.com/GioNob/ouf-deploy/actions/runs/38174333532), job114573369985: SUCCESS,12 diagnosis/delivery tests and9 existing R12 custody tests. Tests exercise paused/exhausted/reconcile/failed states, secret suppression, finite numeric bounds, complete module closure, every download/hash failure before sudo, every root-bootstrap tamper position, portable client fallback and exit propagation. CI is qualification evidence, not an execution of the protected VPS diagnostic.

## Operator read

Root access from the runner is unavailable. Execute this exact sealed readonly operation as oufadmin on the VPS, then return only OUF_R12_READINESS_DIAGNOSIS and OUF_R12_READINESS_DIAGNOSIS_LAUNCHER_EXIT lines.

```bash
(
  set -euo pipefail
  umask 077
  OUF_GH="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
  if [ ! -x "$OUF_GH" ]; then OUF_GH="$(command -v gh)"; fi
  OUF_LAUNCH="$(mktemp "$HOME/ouf-r12-diagnosis-launch.XXXXXXXX")"
  "$OUF_GH" api -H 'Accept: application/vnd.github.raw' 'repos/GioNob/ouf-deploy/contents/releases/r12-readiness-diagnosis-20261011.sh?ref=b7d9710b6decdb2284dffe85dc546390582ee8c5' > "$OUF_LAUNCH"
  printf '%s  %s\n' 'afc17132c3a88bfdc1be8560347a60047da9e996534bd993bbe842d92c9726a5' "$OUF_LAUNCH" | sha256sum -c -
  bash "$OUF_LAUNCH"
)
```

Do not replay R10/R11/R12 apply, the consumed image import, or the native private-plan preparation to hide this failure. Decide any recovery from the current retained reason, cumulative budget and governed finite authority. The semantic V11 deployment and CSV Teatri→ACK→search acceptance remain OPEN.
