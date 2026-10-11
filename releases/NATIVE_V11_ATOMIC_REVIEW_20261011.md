# Native V11 atomic review intake — 11 October 2026

The operator completed the corrected R12 diagnostic and native V11 private-plan preparation at the23:22:02 CEST submission. [R12 complete observation](../evidence/r12-complete-readiness-target-20261011.json): both flows LEASE_READY, one address each, native TTL17s, worker ACTIVE/RENEWED, MainPID2446150, no restart, all nine readiness predicates pass before/after,12 consumed attempts and78133.9408197403s of cumulative recovery budget remaining. This is a dated observation, not continuing readiness or transition authority.

[Prepared native plan](../evidence/native-v11-plan-prepared-target-20261011.json): /etc/ouf/deploy-snapshots/semantic-native-v11-plan-vj30camx; declarationfc94b491d05e267b49da6e2e2fe50cc7e02e7986783bad7ebf1289b0914a0a68, request59181588fd8bbc0836f892789156532ebcc1cce304197560ca1274f05267d552, creation-plan8f2b687846d936b91b9651e95371b5e009f3d555edb3f3cce12cf7c7823f506c. Exactly four root-private files were written; import stays VERIFIED/version2 with one cumulative effect attempt. Native digestbd48… and original config836… remain separately bound. All eight original publisher subjects were freshly verified. No runtime/DB/provider/firewall/signature/import effect occurred.

## Integration qualified since preparation

[CI38176804114](https://github.com/GioNob/ouf-deploy/actions/runs/38176804114), job114580802467 SUCCESS,39 unit tests plus actual original-package/containerd integration. The original signed image is created by its native manifest; process death leaves a durable creation intent, and reopening reconciles the same stopped container without duplicate creation. This also passes through the new ordered Executor and CreationAdapter. The JVM never starts. External authority and preceding cutover phases in this isolated fixture are synthetic; complete target OCI/transport/installer or CSV acceptance is not claimed. [Evidence](../evidence/native-v11-composed-creation-qualified-20261011.json).

## Concrete next protected operation

The four draft files currently have sequential publication. The next operation copies their exact bytes into one complete immutable private review directory, alongside an intake.json manifest of file hashes and sealed source hashes. Linux renameat2(RENAME_NOREPLACE) publishes the whole directory atomically without replacing an existing path. Before rename, partial files remain in private staging only. Interrupted staging is retained. If the same complete intake already exists, its exact files/modes/ownership are verified and durability synchronized, with no content rewrite. A race verifies the winning complete intake; an empty/foreign/tampered destination is never replaced.

The root helper authenticates exact declaration/request/public-plan hashes, original publisher/config binding, native-image proof and VERIFIED version2 import history recorded by the prepared plan. It reads all source files again before and after publication. Inputs remain unchanged; no package import, worker action, database/network/provider call, claim/signature/key read or budget reset occurs. Five new protected files are written on first publication. Resulting observations remain explicitly historical. Atomic content publication is not atomic runtime transition authority; all live runtime gates still need current owner proof.

| Sealed artifact | Commit | SHA256 |
|---|---|---|
| Root publisher | bdcf4594d152ea12d6b9b39b51e0d2533d83b7ef | 469de574b7c8cfa4ba2c33a51fb747efe3b8b31fbc1366a70573dcb06da2ca06 |
| Atomic publisher library | bdcf4594d152ea12d6b9b39b51e0d2533d83b7ef | c113f578b027c39573b4562cd3ac324abb8108a393b82dde19f8eb53d98e0ea6 |
| Launcher | 65a075f50849b3e7111739f7d331097467631d92 | c2a8760542e7a571ecf9bc2fb6f83e4598fb5f42ab60d8161d17228b9cd8f03c |

[CI38177286427](https://github.com/GioNob/ouf-deploy/actions/runs/38177286427), job114582239229 SUCCESS:7 filesystem tests and10 source/entry/delivery tests. Coverage includes complete publication/repeat, all before-publication fault points, crash after rename, two actual concurrent publishers, no replacement of an empty foreign path, missing/tampered/symlink/permissive files, preserved original package/import bindings, authority/budget-promotion denial, and every source download/hash failure before sudo/root execution. All three immutable downloaded source files and the launcher have been independently hash-verified from GitHub. [Qualification](../evidence/native-v11-atomic-review-qualified-20261011.json).

Root access is unavailable to the runner. Execute this exact operation as oufadmin:

```bash
(
  set -euo pipefail
  umask 077
  OUF_GH="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
  if [ ! -x "$OUF_GH" ]; then OUF_GH="$(command -v gh)"; fi
  OUF_LAUNCH="$(mktemp "$HOME/ouf-native-v11-intake-launch.XXXXXXXX")"
  "$OUF_GH" api -H 'Accept: application/vnd.github.raw' 'repos/GioNob/ouf-deploy/contents/releases/native-v11-review-intake-20261011.sh?ref=65a075f50849b3e7111739f7d331097467631d92' > "$OUF_LAUNCH"
  printf '%s  %s\n' 'c2a8760542e7a571ecf9bc2fb6f83e4598fb5f42ab60d8161d17228b9cd8f03c' "$OUF_LAUNCH" | sha256sum -c -
  bash "$OUF_LAUNCH"
)
```

Return only OUF_NATIVE_V11_REVIEW_INTAKE and OUF_NATIVE_V11_REVIEW_INTAKE_LAUNCHER_EXIT. The new intake binds review inputs for the future source-bound finite transition; it does not issue that transition authority or qualify the unwired target adapters. Next gates remain authenticated finite HUMAN infrastructure decision, coordinated R12 stop/revoke preserving current cumulative history, quiescence and fresh fenced backup, exclusive endpoint release, new complete OCI/reciprocal peer, separately signed transport/distinct worker, migration-aware admission and application/CSV readiness. Cinema and Teatri are preserved; CSV→ACK→object search remains OPEN.
