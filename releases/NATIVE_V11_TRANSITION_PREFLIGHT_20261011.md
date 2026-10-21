# Current target observation — 12 October 2026

The operator supplied a successful preflight at policyObservationAt1791779294. All five intake files were reverified. Both existing installer and attestor entries are ACTIVE with eligible current role windows, expiresAt1798908417 and 7,129,123 seconds remaining at observation. Both private-key metadata checks match; no key bytes were read. No renewal is indicated by this observation. [Target receipt](../evidence/native-v11-transition-preflight-target-20261012.json).

This is historical public-policy and metadata evidence, not signature verification, R12 liveness, an execution mandate, source closure or runtime authority. Every runtime effect remains zero. The target applicator and CSV acceptance remain OPEN; no further policy-read command is required on this evidence alone.

# Native V11 transition policy preflight — 11 October intake

The operator's23:50:49 CEST submission confirms the complete native V11 review intake is published atomically: /etc/ouf/deploy-snapshots/semantic-native-v11-intake-9ec18cf053e5925e42df93b75990343cc1d09696975fc2a224d76b4b28becdae. Five attempted/confirmed private writes, no runtime/key/signature/lease/budget effect. [Receipt](../evidence/native-v11-atomic-review-target-20261011.json). The original draft and VERIFIED import remain retained.

## Code completed before requesting the protected read

[CutoverAuthority](../tools/semantic_application_cutover/cutover_authority.py), source38f3fd0a250a8e4a64f37908e923fea3ebdd979d, reuses the existing DetachedAuthenticator, role-framed Ed25519 signing bytes and protected-policy verification. It accepts no no-op verifier, hash-only evidence or implicit approval. The sealed installer must supply an independently reviewed HUMAN mandate hash, exact intake/source/request/predecessor bindings and installed authority context. Both DEPLOYMENT_INTENT and FINAL_DEPLOYMENT_APPROVAL signatures are freshly verified; the finite execution window is contained in HUMAN approval and current installer/attestor policy windows. Root HUMAN bytes, installed policy, scope and clock are rechecked. This module issues no signature/authority and executes no target effect. The future root entrypoint must record actual explicit human approval; the development delegation and intake do not supply it. Attestor window eligibility here is policy preflight, not verification of the future new-generation OCI attestation.

[CI38179920440](https://github.com/GioNob/ouf-deploy/actions/runs/38179920440), job114590111922 SUCCESS:10 root-custody/actual Ed25519 tests, including real dual-signature verification with all13 ordered synthetic fixture phases; malformed/missing/cross-entity signatures, corruption, HUMAN expiry/revocation, policy/key expiry, no-op verifier and insufficient installer/attestor windows are denied. Keys, HUMAN records and non-creation effects in these tests are disposable synthetic fixtures. Target key bytes and target decisions are never used.

The root preflight has11 further scope/entry/delivery tests. Its complete entrypoint is exercised over actual private POSIX fixture files; selected key paths are not opened, secrets are not projected, and every source download/hash failure stops before sudo or root execution.

## Why this read is necessary

Current installed policy files are root-private and unavailable to the runner. Historical signing/activation receipts cannot establish whether the current keys/roles are still within their windows, revoked or custody metadata has changed. Before wiring target issuance and phase checkpoints, read the exact previously selected authority profile7fb7880d… and trust policy21122630… and compare them with the complete intake. No search for another authority, key refresh, policy replacement, role grant or credential fallback occurs.

[Reader](../scripts/read-native-v11-transition-preflight.py), source7decb29bd88696569346f4ff490fdf9f3c64e9f8, SHA256a8ae3dad3ad70efaff000904590ddea5939b4fa0f1fde11a2b4f87ae7788c35a. It verifies the intake manifest SHA9ec18cf0…, exact complete five-file set, all four payload hashes and original V11/import bindings; authenticates the selected installed profile/policy and rereads every consumed input. Output contains selected public identity/role/time-window/hash metadata only. Private keys receive lstat metadata checks only; no private key is opened/read, copied/exported, generated or signed. Private-key content custody remains explicitly unproven. Current policy eligibility is metadata, never signature verification or runtime permission.

[Launcher](native-v11-transition-preflight-20261011.sh), source30becfec5408f6d1de4715fc98ba8724d26f7f51, SHA256906bdca332d37def9c43d94cd81196b0e7ab1f3083d53a6a2d12f9608daa0e68. All four downloaded source files are verified before sudo and again before root execution, and all three module hashes precede module execution. [Qualification receipt](../evidence/native-v11-authority-preflight-qualified-20261011.json).

```bash
(
  set -euo pipefail
  umask 077
  OUF_GH="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
  if [ ! -x "$OUF_GH" ]; then OUF_GH="$(command -v gh)"; fi
  OUF_LAUNCH="$(mktemp "$HOME/ouf-native-v11-preflight-launch.XXXXXXXX")"
  "$OUF_GH" api -H 'Accept: application/vnd.github.raw' 'repos/GioNob/ouf-deploy/contents/releases/native-v11-transition-preflight-20261011.sh?ref=30becfec5408f6d1de4715fc98ba8724d26f7f51' > "$OUF_LAUNCH"
  printf '%s  %s\n' '906bdca332d37def9c43d94cd81196b0e7ab1f3083d53a6a2d12f9608daa0e68' "$OUF_LAUNCH" | sha256sum -c -
  bash "$OUF_LAUNCH"
)
```

Return only OUF_NATIVE_V11_TRANSITION_PREFLIGHT and OUF_NATIVE_V11_TRANSITION_PREFLIGHT_LAUNCHER_EXIT. Protected/runtime writes, signatures, key bytes, claims, DB/provider/DNS/firewall/container operations and common network locks remain zero. No apply is attempted. Policy drift/expiry must be handled by the appropriate scoped human process, without resetting claims or budgets.

The complete target applicator remains OPEN: actual source/command/secret/host custody, coordinated R12 stop/revoke preserving latest cumulative history, inventoried producer quiescence, fresh fenced backup, exclusive endpoint release, complete live OCI/reciprocal peer, separately authenticated transport and distinct worker, migration-aware admission and application/CSV acceptance still require their target adapters and qualified root entrypoint. No runtime approval is requested for an unfinished applicator. Cinema and Teatri remain preserved; CSV→ACK→object search remains OPEN.
