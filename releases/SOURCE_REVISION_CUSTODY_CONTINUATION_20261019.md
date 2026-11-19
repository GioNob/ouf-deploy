# MCP retained metadata custody continuation — 2026-10-19

Technical8/8; functional4/6. Source and immutable delivery qualification PASS:136 tests. VPS private preparation and runtime are not yet executed.

## New target evidence takes precedence

The protected after-APPROVO read supplied by the operator records dvf517sr with22 retained files, two signatures, issuance and logical-scope claims and matching decision/review bindings. Its update journal is version0/nextStage0/effects[] with an expired authority. No backup dump/receipt is present; four application identities/processes are unchanged and running. This is bounded target readback, not end-to-end completion or a claim that no authority was issued. See `evidence/source-revision-after-approval-custody-target-20261019.json`.

The cause is exact: the three hash-matching retained MCP permit/policy/profile documents are root-owned, service group10005, mode0440. The generic root:root0600 private reader rejects them. Preserve their bytes, mode, group, original images/documents, the expired authority and all claims/journals. Never chmod/chown them to force acceptance.

## Explicit successor under qualification

Only sealed successor native/entry/login modules change. The original generic private reader remains unchanged. A separate retained-MCP reader binds the three approved paths and hashes plus device/inode/UID/GID/mode/link count/size/mtime/ctime; it requires root-controlled ancestry, regular files, no symlinks/hardlinks and0440 read-only service custody. Any drift blocks.

A new case and source closure bind the original dvf claim, expired authority, plan, review and zero-effect journal. Only a same-boot expired predecessor with version0, nextStage0, zero effect/readiness attempts and unchanged budget qualifies. After a NEW native APPROVO and fresh signed authority, the runtime appends one exclusive `logical-successor.claim.json` under the predecessor invocation lock. Existing global claim, authority and journal bytes remain untouched. A second successor, changed history, old authority/new plan mismatch or stale child binding blocks. No budget is renewed; the predecessor consumed zero readiness attempts. Any ambiguous partial result requires protected readback, never replay.

Private preparation revalidates host/provider/generations, all81 frozen files, and original inputs at their actual retained kfy paths. It freezes three explicit module successors and compiles a base plan and bound continuation plan before END/new-process handoff. Maximum300 seconds; zero OAuth/runtime effects during preparation. The existing HUMAN must still be READY188/256 with more than1200seconds; native refresh is bounded by the unchanged window and cumulative256 maximum. No new login is opened. The new native review covers backup, V34, Onboarding/MCP, two additive routes and revision capabilities/scopes/proposed role. Role confirmation remains in native THS. Profile publication, CSV acquisition and job retries are excluded.

## Normative review and limits

Consulted original PET Source Onboarding/Configuration/THS1.6 §§109.14–109.15 from the checksum-verified1.7 baseline attachment: expired challenges are not revived; owner remains authoritative; evidence/observability remains explicit. Matrix1.7 precedence remains unchanged. This is an installation-specific retained recovery, not a reusable distributed installer or proof of complete PET compliance.

No target successor was executed by cloud development. The operator still supplies sudo and the actual fresh native APPROVO; authorization in chat does not substitute runtime authority or THS.

## Source qualification and staged bytes

Run [39206613640](https://github.com/GioNob/ouf-deploy/actions/runs/39206613640), source5571f70b501fffa81b6c9e18b5bb67b0957ed2d9: **133 tests PASS** (native100 of105 discovered, five older governed-only fixture tests explicitly skipped; signed Java-owner11; postboot18; custody-capsule4). The exact81-file verifier successfully reloads the original private preparation from its separate retained kfy context; it does not assume copies in the governed capsule. Initial signed-fixture name collision was corrected and the final source fully qualified; no target preparation was attempted.

Source-only stage job117911056668 succeeded: `/home/oufadmin/ouf-deploy-runner/_work/ouf-deploy/ouf-source-revision-custody-code-39206613640`, manifestSHA256 `7145b253a4946fdc6e85de99de59a67cf2516d40ea261c5e6bfe3dc7df85101b`, five files. Stage receipt reports zero authority and zero runtime mutations. See the exact hashes and test boundaries in `evidence/source-revision-custody-continuation-qualified-20261019.json`.

Also consulted original Authorization PET1.5 §109.6 (fail closed; no application retry for invalid JWT; bounded recovery) and Matrix1.7 §1 (frozen ownership and THS authority). No relaxation of these contracts is inferred from development authorization.

## Immutable delivery qualified; physical gate remaining

[Run39206831574](https://github.com/GioNob/ouf-deploy/actions/runs/39206831574), job117911401418: three delivery tests PASS. Total136 passed; five explicit old-source fixture skips remain separately reported. Commit14c6e69b0d0b0142588859ecf4f05076d20080de contains the immutable launcher. Its Git blob19dc4c2498620699a09f104b6298c80e5677cbd5 was independently fetched through the GitHub connector and matched byte-for-byte. SHA256 `9d185110b3ec1f53d0ffb50f18151f609ef6a17aca2726fe40883af4268d94da`. No private preparation or runtime authority was executed by these CI jobs.

Execute ONCE as oufadmin on the VPS. The existing authenticated GitHub client fetches only the immutable verified launcher; sudo and the actual new APPROVO remain physical/native gates. No generic repository/MCP consent is needed. If the existing IAM/HUMAN context is unavailable or too short, STOP; no implicit login is opened. After any STOP/interruption, preserve the printed log and reconcile before further action.

```bash
(
  set -euo pipefail
  umask 077
  ouf_gh="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
  [[ -x "$ouf_gh" ]] || ouf_gh="$(command -v gh)"
  [[ -x "$ouf_gh" ]] || { echo 'STOP: gh non disponibile'; exit 1; }
  ouf_launch="$(mktemp -d "$HOME/ouf-custody-launch.XXXXXXXX")"
  "$ouf_gh" api repos/GioNob/ouf-deploy/git/blobs/19dc4c2498620699a09f104b6298c80e5677cbd5 --jq .content | base64 --decode > "$ouf_launch/run.sh"
  printf '%s  %s\n' '9d185110b3ec1f53d0ffb50f18151f609ef6a17aca2726fe40883af4268d94da' "$ouf_launch/run.sh" | sha256sum --check
  bash "$ouf_launch/run.sh"
)
```

The old dvf authority and old launchers must not be replayed. The new source appends one bound child claim only after fresh native approval and signed authority; it does not reset or renew the expired original. Role publication still requires THS. Generic profile publication and functional5/6 remain outside this runtime review.
