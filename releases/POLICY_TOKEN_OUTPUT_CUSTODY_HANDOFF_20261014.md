# One governed token output custody handoff — 2026-10-14

**This is a new HUMAN custody boundary, not a repeated collection or old root apply.** The first controlled grant requires an actual root:gid10001/0750 output child. Completed roots stay root:root/0700; the consumed claim that created them does not authorize this child. Development delegation is not runtime HUMAN authority (AGENTS.md).

Qualified launcher: `scripts/custody-policy-token-output.py` at commit `f256d59687f0183162cb7d6c3a782746cfd60f71`, SHA-256 `16ba955100c1793e376c13a6e51d49e200e180de3b97f125ec63fbfddb51be4f`. Native runs [38520854225](https://github.com/GioNob/ouf-deploy/actions/runs/38520854225) and [38520849159](https://github.com/GioNob/ouf-deploy/actions/runs/38520849159) passed43 tests in4 suites, including9 actual launcher cases with native role signatures/filesystem. HUMAN response and Registry query are explicit synthetic seams in these tests.

The launcher fetches the immutable qualified29-module capsule from commit3391eeb9, verifies SHA-256 before sudo, loads in Python -I -B -S, reads retained host/review/root evidence, checks current selected Registry generation, and publishes a private scope review. It then requires the exact terminal phrase displayed. Only after that decision does it reserve the stable issuance claim and access the existing installer key for two role signatures.

Scope: one output child `/var/lib/ouf/policy-token/semantic/token-output`, one mkdir attempt and300 seconds, root:gid10001/0750. Authority-context evidence is also persisted privately. No old root creation, permission widening, IAM calls, credential reads, service operations, token requests or application runtime actions occur. Partial outcomes/consumed issuance cannot be rerun automatically.

The operator must paste the public receipt only. Expected status is `OUTPUT_CHILD_CUSTODIED_NOT_RUNTIME_ACCEPTED`, createdOutputDirectoryCount1, createdMigrationRootCount0, signaturesIssued2, inputReviewHash92b32769 and outputEvidenceHash/sourceClosureHash. Actual device/inode identities remain in the protected ledger. No target execution has yet been reported. This custody result alone is not a full owner installer, periodic owner authority, cutover or Teatri acceptance.

After the receipt, consume the retained output identity in the operational migration driver. Still qualify actual IAM/TLS/peer bindings and the periodic owner; do not retire the legacy writer or request a real first grant merely because this child exists.

## Complete VPS command

Run once. At the terminal prompt, review the displayed scope and type the exact approval phrase only if approving it. Paste the final public JSON receipt; never paste private snapshot or key contents.

```bash
(
  set -euo pipefail
  umask 077

  gh_bin="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
  if [[ ! -f "$gh_bin" || ! -x "$gh_bin" ]]; then
    gh_bin="$(command -v gh || true)"
  fi
  if [[ -z "$gh_bin" || ! -x "$gh_bin" ]]; then
    printf '%s\n' 'phase=DELIVERY reason=EXISTING_GH_UNAVAILABLE; no sudo executed' >&2
    exit 1
  fi

  work="$(mktemp -d "$HOME/ouf-token-output-custody.XXXXXXXX")"
  trap 'printf "Evidenze launcher conservate: %s. Se compare un errore, incolla la ricevuta e non ripetere automaticamente.\n" "$work" >&2' ERR

  "$gh_bin" api 'repos/GioNob/ouf-deploy/contents/scripts/custody-policy-token-output.py?ref=f256d59687f0183162cb7d6c3a782746cfd60f71' --jq '.content' |
    base64 --decode > "$work/run.py"

  printf '%s  %s\n' \
    '16ba955100c1793e376c13a6e51d49e200e180de3b97f125ec63fbfddb51be4f' \
    "$work/run.py" | sha256sum -c -

  /usr/bin/python3 -I -B -S "$work/run.py"
)
```
