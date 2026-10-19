# Custody successor IAM STOP and one-use resume — 2026-10-19

Technical8/8; functional4/6. Qualification PASS:18 tests; target reconciliation and one-use IAM login remain physical gates.

The operator reports successful private preparation of `/etc/ouf/deploy-snapshots/source-revision-custody-continuation-dvf517sr`: all81 predecessor files verified, four read-only database sessions, new case/package/source closure and both plans frozen, zero OAuth and runtime effects, images/documents reused. New-process execution kcw73ask stopped at EXISTING_IAM_SESSION_EXPIRED. This does not invalidate or authorize rerunning the successful preparation. See exact target pins in `evidence/source-revision-custody-iam-stop-20261019.json`. The STOP reports no authority, but protected inventory must establish this before resumption; do not assume it.

The new installation-specific delivery first reads the exact prepared receipt/case/package, all81 frozen files without executing them, retained kfy inputs, both plans and predecessor claim/journal bindings. It requires the old dvf successor claim absent and its zero-effect history unchanged. It reconciles exactly nine kcw files (seven compiler sources and candidate review/base plan), refuses every additional login/authority file, and reads only HUMAN journal metadata with the same current boot/binding, READY188/256 and over1200 seconds in the original wall/monotonic window. No bearer/key/dump is opened, no journal hash or credential is printed, and the reader performs no network, Engine or database calls.

Only after these checks does one new exclusive durable IAM fence bind the observed nine-file closure, prepared receipt and Keycloak generation. The previously qualified native admin-login implementation is reused byte-for-byte: one terminal password prompt, timeout ambiguity reconciled by one fixed metadata GET, no repeated login, no password argument or delivery capture. Docker binary/socket and Keycloak generation remain pinned. An unavailable/short HUMAN window blocks before password; it is never renewed implicitly. The fence is consumed even on interruption. The old tvc IAM fence is untouched.

After successful IAM readback, the delivery repeats reconciliation and all81-file verification, then uses a new isolated interpreter to reload the existing prepared executor. It does not recompile a successor or change any sealed library/case. The native executor recompiles/read-validates current state, refreshes the existing HUMAN within its original cumulative256 budget, and presents a NEW APPROVO for the current review. Existing dvf authority/claim is not reused; one explicit child claim remains conditional on fresh signed approval. THS owns the later role confirmation; profile publication, CSV acquisition and job retries are excluded.

Consulted original PET Onboarding/Configuration/THS1.6 §§109.14–109.15 from the verified baseline; Matrix1.7 precedence, owner authority and expired-challenge rules remain. This is not proof of runtime completion or full PET compliance. Physical sudo, terminal IAM password and native APPROVO remain operator gates. No generic repository/MCP consent is required. After any STOP/interruption, preserve the log and reconcile; never rerun the launcher.

## Qualification and immutable delivery

[Run39209506145](https://github.com/GioNob/ouf-deploy/actions/runs/39209506145), job117919529140, source7b9f3018f52423ebe0303991cd04877beea0ee53: **18 tests PASS**, no skips. Actual root file custody; explicit fixture boundaries for terminal, Engine/IAM and exec. The helper Git blob8885224191dd62917a4a41425700f23b2266ee6a was independently fetched through the GitHub connector and matched byte-for-byte; helper SHA256789f1a339ad74d89ff8002f2c22ab142d350206d9bc82e43512156df4c147409. The qualified root shim rejects a changed helper before any protected read. No target login/preparation/runtime effects were executed by CI.

Execute ONCE on the VPS. First protected reconciliation is read-only; one IAM terminal login is entered only if it succeeds. Password only at Keycloak prompt, never chat. After successful GET readback and a second reconciliation, the native executor owns current-state checks/HUMAN refresh/new APPROVO; THS role decision remains separate. Any STOP/interruption consumes the relevant fence and requires reconciliation; do not rerun.

```bash
(
  set -euo pipefail
  umask 077
  ouf_gh="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
  [[ -x "$ouf_gh" ]] || ouf_gh="$(command -v gh)"
  [[ -x "$ouf_gh" ]] || exit 1
  ouf_launch="$(mktemp -d "$HOME/ouf-custody-iam-launch.XXXXXXXX")"
  "$ouf_gh" api repos/GioNob/ouf-deploy/git/blobs/6af4851559361ec229f0fae6ab6bbae04edea1ed --jq .content | base64 --decode > "$ouf_launch/run.sh"
  printf '%s  %s\n' '178f6c8cbb9c5a4606412b73a6cb8dfe3538c3ec75817c6590b0e2e30e398244' "$ouf_launch/run.sh" | sha256sum --check
  bash "$ouf_launch/run.sh"
)
```
