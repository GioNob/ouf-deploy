# Approved provider execution — 2026-10-09

Human approval: OUF_PROVIDER_V2_SIGN_START_HUMAN_APPROVAL_20261009_075624, recorded in a355a4f738ed1d5a713b911f33f7f63a4952aa6a. Scope: releases/PROVIDER_V2_SIGN_START_REVIEW_20261009.md at 5dceb35b75a456ea219f3f2349e68fee9114747c.

The helper below is pinned to 7e4d87983a1c67c689d87651f0b15033b974344d and SHA256 40585829c940685cce8ba82203d4bb057a94dc9ba6ca286dc935aa9581251cbe. Its seven scope/freshness/issuer-preflight checks passed in GitHub run 37891798745, job 113694151600. CI is not a target observation or authorization.

## Operator step

This signs the bounded transaction, publishes the authenticated runtime configuration and requests the two approved Docker starts through the admitted runtime. It reuses the sixteen inputs and sealed source package /etc/ouf/deploy-snapshots/semantic-provider-v2-transaction-source-ff13uh3n. Do not repeat source preparation.

The entire 240-second authority window must fit before dependency evidence expiry 2026-10-09T06:31:48Z (08:31:48 Europe/Rome). The helper refuses an insufficient window before keys are read; accepted inputs are not silently refreshed.

Run once in the existing VPS shell:

```bash
if (
  set -euo pipefail
  gh_bin="$(command -v gh || true)"
  if [[ -z "$gh_bin" ]]; then
    gh_bin="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
  fi
  [[ -x "$gh_bin" ]]
  work="$(mktemp -d "$HOME/ouf-approved-provider.XXXXXXXX")"
  "$gh_bin" api 'repos/GioNob/ouf-deploy/contents/tools/semantic_target_review/execute_approved_provider_transaction.py?ref=7e4d87983a1c67c689d87651f0b15033b974344d' --jq '.content' | base64 --decode > "$work/execute.py"
  printf '%s  %s\n' '40585829c940685cce8ba82203d4bb057a94dc9ba6ca286dc935aa9581251cbe' "$work/execute.py" | sha256sum -c -
  sudo /usr/bin/python3.13 -I -B - "$work/execute.py" 'OUF_PROVIDER_V2_SIGN_START_HUMAN_APPROVAL_20261009_075624' <<'OUF_VERIFIED_APPROVED_OPERATOR'
import hashlib, pathlib, sys
raw = pathlib.Path(sys.argv[1]).read_bytes()
if hashlib.sha256(raw).hexdigest() != "40585829c940685cce8ba82203d4bb057a94dc9ba6ca286dc935aa9581251cbe":
    raise SystemExit("APPROVED_OPERATOR_HASH_DRIFT")
sys.argv = [sys.argv[1], sys.argv[2]]
exec(compile(raw, sys.argv[0], "exec"), {"__name__": "__main__", "__file__": sys.argv[0]})
OUF_VERIFIED_APPROVED_OPERATOR
); then
  printf 'APPROVED_TRANSACTION_EXIT=0\n'
else
  rc=$?
  printf 'APPROVED_TRANSACTION_EXIT=%s\n' "$rc"
fi
```

Return OUF_PROVIDER_TRANSACTION_INTAKE, OUF_APPROVED_PROVIDER_TRANSACTION and APPROVED_TRANSACTION_EXIT. A denial preserves its phase/reason and context. Do not rerun after a partial result; inspect preserved evidence first. No automatic rollback, provider lease grant, daemon restart, general sudo grant, national Teatri job or release acceptance is included.

Status at publication: human scope approved; helper CI passed; operator target execution pending. No VPS execution has been performed from cloud.
