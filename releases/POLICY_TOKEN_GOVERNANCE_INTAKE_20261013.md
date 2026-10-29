# Existing authority and exact IAM review: governed preparation intake — 2026-10-13

The existing signer route is recovered, so no technical routing answer is needed from the operator. This command reads the exact retained private plan4a3d1c444012c8f30bf4480a518dea8448d815397cb1d71f97d26d99ad1fef76 and metadata7e0f46ad0f66ee40b2ce0f662fdb70007744f81f933865264fdf279227681927, checks the existing profile7fb7880d58e43ab40f9f53dac07a5dbad462d12e3a96f3b1287c6763b1d7ce18 and policy21122630e52cb63c3744fee89f5c81ed926dad55231190243ca11be6d481bd42, observes current role-policy windows and native Python/OpenSSL/Docker bindings, and checks the same complete selected IAM baseline twice. Existing IAM core/scope changes block before reading newly selected scopes. Key references stay private; private key files are never opened or probed. Public summaries do not contain client identifiers, mapper values or key paths.

The new host observations are necessary to compose the separately sealed apply package; the last V11 profile/policy receipt is historical and does not bind today's Python/OpenSSL/Docker bytes. No old preflight or consumed activation is replayed. The preparation source closure contains exactly3 modules, hash-checked before sudo and again in the isolated root process, imported from verified memory. Existing portable gh is selected first; no reinstall or login is attempted.

At most48 native metadata GETs/180seconds,200second root preparation deadline,220second outer root wait, no automatic retries. Writes at most one root600 content-addressed intake under the existing protected evidence parent, fsynced and idempotently reconciled. It does not read credentials/mounted tokens/private keys, sign, grant, POST IAM, initialize runtime roots/journals, change services or reset budget/R12. The existing admin session is used by native kcadm GETs. An unavailable session yields a fixed phase/reason; expiry is not inferred. Preserve output and diagnose; do not automatically rerun unknown or drift failures.

The artifact explicitly records observationsAreHistorical=true, freshAuthorityAndReconciliationRequiredBeforePost=true, applySourceClosurePrepared=false, runtimeAuthorityIssued=false, productionApplyReady=false and notReleaseAcceptance=true. This command requests preparation only; it is not the later HUMAN approval or IAM operation.

## Command for the VPS

Copy the whole block once as oufadmin and return the final JSON. The only password prompt can be the existing sudo prompt in the terminal. The summary is saved to a new unique home file; earlier outputs are preserved.

```bash
set -o pipefail
ouf_intake_receipt="$(mktemp "$HOME/ouf-policy-token-governance-intake.XXXXXXXX.json")"
python3 -I -B - <<'PY' | tee "$ouf_intake_receipt"
import base64,hashlib,os,pathlib,shutil,subprocess
preferred=pathlib.Path.home()/'ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh'
gh=str(preferred) if preferred.is_file() and os.access(preferred,os.X_OK) else shutil.which('gh')
if not gh:raise SystemExit('phase=DELIVERY reason=EXISTING_GH_UNAVAILABLE; no sudo executed')
endpoint='repos/GioNob/ouf-deploy/contents/scripts/prepare-policy-token-governance-intake.py?ref=97b67634fb8d927dc61055f354b5450018a7b25b'
try:
    reply=subprocess.run([gh,'api',endpoint,'--jq','.content'],check=True,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=30)
    if len(reply.stdout)>131072:raise ValueError()
    raw=base64.b64decode(b''.join(reply.stdout.split()),validate=True)
except Exception:raise SystemExit('phase=DELIVERY reason=QUALIFIED_DELIVERY_UNAVAILABLE; no sudo executed')
if hashlib.sha256(raw).hexdigest()!='0fd02720aaee54797574b34c832bb44b48ddfc833ca11c2ef9f4a6f38c39a63b':
    raise SystemExit('phase=DELIVERY reason=DELIVERY_HASH_MISMATCH; no sudo executed')
namespace={'__name__':'verified_governance_delivery'}
exec(compile(raw,'verified-governance-delivery','exec'),namespace)
raise SystemExit(namespace['main']())
PY
```

## Qualification

Code source4d3d10e26b584a1d6e28811754e169e93723f396: [CI38391007884](https://github.com/GioNob/ouf-deploy/actions/runs/38391007884),144 tests without skips and actual governance-intake compilation with native Keycloak CLI/root executable custody on the exact official target RepoDigest. Existing real signed mapper/no-replay/introspection/denial checks also passed. Delivery source97b67634fb8d927dc61055f354b5450018a7b25b adds three tests for portable gh outside PATH, pre-sudo source failure and actual isolated root hash rejection; final combined CI result is recorded in the qualification receipt. Synthetic profile/keys are fixture-only; no VPS execution is claimed.

Final combined source97b67634fb8d927dc61055f354b5450018a7b25b: [push CI38391391820](https://github.com/GioNob/ouf-deploy/actions/runs/38391391820) and [PR CI38391397937](https://github.com/GioNob/ouf-deploy/actions/runs/38391397937) both SUCCESS,147 tests without skips. Full native fixture verified governance intake, existing authority roles, single scoped POST/no-replay and actual online token admission/introspection/revocation. [Qualification receipt](../evidence/policy-token-governance-intake-qualified-20261013.json).
