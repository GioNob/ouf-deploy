# Existing admin session reauthentication and guarded preparation resume — 2026-10-13

At15:04:49 Europe/Rome the operator diagnostic reports the selected container running, inspect exit0, one exact IAM GET exit1 and SESSION_AUTH_FAILURE_TEXT_OBSERVED without raw text/truncation. This supports reauthentication via the existing native CLI. It does not independently prove the exact expiry cause. Prior failure and diagnosis remain retained; no budget or runtime claim is reset.

The only credential interaction is the existing terminal-only oufadmin login to master at the established internal server. Enter the password at the CLI prompt; never paste it into chat. This login refreshes the existing admin session/cache, a distinct action from service-token grants or IAM configuration changes. Its actual successful execution is not claimed before operator output. Login exit0 gates one invocation of the already147-test-qualified preparation, with unchanged commit/source hashes/private snapshot and review. Failed login stops before preparation. No duplicate preliminary GET is required. Output uses a new unique home file; old evidence remains intact.

The resumed preparation rechecks current complete metadata/core and existing exact profile/policy, proposes root executable bindings and publishes at most one immutable private intake. It cannot sign, grant service tokens, apply IAM or restart anything. New observed drift/unknown failure blocks; no automatic retry or baseline refresh. Current HUMAN/dual-role authority, separately sealed apply closure and all owner/accounting/THS/CSV gates remain open.

## One VPS block

```bash
if sudo docker exec -it ouf-keycloak /opt/keycloak/bin/kcadm.sh config credentials --server http://localhost:8080 --realm master --user oufadmin; then
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
else
  printf '%s\n' 'phase=ADMIN_REAUTH reason=LOGIN_FAILED; preparation not executed' >&2
fi
```

Return the final preparation JSON, or the fixed failure summary. Do not disclose the password or session-cache contents. Delivery source97b67634fb8d927dc61055f354b5450018a7b25b and SHA2560fd02720aaee54797574b34c832bb44b48ddfc833ca11c2ef9f4a6f38c39a63b are unchanged from [qualified preparation](POLICY_TOKEN_GOVERNANCE_INTAKE_20261013.md). The command composes the existing interactive login with that same delivery; no new source qualification or installation is asserted.
