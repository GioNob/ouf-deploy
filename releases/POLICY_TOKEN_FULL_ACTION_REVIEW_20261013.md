# Complete IAM action closure and target host review — 2026-10-13

The operator has completed governed preparation: private intake850b0cf1a0b6fc6810ecba6d1ac846efc17e440c2660adddbabbdfb3a8fb7b2f, unchanged complete IAM baseline28 GETs, current existing profile/policy, one private write and no key/signing/IAM/service/grant effects. [Target receipt](../evidence/policy-token-governance-intake-target-compiled-20261013.json). Do not repeat that preparation or login for this next read-only step.

## Concrete next operation

Reuse that exact intake, review plan4a3d1c444012c8f30bf4480a518dea8448d815397cb1d71f97d26d99ad1fef76 and snapshot7e0f46ad0f66ee40b2ce0f662fdb70007744f81f933865264fdf279227681927. The new review adds the actual full19-module action/signer/authority source closure, loader hash, exact interpreter route/bytes, native OpenSSL/Docker bindings and Python standard-library byte map. The previous3-module preparation did not contain these apply dependencies or stdlib bytes; GitHub/CI cannot supply the VPS-specific map. All source imports use verified memory with no local fallback in an isolated no-bytecode/no-site process(-I -B -S). No code is installed to runtime roots; only an immutable proposed review artifact is published under the existing root evidence parent.

No IAM/DNS/HTTPS GET is required for this review: the already acquired baseline remains labeled historical, and fresh complete reconciliation is enforced by the later approved action. No keys/tokens/credentials opened, signatures, service grant, IAM/service mutation, budget reset or R12 effect. Existing public policy windows and prior executable proposals are rechecked for drift before publication. One root600 content-addressed review write maximum, fsynced/idempotently reconciled,300second root deadline/320second outer wait, no automatic retry.

The review proposes exactly one conditional caller-audience mapper on the registered SERVICE client, two existing installer role signatures, first invocation within15minutes of a later explicit HUMAN decision and a240second signed authority lifetime. The action code durably consumes issuance before key access and uses the existing no-replay IAM transaction ledger. Unknown/ambiguous effects are retained for reconciliation; a new job does not refund consumed issuance or POST. Code never invents HUMAN approval from development delegation, admin login or a review file. The signed-context human mandate remains current/hash-bound through signing and POST. Private-key access in an approved action is reported explicitly; exact key-read counts are not falsely claimed0. This command only prepares a review, takes no approval input and cannot select apply mode.

Standard-library link finding: Ubuntu's config-3.12-x86_64-linux-gnu/libpython3.12.so is a system interpreter shared-library reference. Only that exact version/multiarch name with canonical system target is allowed, followed by strict root ancestry/custody and byte hashing; arbitrary external targets still deny. Disabled sitecustomize/usercustomize startup hooks are excluded only under-S. Libraries/packages outside the approved graph remain excluded. No custody predicates were relaxed. The local runtime's stdlib is owned by65534 and therefore correctly denies; hosted CI root-owned stdlib passes. Earlier failed CI results are retained separately.

## VPS command

Copy once as oufadmin and return the final JSON. Password prompts can only be the existing sudo prompt; no Keycloak login is needed here. The wrapper fetches one pinned script, then one immutable capsule instead of19 separate sources. All hashes are checked before sudo and again in root memory execution. A unique local output file preserves prior receipts.

```bash
set -o pipefail
ouf_action_review="$(mktemp "$HOME/ouf-policy-token-full-action-review.XXXXXXXX.json")"
python3 -I -B - <<'PY' | tee "$ouf_action_review"
import base64,hashlib,os,pathlib,shutil,subprocess
preferred=pathlib.Path.home()/'ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh'
gh=str(preferred) if preferred.is_file() and os.access(preferred,os.X_OK) else shutil.which('gh')
if not gh:raise SystemExit('phase=DELIVERY reason=EXISTING_GH_UNAVAILABLE; no sudo executed')
endpoint='repos/GioNob/ouf-deploy/contents/scripts/prepare-policy-token-full-action-review.py?ref=f6cb9fe4dc8d35f9d044f88d8bb84bab55e9f9e0'
try:
    reply=subprocess.run([gh,'api',endpoint,'--jq','.content'],check=True,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=30)
    if len(reply.stdout)>131072:raise ValueError()
    raw=base64.b64decode(b''.join(reply.stdout.split()),validate=True)
except Exception:raise SystemExit('phase=DELIVERY reason=FULL_REVIEW_DELIVERY_UNAVAILABLE; no sudo executed')
if hashlib.sha256(raw).hexdigest()!='12b5687426d9572d7a3711d138b9a956714824bb1fa78186d0c168b29bd392e9':
    raise SystemExit('phase=DELIVERY reason=DELIVERY_HASH_MISMATCH; no sudo executed')
namespace={'__name__':'verified_full_action_review_delivery'}
exec(compile(raw,'verified-full-action-review-delivery','exec'),namespace)
raise SystemExit(namespace['main']())
PY
```

This produces applySourceClosurePrepared=true and freshHumanApprovalRequired=true in a review artifact, while productionApplyReady/runtimeAuthorityIssued/release acceptance remain false. It is not the later scoped approval or IAM apply. Owner credential reestablishment, actual target bearer/introspection, historical accounting, six mounts, complete installation, THS and CSV13 ACK/lineage/dedup/merge/search remain open.

## Final qualification

[Push CI38410165000](https://github.com/GioNob/ouf-deploy/actions/runs/38410165000) and [PR CI38410174598](https://github.com/GioNob/ouf-deploy/actions/runs/38410174598), sourcef6cb9fe4dc8d35f9d044f88d8bb84bab55e9f9e0: both SUCCESS,160 tests without skips. Existing-owner current-HUMAN issuer produces two real Ed25519 role signatures and one actual native Keycloak POST; exact effect and no-replay reconciliation, real HTTPS grant/introspection, wrong-audience/tampering/client-revocation denial passed. No-site verified-memory import of19 modules and1080 stdlib byte bindings passed on the hosted root fixture. Native TLS fixture setup uses OpenSSL; no third-party cryptography package enters the no-site action process. [Complete qualification and preserved failures](../evidence/policy-token-full-iam-action-qualified-20261013.json). These results remain disposable CI evidence, not target IAM/token/installation acceptance.
