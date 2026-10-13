# Approved UNKNOWN-history contract: component and missing host bindings

The owner approved proposal SHA256 `f1200b4de0b33899760b1db1406725b6b7d633451b037ec9dc638754ecbcaa17` at17:05:55 Europe/Rome on13October. [Design decision](../evidence/policy-token-accounting-gap-contract-design-approved-20261013.json). Approval covers implementation/qualification of the contract, not token requests, budget issuance, service changes, credential access/rotation, runtime authority or historical-gap resolution. The immutable original proposal retains its historical PROPOSED label; the separate decision binds its exact bytes. No approval is inferred from a development delegation or component CI.

`accounting_gap_session.py`, SHA256 `e22d2283d7133eb766b9523e72c4753cb2b67e621c207a3f28fdb79e91090451`, implements one first future attempt slot. It requires actual `CutoverAuthority`, the existing verifier and current HUMAN plus both role signatures; an exact new `policyTokenAccountingGapMigration` scope, source-closure binding, contract/gap hashes and fixed1attempt/300second limits are mandatory. It rereads the exact root600 retained gap bytes and rejects a false reconciled/zero-total disposition. Its logical operation excludes approval/job/source IDs: another approval or process cannot create another first slot. No source-path fallback, no default no-op authority, no grant/client-secret/worker API exists.

Before any caller effect, consumption is atomically saved and fsynced under an exclusive scoped invocation fence. The state deliberately remains ATTEMPT_SLOT_CONSUMED_OUTCOME_UNPROVEN: a spent budget is not proof of a successful grant or admission. Legacy cumulative attempts stay null and gap OPEN; only this new session's prospective attempt slots are counted. Opening an existing unconsumed row never extends its original deadline. Wall and monotonic clocks plus kernel boot identity persist; backwards clocks, expiry or reboot deny instead of refilling time. An open/read uses current authority; consume never implicitly initializes a missing session. Partial creation is never overwritten as a fresh record. No automatic session renewal, refund, or unknown-effect replay is implemented.

Eight tests use actual existing role verification/Ed25519 and root file custody with a synthetic HUMAN/gap fixture: session/consumption persistence, new approval/restart not refunding, no implicit initialization, expiry/clock regression, absent/wrong scope/no-op verifier, unknown totals not converted to zero, revoked HUMAN/exclusive operator fence, actual fork/os._exit after consumption and boot/monotonic drift. Locally `/proc/sys/kernel/random/boot_id` is unavailable and the unit fixture substitutes an explicit synthetic UUID; this is not target boot evidence. On the hosted Linux fixture, the reader uses the available native kernel file. Neither fixture creates a real provider grant. The complete installer/credential/issuer/publication/mount integration remains unqualified; the existing worker must not be started using this component.

## Necessary new VPS inputs

The previous target review bound Python/OpenSSL/Docker and1,112 stdlib files. It did not bind `/usr/bin/systemctl`, kernel boot identity or proposed-root parent device/inode identities. Those are required to construct the future exact controlled writer transition and ensure a reboot/replacement cannot renew a session implicitly. The new read-only command reuses review8bbc31ce396711acf94ebbc6b541ba60cd99d715315c29736ab697b62b6f78bc, intake850b0cf1a0b6fc6810ecba6d1ac846efc17e440c2660adddbabbdfb3a8fb7b2f and gapfbd34408e376a0aca98aed5ba418bf5259a3c390be2a4efff7d8bce007a297d1. It adds only the missing native/root bindings, with stable before/after observations and at most one immutable private input proposal.

No budget or session is created; the component's open/consume methods are not invoked. No IAM/DNS/HTTPS GET, admin login, token/credential/key contents, signatures, grants, code installation, directory creation or service mutation. It reads only byte hashes of the exact systemctl executable, the kernel's public boot identity, lstat metadata of three previously proposed roots/ancestors and the fixed5 state properties of the two already identified legacy units. Unit commands/environments, journal contents and root members are not inspected. Absence is observed, never accepted custody or permission to initialize at zero. Existing roots are labeled EXISTING_NOT_ACCEPTED, never taken over automatically. The old IAM action is already APPLIED_RECONCILED and is not called or repeated.

Root deadline120seconds, systemctl metadata call10seconds, response cap8192bytes, outer140seconds, no automatic retry. Phase/reason/errno/systemctl exit distinguish delivery, exact gap/profile/source drift, kernel boot availability, root ancestry, unit metadata and partial publication. Runtime authority, production apply, full installer qualification, historical reconciliation and budget/session flags remain false.

## Operator command

Pinned source `bf75988637a97ca4b303b6ed776c398375d48105/scripts/prepare-policy-token-migration-host-inputs.py`, SHA256 `7d8721b328b618e692592743c98a6c31eb7a77e87827ae2b93cef57db65c3292`. It checks the existing memory capsule and separate gap-component bytes before use, under root -I -B -S. Existing portable gh remains the first route. Copy once as oufadmin and return the final JSON; this is host-input preparation, not a new runtime approval request.

```bash
set -o pipefail
ouf_migration_host_review="$(mktemp "$HOME/ouf-policy-token-migration-host-review.XXXXXXXX.json")"
python3 -I -B - <<'PY' | tee "$ouf_migration_host_review"
import base64,hashlib,os,pathlib,shutil,subprocess
preferred=pathlib.Path.home()/'ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh'
gh=str(preferred) if preferred.is_file() and os.access(preferred,os.X_OK) else shutil.which('gh')
if not gh:raise SystemExit('phase=DELIVERY reason=EXISTING_GH_UNAVAILABLE; no sudo executed')
endpoint='repos/GioNob/ouf-deploy/contents/scripts/prepare-policy-token-migration-host-inputs.py?ref=bf75988637a97ca4b303b6ed776c398375d48105'
try:
    reply=subprocess.run([gh,'api',endpoint,'--jq','.content'],check=True,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=30)
    if len(reply.stdout)>131072:raise ValueError()
    raw=base64.b64decode(b''.join(reply.stdout.split()),validate=True)
except Exception:raise SystemExit('phase=DELIVERY reason=MIGRATION_HOST_REVIEW_DELIVERY_UNAVAILABLE; no sudo executed')
if hashlib.sha256(raw).hexdigest()!='7d8721b328b618e692592743c98a6c31eb7a77e87827ae2b93cef57db65c3292':
    raise SystemExit('phase=DELIVERY reason=DELIVERY_HASH_MISMATCH; no sudo executed')
namespace={'__name__':'verified_migration_host_review_delivery'}
exec(compile(raw,'verified-migration-host-review-delivery','exec'),namespace)
raise SystemExit(namespace['main']())
PY
```

Three further delivery checks verify native lstat absence/existing/symlink behavior without custody acceptance or directory creation, exact component/capsule/portable-gh/no-session root invocation and actual isolated checksum denial before reads/writes. Hosted results are recorded separately. No target budget/grant or actual target introspection is claimed. Owner credential reestablishment, full installer and new execution authority, six mounts, THS and CSV13 remain open; consumed R12 history remains unchanged.

Final exact-source qualification: [push38421739199](https://github.com/GioNob/ouf-deploy/actions/runs/38421739199) and [PR38421751936](https://github.com/GioNob/ouf-deploy/actions/runs/38421751936) SUCCESS;183 tests, zero skips, including8 gap-session and3 host-delivery tests. Existing real disposable issuer/owner/IAM/audit/TLS checks also pass. [Detailed evidence](../evidence/policy-token-approved-gap-component-and-host-review-qualified-20261013.json). This qualifies components and read-only preparation, not a completed owner installer or target runtime authority.
