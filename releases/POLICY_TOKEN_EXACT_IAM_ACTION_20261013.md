# Exact retained target review: explicit HUMAN IAM action

**Completed on target at16:31 Europe/Rome. Do not execute the historical apply command again.** The operator reported APPLIED_RECONCILED, one IAM mutation, two signatures and consumed issuance; zero service/grant effects and no runtime authority. [Retained target receipt](../evidence/policy-token-scoped-iam-action-applied-target-20261013.json). The next independent read-only step is [existing-owner accounting evidence](POLICY_TOKEN_OWNER_ACCOUNTING_OBSERVATION_20261013.md), not another approval or mapper POST.

Target review receipt observed on 2026-10-13 at 16:16 Europe/Rome: `8bbc31ce396711acf94ebbc6b541ba60cd99d715315c29736ab697b62b6f78bc`; full source closure `bf9c2aad3ff684a9e2b8fced56d7c0e76e0e7647e7309dc66739d5be3e6db4e6`. The VPS prepared 19 modules and 1,112 standard-library byte bindings, with one private review write, no key access, signatures, IAM/service mutations or token grants. [Target receipt](../evidence/policy-token-full-action-review-target-20261013.json). This supersedes the pending host-review step; do not repeat preparation.

The proposed action adds only `ouf-policy-token-self-introspection-audience`, an `oidc-audience-mapper` on the SERVICE client registered in that exact review. The audience value is that same client's registered clientId. Access-token and introspection channels are true, ID-token channel false; the only accepted additional provider normalization is the already qualified false UserInfo fallback. It does not change issuer, tenant/actor bindings, scopes or introspection enforcement. It uses the existing installation owner's Ed25519 key for two separately role-framed signatures, a 240-second authority, one durable logical mapper transaction and at most one IAM POST. Existing complete metadata must be reconciled again before signing. No runtime authority, token grant, service changes, credential installation, release acceptance, budget reset or R12 replay is included.

[AGENTS.md](../AGENTS.md) states: “Development delegation is not runtime HUMAN authority.” The previous autonomous-development permission and prepared review are not that approval. The pinned delivery prompts the existing VPS operator on `/dev/tty` to type the exact public review-bound decision below. Refusal, no controlling terminal or the 120-second prompt deadline blocks before the witness, issuance claim, keys, signatures or POST. The script never supplies a default answer. The explicit answer is preserved as an immutable root600 HUMAN witness, with both hashes and its original timestamp. The derived approvalRef binds its exact bytes; first invocation is limited to 900 seconds from the actual typed answer. The existing action consumes issuance durably before key access and retains its one-POST ledger independently of operator/job IDs.

```
APPROVO IAM 8bbc31ce396711acf94ebbc6b541ba60cd99d715315c29736ab697b62b6f78bc
```

Before asking for approval, one bounded exact `GET clients/<review-bound UUID> --fields id` checks the retained admin session. This is necessary because the previously observed failure was categorized as session authentication failure; it prevents that known failure from consuming a HUMAN issuance. The interpreter/source/executable/current public policy bindings are checked before this GET. Raw CLI output is not printed. On failure, only exit code, finite diagnostic categories and truncation state are returned; text categories are not root-cause proof. No login, credentials, refresh-token files or keys are opened by the wrapper itself. No automatic retry is performed. An explicitly observed session-auth failure requires the existing owner login from the operator terminal, then a newly deliberate invocation; review preparation remains retained. Unknown, drift or failures after issuance must be diagnosed from the receipt and durable evidence, without blindly rerunning or refunding consumption.

Delivery source: `e5a5c58c57b8955718a2cce8cbeb1b6da44260d2/scripts/apply-policy-token-exact-reviewed-iam.py`; SHA256 `3badedbb1e93d175423657f19d2dc9d0b6a91013bc8e829d4d0470be5d4e5bed`. It reuses immutable capsule commit `1aa054279ad2d4f21bc27b65585be7dc40cb6f79`, SHA256 `e6fe660992f5f018975de73aaf9c83dfe4df9036620257735a5f59b7cf60379d`. The actual reviewed 19-module action bytes are unchanged. The independent HUMAN witness launcher is separately pinned and qualified, never substituted for or silently added to the approved source closure. Source is executed from verified memory under root `/usr/bin/python3 -I -B -S`; outer operation limit 440 seconds, including finite operator prompt and the action's 300-second deadline. No installed runtime code or unrelated root is written.

## Operator command

Run once as the existing `oufadmin` operator. If the session check succeeds, the script displays the exact scope and asks for the explicit phrase above. Enter it only if approving that one action. Return the final JSON in either case; do not automatically rerun a failed or interrupted action.

```bash
set -o pipefail
ouf_iam_action="$(mktemp "$HOME/ouf-policy-token-exact-iam-action.XXXXXXXX.json")"
python3 -I -B - <<'PY' | tee "$ouf_iam_action"
import base64,hashlib,os,pathlib,shutil,subprocess
preferred=pathlib.Path.home()/'ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh'
gh=str(preferred) if preferred.is_file() and os.access(preferred,os.X_OK) else shutil.which('gh')
if not gh:raise SystemExit('phase=DELIVERY reason=EXISTING_GH_UNAVAILABLE; no sudo executed')
endpoint='repos/GioNob/ouf-deploy/contents/scripts/apply-policy-token-exact-reviewed-iam.py?ref=e5a5c58c57b8955718a2cce8cbeb1b6da44260d2'
try:
    reply=subprocess.run([gh,'api',endpoint,'--jq','.content'],check=True,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=30)
    if len(reply.stdout)>131072:raise ValueError()
    raw=base64.b64decode(b''.join(reply.stdout.split()),validate=True)
except Exception:raise SystemExit('phase=DELIVERY reason=EXACT_IAM_DELIVERY_UNAVAILABLE; no sudo executed')
if hashlib.sha256(raw).hexdigest()!='3badedbb1e93d175423657f19d2dc9d0b6a91013bc8e829d4d0470be5d4e5bed':
    raise SystemExit('phase=DELIVERY reason=DELIVERY_HASH_MISMATCH; no sudo executed')
namespace={'__name__':'verified_exact_iam_delivery'}
exec(compile(raw,'verified-exact-iam-delivery','exec'),namespace)
raise SystemExit(namespace['main']())
PY
```

## Qualification and remaining scope

Five new delivery tests exercise actual isolated no-site root processes and controlling pseudo-terminals, root600 hash-bound witness publication, exact approval/refusal/no-terminal/changed-review outcomes, one pinned portable-gh source retrieval before sudo and a categorized expired session before witness/issuance. Their entry/CLI fixtures are synthetic and do not claim real provider behavior. Existing full-owner qualification covers actual Ed25519 signatures, one native Keycloak mapper POST, no-replay reconciliation and HTTPS grant/introspection in a disposable realm. Hosted qualification status is recorded separately after completion. Neither set of disposable tests is target IAM or token acceptance.

After a successful target action, actual target bearer/introspection, current provider implementation, runtime owner/credential/accounting, six mounts, complete installation, THS and CSV13 ACK/lineage/dedup/merge/search remain open. R12 remains consumed and is never reset or replayed.

Hosted push qualification [38412804314](https://github.com/GioNob/ouf-deploy/actions/runs/38412804314), exact source `e5a5c58c57b8955718a2cce8cbeb1b6da44260d2`: SUCCESS; log aggregate 166 tests, zero skips, actual disposable existing-owner two-signature/one-POST/no-replay/HTTPS-introspection flow passed. [Detailed evidence](../evidence/policy-token-exact-human-iam-delivery-qualified-20261013.json). The target action still requires its actual explicit terminal HUMAN decision.
