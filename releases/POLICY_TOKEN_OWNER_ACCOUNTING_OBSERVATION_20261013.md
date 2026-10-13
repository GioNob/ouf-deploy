# Applied IAM action and owner accounting evidence

The operator reported at 16:31:31 Europe/Rome that the exact approved mapper action reached `APPLIED_RECONCILED`: two existing owner signatures, one IAM mutation, issuance consumed, effect proven/reconciled, zero service mutations/grants and no runtime authority. Exact context `/etc/ouf/deploy-snapshots/policy-token-iam-signed-context-de54361718af9ab4f2ebd735f0d07576735f7e62abaa2922f3038d0a154214e0`. [Retained receipt](../evidence/policy-token-scoped-iam-action-applied-target-20261013.json). This is operator-reported target output, not an independent live readback. Do not replay the action or ask for its approval again. `privateEvidenceWrites` and `privateKeyReadCount` remain null as reported; they are not rewritten as zero. Accounting acceptance, actual target bearer/introspection, installation, six mounts, THS and CSV13 remain open.

## Next independent read-only scope

The new observation asks the existing Keycloak owner whether the selected client's event store can contribute to historical accounting. It does not reconstruct the history from job IDs or create a zero-initialized journal. It reads `events/config` once. Only when event storage and each relevant type are explicitly enabled does it read a sample of that type for the already selected client: `CLIENT_LOGIN` and `CLIENT_LOGIN_ERROR`, maximum101 records per type with100 retained to detect truncation. Projected fields are only `time,type,clientId`; usernames, source IPs and event details are neither projected nor printed. There is no widening to other clients or other audit types. A second config read checks stability only when samples were obtained.

The authoritative endpoint behavior was reviewed in [RealmAdminResource26.7.4](https://github.com/keycloak/keycloak/blob/26.7.4/services/src/main/java/org/keycloak/services/resources/admin/RealmAdminResource.java): the event-config GET requires view-events authority and expands missing/default type lists; the events GET filters by OAuth client name and type. The script does not enable audit or use the PUT/DELETE APIs. An example-token endpoint was excluded: its provider source creates a persistent session temporarily and removes it in finally, so its GET method would not justify calling it a strictly read-only historical probe.

Observed client-login events are not independently proven service-token grant attempts; a bounded or empty sample is not complete all-time coverage, even when event expiration is0. Missing installation start, old retention/configuration changes, manual invocations, disabled storage or missing relevant types remain gaps. Accordingly `historicalGrantAttemptCount=null` and `historicalAccountingReconciled=false` on every successful observation. Zero sample records never means zero historical usage. Unknown/disabled/incomplete evidence keeps the token-owner admission gate closed; no budget is created, reset or renewed.

The observer is separately hash-pinned read-only source, not silently included in the previously approved action. It reuses the exact verified19-module capsule and the target host review to validate interpreter/stdlib/native Docker bytes and the existing public profile/policy routing. It does not invoke the action entry, request another approval, sign, open installation keys, read secret/token files, request a token, mutate IAM/services, install runtime code or alter R12. It publishes at most one immutable root600 proposed accounting observation under the existing evidence parent. The earlier IAM action remains a separately recorded one-mutation effect; this observation's zero mutation count does not reset that history.

Limits: at most4 metadata GETs, each15seconds with a70second aggregate CLI deadline; root deadline120seconds and outer140seconds;1MiB native stdout/stderr file cap; response projection262144bytes and diagnostic65536bytes. No retry/fallback or retained-session login. Failure reports phase, safe code, exit/category/truncation and publication uncertainty without raw diagnostic text. Session-auth classification requires the existing owner terminal login, then a deliberate observation invocation. It never repeats the already applied mapper POST.

## Exact VPS command

Qualified script source `ca0278fe096fd93cfd3095d13f46454a8071f937`, delivery SHA256 `2f0fef40c7394525bdd12baf88767dd896c14c9c04845c0787727401dd750e0e`, observer SHA256 `2cc7c37f96929c918c559be4fad4df7aee540ee17ee6e1da4a2858d5418ad44e`. Existing portable gh is reused outside PATH; immutable capsule commit/hash are unchanged. Copy once as oufadmin and return the final JSON. No Keycloak login is requested unless the exact existing-session GET reports that failure.

```bash
set -o pipefail
ouf_accounting_observation="$(mktemp "$HOME/ouf-policy-token-owner-accounting.XXXXXXXX.json")"
python3 -I -B - <<'PY' | tee "$ouf_accounting_observation"
import base64,hashlib,os,pathlib,shutil,subprocess
preferred=pathlib.Path.home()/'ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh'
gh=str(preferred) if preferred.is_file() and os.access(preferred,os.X_OK) else shutil.which('gh')
if not gh:raise SystemExit('phase=DELIVERY reason=EXISTING_GH_UNAVAILABLE; no sudo executed')
endpoint='repos/GioNob/ouf-deploy/contents/scripts/observe-policy-token-owner-accounting.py?ref=ca0278fe096fd93cfd3095d13f46454a8071f937'
try:
    reply=subprocess.run([gh,'api',endpoint,'--jq','.content'],check=True,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=30)
    if len(reply.stdout)>131072:raise ValueError()
    raw=base64.b64decode(b''.join(reply.stdout.split()),validate=True)
except Exception:raise SystemExit('phase=DELIVERY reason=ACCOUNTING_OBSERVATION_DELIVERY_UNAVAILABLE; no sudo executed')
if hashlib.sha256(raw).hexdigest()!='2f0fef40c7394525bdd12baf88767dd896c14c9c04845c0787727401dd750e0e':
    raise SystemExit('phase=DELIVERY reason=DELIVERY_HASH_MISMATCH; no sudo executed')
namespace={'__name__':'verified_accounting_observation_delivery'}
exec(compile(raw,'verified-accounting-observation-delivery','exec'),namespace)
raise SystemExit(namespace['main']())
PY
```

## Qualification scope

Six new tests cover disabled storage/missing types, empty/truncated samples with unknown historical totals, another client/type/unbounded response/config drift, exact GET-only route and redacted session failure, finite CLI timeout without retry, independent observer source hash and capsule delivery with no action entry. The disposable native Keycloak qualification enables fixture event storage during realm setup and proves the actual config and filtered selected-client samples after its existing fixture grant; it requires at least one CLIENT_LOGIN event but never equates sample counts to complete historical accounting. This fixture setup is not a target audit configuration change. Hosted results are recorded separately after completion.

Final hosted qualification on exact source `ca0278fe096fd93cfd3095d13f46454a8071f937`: [push38416126024](https://github.com/GioNob/ouf-deploy/actions/runs/38416126024) and [PR38416137333](https://github.com/GioNob/ouf-deploy/actions/runs/38416137333) SUCCESS. Log aggregate172 tests, zero skips, actual native config and client-event projection passed; fixture CLIENT_LOGIN sample1 and CLIENT_LOGIN_ERROR sample0, explicitly not accepted historical grant counters. [Detailed qualification](../evidence/policy-token-owner-accounting-observation-qualified-20261013.json). Target accounting remains unobserved until the operator executes the bounded read.
