# Diagnose the first selected IAM GET — 2026-10-13

The operator receipt at14:05:17 Europe/Rome blocked in CURRENT_SELECTED_IAM_BASELINE_READ, iamMetadataGetAttempts=1, reasonEXISTING_IAM_GET_UNAVAILABLE, privateEvidenceWrites=0 and all key/grant/signing/IAM/service effects0. Existing exact public profile and role policy were read before that phase. The suppressed original stderr was not retained, so session expiry is not proven. Preserve the failure; never reset budget or infer a login fix from the generic reason.

New isolated diagnostic scope: exact retained snapshot hash7e0f46ad0f66ee40b2ce0f662fdb70007744f81f933865264fdf279227681927; one selected Docker running-state read, at most one core-client GET with the old exact realm/server route and explicit7 public fields. Anonymous private temporary streams capture bounded stdout262144 and stderr65536; raw bodies/tokens/errors never appear publicly. Fixed text categories are observations, not authenticated root-cause proof. No login, private key/credential/mounted-token read, persistent protected evidence write, retry, grant, IAM/service mutation or authority issuance.30second root deadline/40second outer wait. If the GET is currently available, report it without automatically replaying preparation. A classified authentication failure will support a separate terminal-only reauthentication through the existing CLI; no password is requested in chat.

## VPS command

Run once as oufadmin and return the final JSON. Existing gh is reused outside PATH; two pinned source hashes are checked before sudo and again before memory import. The output is saved in a unique home file. This is a new diagnostic observation of the unavailable GET, not a rerun of the full preparation.

```bash
set -o pipefail
ouf_diag_receipt="$(mktemp "$HOME/ouf-policy-token-admin-diagnostic.XXXXXXXX.json")"
python3 -I -B - <<'PY' | tee "$ouf_diag_receipt"
import base64,hashlib,json,os,pathlib,shutil,subprocess
preferred=pathlib.Path.home()/'ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh'
gh=str(preferred) if preferred.is_file() and os.access(preferred,os.X_OK) else shutil.which('gh')
if not gh:raise SystemExit('phase=DELIVERY reason=EXISTING_GH_UNAVAILABLE; no sudo executed')
commit='5c0623f0f6036257a85056db47a90ddae8be1928'
hashes={
 'iam_binding_candidate':'a8cf18ea78b3acc7261838711345a218e678bfaf11e498dcba6859862d6b655d',
 'iam_admin_get_diagnostic':'904b61e82a772fffee19048369e8566ad9afd9561c3e2782371db74a8e3621da'}
sources={}
for name,expected in hashes.items():
    endpoint='repos/GioNob/ouf-deploy/contents/tools/semantic_policy_token_owner/'+name+'.py?ref='+commit
    try:
        reply=subprocess.run([gh,'api',endpoint,'--jq','.content'],check=True,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=30)
        if len(reply.stdout)>131072:raise ValueError()
        raw=base64.b64decode(b''.join(reply.stdout.split()),validate=True)
    except Exception:raise SystemExit('phase=DELIVERY reason=DIAGNOSTIC_SOURCE_UNAVAILABLE; no sudo executed')
    if hashlib.sha256(raw).hexdigest()!=expected:raise SystemExit('phase=DELIVERY reason=SOURCE_HASH_MISMATCH; no sudo executed')
    sources[name]=base64.b64encode(raw).decode()
root_code='HASHES='+repr(hashes)+'\n'+r'''
import base64,hashlib,json,sys,types
raw=sys.stdin.buffer.read(131073)
if not 0<len(raw)<=131072:raise SystemExit('phase=ROOT_DELIVERY reason=PAYLOAD_UNBOUNDED')
values=json.loads(raw)
if type(values)is not dict or set(values)!=set(HASHES):raise SystemExit('phase=ROOT_DELIVERY reason=EXACT_SOURCE_SET_REQUIRED')
checked={}
for name,expected in HASHES.items():
    data=base64.b64decode(values[name],validate=True)
    if hashlib.sha256(data).hexdigest()!=expected or name in sys.modules:raise SystemExit('phase=ROOT_DELIVERY reason=SOURCE_HASH_OR_NAMESPACE_DRIFT')
    checked[name]=data
for name in HASHES:
    module=types.ModuleType(name);sys.modules[name]=module
    exec(compile(checked[name],'verified-diagnostic-'+name,'exec'),module.__dict__)
raise SystemExit(sys.modules['iam_admin_get_diagnostic'].main())
'''
try:
    result=subprocess.run(['sudo','--','/usr/bin/python3','-I','-B','-c',root_code],input=json.dumps(sources).encode(),timeout=40)
except Exception:raise SystemExit('phase=ROOT_EXECUTION reason=DIAGNOSTIC_RESULT_UNAVAILABLE; preserve output')
raise SystemExit(result.returncode)
PY
```

## Qualification

Source5c0623f0f6036257a85056db47a90ddae8be1928: [push CI38395303618](https://github.com/GioNob/ouf-deploy/actions/runs/38395303618) and [PR CI38395311531](https://github.com/GioNob/ouf-deploy/actions/runs/38395311531), both SUCCESS. Five focused tests verify fixed-category redaction, one exact failed GET/no login/no write, stopped container/hash drift before GET, successful read without automatic replay, and actual child stderr bounded to65537 bytes for truncation detection. Real root-private filesystem custody is exercised; IAM/Docker outputs in these tests are synthetic. No target diagnosis or current cause is inferred from CI. Previous147-test governance qualification remains separate.
