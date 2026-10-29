# Policy token governed installation inputs — 2026-10-13

The target v3 candidate b825fe2618383935064f80b5321758a8a9b92b120185297787777a370e41cc7b has29 interpreted mapper effects, no review reasons and complete static constraints. Receipt: evidence/policy-token-mapper-effects-review-target-20261013.json. This is not target provider/bearer/credential/peer/accounting authority.

## Concrete next step

Read only selected Docker image ID/version/code mount metadata and the exact retained candidate; observe public issuer DNS addresses and directly connect to each address using system CA/hostname-verified TLS for the exact discovery path. No proxy/redirect, no introspection or token endpoint, no login, no credential/source-token/journal read, no IAM/service mutation, no runtime root creation or budget/R12 changes. Only one exclusive root0600 install-input proposal can be written under the existing evidence parent. Proposed peers/trust are not approved runtime pins. Public JSON contains counts/hashes and bounded declared version only, not addresses, principals, mount paths or configuration values. Original candidate remains stable and immutable. Identical proposal publication reconciles; partial outputs block.

Single-attempt observation v1:90second total root deadline, at most8 selected discovery GETs,8second socket timeouts,10second selected Docker command deadlines; no retry. Unknown/transient/unreachable/HTTP/issuer/CA/hostname/integrity/drift outcomes block without inventing authority. All proposed DNS peers must be globally routable and pass; DNS and image fields are reread before proposal publication. The metadata does not prove executing JVM bytecode even if the image ID matches the disposable fixture; custom code mount observation is explicit.

Source59130d56265e9a7b7d3f580c16bcd971abaeae2a, probe9d7122471257e8c7dfab4e0000ee0aff23c59826fe49526a64a4b2992f106589 and qualified custody guarda8cf18ea78b3acc7261838711345a218e678bfaf11e498dcba6859862d6b655d. Six local tests pass with real loopback TLS and private root publication. Full CI/Docker fixture qualification must be green before delivery; receipt recorded separately. This is a prerequisite observation, not an installer.

```bash
set -o pipefail
python3 - <<'PY' | tee ouf-policy-token-install-inputs.json
import base64,hashlib,pathlib,shutil,subprocess,os
preferred=pathlib.Path.home()/'ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh'
gh=str(preferred) if preferred.is_file() and os.access(preferred,os.X_OK) else shutil.which('gh')
if not gh:raise SystemExit('phase=DELIVERY reason=EXISTING_GH_UNAVAILABLE; no sudo executed')
ref='59130d56265e9a7b7d3f580c16bcd971abaeae2a'
sources=[('binding','iam_binding_candidate.py','a8cf18ea78b3acc7261838711345a218e678bfaf11e498dcba6859862d6b655d'),('probe','iam_install_inputs_probe.py','9d7122471257e8c7dfab4e0000ee0aff23c59826fe49526a64a4b2992f106589')]
records=[]
for name,file,expected in sources:
    endpoint='repos/GioNob/ouf-deploy/contents/tools/semantic_policy_token_owner/'+file+'?ref='+ref
    try:
        reply=subprocess.run([gh,'api',endpoint,'--jq','.content'],check=True,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=30)
        if len(reply.stdout)>65536:raise ValueError()
        raw=base64.b64decode(b''.join(reply.stdout.split()),validate=True)
    except Exception:raise SystemExit('phase=DELIVERY reason=QUALIFIED_SOURCE_UNAVAILABLE module='+name+'; no sudo executed')
    if hashlib.sha256(raw).hexdigest()!=expected:raise SystemExit('phase=DELIVERY reason=SOURCE_HASH_MISMATCH module='+name+'; no sudo executed')
    records.append((name,base64.b64encode(raw).decode('ascii'),expected))
args=['qualified-install-input-probe','--candidate','/etc/ouf/deploy-snapshots/policy-token-iam-binding-b825fe2618383935064f80b5321758a8a9b92b120185297787777a370e41cc7b.private.json','--candidate-sha256','b825fe2618383935064f80b5321758a8a9b92b120185297787777a370e41cc7b']
bootstrap='import base64,hashlib,sys,types\nrecords='+repr(records)+'\nverified={}\nfor name,payload,expected in records:\n raw=base64.b64decode(payload,validate=True)\n if hashlib.sha256(raw).hexdigest()!=expected:raise SystemExit("phase=ROOT_DELIVERY reason=SOURCE_HASH_MISMATCH")\n verified[name]=raw\nmodule=types.ModuleType("iam_binding_candidate")\nsys.modules[module.__name__]=module\nexec(compile(verified["binding"],"qualified-binding","exec"),module.__dict__)\nsys.argv='+repr(args)+'\nexec(compile(verified["probe"],"qualified-install-input-probe","exec"),{"__name__":"__main__"})\n'
try:
    result=subprocess.run(['sudo','/usr/bin/python3','-I','-B','-'],input=bootstrap.encode(),timeout=100)
except Exception:raise SystemExit('phase=ROOT_EXECUTION reason=ROOT_EXECUTION_UNAVAILABLE')
raise SystemExit(result.returncode)
PY
```

Return public JSON only. Preserve private proposal for the signed owner binding. No login/mapper recovery repeat needed.

## Governed installation gates

Do not copy the unproven old writer credential, mask its active timer ad hoc, assume zero attempts or replay R12 activation. The proposed roots are observed absent: /usr/local/libexec/ouf-policy-token, /etc/ouf/policy-token/credentials/semantic, /var/lib/ouf/policy-token/semantic. They are not accepted custody.

Installation still needs independently proven running provider implementation and real IAM owner credential reestablishment, conservative allowed scope envelope plus actual grant/introspection, approved HTTPS peer/trust binding, durable historical accounting reconciliation without reset, a complete sealed loader/interpreter/dependency closure, a staged source/owner binding, current HUMAN mandate and dual role signatures, governed legacy-writer fencing and six-mount acceptance. No current acceptance flags are promoted by this proposal. Credential/accounting/current-authority prerequisites must be concrete before root apply is offered.

Then governed V11 rollout,21 Teatri drafts/reviews and THS HUMAN acceptance, followed by CSV13 real ACK/lineage/dedup/merge/search proof. Production cards and end-to-end CSV remain open.
