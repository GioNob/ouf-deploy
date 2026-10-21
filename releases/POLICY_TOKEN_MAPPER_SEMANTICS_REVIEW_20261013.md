# Exact retained Keycloak mapper effects review — 2026-10-13

## Evidence and semantics

Target snapshot 7e0f46ad0f66ee40b2ce0f662fdb70007744f81f933865264fdf279227681927 contains29 interpretable mappers. Redacted category observation reports ACR, allowed origins, four user session note mappers and one provider hash84f687b2fa1b64b283570c0fa2d5726c9c2e340b7810ad680db6fe82c77661f1, which equals SHA256(oidc-sub-mapper). The reserved finding is an unnested client_id session-note mapper with explicit access/introspection flags, not a hardcoded claim. Its note value was not printed; the next review verifies the exact allowed source locally.

The review policy is based on official Keycloak26.0.8 source, the qualified disposable version. This does not prove the target provider implementation/version or actual bearer.

- [SubMapper](https://github.com/keycloak/keycloak/blob/26.0.8/services/src/main/java/org/keycloak/protocol/oidc/mappers/SubMapper.java) takes subject from session user ID. Access/introspection flags must be explicit when observed. Other subject writers remain unresolved.
- [UserSessionNoteMapper](https://github.com/keycloak/keycloak/blob/26.0.8/services/src/main/java/org/keycloak/protocol/oidc/mappers/UserSessionNoteMapper.java) maps the selected session note through claim configuration. Only exact client_id, String, single value, explicit access/introspection and note client_id/clientId qualifies as the standard service client binding. Foreign note, nested claim, other reserved claim or missing flags retain review.
- [ClientCredentialsGrantType](https://github.com/keycloak/keycloak/blob/26.0.8/services/src/main/java/org/keycloak/protocol/oidc/grants/ClientCredentialsGrantType.java) sets both current and legacy client notes from the authenticated client. [ServiceAccountConstants](https://github.com/keycloak/keycloak/blob/26.0.8/common/src/main/java/org/keycloak/common/constants/ServiceAccountConstants.java) defines their literal keys.
- [AcrProtocolMapper](https://github.com/keycloak/keycloak/blob/26.0.8/services/src/main/java/org/keycloak/protocol/oidc/mappers/AcrProtocolMapper.java) has a fixed ACR effect; [AllowedWebOriginsProtocolMapper](https://github.com/keycloak/keycloak/blob/26.0.8/services/src/main/java/org/keycloak/protocol/oidc/mappers/AllowedWebOriginsProtocolMapper.java) has a fixed allowed origins effect. These do not choose arbitrary protected claim targets. Custom providers stay unsupported.

## Operator step

A separate review module leaves the previously qualified compiler and all retained files unchanged. It creates a v3 review-only candidate, linked to the v2 parent hash, from the exact enriched snapshot. One new root0600 private file at most, identical outputs reconcile without rewriting; ambiguous/partial outputs block. Zero provider calls, credentials, grants, IAM/service mutations, baseline refresh, budgets or R12 changes. Finite30second root deadline, no internal retries. Custody/read/publication checks reuse the qualified pinned compiler. Target implementation, bearer, credential provenance, peer, historical accounting and current HUMAN/governed installer remain unproven even when static constraints are complete. THS and CSV13 ACK/lineage/search remain open.

Local six adversarial/root publication tests pass; disposable issuer CI qualification must be green before target delivery. Operator command pins source54202c6eda5d50f937d0538f3b2df3d7ee229885 and both hashes. Source qualification receipt is recorded separately.

```bash
set -o pipefail
python3 - <<'PY' | tee ouf-policy-token-mapper-semantics-review.json
import base64,hashlib,pathlib,shutil,subprocess,os
preferred=pathlib.Path.home()/'ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh'
gh=str(preferred) if preferred.is_file() and os.access(preferred,os.X_OK) else shutil.which('gh')
if not gh:raise SystemExit('phase=DELIVERY reason=EXISTING_GH_UNAVAILABLE; no sudo executed')
ref='54202c6eda5d50f937d0538f3b2df3d7ee229885'
sources=[('binding','iam_binding_candidate.py','a8cf18ea78b3acc7261838711345a218e678bfaf11e498dcba6859862d6b655d'),('review','iam_mapper_semantics_review.py','6311342ec38a523a0ae5d1614bc89b359799eae508807a26b5c33b35aa6d1888')]
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
args=['qualified-mapper-semantics-review','--snapshot','/etc/ouf/deploy-snapshots/policy-token-iam-metadata-830709d5bc5348309025c3a82212a62e.private.json','--snapshot-sha256','7e0f46ad0f66ee40b2ce0f662fdb70007744f81f933865264fdf279227681927','--issuer','https://auth.ouf-lab.it/realms/ouf','--tenant','ouf-lab','--audience','ouf-api-gateway']
bootstrap='import base64,hashlib,sys,types\nrecords='+repr(records)+'\nverified={}\nfor name,payload,expected in records:\n raw=base64.b64decode(payload,validate=True)\n if hashlib.sha256(raw).hexdigest()!=expected:raise SystemExit("phase=ROOT_DELIVERY reason=SOURCE_HASH_MISMATCH")\n verified[name]=raw\nmodule=types.ModuleType("iam_binding_candidate")\nsys.modules[module.__name__]=module\nexec(compile(verified["binding"],"qualified-binding","exec"),module.__dict__)\nsys.argv='+repr(args)+'\nexec(compile(verified["review"],"qualified-mapper-semantics-review","exec"),{"__name__":"__main__"})\n'
try:
    result=subprocess.run(['sudo','/usr/bin/python3','-I','-B','-'],input=bootstrap.encode(),timeout=45)
except Exception:raise SystemExit('phase=ROOT_EXECUTION reason=ROOT_EXECUTION_UNAVAILABLE')
raise SystemExit(result.returncode)
PY
```

Return only public JSON; private evidence stays on the VPS. No login or live mapper reread is needed. Failure reports phase/reason and possible partial publication; do not delete existing files, reset budgets or infer runtime acceptance.
