# Keycloak26.7.4 caller-audience prerequisite and conditional IAM-owner review — 2026-10-13

Target image82a77884f3af238beab1e7afd63b5f530e1b5c0590bd7aa60b40a40463e29b2c declares26.7.4. HTTPS/discovery and one proposed peer were observed with system CA/hostname validation. Retained install proposal hashdb882da50e7b1da53ade4b8b1a3bb22421b0b421670c1e9977d804680c3b741a; snapshot7e0f46ad0f66ee40b2ce0f662fdb70007744f81f933865264fdf279227681927; v3 candidateb825fe2618383935064f80b5321758a8a9b92b120185297787777a370e41cc7b. Existing26.0.8-based static mapper review remains retained, not upgraded to26.7.4 runtime admission.

## Version-specific evidence

Official [AccessTokenIntrospectionProvider.verifyAudience](https://github.com/keycloak/keycloak/blob/26.7.4/services/src/main/java/org/keycloak/protocol/oidc/AccessTokenIntrospectionProvider.java) requires the authenticated introspection caller among original/transformed token audiences, unless an independently configured server/client compatibility exception applies. The worker uses its SERVICE client for grant and introspection, so the application audience alone does not prove this prerequisite. Presence of audience-resolve does not prove the caller's client roles. Do not disable the server/client check to pass qualification.

Official26.7.4 source review covers UserSessionNoteMapper, SubMapper, AcrProtocolMapper, AllowedWebOriginsProtocolMapper, OIDCAttributeMapperHelper, ClientCredentialsGrantType and ServiceAccountConstants. Protected String/single-value client_id/session user subject semantics remain the same; the helper changes for conversion/organization/nested claims are not blanket approval of unknown configurations. [ClientManager](https://github.com/keycloak/keycloak/blob/26.7.4/services/src/main/java/org/keycloak/services/managers/ClientManager.java) now attaches service-account mappers through a scope; the disposable explicit-scope fixture registers the observed standard client_id effect explicitly.

The initial26.7.4 fixture stopped at missing client_id setup; after explicit registration its real grant/introspection stopped with active:false. The next fixture declares the SERVICE client's audience without disabling any checks. No target grant/introspection or IAM mutation has been executed. These fixture failures are not proof that the existing target bearer fails. Existing role-resolved audiences or compatibility settings remain unproven from retained metadata.

## Operator read and review proposal

Exact-file compiler with selected Docker distribution metadata: no IAM/DNS/HTTPS call, credential read, grant, service mutation, runtime directory/budget initialization, signing or R12 effect. Single45second root observation, no retries. Read the exact retained metadata and install proposal with qualified root custody guard, reproduce the v3 candidate and compare it with the embedded candidate. Detect a direct caller-audience mapper only in effective scopes with explicit access/introspection flags.

If a direct caller audience exists, proposed mutations=0. Otherwise create a conditional ONE-mapper IAM-owner proposal: included.client.audience equals the exact registered client, access/introspection=true, id.token=false. Primary application audience, issuer, tenant/actor claims and scope assignments remain unchanged. Deterministic mapper UUID/fixed managed name; retained name/ID collision blocks. Fresh IAM drift/current approved caller-audience reconciliation and the existing IAM owner's approval are prerequisites to any later apply. The planner has no apply operation. It never assumes that role resolution is absent or current tokens fail.

One root0600 private review file at most under the existing evidence parent; original two inputs stay immutable and identical outputs reconcile without rewriting. Public receipt reports bounded booleans/counts/hashes, not client/mapper values or principals. Partial publication stays available for reconciliation. Credential reestablishment, actual current bearer, historical accounting, complete governed installation/current HUMAN+dual role signatures/six mounts and THS/CSV13 remain open.

Six local adversarial/root publication tests pass. Source286c4aa31fcfdefe15fbb2d195dbc2dc239d2036; full current-version CI must be green before delivery; qualification receipt recorded separately.

```bash
set -o pipefail
python3 - <<'PY' | tee ouf-policy-token-introspection-audience-plan.json
import base64,hashlib,pathlib,shutil,subprocess,os
preferred=pathlib.Path.home()/'ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh'
gh=str(preferred) if preferred.is_file() and os.access(preferred,os.X_OK) else shutil.which('gh')
if not gh:raise SystemExit('phase=DELIVERY reason=EXISTING_GH_UNAVAILABLE; no sudo executed')
ref='286c4aa31fcfdefe15fbb2d195dbc2dc239d2036'
sources=[('binding','iam_binding_candidate.py','a8cf18ea78b3acc7261838711345a218e678bfaf11e498dcba6859862d6b655d'),('review','iam_mapper_semantics_review.py','6311342ec38a523a0ae5d1614bc89b359799eae508807a26b5c33b35aa6d1888'),('planner','iam_introspection_audience_plan.py','ae7e2d81a28a88d4296c88ea6cd074eb96628ac69689fb57abe18d080570e80e')]
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
args=['qualified-introspection-audience-plan','--metadata','/etc/ouf/deploy-snapshots/policy-token-iam-metadata-830709d5bc5348309025c3a82212a62e.private.json','--metadata-sha256','7e0f46ad0f66ee40b2ce0f662fdb70007744f81f933865264fdf279227681927','--proposal','/etc/ouf/deploy-snapshots/policy-token-install-inputs-db882da50e7b1da53ade4b8b1a3bb22421b0b421670c1e9977d804680c3b741a.private.json','--proposal-sha256','db882da50e7b1da53ade4b8b1a3bb22421b0b421670c1e9977d804680c3b741a']
bootstrap='import base64,hashlib,sys,types\nrecords='+repr(records)+'\nverified={}\nfor name,payload,expected in records:\n raw=base64.b64decode(payload,validate=True)\n if hashlib.sha256(raw).hexdigest()!=expected:raise SystemExit("phase=ROOT_DELIVERY reason=SOURCE_HASH_MISMATCH")\n verified[name]=raw\nfor label,name in [("binding","iam_binding_candidate"),("review","iam_mapper_semantics_review")]:\n module=types.ModuleType(name)\n sys.modules[name]=module\n exec(compile(verified[label],"qualified-"+label,"exec"),module.__dict__)\nsys.argv='+repr(args)+'\nexec(compile(verified["planner"],"qualified-introspection-audience-plan","exec"),{"__name__":"__main__"})\n'
try:
    result=subprocess.run(['sudo','/usr/bin/python3','-I','-B','-'],input=bootstrap.encode(),timeout=55)
except Exception:raise SystemExit('phase=ROOT_EXECUTION reason=ROOT_EXECUTION_UNAVAILABLE')
raise SystemExit(result.returncode)
PY
```

Return only public JSON. Private mapper proposal stays on the VPS and grants no IAM or runtime authority.

## Image distribution distinction

Official CI26.7.4 image IDb2f3e1b85071d17a1da8d2cbcc54707853d19c74ae027071789ea1bb12b3ec89 differs from observed target82a77884f3af238beab1e7afd63b5f530e1b5c0590bd7aa60b40a40463e29b2c. Same declared version does not prove same artifact. The operator command also performs two bounded selected Docker metadata reads: live selected image/running, then exact image architecture/OS/RepoDigests. A changed image blocks. Private registry names stay only in the private plan; public references are restricted to recognized official repositories and sha256 digests. This provides a route to an exact-distribution comparison, not running-bytecode proof. No Docker lifecycle action, image pull on target, IAM call or configuration mutation is performed. Actual Docker template behavior is qualified on a disposable container.
