import hashlib,json,pathlib,subprocess,zipfile
from xml.etree import ElementTree as E
archive=pathlib.Path('target/platform-logical-native.zip')
expected='a0f6a91488f28ec5213d334764eb11c72585abb6'
digest=hashlib.sha256(archive.read_bytes()).hexdigest()
assert archive.stat().st_size==132306 and digest=='420541c2374b84930507034aa05b7bcd66ae32298048a438b4ce17062c6d19ed'
with zipfile.ZipFile(archive) as z:
    assert len(z.namelist())==len(set(z.namelist()))
    data={n:z.read(n) for n in z.namelist()}
manifest={}
for line in data['upload-native/SHA256SUMS'].decode().splitlines():
    h,name=line.split('  ',1);assert name not in manifest;manifest[name]=h
assert set(manifest)==set(data)-{'upload-native/SHA256SUMS'}
for name,h in manifest.items():assert hashlib.sha256(data[name]).hexdigest()==h,name
assert data['upload-native/source-commit.txt'].decode().strip()==expected
assert subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip()==expected
bindings=json.loads(data['upload-native/source-bindings.json'])
for path,h in bindings.items():
    assert hashlib.sha256(subprocess.check_output(['git','show',expected+':'+path])).hexdigest()==h,path
suite=E.fromstring(data['surefire-reports/TEST-it.comune.trieste.ouf.onboarding.application.ManagedFileUploadNativeTest.xml'])
assert int(suite.attrib['tests'])==71 and all(int(suite.attrib[k])==0 for k in ('failures','errors','skipped'))
proofs=[]
for value in (False,True):
    p=json.loads(data['upload-native/logical-rollback-'+str(value).lower()+'.json'])
    assert p['externalRevoked'] is value and p['externalGeneration']==2
    assert p['postmasterBefore']==p['postmasterAfter']
    assert p['snapshot']==p['snapshotAfterDeniedAttempts']
    assert p['reconciliationReads']==128 and p['getCalls']==0
    before={k:json.loads(v) for k,v in p['snapshot'].items()}
    assert len(before)==7
    assert before['ouf_authorization.active_policy_bundle'][0]['version']==1
    decision=before['ouf_authorization.storage_recovery_decision'];assert len(decision)==1
    assert decision[0]['state']=='DELIVERED' and decision[0]['authority_generation']==1
    assert decision[0]['runtime_session_id']==p['runtimeSession']
    assert before['ouf_onboarding.storage_recovery_authority_projection'][0]['decision_id']==decision[0]['decision_id']
    proofs.append(dict(externalRevoked=value,postmasterUnchanged=True,runtimeMatchesRestoredDecision=True,restoredTables=len(before),snapshotUnchanged=True,reconciliationReads=128,getCalls=0))
result=dict(status='PASS',artifactId=13410549610,commit=expected,archiveSha256=digest,archiveBytes=archive.stat().st_size,members=len(data),checksums=len(manifest),sourceGitBlobsVerified=len(bindings),nativeTests=71,proofs=proofs,nativeExecutionRepeated=False,targetOperations=0)
pathlib.Path('target/platform-logical-local-readback.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps(result))
