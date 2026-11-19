"""CI only: thirteen disposable peers, real Docker29/root socket/process pins. No SQL."""
import copy,importlib.util,json,os,shutil,socket,stat,struct,subprocess
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('owner_inputs_fixture',ROOT/'tests/test_managed_file_owner_inputs.py');f=importlib.util.module_from_spec(spec);spec.loader.exec_module(f);m=f.m
assert os.geteuid()==os.getegid()==0
root=Path('/var/lib/ouf-owner-inputs-native-ci');root.mkdir(mode=0o700);root.chmod(0o700)
docker=str(Path(shutil.which('docker')).resolve());ids=[]
def cli(*args):return subprocess.check_output([docker,*args],text=True).strip()
def inspect(cid):return json.loads(cli('inspect',cid))[0]
def save(folder,name,value):p=folder/name;p.write_bytes(m.encoded(value));p.chmod(0o400)
try:
    assert cli('version','--format','{{.Server.Version}}')=='29.8.1'
    case,review,result,journal,retained,_,_,_=f.fixture()
    observed={}
    for role in ['onboarding','mcp']+['peer-'+str(i)for i in range(11)]:
        cid=cli('run','-d','--name','ouf-owner-inputs-ci-'+role,'--user','10003:10003','--network','none','-e','PRIVATE_FIXTURE_SECRET=not-public','alpine:3.21','sleep','300');ids.append(cid);observed[role]=inspect(cid)
    cohort={role:m.stable_binding(v)for role,v in observed.items()};generations={role:m.process_pin(v['State']['Pid'])for role,v in observed.items()}
    selected=Path('/var/run/docker.sock').resolve();st=selected.lstat();sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);sock.connect(str(selected))
    peer=list(struct.unpack('3i',sock.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12)));sock.close()
    binding={'socketPath':str(selected),'socketBinding':[st.st_dev,st.st_ino,st.st_uid,st.st_gid,stat.S_IMODE(st.st_mode)],'peerCredentials':peer}
    case.update(installedRoot=str(root/'retained-apply'),ownerReadRoot=str(root/'retained-read'),nativeImageId=observed['onboarding']['Image'],nativeBindingHash=m.digest(cohort['onboarding']))
    # Synthetic predecessor records over actual containers; the database role is opaque, never queried.
    proposal={'existingApplications':copy.deepcopy(cohort),'engineBinding':binding,'boundDatabaseProfile':{'postgresRuntimeBinding':{'containerId':cohort['peer-0']['containerId']}}}
    proposal['existingApplications']['onboarding']['containerId']='f'*64
    case['frozenPlanHash']=m.digest(proposal);review.update(executionRoot=case['installedRoot'],bootId=Path('/proc/sys/kernel/random/boot_id').read_text().strip(),frozenPlanHash=case['frozenPlanHash'],nativePlan={'proposal':proposal})
    case['reviewHash']=m.digest(review)
    result.update(reviewHash=case['reviewHash'],nativeBindingHash=case['nativeBindingHash'],nativeImageId=case['nativeImageId'],generation=generations['onboarding']);case['resultHash']=m.digest(result)
    journal.update(reviewHash=case['reviewHash'],candidates={'onboarding':{'id':cohort['onboarding']['containerId'],'configurationVerified':True,'readinessProven':True,'generation':generations['onboarding']}})
    for e in journal['effects']:e['intentHash']=m.digest({'reviewHash':case['reviewHash'],'stage':e['stage']})
    retained['contextPath']=case['ownerReadRoot'];case['ownerReadHash']=m.digest(retained)
    for folder,values in [(Path(case['installedRoot']),{'review.json':review,'result.json':result,'recovery.json':journal}),(Path(case['ownerReadRoot']),{'result.json':retained})]:
        folder.mkdir(mode=0o700)
        for name,value in values.items():save(folder,name,value)
    before={p:p.read_bytes()for folder in(case['installedRoot'],case['ownerReadRoot'])for p in Path(folder).iterdir()}
    cap=m.Capture(root/'positive',13);out=m.capture_inputs(cap,case)
    assert cap.counts['privateMetadataReads']==4 and cap.counts['engineGets']==27 and out['sqlSessions']==0
    assert out['captureAccounting']['cumulativeCounts']['privateMetadataReads']==7 and out['captureAccounting']['cumulativeCounts']['engineGets']==32
    assert not out['currentJobOrBudgetStateObserved']and not out['databaseSchemaObservedByThisCapture']and not out['runtimeAuthorityIssued']
    assert 'not-public'not in json.dumps(out)and 'not-public'in(cap.root/'inputs.json').read_text()
    assert all(stat.S_IMODE(p.stat().st_mode)==0o600 for p in cap.root.iterdir())
    saved=(cap.root/'result.json').read_bytes()
    try:m.Capture(cap.root,13);raise AssertionError('same scope replayed')
    except m.Stop as error:assert 'NO_REPLAY'in str(error)
    assert (cap.root/'result.json').read_bytes()==saved
    assert all(p.read_bytes()==raw for p,raw in before.items())
    assert all(m.stable_binding(inspect(v['Id']))==cohort[role]for role,v in observed.items())
    # A separate new fixture scope sees the stopped exact peer and denies before any plan or write.
    cli('stop','--time','1',cohort['peer-0']['containerId']);denied=m.Capture(root/'peer-stopped',13)
    try:m.capture_inputs(denied,case);raise AssertionError('stopped retained peer accepted')
    except m.Stop:pass
    assert not(denied.root/'inputs.json').exists()and denied.counts['engineGets']<=14
    print(json.dumps({'status':'OWNER_INPUT_CAPTURE_NATIVE_DOCKER29_PASS','actualDisposableCohort':13,'metadataReads':4,'engineGets':27,'sqlSessions':0,'realUnixRootPeer':True,'realProcessAndNamespacePins':True,'sourceContainersUnchangedInPositiveCase':True,'retainedFilesUnchanged':True,'privateOutputs600':True,'sameScopeReplayDenied':True,'changedPeerDenied':True,'syntheticPredecessorMetadata':True,'browserIdentityProven':False,'databaseSchemaObserved':False,'targetExecuted':False,'applicationE2EProven':False},sort_keys=True))
finally:
    for cid in ids:subprocess.run([docker,'rm','-f',cid],capture_output=True)
