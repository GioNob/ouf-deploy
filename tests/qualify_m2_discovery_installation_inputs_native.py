"""CI: real Docker29/root peer/process pins, thirteen disposable containers, no DB."""
import copy,importlib.util,json,os,shutil,socket,stat,struct,subprocess
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('binding_fixture',ROOT/'tests/test_m2_discovery_bindings.py')
f=importlib.util.module_from_spec(spec);spec.loader.exec_module(f);m=f.m
assert os.geteuid()==os.getegid()==0
root=Path('/var/lib/ouf-m2-discovery-bindings-native-ci');root.mkdir(mode=0o700);root.chmod(0o700)
docker=str(Path(shutil.which('docker')).resolve());ids=[]
def cli(*args):return subprocess.check_output([docker,*args],text=True).strip()
def inspect(cid):return json.loads(cli('inspect',cid))[0]
def save(folder,name,value):
    path=folder/name;path.write_bytes(m.encoded(value));path.chmod(0o400)
try:
    assert cli('version','--format','{{.Server.Version}}')=='29.8.1'
    case,review,result,journal,_,_=f.fixture()
    observed={}
    for role in ['onboarding']+['peer-'+str(i) for i in range(1,13)]:
        cid=cli('run','-d','--name','ouf-m2-bindings-ci-'+role,'--user','10003:10003',
            '--network','none','-e','PRIVATE_FIXTURE_SECRET=not-public',
            '-e','OUF_SCHEMA_GOV_ENABLED=false','-e','OUF_DISCOVERY_WORKER_ENABLED=false',
            'alpine:3.21','sleep','300')
        ids.append(cid);observed[role]=inspect(cid)
    cohort={role:m.stable_binding(value) for role,value in observed.items()}
    generations={role:m.process_pin(value['State']['Pid']) for role,value in observed.items()}
    selected=Path('/var/run/docker.sock').resolve();info=selected.lstat()
    sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);sock.connect(str(selected))
    peer=list(struct.unpack('3i',sock.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12)));sock.close()
    binding={'socketPath':str(selected),'socketBinding':[info.st_dev,info.st_ino,info.st_uid,info.st_gid,stat.S_IMODE(info.st_mode)],'peerCredentials':peer}
    case.update(installedRoot=str(root/'retained-v38'),outputRoot=str(root/'positive'),
        nativeImageId=observed['onboarding']['Image'],nativeBindingHash=m.digest(cohort['onboarding']))
    proposal={'existingApplications':copy.deepcopy(cohort),'engineBinding':binding}
    proposal['existingApplications']['onboarding']['containerId']='f'*64
    case['frozenPlanHash']=m.digest(proposal)
    review.update(executionRoot=case['installedRoot'],bootId=Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
        frozenPlanHash=case['frozenPlanHash'],nativePlan={'proposal':proposal,'frozenPlanHash':case['frozenPlanHash']})
    case['reviewHash']=m.digest(review)
    result.update(contextPath=case['installedRoot'],reviewHash=case['reviewHash'],
        frozenPlanHash=case['frozenPlanHash'],nativeBindingHash=case['nativeBindingHash'],
        nativeImageId=case['nativeImageId'],generation=generations['onboarding'])
    case['resultHash']=m.digest(result)
    journal.update(reviewHash=case['reviewHash'],candidates={'onboarding':{'id':cohort['onboarding']['containerId'],
        'configurationVerified':True,'readinessProven':True,'generation':generations['onboarding']}})
    for effect in journal['effects']:
        effect['intentHash']=m.digest({'reviewHash':case['reviewHash'],'stage':effect['stage']})
    retained=Path(case['installedRoot']);retained.mkdir(mode=0o700)
    for name,value in [('review.json',review),('result.json',result),('recovery.json',journal)]:save(retained,name,value)
    before={path:path.read_bytes() for path in retained.iterdir()}
    cap=m.Capture(case['outputRoot'],13);out=m.capture_bindings(cap,case)
    assert cap.counts['privateMetadataReads']==3 and cap.counts['engineGets']==27
    assert out['sqlSessions']==out['engineWrites']==out['credentialFileReads']==out['oauthRequests']==0
    assert len(out['bindings'])==13 and all(row['effectiveDiscoveryConfigurationProven'] is False for row in out['bindings'])
    assert 'not-public' not in json.dumps(out) and 'not-public' in (cap.root/'inputs.json').read_text()
    assert all(stat.S_IMODE(path.stat().st_mode)==0o600 for path in cap.root.iterdir())
    saved=(cap.root/'result.json').read_bytes()
    try:m.Capture(cap.root,13);raise AssertionError('scope replayed')
    except m.Stop as error:assert 'NO_REPLAY' in str(error)
    assert (cap.root/'result.json').read_bytes()==saved and all(path.read_bytes()==raw for path,raw in before.items())
    assert all(m.stable_binding(inspect(value['Id']))==cohort[role] for role,value in observed.items())

    # New reader consumes the exact successful synthetic capture as provenance,
    # then observes only four selected live containers; it never replays it.
    spec2=importlib.util.spec_from_file_location('installation_inventory',ROOT/'scripts/read-m2-discovery-installation-inputs-20261029.py')
    inventory=importlib.util.module_from_spec(spec2);spec2.loader.exec_module(inventory)
    new_case=copy.deepcopy(inventory.CASE)
    new_case.update(sourceRoot=str(cap.root),sourceInputsHash=out['inputsHash'],
        sourceResultHash=inventory.digest(out),outputRoot=str(root/'installation-inputs-positive'),targets={})
    for target,old_role in zip(('mcp','semantic','gateway-owner','apisix'),('peer-2','peer-3','peer-4','peer-5')):
        new_case['targets'][target]={'containerId':cohort[old_role]['containerId'],
            'imageId':cohort[old_role]['imageId'],'nativeBindingHash':inventory.digest(cohort[old_role])}
    captured_before={path:path.read_bytes() for path in cap.root.iterdir()}
    native_inventory=inventory.Capture(new_case['outputRoot'],4)
    reference_result=inventory.installation_inputs(native_inventory,new_case)
    assert native_inventory.counts['engineGets']==9 and native_inventory.counts['privateMetadataReads']==2
    assert reference_result['selectedTargetCount']==4 and reference_result['otherNinePeersReobserved'] is False
    assert 'not-public' not in json.dumps(reference_result)
    assert 'not-public' in (native_inventory.root/'inputs.json').read_text()
    assert all(stat.S_IMODE(path.stat().st_mode)==0o600 for path in native_inventory.root.iterdir())
    assert all(path.read_bytes()==raw for path,raw in captured_before.items())
    assert all(inventory.stable_binding(inspect(target['containerId']))==cohort[old_role]
        for target,old_role in zip(new_case['targets'].values(),('peer-2','peer-3','peer-4','peer-5')))
    saved_inventory=(native_inventory.root/'result.json').read_bytes()
    try:inventory.Capture(native_inventory.root,4);raise AssertionError('new inventory scope replayed')
    except inventory.Stop as error:assert 'NO_REPLAY' in str(error)
    assert (native_inventory.root/'result.json').read_bytes()==saved_inventory
    cli('stop','--time','1',cohort['peer-2']['containerId'])
    changed_case={**new_case,'outputRoot':str(root/'installation-inputs-stopped-peer')}
    changed=inventory.Capture(changed_case['outputRoot'],4)
    try:inventory.installation_inputs(changed,changed_case);raise AssertionError('changed selected peer accepted')
    except inventory.Stop:pass
    assert not (changed.root/'inputs.json').exists() and changed.counts['engineGets']<=5
    assert all(path.read_bytes()==raw for path,raw in captured_before.items())
    print(json.dumps({'status':'M2_DISCOVERY_INSTALLATION_INPUTS_NATIVE_PASS','selectedTargets':4,
        'engineGets':9,'metadataReads':2,'realEngine29RootSocketAndProcessPins':True,
        'previousCaptureAndPositiveBindingsUnchanged':True,'privateOutputs600':True,
        'secretValuesExcludedFromPublicOutput':True,'changedPeerAndScopeReplayDenied':True,
        'syntheticPredecessorMetadata':True,'targetExecuted':False,'applicationE2EProven':False},sort_keys=True))

    cli('stop','--time','1',cohort['peer-1']['containerId'])
    denied_case={**case,'outputRoot':str(root/'changed-peer')}
    denied=m.Capture(denied_case['outputRoot'],13)
    try:m.capture_bindings(denied,denied_case);raise AssertionError('stopped peer accepted')
    except m.Stop:pass
    assert not (denied.root/'inputs.json').exists() and denied.counts['engineGets']<=14
    print(json.dumps({'status':'M2_DISCOVERY_BINDINGS_NATIVE_DOCKER29_PASS','actualDisposableCohort':13,
        'metadataReads':3,'engineGets':27,'realUnixRootPeer':True,'actualProcessNamespacePins':True,
        'retainedFilesAndPositiveContainerBindingsUnchanged':True,'privateOutputs600':True,
        'secretValuesExcludedFromPublicOutput':True,'sameScopeReplayDenied':True,'changedPeerDenied':True,
        'effectiveProviderConfigurationProven':False,'sqlSessions':0,'oauthRequests':0,
        'syntheticPredecessorMetadata':True,'targetExecuted':False,'applicationE2EProven':False},sort_keys=True))
finally:
    for cid in ids:subprocess.run([docker,'rm','-f',cid],capture_output=True)

