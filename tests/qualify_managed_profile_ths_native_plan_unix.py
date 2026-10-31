"""CI only: synthetic Engine metadata over real Unix/root peer, processes and files."""
import copy,http.server,importlib.util,json,os,socketserver,stat,subprocess,sys,threading
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('native_plan_fixture',ROOT/'tests/test_managed_profile_ths_native_plan.py')
f=importlib.util.module_from_spec(spec);spec.loader.exec_module(f);m=f.m
assert os.geteuid()==os.getegid()==0
root=Path('/var/lib/ouf-ths-native-plan-unix-fixture');root.mkdir(mode=0o700);root.chmod(0o700)
case,review,result,journal,cohort,observations,generations,iam,profile,captured=f.fixture()
processes=[];server=None
try:
    for role in generations:
        p=subprocess.Popen(['/usr/bin/sleep','240'],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL);processes.append(p)
        pin=m.process_pin(p.pid);generations[role]=pin;observations[cohort[role]['containerId']]['State']['Pid']=p.pid
    for role in cohort:
        cohort[role]=m.stable_binding(observations[cohort[role]['containerId']])
        review['nativePlan']['proposal']['existingApplications'][role]=copy.deepcopy(cohort[role])
    for n,role in enumerate(('onboarding','mcp'),90):review['nativePlan']['proposal']['existingApplications'][role]['containerId']='%064x'%n
    for role in ('onboarding','mcp'):
        case['nativeBindingHashes'][role]=m.digest(cohort[role]);journal['candidates'][role]['generation']=generations[role]
        result['ownerProofs'][role].update(generation=generations[role],nativeBindingHash=case['nativeBindingHashes'][role])
    old=root/'retained-control';old.mkdir(mode=0o700);old.chmod(0o700)
    iamroot=root/'consumed-iam';iamroot.mkdir(mode=0o700);iamroot.chmod(0o700)
    case['installedRoot']=str(old);case['iamRoot']=str(iamroot);iam['contextPath']=str(iamroot)
    case['iamResultHash']=m.digest(iam);review['executionRoot']=str(old)
    requests=[];seen={};drift=[False]
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            requests.append(self.path)
            if self.path=='/v1.44/info':value=copy.deepcopy(captured['engineInfo'])
            else:
                cid=self.path.split('/')[-2];value=copy.deepcopy(observations[cid]);seen[cid]=seen.get(cid,0)+1
                if drift[0]and cid==cohort['onboarding']['containerId']and seen[cid]>1:value['Config']['Env'].append('UNEXPECTED_DRIFT=1')
            raw=m.encoded(value);self.send_response(200);self.send_header('Content-Length',str(len(raw)));self.end_headers();self.wfile.write(raw)
        def log_message(self,*args):pass
    socket_path=root/'engine.sock'
    server=socketserver.UnixStreamServer(str(socket_path),Handler);socket_path.chmod(0o600)
    thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    st=socket_path.lstat();binding={'socketPath':str(socket_path),'socketBinding':[st.st_dev,st.st_ino,st.st_uid,st.st_gid,stat.S_IMODE(st.st_mode)],'peerCredentials':[os.getpid(),0,0]}
    review['nativePlan']['proposal']['engineBinding']=binding;review['bootId']=Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    case['frozenPlanHash']=m.digest(review['nativePlan']['proposal']);review['frozenPlanHash']=case['frozenPlanHash'];case['reviewHash']=m.digest(review)
    result.update(reviewHash=case['reviewHash'],frozenPlanHash=case['frozenPlanHash']);journal['reviewHash']=case['reviewHash']
    for effect in journal['effects']:
        effect['intentHash']=m.digest({'reviewHash':case['reviewHash'],'stage':effect['stage']})
        if effect['stage']=='VERIFY_FINAL':effect['proof']['ownerProofs']=copy.deepcopy(result['ownerProofs'])
    for folder,name,value in [(old,'review.json',review),(old,'result.json',result),(old,'recovery.json',journal),(iamroot,'result.json',iam),(iamroot,'configuration-profile.json',profile)]:
        path=folder/name;path.write_bytes(m.encoded(value));path.chmod(0o400)
    inputs={path:path.read_bytes()for folder in (old,iamroot)for path in folder.iterdir()}
    cap=m.PlanCapture(root/'positive-scope',13);out=m.prepare(cap,case)
    assert out['complete']and out['counts']['privateMetadataReads']==5 and out['counts']['engineGets']==len(requests)==27
    assert out['unchangedPeers']==12 and out['targetRoles']==['onboarding']and not out['targetApplyAuthorized']and not out['runtimeAuthorityIssued']
    assert out['sqlSessions']==out['iamRequests']==out['engineWrites']==0
    plan=json.loads((cap.root/'execution-plan.json').read_bytes());private=json.loads((cap.root/'execution-inputs.json').read_bytes())
    assert m.digest(plan)==out['conditionalNativePlanHash']and m.digest(private)==out['executionInputsHash']
    assert plan['replacements']['onboarding']['request']['Env']==profile['replacementEnvironment']
    assert all(stat.S_IMODE(p.stat().st_mode)==0o600 for p in cap.root.iterdir())and 'PRIVATE_'not in json.dumps(out)
    saved=(cap.root/'result.json').read_bytes()
    try:m.PlanCapture(cap.root,13);raise AssertionError('scope replayed')
    except m.Stop as e:assert str(e)=='CSV_RECOVERY_CAPTURE_CONSUMED_NO_REPLAY'
    assert (cap.root/'result.json').read_bytes()==saved
    drift[0]=True;seen.clear();bad=m.PlanCapture(root/'negative-drift-scope',13)
    try:m.prepare(bad,case);raise AssertionError('generation drift accepted')
    except m.Stop as e:assert str(e)=='CURRENT_CAPTURE_GENERATION_DRIFT'
    assert not(bad.root/'execution-plan.json').exists()
    assert all(path.read_bytes()==raw for path,raw in inputs.items())
    print(json.dumps({'status':'THS_NATIVE_PLAN_REAL_UNIX_CUSTODY_PASS','metadataReads':5,'engineGetsPositive':27,
        'actualRootPeerAndUnixHttp':True,'real13ProcessPins':True,'oldInputsUnchanged':True,'private600':True,
        'sameImageSingleOnboarding':True,'retainedTwelvePeers':True,'macIpAliasesPortsResourcesPreserved':True,
        'nativePlanAndInputsHashesVerified':True,'driftDeniedBeforePlan':True,'replayDenied':True,
        'iamRequests':0,'sqlSessions':0,'engineWrites':0,'credentialOrConfigurationFileReads':0,
        'syntheticEngineMetadata':True,'targetExecuted':False,'applicationE2EProven':False},sort_keys=True))
finally:
    if server is not None:server.shutdown();server.server_close();thread.join()
    for p in processes:p.terminate()
    for p in processes:p.wait(timeout=5)
