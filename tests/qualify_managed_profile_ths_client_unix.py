"""CI only. Real root custody/SO_PEERCRED and mounted inode; synthetic container/process metadata."""
import copy,hashlib,http.server,importlib.util,json,os,socketserver,stat,threading
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('client_fixture',ROOT/'tests/test_managed_profile_ths_client.py');f=importlib.util.module_from_spec(spec);spec.loader.exec_module(f);m=f.m
assert os.geteuid()==os.getegid()==0
root=Path('/var/lib/ouf-ths-client-unix-fixture');root.mkdir(mode=0o700);root.chmod(0o700)
# Disposable hosted runner /opt may belong to its runner account. Build the
# production-shaped ancestry in this CI fixture; never relax the source guard.
os.chown('/opt',0,0);os.chmod('/opt',0o755)
config=Path('/opt/ouf/secrets/onboarding-ths.yaml')
config.parent.parent.mkdir(exist_ok=True);os.chown(config.parent.parent,1000,1000);config.parent.parent.chmod(0o750)
config.parent.mkdir();os.chown(config.parent,1000,1000);config.parent.chmod(0o700)
case,review,inputs,receipt,raw,retained=f.fixture(str(config));config.write_bytes(raw);os.chown(config,10003,10003);config.chmod(0o400)
retained['binding']['metadata']=list(m.frame(config.stat()))
# Use the actual CI process root for the positive mounted-file identity check.
onb=inputs['currentObservations']['onboarding'];onb['State']['Pid']=os.getpid()
onb['Mounts'][0]['Destination']=retained['target']=str(config)
onb['Config']['Env'][-1]='SPRING_CONFIG_ADDITIONAL_LOCATION=file:'+str(config)
inputs['currentProcessPins']['onboarding']=m.process_pin(os.getpid())
inputs['scopeInspection'],inputs['conditionalOnboardingEnvironment']=m.scope_patch(onb)
receipt['scopeInspection']=inputs['scopeInspection'];case['onboardingBindingHash']=m.digest(m.stable_binding(onb))
old=root/'scope-capture';old.mkdir(mode=0o700);case['priorRoot']=str(old);receipt['contextPath']=str(old)
installed=root/'installed-update';installed.mkdir(mode=0o700);case['installedRoot']=str(installed);review['executionRoot']=str(installed)
observations={v['Id']:v for v in inputs['currentObservations'].values()};requests=[];drift=[False];seen={}
class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        requests.append(self.path)
        if self.path=='/v1.44/info':value={'ServerVersion':'29.8.1'}
        else:
            cid=self.path.split('/')[-2];value=copy.deepcopy(observations[cid]);seen[cid]=seen.get(cid,0)+1
            if drift[0]and value['Name']=='/onboarding'and seen[cid]>1:value['Config']['Env'].append('DRIFT=1')
        data=m.encoded(value);self.send_response(200);self.send_header('Content-Length',str(len(data)));self.end_headers();self.wfile.write(data)
    def log_message(self,*args):pass
server=socketserver.UnixStreamServer(str(root/'engine.sock'),Handler);(root/'engine.sock').chmod(0o600)
thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
s=(root/'engine.sock').lstat();binding={'socketPath':str(root/'engine.sock'),'socketBinding':[s.st_dev,s.st_ino,s.st_uid,s.st_gid,stat.S_IMODE(s.st_mode)],'peerCredentials':[os.getpid(),0,0]}
inputs['engineBinding']=review['nativePlan']['proposal']['engineBinding']=binding
inputs['currentRootProcessPins']={'pid1':m.process_pin(1),'engine':m.process_pin(os.getpid())}
case['frozenPlanHash']=review['frozenPlanHash']=m.digest(review['nativePlan']['proposal'])
inputs['retainedReviewHash']=case['reviewHash']=m.digest(review);receipt['inputsHash']=case['inputsHash']=m.digest(inputs)
for path,value in [(old/'inputs.json',inputs),(old/'result.json',receipt),(installed/'review.json',review)]:path.write_bytes(m.encoded(value));path.chmod(0o400)
history={str(p):p.read_bytes()for p in [old/'inputs.json',old/'result.json',installed/'review.json',config]}
boot=root/'boot';boot.write_text('fixture-boot');boot.chmod(0o400)
pins={v['pid']:v for v in inputs['currentProcessPins'].values()};pins[1]=m.process_pin(1);pins[os.getpid()]=m.process_pin(os.getpid())
try:
    cap=m.Capture(root/'positive-scope',2)
    out=m.inspect_client(cap,case,pin=lambda pid:pins[pid],boot_path=boot)
    assert out['complete']and out['counts']['engineGets']==len(requests)==5 and out['counts']['privateMetadataReads']==3 and out['counts']['configurationFileContentReads']==1
    assert out['clientMetadata']['clientId']=='human-ui-fixture'and not out['clientMetadata']['iamBindingObserved']
    assert out['mountedFileContentIdentityProven']and not out['scopePatchApplied']and not out['targetApplyAuthorized']
    assert all(stat.S_IMODE(p.stat().st_mode)==0o600 for p in cap.root.iterdir())
    assert all(b'NEVER_PUBLIC_PRIVATE_CANARY'not in p.read_bytes()for p in cap.root.iterdir())
    saved=(cap.root/'result.json').read_bytes()
    try:m.Capture(cap.root,2);raise AssertionError('replayed')
    except m.Stop as error:assert 'NO_REPLAY'in str(error)
    assert saved==(cap.root/'result.json').read_bytes()
    drift[0]=True;seen.clear();bad=m.Capture(root/'negative-generation-scope',2)
    try:m.inspect_client(bad,case,pin=lambda pid:pins[pid],boot_path=boot);raise AssertionError('drift accepted')
    except m.Stop as error:assert str(error)=='EXACT_CAPTURED_THS_AND_IAM_GENERATIONS_REQUIRED'
    drift[0]=False;seen.clear();badmount=m.Capture(root/'negative-mounted-file-scope',2)
    other=root/'different-inode';other.write_bytes(raw);other.chmod(0o400)
    try:m.inspect_client(badmount,case,pin=lambda pid:pins[pid],boot_path=boot,mounted_stat=lambda _:other.stat());raise AssertionError('different mount accepted')
    except m.Stop as error:assert str(error)=='MOUNTED_OWNER_FILE_CONTENT_IDENTITY_REQUIRED'
    assert all(Path(p).read_bytes()==data for p,data in history.items())
    print(json.dumps({'status':'THS_CLIENT_SELECTION_REAL_UNIX_AND_ROOT_CUSTODY_PASS','metadataReadsPositive':3,'engineGetsPositive':5,'configurationFileReadsPositive':1,
                     'actualUnixHttpAndRootPeerCredentials':True,'actualPositiveProcessRootAndFileIdentity':True,'observedOwnerCustody10003Mode400':True,'rawOverlayNotRetained':True,'credentialValuesPrinted':False,
                     'retainedInputsUnchanged':True,'privateMode600':True,'noReplay':True,'generationDriftDenied':True,'differentMountedInodeDenied':True,
                     'iamRequests':0,'oauthRequests':0,'engineWrites':0,'runtimeAuthorityIssued':False,'targetExecuted':False},sort_keys=True))
finally:server.shutdown();server.server_close();thread.join()
