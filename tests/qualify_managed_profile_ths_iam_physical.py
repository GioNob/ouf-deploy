"""Disposable CI only: real Docker/setns/PTY/Keycloak26, no production authority."""
import copy,hashlib,importlib.util,json,os,pwd,re,select,signal,socket,stat,struct,subprocess,sys,termios,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('physical_iam_reader',ROOT/'scripts/read-managed-profile-ths-iam-bindings-20261028.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
assert os.geteuid()==os.getegid()==0 and os.environ.get('GITHUB_ACTIONS')=='true'
root=Path('/var/lib/ouf-ths-iam-physical');root.mkdir(mode=0o700);root.chmod(0o700)
containers=[]
def run(argv,**kwargs):return subprocess.run(argv,capture_output=True,check=True,timeout=240,**kwargs)
def start(argv):
 cid=run(['docker','run','-d','--network','none']+argv).stdout.decode().strip();containers.append(cid);return cid
def inspect(cid):return json.loads(run(['docker','inspect',cid]).stdout)[0]
def protected(path,value,mode=0o400):
 path.write_bytes(m.encoded(value)if not isinstance(value,bytes)else value);path.chmod(mode)

# Only this fixture setup may create resources. Production CHILD has no such
# verbs/routes; setup and baseline credentials are wholly synthetic.
SETUP=r'''import hashlib,http.client,json,sys,urllib.parse
v=json.load(sys.stdin);h=http.client.HTTPConnection('127.0.0.1',8080,timeout=8)
def call(method,path,body=None,token=None):
 headers={'Content-Type':'application/json','Accept':'application/json'}
 if token:headers['Authorization']='Bearer '+token
 h.request(method,path,body=json.dumps(body)if body is not None else None,headers=headers);r=h.getresponse();raw=r.read();assert r.status in(200,201,204),r.status
 return json.loads(raw)if raw else None
form=urllib.parse.urlencode({'client_id':'admin-cli','grant_type':'password','username':'fixture-admin','password':v['password'],'scope':'openid'})
h.request('POST','/realms/master/protocol/openid-connect/token',body=form,headers={'Content-Type':'application/x-www-form-urlencoded'});r=h.getresponse();assert r.status==200;rbody=json.loads(r.read());token=rbody['access_token'];del rbody
base='/admin/realms/fixture'
if v['create']:
 call('POST','/admin/realms',{'realm':'fixture','enabled':True},token)
 call('POST',base+'/clients',{'clientId':'fixture-authorization-ths','enabled':True,'protocol':'openid-connect','standardFlowEnabled':True,'publicClient':False,'secret':'PRIVATE_CLIENT_SECRET_CANARY'},token)
 client=call('GET',base+'/clients?clientId=fixture-authorization-ths&exact=true',token=token)[0]
 for i,name in enumerate(v['required']):
  call('POST',base+'/client-scopes',{'name':name,'protocol':'openid-connect','attributes':{'include.in.token.scope':'true'}},token)
  row=next(x for x in call('GET',base+'/client-scopes',token=token)if x['name']==name)
  call('PUT',base+'/clients/'+client['id']+('/default-client-scopes/'if i==0 else'/optional-client-scopes/')+row['id'],token=token)
client=call('GET',base+'/clients?clientId=fixture-authorization-ths&exact=true',token=token)[0]
client=call('GET',base+'/clients/'+client['id'],token=token);client.pop('secret',None)
data={'client':client,'defaults':call('GET',base+'/clients/'+client['id']+'/default-client-scopes',token=token),'optionals':call('GET',base+'/clients/'+client['id']+'/optional-client-scopes',token=token),'definitions':call('GET',base+'/client-scopes',token=token)}
print(json.dumps({'baselineHash':hashlib.sha256(json.dumps(data,sort_keys=True,separators=(',',':')).encode()).hexdigest(),'clientUuid':client['id']}))
'''
def setup(pid,create):
 reply=run(['nsenter','--target',str(pid),'--net','--','/usr/bin/python3','-I','-S','-B','-c',SETUP],input=m.encoded({'password':'PRIVATE_IAM_PASSWORD_CANARY','create':create,'required':list(m.REQUIRED)}))
 return json.loads(reply.stdout)

def pty_run(harness,*,credentials=True):
 import errno,pty
 pid,fd=pty.fork()
 if pid==0:os.execv('/usr/bin/python3',['/usr/bin/python3','-I','-S','-B',str(harness)])
 data=b'';sent=0;ended=False;deadline=time.monotonic()+110
 try:
  while time.monotonic()<deadline:
   if select.select([fd],[],[],.2)[0]:
    try:chunk=os.read(fd,65536)
    except OSError as error:
     if error.errno==errno.EIO:ended=True;break
     raise
    if not chunk:ended=True;break
    data+=chunk
    if credentials and sent==0 and data.endswith(b'> ')and b'Scrivi esattamente: 'in data:
     phrase=data.rsplit(b'Scrivi esattamente: ',1)[1].split(b'\r\n',1)[0];assert re.fullmatch(rb'AUTORIZZO LETTURA IAM [0-9a-f]{64}',phrase)
     os.write(fd,phrase+b'\n');sent=1
    elif credentials and sent==1 and b'Password IAM per fixture-admin'in data and data.endswith(b'> '):
     assert not(termios.tcgetattr(fd)[3]&termios.ECHO),'Password echo enabled'
     os.write(fd,b'PRIVATE_IAM_PASSWORD_CANARY\n');sent=2
  if not ended:os.kill(pid,signal.SIGKILL);raise AssertionError('finite fixture PTY timeout')
  _,status=os.waitpid(pid,0);return os.waitstatus_to_exitcode(status),data.decode().replace('\r\n','\n')
 finally:os.close(fd)

try:
 iam_id=start(['-e','KC_BOOTSTRAP_ADMIN_USERNAME=fixture-admin','-e','KC_BOOTSTRAP_ADMIN_PASSWORD=PRIVATE_IAM_PASSWORD_CANARY',
               'quay.io/keycloak/keycloak:26.2.5','start-dev','--hostname=https://idp.fixture.test'])
 ready=False
 for _ in range(120):
  p=subprocess.run(['docker','exec',iam_id,'bash','-c','exec 3<>/dev/tcp/127.0.0.1/8080'],capture_output=True,timeout=5)
  if p.returncode==0:ready=True;break
  time.sleep(.5)
 assert ready,'Disposable IAM did not become ready'
 iam=inspect(iam_id);baseline=setup(iam['State']['Pid'],True)
 overlay=root/'overlay.json';protected(overlay,{'fixture':'not-an-application-config-parser-test'});os.chown(overlay,10003,10003)
 request={'spring.security.oauth2.client.registration.ouf-ths.scope':['openid','resolution.issue.read','resolution.match.approve']}
 onb_id=start(['--read-only','--mount','type=bind,src='+str(overlay)+',dst=/run/secrets/onboarding-ths.yaml,readonly',
               '-e','SPRING_APPLICATION_JSON='+json.dumps(request),'-e','SPRING_CONFIG_ADDITIONAL_LOCATION=file:/run/secrets/onboarding-ths.yaml',
               'python:3.13.5-slim','python3','-I','-S','-B','-c','import time;time.sleep(600)'])
 onb=inspect(onb_id);socket_path=Path('/var/run/docker.sock').resolve();s=socket_path.stat()
 peer=socket.socket(socket.AF_UNIX);peer.connect(str(socket_path));credentials=list(struct.unpack('3i',peer.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12)));peer.close();assert credentials[1:]==[0,0]
 binding={'socketPath':str(socket_path),'socketBinding':[s.st_dev,s.st_ino,s.st_uid,s.st_gid,stat.S_IMODE(s.st_mode)],'peerCredentials':credentials}
 boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip();version=run(['docker','info','--format','{{json .ServerVersion}}']).stdout.decode().strip();version=json.loads(version)
 old=root/'retained-client-selection';old.mkdir(mode=0o700);new=root/'current-iam-read'
 identity={'authorizationGrantTypeConfigured':'authorization_code','registrationId':'ouf-ths','clientId':'fixture-authorization-ths','issuer':'https://idp.fixture.test/realms/fixture','realm':'fixture','providerId':'fixture','providerIdExplicit':True,'fileSelectionAndPrecedenceVerified':True,'selectedMountTarget':'/run/secrets/onboarding-ths.yaml'}
 file_binding={'path':str(overlay),'sha256':hashlib.sha256(overlay.read_bytes()).hexdigest(),'metadata':list(m.frame(overlay.stat()))}
 inputs={'schema':'ouf.managed-profile-ths-client-selection-inputs.v1','priorInputsHash':'4'*64,'bootId':boot,'engineBinding':binding,
         'currentObservations':{'onboarding':onb,'iam':iam},'currentProcessPins':{'onboarding':m.process_pin(onb['State']['Pid']),'iam':m.process_pin(iam['State']['Pid'])},
         'currentRootProcessPins':{'pid1':m.process_pin(1),'engine':m.process_pin(credentials[0])},'iamRole':'iam','clientMetadata':identity,'overlayBinding':file_binding,
         **{k:False for k in ('executionEntryQualified','runtimeAuthorityIssued','targetApplyAuthorized','automaticReplayAllowed','budgetReset')}}
 case=copy.deepcopy(m.CASE);case.update(priorRoot=str(old),outputRoot=str(new),inputsHash=m.digest(inputs),priorInputsHash='4'*64,priorCounts={'fixture':True},clientId=identity['clientId'],issuer=identity['issuer'],realm='fixture',overlaySha256=file_binding['sha256'],installationRef='disposable-ci-profile',expectedEngineVersion=version)
 case['adminEndpoint']['expectedAdminUser']='fixture-admin'
 receipt={'schema':'ouf.managed-profile-ths-client-selection-result.v1','complete':True,'status':'MANAGED_PROFILE_THS_CLIENT_SELECTED_IAM_BINDING_NOT_OBSERVED','contextPath':str(old),'inputsHash':case['inputsHash'],'priorInputsHash':'4'*64,'counts':case['priorCounts'],'clientMetadata':identity,'mountedFileContentIdentityProven':True,'sameImageAndGeneration':True,
          **{k:0 for k in ('iamRequests','oauthRequests','engineWrites','humanBudgetsGranted','resumes')}}
 protected(old/'inputs.json',inputs);protected(old/'result.json',receipt);history={p.name:p.read_bytes()for p in old.iterdir()}
 code=Path('/usr/local/lib/ouf-ths-iam-physical-fixture');code.mkdir(mode=0o700);protected(code/'read.py',(ROOT/'scripts/read-managed-profile-ths-iam-bindings-20261028.py').read_bytes());protected(code/'case.json',case)
 try:account=pwd.getpwnam('oufadmin')
 except KeyError:run(['/usr/sbin/useradd','-M','-U','oufadmin']);account=pwd.getpwnam('oufadmin')
 harness=code/'harness.py';protected(harness,('import importlib.util,json,os,sys\nfrom pathlib import Path\ns=importlib.util.spec_from_file_location("actual_sealed_iam",'+repr(str(code/'read.py'))+');m=importlib.util.module_from_spec(s);s.loader.exec_module(m)\nm.CASE.update(json.loads(Path('+repr(str(code/'case.json'))+').read_bytes()))\nos.environ["SUDO_UID"]='+repr(str(account.pw_uid))+'\nsys.argv=['+repr(str(code/'read.py'))+']\nraise SystemExit(m.main())\n').encode())
 exit_code,output=pty_run(harness);assert exit_code==0,output
 result=json.loads(output.splitlines()[-1]);assert result['complete']and result['configurationProfilePrepared'],result
 assert result['counts']['privateMetadataReads']==2 and result['counts']['engineGets']==5 and result['counts']['oauthRequestsReserved']==1 and result['counts']['adminGetsReserved']==16,result
 assert result['adminIdentityApiVerified']and not result['effectiveBrowserTokenScopesProven']and not result['targetApplyAuthorized']
 assert not('PRIVATE_IAM_'in output or'PRIVATE_CLIENT_'in output)
 for path in new.iterdir():
  data=path.read_bytes();assert stat.S_IMODE(path.stat().st_mode)==0o600
  assert b'PRIVATE_IAM_'not in data and b'PRIVATE_CLIENT_'not in data and not re.search(rb'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+',data),path.name
 assert all(p.read_bytes()==history[p.name]for p in old.iterdir())
 assert setup(iam['State']['Pid'],False)==baseline,'IAM configuration changed'
 saved={p.name:p.read_bytes()for p in new.iterdir()};replay_code,replay=pty_run(harness,credentials=False)
 assert replay_code==2 and 'THS_IAM_READ_SCOPE_CONSUMED_NO_REPLAY'in replay
 assert all(p.read_bytes()==saved[p.name]for p in new.iterdir())
 print(json.dumps({'status':'THS_IAM_REAL_KEYCLOAK_DOCKER_NAMESPACE_PTY_PASS','keycloakVersion':'26.2.5','actualDockerEngineNamespaceAndRootPeer':True,'actualProcessRootAndMountIdentity':True,
                   'protectedRoot400MainExecuted':True,'passwordEchoDisabledAndRestoredByTerminal':True,'fixtureConsentOnly':True,'productionConsentSimulated':False,
                   'newAuthenticationRequestsInReader':1,'adminGetsInReader':16,'engineGetsInReader':5,'privateMetadataReadsInReader':2,'iamConfigurationBeforeAfterEqual':True,
                   'newCredentialOrTokenMaterialPersisted':False,'iamEnvironmentNotRepersisted':True,'oldInputBytesUnchanged':True,'allPrivateFiles600':True,'replayDenied':True,
                   'conditionalProfileOnly':True,'runtimeAuthorityIssued':False,'targetExecuted':False,'applicationE2EProven':False},sort_keys=True))
finally:
 for cid in reversed(containers):subprocess.run(['docker','rm','-f',cid],capture_output=True,timeout=30)
