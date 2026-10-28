"""CI-only real Keycloak/Docker/PTY correction, including lost write responses."""
import copy,hashlib,importlib.util,json,os,pwd,re,select,signal,socket,stat,struct,subprocess,sys,termios,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('physical_correction',ROOT/'scripts/correct-managed-profile-ths-iam-bindings-20261028.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
assert os.geteuid()==os.getegid()==0 and os.environ.get('GITHUB_ACTIONS')=='true'
root=Path('/var/lib/ouf-ths-iam-correction-physical');root.mkdir(mode=0o700);root.chmod(0o700);containers=[]
def run(argv,**kwargs):return subprocess.run(argv,capture_output=True,check=True,timeout=240,**kwargs)
def start(argv):
 cid=run(['docker','run','-d','--network','none']+argv).stdout.decode().strip();containers.append(cid);return cid
def inspect(cid):return json.loads(run(['docker','inspect',cid]).stdout)[0]
def protected(path,value):path.write_bytes(m.encoded(value)if not isinstance(value,bytes)else value);path.chmod(0o400)

SETUP=r'''import hashlib,http.client,json,sys,urllib.parse
v=json.load(sys.stdin);h=http.client.HTTPConnection('127.0.0.1',8080,timeout=8)
def sha(x):return hashlib.sha256(json.dumps(x,sort_keys=True,separators=(',',':')).encode()).hexdigest()
def call(method,path,body=None,token=None):
 headers={'Content-Type':'application/json','Accept':'application/json'}
 if token:headers['Authorization']='Bearer '+token
 h.request(method,path,body=json.dumps(body)if body is not None else None,headers=headers);r=h.getresponse();raw=r.read();assert r.status in(200,201,204),r.status
 return json.loads(raw)if raw else None
form=urllib.parse.urlencode({'client_id':'admin-cli','grant_type':'password','username':'fixture-admin','password':v['password'],'scope':'openid'})
h.request('POST','/realms/master/protocol/openid-connect/token',body=form,headers={'Content-Type':'application/x-www-form-urlencoded'});r=h.getresponse();assert r.status==200;token=json.loads(r.read())['access_token']
base='/admin/realms/'+v['realm']
if v['create']:
 call('POST','/admin/realms',{'realm':v['realm'],'enabled':True},token)
 call('POST',base+'/clients',{'clientId':v['clientId'],'enabled':True,'protocol':'openid-connect','standardFlowEnabled':True,'publicClient':False,'secret':'PRIVATE_CLIENT_SECRET_CANARY'},token)
 for name in v['required'][:2]:call('POST',base+'/client-scopes',{'name':name,'protocol':'openid-connect','attributes':{'include.in.token.scope':'true'}},token)
client=call('GET',base+'/clients?clientId='+v['clientId']+'&exact=true',token=token)[0];client=call('GET',base+'/clients/'+client['id'],token=token)
definitions=call('GET',base+'/client-scopes',token=token);roles={}
for row in definitions:
 if row['name']in v['required']:roles[row['name']]=call('GET',base+'/client-scopes/'+row['id']+'/scope-mappings',token=token)
defaults=call('GET',base+'/clients/'+client['id']+'/default-client-scopes',token=token);optionals=call('GET',base+'/clients/'+client['id']+'/optional-client-scopes',token=token)
static={k:x for k,x in client.items()if k not in ('secret','registrationAccessToken','defaultClientScopes','optionalClientScopes')}
fields=('id','clientId','enabled','protocol','standardFlowEnabled','publicClient','consentRequired','fullScopeAllowed','directAccessGrantsEnabled','serviceAccountsEnabled')
result={'client':{k:client[k]for k in fields if k in client},'defaults':defaults,'optionals':optionals,'definitions':definitions,'roles':roles,
        'clientIntegrity':sha(static),'definitionIntegrity':{row['id']:{'name':row['name'],'metadataHash':sha(row)}for row in definitions},
        'realmDefaults':{'DEFAULT':call('GET',base+'/default-default-client-scopes',token=token),'OPTIONAL':call('GET',base+'/default-optional-client-scopes',token=token)}}
print(json.dumps(result))
'''
def setup(pid,realm,client_id,create):
 p=run(['nsenter','--target',str(pid),'--net','--','/usr/bin/python3','-I','-S','-B','-c',SETUP],input=m.encoded({'password':'PRIVATE_IAM_PASSWORD_CANARY','realm':realm,'clientId':client_id,'create':create,'required':list(m.REQUIRED)}))
 return json.loads(p.stdout)

def pty_run(harness,*,approval=True):
 import errno,pty
 pid,fd=pty.fork()
 if pid==0:os.execv('/usr/bin/python3',['/usr/bin/python3','-I','-S','-B',str(harness)])
 raw=b'';sent=0;ended=False;deadline=time.monotonic()+110
 try:
  while time.monotonic()<deadline:
   if select.select([fd],[],[],.2)[0]:
    try:part=os.read(fd,65536)
    except OSError as error:
     if error.errno==errno.EIO:ended=True;break
     raise
    if not part:ended=True;break
    raw+=part
    if approval and sent==0 and raw.endswith(b'> ')and b'Scrivi esattamente: 'in raw:
     phrase=raw.rsplit(b'Scrivi esattamente: ',1)[1].split(b'\r\n',1)[0];assert re.fullmatch(rb'APPROVO CORREZIONE IAM [a-f0-9]{64}',phrase)
     os.write(fd,phrase+b'\n');sent=1
    elif approval and sent==1 and raw.endswith(b'> ')and b'Password IAM per fixture-admin'in raw:
     assert not(termios.tcgetattr(fd)[3]&termios.ECHO);os.write(fd,b'PRIVATE_IAM_PASSWORD_CANARY\n');sent=2
  if not ended:os.kill(pid,signal.SIGKILL);raise AssertionError('finite correction fixture PTY timeout')
  _,status=os.waitpid(pid,0);return os.waitstatus_to_exitcode(status),raw.decode().replace('\r\n','\n')
 finally:os.close(fd)

try:
 iam_id=start(['-e','KC_BOOTSTRAP_ADMIN_USERNAME=fixture-admin','-e','KC_BOOTSTRAP_ADMIN_PASSWORD=PRIVATE_IAM_PASSWORD_CANARY','quay.io/keycloak/keycloak:26.2.5','start-dev','--hostname=https://idp.fixture.test'])
 ready=False
 for _ in range(120):
  p=subprocess.run(['docker','exec',iam_id,'bash','-c','exec 3<>/dev/tcp/127.0.0.1/8080'],capture_output=True,timeout=5)
  if p.returncode==0:ready=True;break
  time.sleep(.5)
 assert ready,'Disposable Keycloak did not become ready';iam=inspect(iam_id)
 try:account=pwd.getpwnam('oufadmin')
 except KeyError:run(['/usr/sbin/useradd','-M','-U','oufadmin']);account=pwd.getpwnam('oufadmin')
 results=[]
 for number,drop in enumerate((False,True),1):
  fixture=root/str(number);fixture.mkdir(mode=0o700);realm='fixture-'+str(number);client_id='fixture-ths-'+str(number)
  before=setup(iam['State']['Pid'],realm,client_id,True)
  report=m.binding_report(before['client'],before['defaults'],before['optionals'],before['definitions'],before['roles'],expected_client=client_id)
  assert not report['bindingAndUnrestrictedEligibilityProven']and report['requiredScopes'][2]['defined']is False
  overlay=fixture/'overlay.json';protected(overlay,{'fixtureOnly':True,'clientId':client_id});os.chown(overlay,10003,10003)
  request={m.SCOPE_PROPERTY:['openid','resolution.issue.read','resolution.match.approve']}
  onb_id=start(['--read-only','--mount','type=bind,src='+str(overlay)+',dst=/run/secrets/onboarding-ths.yaml,readonly','-e','SPRING_APPLICATION_JSON='+json.dumps(request),
                'python:3.13.5-slim','python3','-I','-S','-B','-c','import time;time.sleep(600)']);onb=inspect(onb_id)
  sock=Path('/var/run/docker.sock').resolve();st=sock.stat();connection=socket.socket(socket.AF_UNIX);connection.connect(str(sock));peer=list(struct.unpack('3i',connection.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12)));connection.close();assert peer[1:]==[0,0]
  binding={'socketPath':str(sock),'socketBinding':[st.st_dev,st.st_ino,st.st_uid,st.st_gid,stat.S_IMODE(st.st_mode)],'peerCredentials':peer}
  old=fixture/'client-selection';old.mkdir(mode=0o700);parent_root=fixture/'retained-iam-read';parent_root.mkdir(mode=0o700)
  identity={'authorizationGrantTypeConfigured':'authorization_code','registrationId':'ouf-ths','clientId':client_id,'issuer':'https://idp.fixture.test/realms/'+realm,'realm':realm,'providerId':'fixture','providerIdExplicit':True,'fileSelectionAndPrecedenceVerified':True,'selectedMountTarget':'/run/secrets/onboarding-ths.yaml'}
  file_binding={'path':str(overlay),'sha256':hashlib.sha256(overlay.read_bytes()).hexdigest(),'metadata':list(m.frame(overlay.stat()))}
  inputs={'schema':'ouf.managed-profile-ths-client-selection-inputs.v1','priorInputsHash':'4'*64,'bootId':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'engineBinding':binding,
          'currentObservations':{'onboarding':onb,'iam':iam},'currentProcessPins':{'onboarding':m.process_pin(onb['State']['Pid']),'iam':m.process_pin(iam['State']['Pid'])},
          'currentRootProcessPins':{'pid1':m.process_pin(1),'engine':m.process_pin(peer[0])},'iamRole':'iam','clientMetadata':identity,'overlayBinding':file_binding,
          **{k:False for k in ('executionEntryQualified','runtimeAuthorityIssued','targetApplyAuthorized','automaticReplayAllowed','budgetReset')}}
  case=copy.deepcopy(m.CASE);case.update(iamContainerName=iam['Name'],priorRoot=str(old),parentRoot=str(parent_root),outputRoot=str(fixture/'current-correction'),inputsHash=m.digest(inputs),priorInputsHash='4'*64,priorCounts={'fixture':True},
          clientId=client_id,issuer=identity['issuer'],realm=realm,overlaySha256=file_binding['sha256'],installationRef='disposable-profile-'+str(number),expectedObservation=report,
          expectedEngineVersion=json.loads(run(['docker','info','--format','{{json .ServerVersion}}']).stdout))
  case['adminEndpoint']['expectedAdminUser']='fixture-admin'
  receipt={'schema':'ouf.managed-profile-ths-client-selection-result.v1','complete':True,'status':'MANAGED_PROFILE_THS_CLIENT_SELECTED_IAM_BINDING_NOT_OBSERVED','contextPath':str(old),'inputsHash':case['inputsHash'],'priorInputsHash':'4'*64,'counts':case['priorCounts'],'clientMetadata':identity,'mountedFileContentIdentityProven':True,'sameImageAndGeneration':True,
           **{k:0 for k in ('iamRequests','oauthRequests','engineWrites','humanBudgetsGranted','resumes')}}
  parent={'schema':'ouf.managed-profile-ths-iam-binding-read-result.v1','status':'THS_IAM_BINDINGS_OBSERVED_CONFIGURATION_PROFILE_BLOCKED','complete':True,'contextPath':str(parent_root),'retainedClientInputsHash':case['inputsHash'],'bindingObservation':report,
          'configurationProfilePrepared':False,'configurationProfileHash':None,'adminIdentityApiVerified':True,'counts':{'oauthRequestsReserved':1,'adminGetsReserved':14,'engineGets':5,'privateMetadataReads':2},
          **{k:0 for k in ('iamMutations','engineWrites','humanBudgetsGranted','resumes')},**{k:False for k in ('runtimeAuthorityIssued','targetApplyAuthorized','automaticReplayAllowed','budgetReset','scopePatchApplied')}}
  case['parentResultHash']=m.digest(parent)
  protected(old/'inputs.json',inputs);protected(old/'result.json',receipt);protected(parent_root/'result.json',parent)
  history={str(p):p.read_bytes()for p in [old/'inputs.json',old/'result.json',parent_root/'result.json']}
  code=Path('/usr/local/lib/ouf-ths-iam-correction-fixture-'+str(number));code.mkdir(mode=0o700)
  protected(code/'apply.py',(ROOT/'scripts/correct-managed-profile-ths-iam-bindings-20261028.py').read_bytes());protected(code/'case.json',case)
  harness=code/'harness.py';text='import importlib.util,json,os,sys\nfrom pathlib import Path\ns=importlib.util.spec_from_file_location("sealed_correction",'+repr(str(code/'apply.py'))+');m=importlib.util.module_from_spec(s);s.loader.exec_module(m)\nm.CASE.update(json.loads(Path('+repr(str(code/'case.json'))+').read_bytes()))\nos.environ["SUDO_UID"]='+repr(str(account.pw_uid))+'\nsys.argv=['+repr(str(code/'apply.py'))+']\n'
  if drop:
   text+='''real=m.dispatch_correction
def lose_response(program,namespace,payload):
 value=real(program,namespace,payload)
 if payload['operation']in('CREATE_SCOPE','ASSIGN_OPTIONAL')and value['status']in(201,204):return {'status':0,'body':None,'retryAfter':'','bytes':value['bytes'],'location':''}
 return value
m.execute_correction.__kwdefaults__['sender']=lose_response
'''
  text+='raise SystemExit(m.main())\n';protected(harness,text.encode())
  status,output=pty_run(harness);assert status==0,output
  result=json.loads(output.splitlines()[-1]);assert result['complete']and result['configurationProfilePrepared']and result['iamMutations']==4,result
  assert result['counts']['oauthRequestsReserved']==1 and result['counts']['iamWritesReserved']==4 and result['counts']['iamWritesObserved']==4
  assert result['counts']['adminGetsReserved']==29 and result['counts']['engineGets']==7 and result['counts']['privateMetadataReads']==3,result
  assert not result['scopePatchApplied']and not result['targetApplyAuthorized']and result['humanBudgetsGranted']==0
  after=setup(iam['State']['Pid'],realm,client_id,False)
  assert before['clientIntegrity']==after['clientIntegrity']
  assert m.link_map(before['defaults'])==m.link_map(after['defaults'])
  want={**m.link_map(before['optionals']),**{r['id']:r['name']for r in result['bindingObservation']['requiredScopes']}}
  assert m.link_map(after['optionals'])==want
  assert all(after['definitionIntegrity'][k]==v for k,v in before['definitionIntegrity'].items())and len(after['definitionIntegrity'])==len(before['definitionIntegrity'])+1
  assert all(m.link_map(before['realmDefaults'][k])==m.link_map(after['realmDefaults'][k])for k in ('DEFAULT','OPTIONAL'))
  assert all(Path(p).read_bytes()==value for p,value in history.items())
  current=Path(case['outputRoot']);saved={p.name:p.read_bytes()for p in current.iterdir()}
  for path in current.iterdir():
   assert stat.S_IMODE(path.stat().st_mode)==0o600
   assert b'PRIVATE_IAM_'not in path.read_bytes()and b'PRIVATE_CLIENT_'not in path.read_bytes()and not re.search(rb'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+',path.read_bytes())
  assert 'PRIVATE_IAM_'not in output and'PRIVATE_CLIENT_'not in output
  replay_status,replay=pty_run(harness,approval=False);assert replay_status==2 and'THS_IAM_CORRECTION_SCOPE_CONSUMED_NO_REPLAY'in replay
  assert all(p.read_bytes()==saved[p.name]for p in current.iterdir())
  results.append({'fixtureProfile':number,'lostWriteResponsesInjected':drop,'actualWrites':4,'writesObserved':result['counts']['iamWritesObserved'],'getAttempts':29,'oldBindingsAndDefinitionsPreserved':True,'realmDefaultsUnchanged':True,'newSecretMaterialPersisted':False,'noReplay':True})
 print(json.dumps({'status':'THS_IAM_CORRECTION_REAL_KEYCLOAK_DOCKER_PTY_PASS','keycloakVersion':'26.2.5','profiles':results,
                  'actualNamespaceProcessRootMountAndProvider':True,'protectedRoot400Source':True,'privateState600':True,'fixtureConsentOnly':True,'productionConsentSimulated':False,'targetExecuted':False,'runtimeAuthorityIssued':False,'applicationE2EProven':False},sort_keys=True))
finally:
 for cid in reversed(containers):subprocess.run(['docker','rm','-f',cid],capture_output=True,timeout=30)
