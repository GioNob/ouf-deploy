"""Post-correction Engine and native health GETs; no auth, logs or lifecycle calls."""
import hashlib,http.client,importlib.util,json,re,signal,socket,sys
from pathlib import Path
spec=importlib.util.spec_from_file_location('retained_read',Path(__file__).with_name('read-retained-udp-startup.py'));m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
def probe(address,selection):
 m.require(re.fullmatch(r'172\.18\.0\.[0-9]{1,3}',address)and selection['port']==8080 and selection['path']in('/actuator/health/readiness','/health/ready'),'CLOSED_NATIVE_HEALTH_TARGET_REQUIRED')
 c=http.client.HTTPConnection(address,selection['port'],timeout=3)
 try:
  c.request('GET',selection['path'],headers={'Connection':'close','Accept':'application/json'});r=c.getresponse();raw=r.read(4097)
  m.require(len(raw)<=4096,'HEALTH_RESPONSE_BOUND');status=None
  if raw:
   try:value=json.loads(raw)
   except(ValueError,UnicodeError):value={}
   if type(value)is dict and value.get('status')in('UP','DOWN','OUT_OF_SERVICE','UNKNOWN'):status=value['status']
  return {'httpStatus':r.status,'nativeStatus':status,'ready':r.status==204 or(r.status==200 and status=='UP'),'bodyPrinted':False,'redirectFollowed':False,'requests':1}
 except (OSError,http.client.HTTPException)as error:return {'ready':False,'errorClass':type(error).__name__,'exceptionMessagePrinted':False,'requests':1,'automaticRetry':False}
 finally:c.close()
def state(row):
 value=row['state'];m.require(type(value['Running'])is bool and value['Status']in('created','running','paused','restarting','removing','exited','dead'),'CLOSED_PROCESS_STATE_REQUIRED')
 return {'running':value['Running'],'status':value['Status'],'pid':value['Pid'],'startedAt':value['StartedAt'],'restartCount':row['restarts'],'health':value.get('Health',{}).get('Status')if value.get('Health',{}).get('Status')in('healthy','unhealthy','starting')else None,'engineErrorPresent':bool(value.get('Error'))}
def collect(profile,applications,probes,probe_fn=probe):
 m.require(set(probes)=={'schema','applications'}and probes['schema']=='ouf.post-host-network-native-health-profile.v1'and set(probes['applications'])==set(applications['currentApplications'])=={'udp','mcp','onboarding'},'CLOSED_HEALTH_PROFILE_REQUIRED')
 ids=[v['containerId']for v in profile['moves']]+[v['containerId']for v in applications['currentApplications'].values()]
 m.require(len(ids)==len(set(ids))==9 and all(re.fullmatch('[a-f0-9]{64}',v)for v in ids),'EXACT_NINE_CONTAINER_SCOPE_REQUIRED')
 fmt='{"id":{{json .Id}},"name":{{json .Name}},"image":{{json .Image}},"revision":{{json (index .Config.Labels "org.opencontainers.image.revision")}},"state":{{json .State}},"restarts":{{json .RestartCount}},"networks":{{json .NetworkSettings.Networks}}}'
 def read():
  rows=[json.loads(line)for line in m.invoke(['inspect','--type','container','--format',fmt,*ids]).splitlines()if line];m.require(len(rows)==9 and {v['id']for v in rows}==set(ids),'EXACT_INSPECT_REQUIRED');return {v['id']:v for v in rows}
 before=read();n=profile['network'];moves=[]
 for pin in profile['moves']:
  row=before[pin['containerId']];m.require(row['image']==pin['imageId']and row['name']=='/'+pin['name'],'CORRECTED_CONTAINER_IDENTITY_CHANGED');e=row['networks'][n['name']]
  m.require(e['NetworkID']==n['id']and e['IPAddress']==pin['newIPv4']and e.get('IPAMConfig')=={'IPv4Address':pin['newIPv4']},'CORRECTED_STATIC_ENDPOINT_NOT_PRESENT')
  moves.append({'name':pin['name'],'containerId':row['id'],'ipv4':e['IPAddress'],'fixedDeclarationMatches':True,'process':state(row)})
 result={}
 for role,pin in applications['currentApplications'].items():
  row=before[pin['containerId']];m.require(row['image']==pin['imageId']and row['revision']==pin['sourceCommit'],'RETAINED_APPLICATION_IDENTITY_CHANGED')
  selected=probes['applications'][role];endpoint=row['networks'][n['name']];m.require(endpoint['NetworkID']==n['id']and endpoint['IPAddress']==selected['ipv4'],'EXACT_APPLICATION_ADDRESS_REQUIRED')
  process=state(row);health=probe_fn(endpoint['IPAddress'],selected)if process['running']else{'ready':False,'notCalled':'PROCESS_NOT_RUNNING','requests':0}
  result[role]={'containerId':row['id'],'imageId':row['image'],'sourceCommit':row['revision'],'process':process,'nativeHealth':health}
 after=read()
 def stable(row):return {**{k:row[k]for k in('id','name','image','revision','restarts','networks')},'process':{k:row['state'].get(k)for k in('Running','Status','Pid','StartedAt','Paused','Restarting','Dead')}}
 m.require({cid:stable(row)for cid,row in after.items()}=={cid:stable(row)for cid,row in before.items()},'PROCESS_OR_ENDPOINT_CHANGED_DURING_READ')
 return {'schema':'ouf.post-host-network-native-read.v1','complete':True,'endpointCorrectionsProven':len(moves),'endpoints':moves,'applications':result,'allThreeNativeReadinessProven':all(v['nativeHealth']['ready']for v in result.values()),'providerReadinessProven':False,'graphIntegrationProven':False,'httpHealthGets':sum(v['nativeHealth']['requests']for v in result.values()),'runtimeMutations':0,'engineWrites':0,'databaseQueriesIssued':0,'credentialFilesRead':0,'credentialValuesPrinted':False,'profilePublications':0,'explicitJobRetries':0,'automaticRetry':False,'completedTechnicalPhases':8,'functionalMilestonesProven':4}
if __name__=='__main__':
 signal.alarm(45)
 try:
  m.require(len(sys.argv)==4,'THREE_VERSIONED_READ_PROFILES_REQUIRED');result=collect(*(json.loads(Path(p).read_bytes())for p in sys.argv[1:]))
 except Exception as error:result={'schema':'ouf.post-host-network-native-read.v1','complete':False,'errorClass':type(error).__name__,'exceptionMessagePrinted':False,'runtimeMutations':0,'engineWrites':0,'automaticRetry':False}
 print(json.dumps(result,sort_keys=True));sys.exit(0 if result['complete']else 2)
