"""Native Engine and qualified APISIX namespace adapters for the exact plan."""
import copy,hashlib,http.client,ipaddress,json,re,tempfile,time
from pathlib import Path
from urllib.parse import quote
from email.utils import parsedate_to_datetime
from engine_creation import Engine,requested_host_config_matches
from image_custody import loaded,runtime_image_id
from tools.semantic_policy_token_owner.owner_installation import AggregateAction
from tools.semantic_mcp_update.native import private_file,env,bounded,command
from tools.chatbot_file_cohort.gateway import NamespaceAdmin,private_config
from tools.teatri_materialization_apply.owner import require,digest,scope,STAGES

NO_RESTART={'Name':'no','MaximumRetryCount':0}
def runtime(actual):
 value=Engine.runtime_binding(actual)
 value['mountsHash']=digest(sorted(actual['Mounts'],key=lambda m:m['Destination']))
 return value
class NativePorts:
 def __init__(self,action,engine,plan,human):
  require(type(action)is AggregateAction and type(engine)is Engine,'REAL_AUTHORITY_AND_ENGINE_REQUIRED')
  self.action,self.engine,self.plan,self.human=action,engine,copy.deepcopy(plan),human
  self.gateway=NamespaceAdmin(engine,plan['gateway']['transport'])
 def boot(self):return Path('/proc/sys/kernel/random/boot_id').read_text().strip()
 def claim_logical_scope(self):
  from tools.semantic_policy_token_owner.producer import protected_directory
  from iam_owner_action import publish
  path=Path(self.plan['authorityDirectory']).parent
  with protected_directory(path)as directory:
   require(publish(directory,'udp-resolution-update-'+self.plan['logicalUpdateRef']+'.claim.json',
    json.dumps({'planHash':digest(self.plan),'authorityHash':self.action.authority_hash,'context':self.plan['authorityDirectory'],
     'automaticReplayAllowed':False},sort_keys=True).encode()),'READINESS_UPDATE_ALREADY_CLAIMED')
 def request(self,method,path,body=None):self.engine.check_socket();return self.engine.request(method,path,body)
 def inspect(self,kind,reference):
  require(kind in('containers','images','networks')and re.fullmatch('[A-Za-z0-9_.:-]{1,128}',reference),'EXACT_ENGINE_REFERENCE_REQUIRED')
  status,value=self.request('GET','/v1.44/'+kind+'/'+quote(reference,safe='')+(''if kind=='networks'else'/json'))
  if status==404:return None
  require(status==200 and type(value)is dict,'NATIVE_OBSERVATION_FAILED');return value
 def guard_current(self,stage):
  require(stage in STAGES,'EXACT_READINESS_STAGE_REQUIRED');p=self.plan
  self.action.guard('udpResolutionUpdate',scope(p));self.engine.check_socket()
  private_file(p['privateReviewBinding']['path'],p['privateReviewBinding']['sha256'],8388608)
  private_config(p['gateway']['projectionBinding']['path'],p['gateway']['projectionBinding'])
  self.gateway.check()
  require(self.human.current()==p['humanBinding'],'SAME_CURRENT_HUMAN_REQUIRED')
  self.route_inventory()
  for retained in p['unchangedApplications'].values():
   actual=self.inspect('containers',retained['containerId'])
   require(actual is not None and actual['State']['Running']is True and runtime(actual)==retained,'UNCHANGED_APPLICATION_GENERATION_REQUIRED')
  n=STAGES.index(stage)
  for name,row in p['replacements'].items():
   old=self.inspect('containers',row['oldRuntimeBinding']['containerId']);require(old is not None,'RETAINED_APPLICATION_ABSENT')
   pin=row['oldRuntimeBinding'];require(old['Image']==pin['imageId']and digest(old['Config'])==pin['configHash']
    and digest(sorted(old['Mounts'],key=lambda m:m['Destination']))==pin['mountsHash'],'RETAINED_APPLICATION_CONFIG_CHANGED')
   host=copy.deepcopy(row['oldNativeHostConfig']);host['RestartPolicy']=copy.deepcopy(NO_RESTART)
   require(old['HostConfig']in(row['oldNativeHostConfig'],host),'RETAINED_APPLICATION_HOST_CHANGED')
   if n<=STAGES.index(name+'.STOP_OLD'):
    observed=runtime(old);observed['hostConfigHash']=pin['hostConfigHash']
    require(old['State']['Running']is True and observed==pin,'OLD_APPLICATION_GENERATION_CHANGED')
   if n>STAGES.index(name+'.STOP_OLD'):
    require(old['State']['Running']is False and old['State']['Pid']==0,'OLD_APPLICATION_NOT_QUIESCENT')
   if n>STAGES.index(name+'.START_REPLACEMENT'):
    require(self.candidate(name,True)is not None,'STARTED_APPLICATION_DISAPPEARED')
 def candidate(self,name,running=False):
  row=self.plan['replacements'][name];actual=self.inspect('containers',row['name'])
  if actual is None:return None
  require(actual['Id']!=row['oldRuntimeBinding']['containerId']and actual['Image']==runtime_image_id(row['imageAudit']),'EXACT_NEW_APPLICATION_IMAGE_REQUIRED')
  request=row['request'];audit=row['imageAudit'];effects={e['stage']:e.get('evidence',{})for e in self.journal.read()['effects']if e['state']=='APPLIED'}
  created=effects.get(name+'.CREATE_REPLACEMENT');started=effects.get(name+'.START_REPLACEMENT')
  if created:require(actual['Id']==created['containerId'],'CREATED_APPLICATION_ID_CHANGED')
  if started:require(actual['State']['Pid']==started['pid']and actual['State']['StartedAt']==started['startedAt'],'STARTED_APPLICATION_GENERATION_CHANGED')
  for key,value in request.items():
   if key in('HostConfig','NetworkingConfig')or key=='Hostname'and not value:continue
   if key=='Env':require(env(actual['Config']['Env'])=={**env(audit['imageConfig'].get('Env')or[]),**env(value)},'NEW_APPLICATION_ENV_CHANGED')
   elif key=='Labels':require(actual['Config'].get(key)=={**(audit['imageConfig'].get('Labels')or{}),**value},'NEW_APPLICATION_LABELS_CHANGED')
   else:require(actual['Config'].get(key)==value,'NEW_APPLICATION_PROCESS_CHANGED')
  host=copy.deepcopy(request['HostConfig']);alternate=copy.deepcopy(host);alternate['RestartPolicy']=row['restoreRestartPolicy']
  require(requested_host_config_matches(host,actual['HostConfig'],started=actual['State']['Running'])or requested_host_config_matches(alternate,actual['HostConfig'],started=actual['State']['Running']),'NEW_APPLICATION_HOST_CHANGED')
  net=row['network'];networks=actual['NetworkSettings']['Networks'];require(set(networks)=={net['name']}and networks[net['name']]['NetworkID']==net['id'],'NEW_APPLICATION_NETWORK_CHANGED')
  endpoint=networks[net['name']]
  if actual['State']['Status']=='created'and actual['State']['Pid']==0:
   require((endpoint.get('IPAMConfig')or{}).get('IPv4Address')==net['ip']and endpoint.get('IPAddress','')in('',net['ip'])
    and endpoint.get('MacAddress','').lower()in('',net['mac'].lower()),'CREATED_APPLICATION_ENDPOINT_CHANGED')
  else:require(endpoint['IPAddress']==net['ip']and endpoint['MacAddress'].lower()==net['mac'].lower(),'NEW_APPLICATION_ENDPOINT_CHANGED')
  mount=lambda v:{(m['Type'],m['Source'],m['Destination'],m['RW'])for m in v}
  require(mount(actual['Mounts'])==mount(row['oldMounts']),'NEW_APPLICATION_MOUNTS_CHANGED')
  if running:require(actual['State']['Running']is True and actual['State']['Pid']>0 and actual['State']['Paused']is False
   and actual.get('RestartCount')==0,'NEW_APPLICATION_NOT_FIRST_RUNNING_GENERATION')
  return actual
 def route_inventory(self,after=False):
  actual=self.gateway.routes();expected=copy.deepcopy(self.plan['gateway']['beforeRoutes'])
  # Gateway is observed only; this profile has zero PUT/DELETE authority.
  require(actual==expected,'COMPLETE_GATEWAY_ROUTE_MAP_CHANGED');return actual
 def verify_inputs(self):
  self.route_inventory()
  for name,row in self.plan['replacements'].items():
   private_file(row['imageArchive']['path'],row['imageArchive']['sha256'],1200000000)
   require(self.inspect('containers',row['retiredName'])is None,'RETIRED_APPLICATION_NAME_ALREADY_EXISTS')
  return {'privateReviewHash':self.plan['privateReviewBinding']['sha256']}
 def apply(self,stage):
  p=self.plan
  if stage=='VERIFY_INPUTS':self.verify_inputs();return
  if stage=='VERIFY_FINAL':return
  name,operation=stage.split('.');row=p['replacements'][name];old=row['oldRuntimeBinding']['containerId']
  if operation=='IMPORT_IMAGE':
   if self.inspect('images',runtime_image_id(row['imageAudit']))is None:
    with tempfile.TemporaryDirectory(prefix='ouf-readiness-load-')as directory:
     bounded([command(p['programs']['docker']),'--host','unix://'+p['engine']['socketPath'],'--config',directory,
      'load','--input',row['imageArchive']['path']],180,65536)
  elif operation=='DISABLE_OLD_RESTART':
   status,_=self.request('POST','/v1.44/containers/'+old+'/update',{'RestartPolicy':NO_RESTART});require(status==200,'OLD_RESTART_DISABLE_UNPROVEN')
  elif operation=='STOP_OLD':
   status,_=self.request('POST','/v1.44/containers/'+old+'/stop?t=10');require(status==204,'STOP_APPLICATION_UNPROVEN')
  elif operation=='DETACH_OLD_ENDPOINT':
   network=self.inspect('networks',row['network']['id']);require(network is not None,'RETAINED_NETWORK_REQUIRED')
   if old in(network.get('Containers')or{}):
    status,_=self.request('POST','/v1.44/networks/'+row['network']['id']+'/disconnect',{'Container':old,'Force':False});require(status==200,'ENDPOINT_RELEASE_UNPROVEN')
  elif operation=='RENAME_OLD':
   require(self.inspect('containers',row['retiredName'])is None,'RETIRED_NAME_ALREADY_EXISTS')
   status,_=self.request('POST','/v1.44/containers/'+old+'/rename?name='+quote(row['retiredName'],safe=''));require(status==204,'RENAME_APPLICATION_UNPROVEN')
  elif operation=='CREATE_REPLACEMENT':
   require(self.inspect('containers',row['name'])is None,'APPLICATION_NAME_ALREADY_EXISTS')
   status,value=self.request('POST','/v1.44/containers/create?name='+quote(row['name'],safe=''),row['request'])
   require(status==201 and re.fullmatch('[0-9a-f]{64}',value.get('Id','')),'CREATE_APPLICATION_UNPROVEN')
  elif operation=='START_REPLACEMENT':
   actual=self.candidate(name);require(actual is not None and actual['State']['Status']=='created'and actual['State']['Pid']==0,'NEVER_STARTED_APPLICATION_REQUIRED')
   status,_=self.request('POST','/v1.44/containers/'+actual['Id']+'/start');require(status==204,'START_APPLICATION_UNPROVEN')
  elif operation=='RESTORE_RESTART_POLICY':
   actual=self.candidate(name,True);status,_=self.request('POST','/v1.44/containers/'+actual['Id']+'/update',{'RestartPolicy':row['restoreRestartPolicy']});require(status==200,'RESTORE_RESTART_POLICY_UNPROVEN')
  else:require(operation=='READINESS','UNKNOWN_APPLICATION_EFFECT')
 def health(self,name,actual):
  row=self.plan['replacements'][name];net=row['network'];selection=row['readiness']
  ip=ipaddress.ip_address(net['ip']);require(ip.is_private and not ip.is_loopback,'REVIEWED_PRIVATE_READINESS_IP_REQUIRED')
  client=http.client.HTTPConnection(str(ip),selection['readinessPort'],timeout=5)
  try:
   client.request('GET',selection['readinessPath'],headers={'Accept':'application/json','Connection':'close'});reply=client.getresponse();raw=reply.read(65537)
   require(len(raw)<=65536,'BOUNDED_READINESS_RESPONSE_REQUIRED')
   if reply.status in(429,502,503,504):
    delay=reply.getheader('Retry-After')or'0'
    if re.fullmatch('[0-9]{1,6}',delay):seconds=int(delay)
    else:
     try:seconds=max(0,parsedate_to_datetime(delay).timestamp()-time.time())
     except(ValueError,TypeError,OverflowError):require(False,'READINESS_RETRY_AFTER_REVIEW_REQUIRED')
    require(0<=seconds<float('inf'),'BOUNDED_READINESS_RETRY_AFTER_REQUIRED');return 'TRANSIENT',{'retryAfterSeconds':seconds}
   require(reply.status==200 and json.loads(raw).get('status')=='UP','READINESS_PERMANENT_FAILURE')
   following=self.candidate(name,True);require(following is not None and runtime(following)==runtime(actual),'GENERATION_CHANGED_DURING_READINESS')
   return 'APPLIED',{'httpStatus':200,'bodyHash':hashlib.sha256(raw).hexdigest()}
  except(OSError,http.client.HTTPException):return 'TRANSIENT',{'retryAfterSeconds':0}
  finally:client.close()
 def observe(self,stage):
  if stage=='VERIFY_INPUTS':return 'APPLIED',self.verify_inputs()
  if stage=='VERIFY_FINAL':
   proofs={}
   for name in self.plan['replacements']:
    actual=self.candidate(name,True);status,proof=self.health(name,actual)
    if status=='TRANSIENT':return status,proof
    require(status=='APPLIED','FINAL_APPLICATION_READINESS_REQUIRED');proofs[name]={'runtimeBinding':runtime(actual),'health':proof}
   return 'APPLIED',{'applications':proofs,'routeMapHash':digest(self.route_inventory(True)),'sourceActivationProven':False}
  name,operation=stage.split('.');row=self.plan['replacements'][name];old=self.inspect('containers',row['oldRuntimeBinding']['containerId'])
  if operation=='IMPORT_IMAGE':
   actual=self.inspect('images',runtime_image_id(row['imageAudit']));return ('UNKNOWN',{})if actual is None else('APPLIED',loaded(row['imageAudit'],actual))
  if operation=='DISABLE_OLD_RESTART':return ('APPLIED',{'restartDisabled':True})if old['HostConfig']['RestartPolicy']==NO_RESTART else('UNKNOWN',{})
  if operation=='STOP_OLD':return ('APPLIED',{'stoppedId':old['Id']})if old['State']['Running']is False and old['State']['Pid']==0 else('UNKNOWN',{})
  if operation=='DETACH_OLD_ENDPOINT':
   network=self.inspect('networks',row['network']['id']);return ('APPLIED',{'oldEndpointReleased':True})if network is not None and old['Id']not in(network.get('Containers')or{})else('UNKNOWN',{})
  if operation=='RENAME_OLD':return ('APPLIED',{'retiredId':old['Id']})if old['Name']=='/'+row['retiredName']else('UNKNOWN',{})
  actual=self.candidate(name,operation!='CREATE_REPLACEMENT')
  if actual is None:return 'UNKNOWN',{}
  proof={'containerId':actual['Id'],'pid':actual['State']['Pid'],'startedAt':actual['State']['StartedAt'],'runtimeHash':digest(runtime(actual))}
  if operation=='READINESS':
   status,health=self.health(name,actual);return status,{**proof,**health}
  if operation=='RESTORE_RESTART_POLICY':require(actual['HostConfig']['RestartPolicy']==row['restoreRestartPolicy'],'APPLICATION_RESTART_NOT_RESTORED')
  return 'APPLIED',proof
