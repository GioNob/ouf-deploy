"""Native Engine and qualified APISIX namespace adapters for the exact plan."""
import copy,hashlib,http.client,ipaddress,json,os,re,stat,tempfile,time
from pathlib import Path
from urllib.parse import quote
from tools.chat_recovery_update.readiness import classify
from engine_creation import Engine,requested_host_config_matches
from image_custody import loaded,runtime_image_id
from tools.semantic_policy_token_owner.owner_installation import AggregateAction
from tools.semantic_mcp_update.native import private_file,env,bounded,command
from tools.chatbot_file_cohort.gateway import NamespaceAdmin,private_config
from tools.source_revision_update.owner import require,digest,scope,STAGES

NO_RESTART={'Name':'no','MaximumRetryCount':0}
def runtime(actual):
 value=Engine.runtime_binding(actual)
 value['mountsHash']=digest(sorted(actual['Mounts'],key=lambda m:m['Destination']))
 return value
def custody_pin(st):
 return [getattr(st,k)for k in('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns')]

def retained_metadata_file(binding,pin):
 require(set(pin)=={'path','sha256','metadata'}and binding=={k:pin[k]for k in('path','sha256')},'EXACT_RETAINED_MCP_METADATA_PIN_REQUIRED')
 path=Path(binding['path']);require(path.is_absolute()and path.resolve()==path and path.name in('permit.json','policy.json','profile.json'),'EXACT_RETAINED_MCP_METADATA_PATH_REQUIRED')
 for parent in path.parents:
  st=parent.lstat();require(stat.S_ISDIR(st.st_mode)and st.st_uid==0 and not st.st_mode&0o022,'MCP_METADATA_ROOT_ANCESTRY_REQUIRED')
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  before=os.fstat(fd);require(stat.S_ISREG(before.st_mode)and before.st_uid==0 and before.st_gid>0
   and stat.S_IMODE(before.st_mode)==0o440 and before.st_nlink==1 and 0<before.st_size<=65536
   and custody_pin(before)==pin['metadata'],'RETAINED_MCP_METADATA_CUSTODY_CHANGED')
  raw=os.read(fd,65537);require(len(raw)==before.st_size and hashlib.sha256(raw).hexdigest()==binding['sha256']
   and custody_pin(before)==custody_pin(os.fstat(fd))==custody_pin(path.lstat()),'RETAINED_MCP_METADATA_BYTES_CHANGED')
 finally:os.close(fd)
 return {'exactBinding':True,'readOnlyServiceMetadata':True,'custodyPreserved':True}

def historical_document(binding):
 private_file(binding['path'],binding['sha256'],8388608)
 fd=os.open(binding['path'],os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  before=os.fstat(fd);raw=os.read(fd,8388609)
  require(custody_pin(before)==custody_pin(os.fstat(fd))==custody_pin(Path(binding['path']).lstat()),'HISTORICAL_SCOPE_CUSTODY_CHANGED')
 finally:os.close(fd)
 require(len(raw)<=8388608 and hashlib.sha256(raw).hexdigest()==binding['sha256'],'HISTORICAL_SCOPE_BYTES_CHANGED')
 return json.loads(raw)

def zero_effect_predecessor(reference,logical):
 require(reference['schema']=='ouf.source-revision-zero-effect-expired-scope.v1'and reference['logicalUpdateRef']==logical,
  'EXACT_ZERO_EFFECT_SCOPE_SUCCESSOR_REQUIRED')
 context=Path(reference['context']);require(context.parent==Path(reference['claimBinding']['path']).parent
  and re.fullmatch('source-revision-execution-[A-Za-z0-9_-]{8,64}',context.name)
  and Path(reference['claimBinding']['path'])==context.parent/('source-revision-update-'+logical+'.claim.json'),
  'EXACT_ORIGINAL_LOGICAL_SCOPE_CLAIM_REQUIRED')
 for key,name in(('journalBinding','recovery.json'),('authorityBinding','authority.json'),('planBinding','execution-plan.json'),('reviewBinding','review.json')):
  require(reference[key]['path']==str(context/name),'EXACT_PREDECESSOR_SCOPE_FILES_REQUIRED')
 row=historical_document(reference['journalBinding']);authority=historical_document(reference['authorityBinding']);plan=historical_document(reference['planBinding']);review=historical_document(reference['reviewBinding']);claim=historical_document(reference['claimBinding'])
 require(row['schema']=='ouf.source-revision-update-journal.v1'and row['version']==0 and row['nextStage']==0 and row['effects']==[]
  and row['budgetReset']is False and row['readinessAttempts']==row['cumulativeReadinessAttempts']==0
  and all(type(row[k])is int for k in ('version','nextStage','readinessAttempts','cumulativeReadinessAttempts'))
  and row['incidentState']=='OPEN'and row['readinessState']=='IDLE'and row['applicationAcceptanceGranted']is False
  and row['authorityHash']==reference['authorityBinding']['sha256'] and row['scopeHash']==digest(review['scopes']['sourceRevisionUpdate'])
  and row['bootId']==Path('/proc/sys/kernel/random/boot_id').read_text().strip()
  and time.time()>=max(row['expiresAt'],authority['expiresAt'])and time.monotonic()>=row['expiresMonotonic'],
  'ONLY_EXPIRED_ZERO_EFFECT_SCOPE_CAN_HAVE_SUCCESSOR')
 require(plan['logicalUpdateRef']==logical and claim=={'planHash':digest(plan),'authorityHash':row['authorityHash'],
  'context':str(context),'automaticReplayAllowed':False}
  and review['authorityDirectory']==str(context)and review['scopes']['sourceRevisionUpdate']['planHash']==digest(plan)
  and authority['scopedExecution']['reviewHash']==reference['reviewBinding']['sha256']
  and authority['sourceClosureHash']==review['sourceClosureHash']
  and authority['sourceRevisionUpdate']==review['scopes']['sourceRevisionUpdate'],'PREDECESSOR_SCOPE_LINEAGE_CHANGED')
 return context

def bind_custody_continuation(plan,reference):
 require(reference['schema']=='ouf.source-revision-mcp-custody-continuation.v1','EXPLICIT_MCP_CUSTODY_CONTINUATION_REQUIRED')
 pins=reference['metadataPins'];bindings=plan['retainedMcpMetadata']
 require(len(bindings)==len(pins)==3 and set(pins)=={v['path']for v in bindings}
  and {Path(v['path']).name for v in bindings}=={'permit.json','policy.json','profile.json'},'EXACT_THREE_RETAINED_METADATA_REQUIRED')
 for binding in bindings:retained_metadata_file(binding,pins[binding['path']])
 predecessor=zero_effect_predecessor(reference['scopeSuccessor'],plan['logicalUpdateRef'])
 require(not os.path.lexists(predecessor/'logical-successor.claim.json'),'PREDECESSOR_SCOPE_SUCCESSOR_ALREADY_CONSUMED')
 value=copy.deepcopy(plan);value['retainedMcpMetadataCustody']=copy.deepcopy(pins);value['logicalScopeSuccessor']=copy.deepcopy(reference['scopeSuccessor']);return value

def claim_zero_effect_successor(plan,authority_hash):
 from tools.semantic_lease_recovery.recovery_journal import Journal
 from tools.semantic_policy_token_owner.producer import protected_directory
 from iam_owner_action import publish
 reference=plan['logicalScopeSuccessor'];context=Path(reference['context'])
 with Journal(context).invocation():
  require(zero_effect_predecessor(reference,plan['logicalUpdateRef'])==context,'PREDECESSOR_SCOPE_CHANGED_BEFORE_CLAIM')
  value={'schema':'ouf.source-revision-logical-scope-successor-claim.v1','logicalUpdateRef':plan['logicalUpdateRef'],
   'predecessorClaimSha256':reference['claimBinding']['sha256'],'predecessorAuthoritySha256':reference['authorityBinding']['sha256'],
   'planHash':digest(plan),'authorityHash':authority_hash,'context':plan['authorityDirectory'],
   'priorCumulativeReadinessAttempts':0,'predecessorEffects':0,'budgetReset':False,'automaticReplayAllowed':False}
  with protected_directory(context)as directory:require(publish(directory,'logical-successor.claim.json',json.dumps(value,sort_keys=True).encode()),
   'LOGICAL_SCOPE_SUCCESSOR_ALREADY_CLAIMED_RECONCILE')
 return value

def guard_zero_effect_successor(plan,authority_hash):
 reference=plan['logicalScopeSuccessor'];context=zero_effect_predecessor(reference,plan['logicalUpdateRef'])
 expected={'schema':'ouf.source-revision-logical-scope-successor-claim.v1','logicalUpdateRef':plan['logicalUpdateRef'],
  'predecessorClaimSha256':reference['claimBinding']['sha256'],'predecessorAuthoritySha256':reference['authorityBinding']['sha256'],
  'planHash':digest(plan),'authorityHash':authority_hash,'context':plan['authorityDirectory'],
  'priorCumulativeReadinessAttempts':0,'predecessorEffects':0,'budgetReset':False,'automaticReplayAllowed':False}
 path=context/'logical-successor.claim.json';binding={'path':str(path),'sha256':hashlib.sha256(json.dumps(expected,sort_keys=True).encode()).hexdigest()}
 require(historical_document(binding)==expected,'LOGICAL_SCOPE_SUCCESSOR_FENCE_CHANGED')

class NativePorts:
 def __init__(self,action,engine,plan,human,database):
  require(type(action)is AggregateAction and type(engine)is Engine,'REAL_AUTHORITY_AND_ENGINE_REQUIRED')
  self.action,self.engine,self.plan,self.human=action,engine,copy.deepcopy(plan),human
  self.database=database;database.ports=self
  self.gateway=NamespaceAdmin(engine,plan['gateway']['transport'])
 def plan_scope(self):return scope(self.plan)
 def boot(self):return Path('/proc/sys/kernel/random/boot_id').read_text().strip()
 def claim_logical_scope(self):
  if 'logicalScopeSuccessor'in self.plan:return claim_zero_effect_successor(self.plan,self.action.authority_hash)
  from tools.semantic_policy_token_owner.producer import protected_directory
  from iam_owner_action import publish
  path=Path(self.plan['authorityDirectory']).parent
  with protected_directory(path)as directory:
   require(publish(directory,'source-revision-update-'+self.plan['logicalUpdateRef']+'.claim.json',
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
  self.action.guard('sourceRevisionUpdate',scope(p));self.engine.check_socket()
  private_file(p['privateReviewBinding']['path'],p['privateReviewBinding']['sha256'],8388608)
  private_config(p['gateway']['projectionBinding']['path'],p['gateway']['projectionBinding'])
  self.gateway.check()
  if 'logicalScopeSuccessor'in p:guard_zero_effect_successor(p,self.action.authority_hash)
  for binding in p.get('retainedMcpMetadata',[]):
   if 'retainedMcpMetadataCustody'in p:retained_metadata_file(binding,p['retainedMcpMetadataCustody'][binding['path']])
   else:private_file(binding['path'],binding['sha256'],65536)
  for overlay in p['nativeFlywayConfiguration'].get('ownerOverlays',[]):
   binding=overlay['binding'];private_config(binding['path'],binding)
  require(self.human.current()==p['humanBinding'],'SAME_CURRENT_HUMAN_REQUIRED')
  self.route_inventory()
  self.database.guard()
  if STAGES.index(stage)>STAGES.index('BACKUP_ONBOARDING'):self.database.verify_backup()
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
   if n<STAGES.index(name+'.STOP_OLD') or n==STAGES.index(name+'.STOP_OLD') and old['State']['Running']:
    observed=runtime(old);observed['hostConfigHash']=pin['hostConfigHash']
    require(old['State']['Running']is True and observed==pin,'OLD_APPLICATION_GENERATION_CHANGED')
   require(old['State']['StartedAt']==pin['startedAt'],'OLD_APPLICATION_PROCESS_REPLACED')
   if n>=STAGES.index(name+'.STOP_OLD') and not old['State']['Running']:
    require(old['State']['Running']is False and old['State']['Pid']==0,'OLD_APPLICATION_NOT_QUIESCENT')
   if n>STAGES.index(name+'.STOP_OLD'):require(old['State']['Running']is False,'OLD_APPLICATION_RESTARTED')
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
 def expected_routes(self,include_claim=False):
  routes=copy.deepcopy(self.plan['gateway']['beforeRoutes'])
  effects=self.journal.read()['effects']
  for effect in effects:
   mode={'GATEWAY_PREPARE_ROUTE':'prepare','GATEWAY_READ_ROUTE':'read'}.get(effect['stage'])
   if mode is not None and (effect['state']=='APPLIED' or include_claim and effect['state']=='CLAIMED'):
    route=self.plan['gateway']['additions'][mode];routes[route['id']]=route
  return routes
 def route_inventory(self,after=False):
  actual=self.gateway.routes();expected=self.expected_routes()
  options=(expected,self.expected_routes(True))
  require(actual in options,'GATEWAY_ROUTE_MAP_CHANGED')
  if after:require(actual==self.plan['gateway']['afterRoutes'],'COMPLETE_REVISED_GATEWAY_REQUIRED')
  return actual
 def verify_inputs(self):
  self.route_inventory();self.database.verify_before()
  for name,row in self.plan['replacements'].items():
   private_file(row['imageArchive']['path'],row['imageArchive']['sha256'],1200000000)
   require(self.inspect('containers',row['retiredName'])is None,'RETIRED_APPLICATION_NAME_ALREADY_EXISTS')
  return {'privateReviewHash':self.plan['privateReviewBinding']['sha256']}
 def apply(self,stage):
  p=self.plan
  if stage=='VERIFY_INPUTS':self.verify_inputs();return
  if stage=='VERIFY_FINAL':return
  if stage in ('GATEWAY_PREPARE_ROUTE','GATEWAY_READ_ROUTE'):
   mode='prepare' if stage=='GATEWAY_PREPARE_ROUTE' else 'read';route=p['gateway']['additions'][mode]
   require(self.gateway.routes()==self.expected_routes(),'GATEWAY_BASE_CHANGED_BEFORE_WRITE')
   require(route['id'] not in self.expected_routes(),'REVISION_ROUTE_ALREADY_PRESENT_RECONCILE')
   status,_=self.gateway.request('PUT','/apisix/admin/routes/'+quote(route['id'],safe=''),route)
   require(status in(200,201),'GATEWAY_PUT_OUTCOME_UNPROVEN');return
  if stage=='BACKUP_ONBOARDING':self.database.backup();return
  if stage=='VERIFY_MIGRATION':return
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
   status,proof=classify('spring-readiness' if name=='onboarding' else 'empty-204',reply.status,raw,
    retry_after=reply.getheader('Retry-After'),now=time.time())
   if status=='TRANSIENT':return status,proof
   following=self.candidate(name,True);require(following is not None and runtime(following)==runtime(actual),'GENERATION_CHANGED_DURING_READINESS')
   return 'APPLIED',{**proof,'bodyHash':hashlib.sha256(raw).hexdigest()}
  except(OSError,http.client.HTTPException):return 'TRANSIENT',{'retryAfterSeconds':0}
  finally:client.close()
 def observe(self,stage):
  if stage=='VERIFY_INPUTS':return 'APPLIED',self.verify_inputs()
  if stage in ('GATEWAY_PREPARE_ROUTE','GATEWAY_READ_ROUTE'):
   actual=self.gateway.routes();require(actual in(self.expected_routes(),self.expected_routes(True)),'GATEWAY_RECONCILIATION_CONFLICT')
   return ('APPLIED',{'routeMapHash':digest(actual)}) if actual==self.expected_routes(True) else ('UNKNOWN',{})
  if stage=='BACKUP_ONBOARDING':return 'APPLIED',self.database.verify_backup()
  if stage=='VERIFY_MIGRATION':return 'APPLIED',self.database.verify_migrated()
  if stage=='VERIFY_FINAL':
   self.database.verify_migrated()
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
