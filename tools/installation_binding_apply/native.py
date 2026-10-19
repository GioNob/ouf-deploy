"""Owner HTTPS lifecycle and one atomic profile publication plus two Gateway PUTs."""
import copy,fcntl,hashlib,json,os,re,ssl,stat,time,urllib.request,urllib.error
from pathlib import Path
from urllib.parse import quote
from engine_creation import Engine
from tools.chatbot_file_cohort.gateway import NamespaceAdmin,private_config
from tools.ingestion_read_authorization.authorization import OwnerTransport,NoRedirect
from tools.source_revision_update.native import runtime
from tools.ingestion_read_gateway_custody.owner import metadata_file
from tools.installation_binding_apply import baseline
from tools.installation_binding_apply.owner import require,digest,encoded,scope,scope_key

class OwnerHttp:
 def __init__(self,selection,human,installation,correlation):
  require(re.fullmatch('[A-Za-z0-9._-]{1,128}',installation),'EXACT_OWNER_INSTALLATION_REQUIRED')
  self.credentials=OwnerTransport(selection,human.token_path,human.token_path,human_session=human)
  self.origin=selection['origin'].rstrip('/');self.root='/api/trusted-human/v1/installations/'+installation
  self.human=human;self.correlation=correlation;self.calls=0;self.posts=0;self.exports=0;self.deadline=time.monotonic()+210
  self.opener=urllib.request.build_opener(urllib.request.HTTPSHandler(context=ssl.create_default_context()),NoRedirect())
 def call(self,method,suffix,body=None,etag=None):
  require(self.calls<24 and time.monotonic()<self.deadline and method in('GET','POST'),'FINITE_EXACT_OWNER_REQUEST_REQUIRED')
  require(method=='GET'and(suffix=='/active'or re.fullmatch('/revisions/[1-9][0-9]{0,18}',suffix)or re.fullmatch(r'/projection\?revision=[1-9][0-9]{0,18}',suffix))
   or method=='POST'and(suffix=='/revisions'or re.fullmatch('/revisions/[1-9][0-9]{0,18}:(?:validate-environment|activate)',suffix)),'CLOSED_OWNER_API_PATH_REQUIRED')
  if method=='POST':require(self.posts<3,'MAXIMUM_THREE_OWNER_POSTS');self.posts+=1
  if suffix.startswith('/projection?'):require(self.exports<1,'MAXIMUM_ONE_AUDITED_EXPORT');self.exports+=1
  self.human.current();require(self.human._read()['accessExpiresAt']>time.time()+15,'CURRENT_TOKEN_REQUIRED_NO_REFRESH_OR_WAIT')
  token=self.credentials.token('admin');headers={'Authorization':'Bearer '+token,'Accept':'application/json','X-Correlation-ID':self.correlation}
  if body is not None:headers['Content-Type']='application/json'
  if etag is not None:headers['If-Match']=etag
  req=urllib.request.Request(self.origin+self.root+suffix,data=encoded(body)if body is not None else None,headers=headers,method=method)
  self.calls+=1
  try:
   with self.opener.open(req,timeout=min(35,max(.1,self.deadline-time.monotonic())))as reply:
    raw=reply.read(2097153);require(reply.status in(200,201)and 0<len(raw)<=2097152,'SUCCESSFUL_BOUNDED_OWNER_RESPONSE_REQUIRED')
    return json.loads(raw),{'ETag':reply.headers.get('ETag'),'revision':reply.headers.get('X-OUF-Installation-Revision'),'checksum':reply.headers.get('X-OUF-Installation-Checksum')}
  except(urllib.error.HTTPError,urllib.error.URLError,TimeoutError):raise ValueError('OWNER_EFFECT_OR_READ_UNPROVEN_NO_REPLAY')from None
 def active(self):
  body,headers=self.call('GET','/active');return baseline.strong_active(body,headers['ETag'])

class Ports:
 def __init__(self,action,plan,human,http,context):
  self.action,self.plan,self.human,self.http,self.context=action,copy.deepcopy(plan),human,http,Path(context)
  self.engine=Engine(plan['engine']['socketPath'],tuple(plan['engine']['socketBinding']));self.gateway=NamespaceAdmin(self.engine,plan['gateway']['transport'])
 def boot(self):return self.human._boot()
 def evidence(self,row,stage):
  found=[e['evidence']for e in row['effects']if e['stage']==stage and e['state']=='APPLIED'];return found[0]if found else None
 def guard_current(self,stage,row):
  self.action.guard(scope_key(self.plan['kind']),scope(self.plan));require(self.human.current()==self.plan['humanBinding'],'SAME_CURRENT_VERIFIED_HUMAN_REQUIRED')
  for name,pin in self.plan['currentApplications'].items():
   status,actual=self.engine.request('GET','/v1.44/containers/'+pin['containerId']+'/json')
   require(status==200 and baseline_runtime(actual,name,self.plan)==pin,'CURRENT_INDEPENDENT_APPLICATION_DRIFT')
  for binding in self.plan['retainedMcpMetadata']:metadata_file(binding)
  owner=self.plan['kind']=='INSTALLATION_BINDING_APPLY';activated=self.evidence(row,'ACTIVATE_EXPECTED')if owner else None
  current=self.http.active();expected=activated['active']if activated else{**self.plan['bindingPlan']['expectedActive'],'etag':self.plan['bindingPlan']['expectedActiveETag']}
  require(current==expected,'OWNER_ACTIVE_VERSION_GENERATION_DRIFT')
  projected=not owner and self.evidence(row,'PUBLISH_ACTIVE_PROJECTION')is not None
  if projected:require(baseline.sha(baseline.read(self.plan['projectionBinding']['path']))==self.plan['projectionHash'],'PUBLISHED_ACTIVE_PROJECTION_DRIFT')
  else:private_config(self.plan['projectionBinding']['path'],self.plan['projectionBinding'])
  expected_routes=copy.deepcopy(self.plan['gateway']['beforeRoutes'])
  if not owner:
   for mode in('status','history'):
    if self.evidence(row,'GATEWAY_'+mode.upper()+'_ROUTE')is not None:expected_routes['mcp-ingestion-'+mode]=self.plan['gateway']['afterRoutes']['mcp-ingestion-'+mode]
  require(self.gateway.routes()==expected_routes,'EXACT_GATEWAY_ROUTE_MAP_DRIFT')
 def apply(self,stage,row):
  plan=self.plan;b=plan['bindingPlan'];owner=plan['kind']=='INSTALLATION_BINDING_APPLY'
  if stage=='CREATE_REVISION':
   revision,_=self.http.call('POST','/revisions',b['candidatePayload'])
   require(revision.get('installationId')==b['expectedActive']['installationId']and type(revision.get('revision'))is int
    and revision['revision']>b['expectedActive']['revision']and revision.get('checksum')==b['candidatePayloadChecksum']
    and revision.get('payload')==b['candidatePayload']and revision.get('validationState')=='VALIDATED'and revision.get('validationFindings')==[],
    'EXACT_NEW_IMMUTABLE_OWNER_REVISION_REQUIRED')
   return {'revision':revision['revision'],'checksum':revision['checksum']}
  if stage=='VALIDATE_ENVIRONMENT':
   revision=self.evidence(row,'CREATE_REVISION')['revision'];result,_=self.http.call('POST','/revisions/'+str(revision)+':validate-environment')
   require(result.get('installationId')==b['expectedActive']['installationId']and result.get('revision')==revision and result.get('overallStatus')=='PASS',
    'OWNER_ENVIRONMENT_VALIDATION_PASS_REQUIRED')
   return {'revision':revision,'overallStatus':'PASS','validationId':result['validationId']}
  if stage=='ACTIVATE_EXPECTED':
   revision=self.evidence(row,'CREATE_REVISION')['revision'];result,_=self.http.call('POST','/revisions/'+str(revision)+':activate',etag=b['expectedActiveETag'])
   require(result.get('installationId')==b['expectedActive']['installationId']and result.get('revision')==revision
    and result.get('checksum')==b['candidatePayloadChecksum']and type(result.get('generation'))is int
    and result['generation']>b['expectedActive']['generation'],'OWNER_CONDITIONAL_ACTIVATION_RESULT_REQUIRED')
   active=self.http.active();require({k:active[k]for k in('installationId','revision','checksum','generation')}==result,'OWNER_CONDITIONAL_ACTIVATION_READBACK_REQUIRED')
   return {'active':active,'ifMatch':b['expectedActiveETag']}
  if stage=='EXPORT_ACTIVE':
   active=self.evidence(row,'ACTIVATE_EXPECTED')['active'];projection,headers=self.http.call('GET','/projection?revision='+str(active['revision']))
   require(headers['revision']==str(active['revision'])and headers['checksum']==active['checksum'],'OWNER_EXPORT_HEADERS_REQUIRED')
   expected=copy.deepcopy(plan['sourceProjection']);expected.update(revision=active['revision'],checksum=active['checksum'])
   expected['services']['bindings']={**expected['services']['bindings'],**b['addedBindings']}
   require(projection==expected,'EXACT_OWNER_EXPORT_SINGLE_BINDING_DELTA_REQUIRED')
   baseline.write_new(self.context/'owner-active-projection.json',encoded(projection))
   return {'projectionBinding':{'path':str(self.context/'owner-active-projection.json'),'sha256':digest(projection)},'active':active}
  if stage=='PUBLISH_ACTIVE_PROJECTION':
   projection=baseline.parsed(plan['exportedProjectionBinding']['path'],plan['projectionHash'])
   publish_active_projection(plan['projectionBinding'],encoded(projection),plan['logicalRef'])
   return {'projectionHash':plan['projectionHash']}
  if stage in('GATEWAY_STATUS_ROUTE','GATEWAY_HISTORY_ROUTE'):
   mode='status'if stage=='GATEWAY_STATUS_ROUTE'else'history';route=plan['gateway']['afterRoutes']['mcp-ingestion-'+mode]
   status,_=self.gateway.request('PUT','/apisix/admin/routes/'+quote(route['id'],safe=''),route)
   require(status in(200,201),'GATEWAY_PUT_OUTCOME_UNPROVEN_NO_REPLAY');return {'routeId':route['id'],'routeHash':digest(route)}
  require(stage in('VERIFY_INPUTS','VERIFY_FINAL'),'EXACT_NATIVE_BINDING_STAGE_REQUIRED')
  return {'verified':True}
 def verify(self,stage,row,evidence):
  effects=copy.deepcopy(row['effects']);effects[-1].update(state='APPLIED',evidence=evidence)
  self.guard_current(stage,{**row,'effects':effects})

def baseline_runtime(actual,name,plan):
 ordered=name!='gateway'or plan['gateway']['transport'].get('runtimeBindingProfile')=='ouf.apisix-runtime-binding.mount-set.v1'
 from tools.installation_binding_plan.discovery import runtime as observed
 return observed(actual,ordered)

def publish_active_projection(binding,raw,logical_ref):
 # All network/owner checks happen before this short local critical section.
 path=Path(binding['path']);require(path.is_absolute()and path.resolve()==path and path.name=='active-projection.json','EXACT_ACTIVE_PROJECTION_PATH_REQUIRED')
 private_config(path,binding);parent=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 lock=None;target=None;temporary=path.name+'.ouf-'+logical_ref[:24]+'.tmp'
 try:
  lock=os.open('.ouf-active-projection.publish.lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600,dir_fd=parent)
  s=os.fstat(lock);require(stat.S_ISREG(s.st_mode)and s.st_uid==s.st_gid==0 and stat.S_IMODE(s.st_mode)==0o600 and s.st_nlink==1,'ROOT_PROFILE_PUBLICATION_LOCK_REQUIRED')
  fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
  old,_=private_config(path,binding);require(hashlib.sha256(old).hexdigest()==binding['sha256'],'ACTIVE_PROJECTION_CAS_PRECONDITION_FAILED')
  target=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=parent)
  with os.fdopen(os.dup(target),'wb')as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())
  # Recheck the reviewed path identity while holding the common publisher lock.
  private_config(path,binding)
  os.replace(temporary,path.name,src_dir_fd=parent,dst_dir_fd=parent);os.fsync(parent)
  require(baseline.read(path)==raw,'ACTIVE_PROJECTION_ATOMIC_PUBLICATION_READBACK_REQUIRED')
 finally:
  if target is not None:os.close(target)
  if lock is not None:os.close(lock)
  os.close(parent)
