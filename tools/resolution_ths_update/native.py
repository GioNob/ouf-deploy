"""Three exact route PUTs using the existing custodied APISIX namespace transport."""
import copy,json,time,urllib.request,urllib.error,email.utils
from pathlib import Path
from engine_creation import Engine
from iam_owner_action import publish
from tools.semantic_policy_token_owner.owner_installation import AggregateAction
from tools.semantic_policy_token_owner.producer import protected_directory
from tools.semantic_policy_token_owner.installed_owner import read_private
from tools.semantic_mcp_update.native import private_file
from tools.chatbot_file_cohort.gateway import NamespaceAdmin,private_config,route_map
from tools.onboarding_audit_update.native import runtime
from tools.onboarding_audit_update.entry import read_active_publication
from tools.semantic_lease_recovery.recovery_journal import Journal
from tools.resolution_ths_update.owner import require,digest,scope,STAGES
from tools.resolution_ths_update.plan import ROUTES
class ReadTransient(RuntimeError):
 def __init__(self,retry_after=None):
  super().__init__('TRANSIENT_ROUTE_READ')
  try:self.retry_after=max(0,float(retry_after or 0))
  except (ValueError,TypeError):
   try:self.retry_after=max(0,email.utils.parsedate_to_datetime(retry_after).timestamp()-time.time())
   except (ValueError,TypeError,OverflowError):self.retry_after=0
  require(self.retry_after<float('inf'),'BOUNDED_RETRY_AFTER_REQUIRED')
class NoRedirect(urllib.request.HTTPRedirectHandler):
 def redirect_request(self,*args):return None
class NativePorts:
 def __init__(self,action,engine,plan,human):
  require(type(action)is AggregateAction and type(engine)is Engine,'REAL_AUTHORITY_AND_ENGINE_REQUIRED')
  self.action,self.engine,self.plan,self.human=action,engine,copy.deepcopy(plan),human
  self.gateway=NamespaceAdmin(engine,plan['gatewayTransport'])
 def boot(self):return Path('/proc/sys/kernel/random/boot_id').read_text().strip()
 def claim_logical_scope(self):
  with protected_directory(Path(self.plan['authorityDirectory']).parent)as directory:
   require(publish(directory,'resolution-route-update-'+self.plan['logicalUpdateRef']+'.claim.json',json.dumps({'planHash':digest(self.plan),'authorityHash':self.action.authority_hash,'contextPath':self.plan['authorityDirectory'],'automaticReplayAllowed':False},sort_keys=True).encode()),'RESOLUTION_ROUTE_UPDATE_ALREADY_CLAIMED_RECONCILE')
 def guard_current(self,stage):
  require(stage in STAGES,'EXACT_ROUTE_UPDATE_STAGE_REQUIRED');p=self.plan
  self.action.guard('resolutionRoutesUpdate',scope(p));self.engine.check_socket();self.gateway.check()
  require(self.human.current()==p['humanBinding'],'CURRENT_SAME_AUTHENTICATED_HUMAN_REQUIRED')
  private_config(p['configuration']['fileBinding']['path'],p['configuration']['fileBinding'])
  for name,pin in p['applicationPins'].items():
   status,actual=self.engine.request('GET','/v1.44/containers/'+pin['containerId']+'/json')
   require(status==200 and actual['State']['Running']is True and runtime(actual)==pin,'UNCHANGED_APPLICATION_GENERATION_REQUIRED')
  worker=p['worker'];require(time.time()<worker['conservativeExpiresAt'],'CURRENT_POLICY_WORKER_WINDOW_REQUIRED')
  fence=Path(worker['fenceBinding']['path']);private_file(fence,digest(worker['fenceBinding']['value']),16384)
  with protected_directory(fence.parent)as directory:
   require(json.loads(read_private(directory,fence.name,16384))==worker['fenceBinding']['value'],'CURRENT_POLICY_FENCE_REQUIRED')
  read_active_publication(Journal(worker['journalPath']),worker['scope'],lambda:self.action.guard('resolutionRoutesUpdate',scope(p)))
 def inventory(self):
  status,body=self.gateway.request('GET','/apisix/admin/routes')
  if status in(429,502,503,504):raise ReadTransient(getattr(self.gateway,'retry_after',None))
  require(status==200 and type(body)is dict and type(body.get('list'))is list and body.get('total')==len(body['list']),'COMPLETE_CURRENT_ROUTE_INVENTORY_REQUIRED')
  return route_map(body['list'])
 def expected(self,count):
  result=copy.deepcopy(self.plan['beforeRoutes'])
  for rid in ROUTES[:count]:result[rid]=copy.deepcopy(self.plan['routes'][rid])
  return result
 def apply(self,stage):
  require(stage in STAGES[1:4],'ONLY_THREE_ROUTE_WRITES_ALLOWED');index=STAGES.index(stage)-1
  require(self.inventory()==self.expected(index),'EXACT_CURRENT_ROUTE_PREFIX_REQUIRED')
  rid=ROUTES[index];status,_=self.gateway.request('PUT','/apisix/admin/routes/'+rid,self.plan['routes'][rid])
  require(status in(200,201),'ROUTE_WRITE_OUTCOME_UNPROVEN_RECONCILE_NO_REPLAY')
 def anonymous_probes(self):
  opener=urllib.request.build_opener(NoRedirect());results={}
  for name,path,allowed in(('page','/trusted-human/resolution/',(302,303,401,403)),('owner','/api/udp/v1/governance/resolution/issues/package',(401,403))):
   request=urllib.request.Request(self.plan['reviewedOrigin'].rstrip('/')+path,headers={'Accept':'application/json'})
   try:
    with opener.open(request,timeout=8)as response:status=response.status
   except urllib.error.HTTPError as error:
    status=error.code;retry_after=error.headers.get('Retry-After');error.close()
    if status in(429,502,503,504):raise ReadTransient(retry_after)
   require(status in allowed,'ANONYMOUS_RESOLUTION_BOUNDARY_UNPROVEN')
   results[name]=status
  return results
 def observe(self,stage):
  try:
   count=0 if stage=='VERIFY_INPUTS'else 3 if stage=='VERIFY_FINAL'else STAGES.index(stage)
   actual=self.inventory();require(actual==self.expected(count),'EXACT_RETAINED_PLUS_RESOLUTION_ROUTE_MAP_REQUIRED')
   proof={'routeMapHash':digest(actual),'preservedRouteCount':len(self.plan['beforeRoutes']),'newRouteCount':count}
   if stage=='VERIFY_FINAL':proof['anonymousBoundaryStatuses']=self.anonymous_probes()
   return 'APPLIED',proof
  except ReadTransient as error:return 'TRANSIENT',{'retryAfterSeconds':error.retry_after}
