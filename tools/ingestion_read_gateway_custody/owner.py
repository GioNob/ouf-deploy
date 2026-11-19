"""Finite two-route publication. No container, database, IAM or source effects."""
import copy,hashlib,json,os,re,stat,time
from pathlib import Path
from urllib.parse import quote
from engine_creation import Engine
from tools.semantic_policy_token_owner.owner_installation import AggregateAction
from tools.semantic_lease_recovery.recovery_journal import Journal
from tools.semantic_policy_token_owner.producer import protected_directory
from iam_owner_action import publish
from tools.chatbot_file_cohort.gateway import NamespaceAdmin,private_config
from tools.source_revision_update.native import runtime
from tools.semantic_mcp_update.native import private_file
PROFILE='ouf.ingestion-read-gateway-custody-correction.v1'
SCOPE_KEY='ingestionReadGatewayCustodyUpdate'
BEFORE_HASH='9b022a247a5777347cd7794733507bb90a9142ffd62c6497ae3e3c1cbd66fcd2'
STAGES=('VERIFY_INPUTS','GATEWAY_STATUS_ROUTE','GATEWAY_HISTORY_ROUTE','VERIFY_FINAL')
FORBIDDEN=('automaticReplayAllowed','budgetReset','newHumanLoginAllowed','automaticRollbackAllowed','containerLifecycleAllowed',
 'databaseMigrationAllowed','grantChangesAllowed','publicMetadataChangesAllowed','sourceActivationAllowed','jobDispatchAllowed','semanticDispatchAllowed')
class UpdateDenied(RuntimeError):pass
def require(ok,reason):
 if not ok:raise UpdateDenied(reason)
def encoded(value):return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def digest(value):return hashlib.sha256(encoded(value)).hexdigest()
def validate_scope(value):
 keys={'profile','planHash','logicalUpdateRef','stages','beforeRouteMapHash','afterRouteMapHash','routeHashes','maximumGatewayWrites',
  'maximumExecutionSeconds','maximumEffectAttemptsPerStage','humanBinding','predecessorEvidenceHash','metadataReadProfile',*FORBIDDEN}
 require(type(value)is dict and set(value)==keys and value['profile']==PROFILE and value['stages']==list(STAGES)
  and value['beforeRouteMapHash']==BEFORE_HASH and set(value['routeHashes'])=={'status','history'}
  and value['maximumGatewayWrites']==2 and value['maximumExecutionSeconds']==900 and value['maximumEffectAttemptsPerStage']==1
  and value['metadataReadProfile']=='PUBLIC_MCP0440_EXACT_BINDING'and re.fullmatch('[0-9a-f]{64}',value['predecessorEvidenceHash'])
  and all(value[k]is False for k in FORBIDDEN)
  and all(type(h)is str and re.fullmatch('[0-9a-f]{64}',h)for h in[value['planHash'],value['logicalUpdateRef'],value['afterRouteMapHash'],*value['routeHashes'].values()])
  and type(value['humanBinding'])is dict,'EXACT_TWO_ROUTE_ONLY_SCOPE_REQUIRED')
 return value

def scope(plan):
 require(plan.get('schema')=='ouf.ingestion-read-gateway-plan.v1'and plan.get('maximumExecutionSeconds')==900
  and plan.get('maximumEffectAttemptsPerStage')==1 and plan.get('maximumGatewayWrites')==2
  and plan.get('replacements')=={}and plan.get('databaseMigration')is None
  and all(plan.get(k)is False for k in FORBIDDEN),'EXACT_GATEWAY_ONLY_PLAN_REQUIRED')
 gateway=plan['gateway'];before=gateway['beforeRoutes'];after=gateway['afterRoutes'];add=gateway['additions']
 require(len(before)==80 and digest(before)==BEFORE_HASH and len(after)==82 and set(add)=={'status','history'}
  and all(after.get(k)==v for k,v in before.items()),'EXACT80_ROUTES_PRESERVED_WITH_TWO_ADDITIONS_REQUIRED')
 expected=copy.deepcopy(before)
 for mode,row in add.items():
  require(row['id']=='mcp-ingestion-'+mode and row['id']not in before and row.get('uri')=='/internal/capabilities/v1/execute/ouf.ingestion.'+mode
   and row.get('methods')==['POST']and row.get('status')==1,'EXACT_DECLARED_READ_ROUTE_REQUIRED')
  plugins=row.get('plugins',{});schema=plugins.get('request-validation',{}).get('body_schema',{});fields=schema.get('properties',{})
  base=[r for r in before.values()if r.get('uri')=='/internal/capabilities/v1/execute']
  require(len(base)==1 and plugins.get('openid-connect')==base[0].get('plugins',{}).get('openid-connect')
   and plugins.get('openid-connect',{}).get('ssl_verify')is True
   and plugins.get('openid-connect',{}).get('use_jwks')is True
   and plugins.get('openid-connect',{}).get('bearer_only')is True
   and plugins.get('openid-connect',{}).get('unauth_action')=='deny'
   and plugins.get('proxy-rewrite')=={'uri':'/api/internal/v1/ingestion/operations/'+mode}
   and row.get('upstream',{}).get('retries')==0
   and fields.get('CapabilityID')=={'const':'ouf.ingestion.'+mode}
   and fields.get('Owner')=={'const':'ingestion'}and fields.get('OperationClass')=={'type':'string','enum':['READ']}
   and fields.get('Arguments',{}).get('additionalProperties')is False,'EXACT_AUTHENTICATED_READ_ROUTE_CONTRACT_REQUIRED')
  expected[row['id']]=row
 require(after==expected and len(plan['unchangedApplications'])==4
  and set(plan['unchangedApplications'])=={'mcp','onboarding','udp','ingestion'},'NO_OTHER_GATEWAY_OR_CONTAINER_DELTA_ALLOWED')
 predecessor_shape(plan['custodyPredecessor'])
 logical=logical_ref()
 require(plan['logicalUpdateRef']==logical,'EXACT_GATEWAY_LOGICAL_ACTION_REQUIRED')
 return validate_scope({'profile':PROFILE,'planHash':digest(plan),'logicalUpdateRef':logical,'stages':list(STAGES),
  'beforeRouteMapHash':BEFORE_HASH,'afterRouteMapHash':digest(after),'routeHashes':{k:digest(v)for k,v in add.items()},
  'maximumGatewayWrites':2,'maximumExecutionSeconds':900,'maximumEffectAttemptsPerStage':1,
  'humanBinding':copy.deepcopy(plan['humanBinding']),'predecessorEvidenceHash':digest(plan['custodyPredecessor']),
  'metadataReadProfile':'PUBLIC_MCP0440_EXACT_BINDING',**{k:False for k in FORBIDDEN}})

ORIGIN=Path('/etc/ouf/deploy-snapshots/mcp-ingestion-read-transport-execution-s_qwngj5')
ORIGIN_PACKAGE='a925da0d4a1a695f22690ac24d351f7dd34ba46b620465fa0198e13feedf0a16'
ORIGIN_PLAN='a316deb877fc9d2506ee41da98915fd43c582ec9f9fc2b7188af90452f19c617'
ORIGIN_REVIEW='f1222de6ac5ab736120fb9cd159443992e4089186296891c8cc61cb2ab50dbd3'
PREDECESSOR_EXPIRES=1792413359
def logical_ref():
 return digest({'profile':'ouf.ingestion-read-gateway-publication.v1','beforeRouteMapHash':BEFORE_HASH,
  'capabilities':['ouf.ingestion.status','ouf.ingestion.history']})
def predecessor_shape(value):
 require(type(value)is dict and set(value)=={'originContext','originPackageHash','originPlanHash','originReviewHash','originalAuthorityExpiresAt','bindings'}
  and value['originContext']==str(ORIGIN)and value['originPackageHash']==ORIGIN_PACKAGE and value['originPlanHash']==ORIGIN_PLAN
  and value['originReviewHash']==ORIGIN_REVIEW and value['originalAuthorityExpiresAt']==PREDECESSOR_EXPIRES,
  'EXACT_EXPIRED_ZERO_EFFECT_PREDECESSOR_REQUIRED')
 bindings=value['bindings'];require(type(bindings)is dict and set(bindings)=={'plan','review','journal','runtimeClaim','logicalClaim'},'EXACT_PREDECESSOR_BINDINGS_REQUIRED')
 for key,binding in bindings.items():
  require(type(binding)is dict and set(binding)=={'path','sha256'}and re.fullmatch('[0-9a-f]{64}',binding['sha256']),
   'EXACT_PRIVATE_PREDECESSOR_BINDING_REQUIRED')
  path=Path(binding['path'])
  wanted={'plan':'execution-plan.json','review':'review.json','journal':'recovery.json','runtimeClaim':'runtime.claim.json'}
  if key in wanted:require(path==ORIGIN/wanted[key],'EXACT_PREDECESSOR_MEMBER_PATH_REQUIRED')
  else:require(path==ORIGIN.parent/('ingestion-read-gateway-'+logical_ref()+'.claim.json'),'EXACT_ORIGINAL_LOGICAL_FENCE_REQUIRED')
 require(bindings['plan']['sha256']==ORIGIN_PLAN and bindings['review']['sha256']==ORIGIN_REVIEW,'EXACT_ORIGINAL_PLAN_AND_REVIEW_HASH_REQUIRED')
def predecessor_unchanged(value,now):
 predecessor_shape(value);require(now>PREDECESSOR_EXPIRES,'PREDECESSOR_AUTHORITY_STILL_LIVE_NO_REPLACEMENT')
 for binding in value['bindings'].values():private_file(binding['path'],binding['sha256'],8388608)

def metadata_file(binding):
 require(type(binding)is dict and set(binding)=={'path','sha256','custody'}and re.fullmatch('[0-9a-f]{64}',binding['sha256']),
  'EXACT_APPROVED_PUBLIC_METADATA_BINDING_REQUIRED')
 path=Path(binding['path']);require(path.is_absolute()and path.resolve()==path and path.name in('profile.json','policy.json','permit.json'),
  'EXACT_PUBLIC_MCP_METADATA_PATH_REQUIRED')
 for parent in path.parents:
  info=parent.lstat();require(stat.S_ISDIR(info.st_mode)and info.st_uid==0 and not info.st_mode&0o022,'ROOT_METADATA_ANCESTRY_REQUIRED')
 expected=binding['custody'];fields=('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size')
 require(type(expected)is dict and set(expected)==set(fields),'EXACT_SIGNED_METADATA_CUSTODY_FIELDS_REQUIRED')
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  before=os.fstat(fd)
  require(stat.S_ISREG(before.st_mode)and before.st_uid==0 and stat.S_IMODE(before.st_mode)==0o440
   and before.st_nlink==1 and 0<before.st_size<=65536 and {k:getattr(before,k)for k in fields}==expected,
   'EXACT_UNCHANGED_PUBLIC_METADATA0440_REQUIRED')
  with os.fdopen(os.dup(fd),'rb')as stream:raw=stream.read(65537)
  pin=lambda s:tuple(getattr(s,k)for k in(*fields,'st_mtime_ns','st_ctime_ns'))
  require(len(raw)==before.st_size and pin(before)==pin(os.fstat(fd))==pin(path.lstat())
   and hashlib.sha256(raw).hexdigest()==binding['sha256'],'APPROVED_PUBLIC_METADATA_BYTES_OR_CUSTODY_CHANGED')
  return {'sha256':binding['sha256'],'bytes':len(raw),'mode':0o440}
 finally:os.close(fd)

class GatewayUpdate:
 def __init__(self,action,engine,plan,human,journal,clock=lambda:(time.time(),time.monotonic())):
  require(type(action)is AggregateAction and type(engine)is Engine and type(journal)is Journal,'REAL_NATIVE_AUTHORITY_ENGINE_JOURNAL_REQUIRED')
  self.action,self.engine,self.plan,self.human,self.journal,self.clock=action,engine,copy.deepcopy(plan),human,journal,clock
  self.scope=scope(plan);self.gateway=NamespaceAdmin(engine,plan['gateway']['transport']);self.expires=json.loads(action.raw)['expiresAt']
 def record(self):
  row=self.journal.read();n=row['nextStage'];effects=row['effects']
  require(row['schema']=='ouf.ingestion-read-gateway-journal.v1'and row['scopeHash']==digest(self.scope)
   and row['authorityHash']==self.action.authority_hash and row['budgetReset']is False
   and type(n)is int and 0<=n<=len(STAGES)and len(effects)in(n,n+1)
   and [e['stage']for e in effects]==list(STAGES[:len(effects)])and all(e['state']=='APPLIED'for e in effects[:n])
   and(len(effects)==n or effects[-1]['state']=='CLAIMED')
   and all(e['intentHash']==digest({'planHash':self.scope['planHash'],'stage':e['stage']})for e in effects),
   'DURABLE_GATEWAY_STAGE_HISTORY_CHANGED')
  return row
 def expected(self,include_claim=False):
  routes=copy.deepcopy(self.plan['gateway']['beforeRoutes'])
  for effect in self.record()['effects']:
   mode={'GATEWAY_STATUS_ROUTE':'status','GATEWAY_HISTORY_ROUTE':'history'}.get(effect['stage'])
   if mode and(effect['state']=='APPLIED'or include_claim and effect['state']=='CLAIMED'):
    row=self.plan['gateway']['additions'][mode];routes[row['id']]=row
  return routes
 def guard(self):
  require(scope(self.plan)==self.scope,'GATEWAY_PLAN_CHANGED');self.action.guard(SCOPE_KEY,self.scope)
  predecessor_unchanged(self.plan['custodyPredecessor'],self.clock()[0])
  row=self.record();wall,mono=self.clock()
  require(Path('/proc/sys/kernel/random/boot_id').read_text().strip()==row['bootId']and wall>=row['lastWall']and mono>=row['lastMonotonic']
   and wall<min(row['expiresAt'],self.expires)and mono<row['expiresMonotonic'],'FINITE_GATEWAY_AUTHORITY_OR_CLOCK_EXPIRED')
  require(self.human.current()==self.plan['humanBinding'],'SAME_CURRENT_HUMAN_REQUIRED')
  self.engine.check_socket();self.gateway.check()
  private_file(self.plan['privateReviewBinding']['path'],self.plan['privateReviewBinding']['sha256'],8388608)
  private_config(self.plan['gateway']['projectionBinding']['path'],self.plan['gateway']['projectionBinding'])
  for binding in self.plan['retainedMcpMetadata']:
   metadata_file(binding)
  for binding in self.plan['unchangedApplications'].values():
   status,actual=self.engine.request('GET','/v1.44/containers/'+binding['containerId']+'/json')
   require(status==200 and actual['State']['Running']is True and runtime(actual)==binding,'UNCHANGED_APPLICATION_DRIFT')
  routes=self.gateway.routes();require(routes in(self.expected(),self.expected(True)),'GATEWAY_ROUTE_MAP_DRIFT');return routes
 def initialize(self):
  self.action.guard(SCOPE_KEY,self.scope);wall,mono=self.clock();predecessor_unchanged(self.plan['custodyPredecessor'],wall);remaining=min(900,self.expires-wall)
  require(remaining>=60 and self.journal.root==Path(self.plan['authorityDirectory']),'SAME_FINITE_GATEWAY_CONTEXT_REQUIRED')
  with protected_directory(self.journal.root.parent)as directory:
   require(publish(directory,'ingestion-read-gateway-custody-'+self.plan['logicalUpdateRef']+'.claim.json',encoded({
    'context':str(self.journal.root),'planHash':self.scope['planHash'],'authorityHash':self.action.authority_hash,
    'automaticReplayAllowed':False,'budgetReset':False})),'GATEWAY_LOGICAL_ACTION_ALREADY_CLAIMED')
  self.journal.initialize({'schema':'ouf.ingestion-read-gateway-journal.v1','scopeHash':digest(self.scope),'authorityHash':self.action.authority_hash,
   'bootId':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'version':0,'nextStage':0,'effects':[],
   'expiresAt':wall+remaining,'expiresMonotonic':mono+remaining,'lastWall':wall,'lastMonotonic':mono,'budgetReset':False,'incidentState':'OPEN'})
 def save(self,row,**changes):
  wall,mono=self.clock();following={**row,**changes,'version':row['version']+1,'lastWall':wall,'lastMonotonic':mono}
  self.journal.compare_and_save(row,following);return following
 def run(self):
  with self.journal.invocation():
   while True:
    actual=self.guard();row=self.record();n=row['nextStage']
    if n==len(STAGES):
     require(actual==self.plan['gateway']['afterRoutes'],'COMPLETE82_ROUTE_READBACK_REQUIRED')
     if row['incidentState']!='RECOVERED':self.save(row,incidentState='RECOVERED')
     return {'schema':'ouf.ingestion-read-gateway-result.v1','complete':True,'gatewayWrites':2,'retainedRoutesPreserved':80,
      'routeCount':82,'routeMapHash':digest(actual),'containerLifecycleOperations':0,'databaseCalls':0,'runtimeAuthorityIssued':True,
      'sourceActivated':False,'notReleaseAcceptance':True,'automaticReplayAllowed':False,'budgetReset':False,
      'completedTechnicalPhases':8,'functionalMilestonesProven':4}
    require(len(row['effects'])==n,'CLAIMED_GATEWAY_EFFECT_REQUIRES_READ_ONLY_RECONCILIATION')
    require(min(row['expiresAt']-self.clock()[0],row['expiresMonotonic']-self.clock()[1])>=45,'INSUFFICIENT_FINITE_GATEWAY_STAGE_WINDOW')
    stage=STAGES[n];effect={'stage':stage,'state':'CLAIMED','intentHash':digest({'planHash':self.scope['planHash'],'stage':stage})}
    row=self.save(row,effects=row['effects']+[effect]);self.guard()
    mode={'GATEWAY_STATUS_ROUTE':'status','GATEWAY_HISTORY_ROUTE':'history'}.get(stage)
    if mode:
     route=self.plan['gateway']['additions'][mode]
     require(self.gateway.routes()==self.expected(),'GATEWAY_CHANGED_BEFORE_EXACT_PUT')
     status,_=self.gateway.request('PUT','/apisix/admin/routes/'+quote(route['id'],safe=''),route)
     require(status in(200,201),'GATEWAY_PUT_OUTCOME_UNPROVEN_NO_REPLAY')
     actual=self.guard();require(actual==self.expected(True),'GATEWAY_PUT_READBACK_UNPROVEN_NO_REPLAY')
    else:
     actual=self.guard()
     if stage=='VERIFY_FINAL':require(actual==self.plan['gateway']['afterRoutes'],'EXACT82_FINAL_ROUTES_REQUIRED')
    effects=copy.deepcopy(row['effects']);effects[-1].update(state='APPLIED',evidence={'routeMapHash':digest(actual)})
    self.save(row,effects=effects,nextStage=n+1)
