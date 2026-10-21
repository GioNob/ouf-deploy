"""Two finite separately signed scopes; no database, IAM, source or container operations."""
import copy,hashlib,json,os,re,time
from pathlib import Path
from iam_owner_action import publish
from tools.semantic_policy_token_owner.producer import protected_directory
from tools.semantic_lease_recovery.recovery_journal import Journal
from tools.semantic_policy_token_owner.owner_installation import AggregateAction
class Denied(RuntimeError):pass
def require(ok,reason):
 if not ok:raise Denied(reason)
def encoded(v):return json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def digest(v):return hashlib.sha256(encoded(v)).hexdigest()
CANDIDATE_HASH='ded675196fa5b7f9c398b249f737ff19df26d66e81afa65ddcf9a5ecfb034a98'
STAGES={'INSTALLATION_BINDING_APPLY':('VERIFY_INPUTS','CREATE_REVISION','VALIDATE_ENVIRONMENT','ACTIVATE_EXPECTED','EXPORT_ACTIVE','VERIFY_FINAL'),
 'INSTALLATION_PROJECTION_ROUTE_APPLY':('VERIFY_INPUTS','PUBLISH_ACTIVE_PROJECTION','GATEWAY_STATUS_ROUTE','GATEWAY_HISTORY_ROUTE','VERIFY_FINAL')}
FORBIDDEN=('automaticReplayAllowed','budgetReset','newHumanLoginAllowed','databaseMigrationAllowed','iamMutationAllowed',
 'grantChangesAllowed','containerLifecycleAllowed','sourceActivationAllowed','jobDispatchAllowed','publicMetadataChangesAllowed','automaticRollbackAllowed')
def scope_key(kind):return 'installationBindingApply'if kind=='INSTALLATION_BINDING_APPLY'else'installationProjectionRouteApply'
def validate_scope(value):
 keys={'profile','kind','planHash','logicalRef','humanBinding','stages','maximumExecutionSeconds','maximumEffectAttemptsPerStage',
 'maximumOwnerPosts','maximumProjectionExports','maximumActiveProjectionWrites','maximumGatewayPuts','expectedActive','expectedActiveETag','candidatePayloadChecksum',*FORBIDDEN}
 require(type(value)is dict and set(value)==keys and value['kind']in STAGES
  and value['profile']=='ouf.installation-ingestion-binding-native.v1'and value['stages']==list(STAGES[value['kind']])
  and value['maximumExecutionSeconds']==210 and value['maximumEffectAttemptsPerStage']==1
  and all(value[k]is False for k in FORBIDDEN),'EXACT_FINITE_INSTALLATION_BINDING_SCOPE_REQUIRED')
 owner=value['kind']=='INSTALLATION_BINDING_APPLY'
 require([value[k]for k in('maximumOwnerPosts','maximumProjectionExports','maximumActiveProjectionWrites','maximumGatewayPuts')]==([3,1,0,0]if owner else[0,0,1,2]),'EXACT_SEPARATE_OWNER_OR_PROJECTION_ROUTE_EFFECTS_REQUIRED')
 require(all(type(value[k])is str and re.fullmatch('[0-9a-f]{64}',value[k])for k in('planHash','logicalRef','candidatePayloadChecksum'))
  and type(value['expectedActive'])is dict and set(value['expectedActive'])=={'installationId','revision','checksum','generation'}
  and value['expectedActiveETag']=='"'+str(value['expectedActive']['revision'])+':'+value['expectedActive']['checksum']+':'+str(value['expectedActive']['generation'])+'"',
  'EXACT_STRONG_ACTIVE_SCOPE_BINDING_REQUIRED')
 return copy.deepcopy(value)
def scope(plan):
 require(type(plan)is dict and plan['kind']in STAGES and plan['schema']=='ouf.installation-binding-native-plan.v1'
  and plan['maximumExecutionSeconds']==210 and plan['maximumEffectAttemptsPerStage']==1
  and all(plan[k]is False for k in FORBIDDEN),'EXACT_INSTALLATION_BINDING_NATIVE_PLAN_REQUIRED')
 owner=plan['kind']=='INSTALLATION_BINDING_APPLY';binding=plan['bindingPlan']
 from tools.installation_binding_plan.plan import canonical_owner
 require(canonical_owner(binding['candidatePayload'])==CANDIDATE_HASH,'REVIEWED_PAYLOAD_CANONICAL_CHECKSUM_REQUIRED')
 require(binding['onlyChange']=='/networking/serviceBindings/ouf-ingestion-runtime'
  and binding['candidatePayloadChecksum']==CANDIDATE_HASH
  and binding['candidatePayload']['networking']['serviceBindings']['ouf-ingestion-runtime']==binding['addedBindings']['ouf-ingestion-runtime'],
  'EXACT_REVIEWED_SINGLE_BINDING_REQUIRED')
 if not owner:
  before=plan['gateway']['beforeRoutes'];after=plan['gateway']['afterRoutes'];changed={k for k in before if before[k]!=after.get(k)}
  require(len(before)==len(after)==82 and set(before)==set(after)and changed=={'mcp-ingestion-status','mcp-ingestion-history'},'EXACT_TWO_ROUTE_REPLACEMENTS_WITH80_RETAINED_REQUIRED')
  for key in changed:
   old=copy.deepcopy(before[key]);new=copy.deepcopy(after[key]);a=old['upstream'].pop('nodes');b=new['upstream'].pop('nodes')
   require(old==new and len(a)==len(b)==1 and list(a.values())==list(b.values())and [x.rsplit(':',1)[-1]for x in a]==[x.rsplit(':',1)[-1]for x in b]
    and all(node.rsplit(':',1)[0]==binding['addedBindings']['ouf-ingestion-runtime']for node in b),
    'ONLY_GOVERNED_ROUTE_HOST_BINDING_MAY_CHANGE')
 return validate_scope({'profile':'ouf.installation-ingestion-binding-native.v1','kind':plan['kind'],'planHash':digest(plan),
  'logicalRef':plan['logicalRef'],'humanBinding':copy.deepcopy(plan['humanBinding']),'stages':list(STAGES[plan['kind']]),
  'maximumExecutionSeconds':210,'maximumEffectAttemptsPerStage':1,'maximumOwnerPosts':3 if owner else 0,
  'maximumProjectionExports':1 if owner else 0,'maximumActiveProjectionWrites':0 if owner else 1,'maximumGatewayPuts':0 if owner else 2,
  'expectedActive':copy.deepcopy(binding['expectedActive']),'expectedActiveETag':binding['expectedActiveETag'],
  'candidatePayloadChecksum':binding['candidatePayloadChecksum'],**{k:False for k in FORBIDDEN}})

class FiniteUpdate:
 def __init__(self,action,plan,ports,journal,clock=lambda:(time.time(),time.monotonic())):
  require(type(action)is AggregateAction and type(journal)is Journal,'REAL_SIGNED_ACTION_AND_PRIVATE_JOURNAL_REQUIRED')
  self.action,self.plan,self.ports,self.journal,self.clock=action,copy.deepcopy(plan),ports,journal,clock;self.scope=scope(plan);self.key=scope_key(plan['kind'])
 def initialize(self):
  wall,mono=self.clock();expires=json.loads(self.action.raw)['expiresAt']
  self.action.guard(self.key,self.scope);self.ports.guard_current('VERIFY_INPUTS',{'effects':[]})
  require(wall<expires<=wall+211,'FINITE_CURRENT_BINDING_AUTHORITY_REQUIRED')
  path=self.journal.root.parent/('installation-binding-native-'+self.scope['logicalRef']+'.claim.json')
  with protected_directory(path.parent)as directory:
   require(publish(directory,path.name,encoded({'context':str(self.journal.root),'scopeHash':digest(self.scope),'authorityHash':self.action.authority_hash,'automaticReplayAllowed':False,'budgetReset':False})),
    'LOGICAL_INSTALLATION_BINDING_ALREADY_CLAIMED')
  self.journal.initialize({'schema':'ouf.installation-binding-native-journal.v1','scopeHash':digest(self.scope),'authorityHash':self.action.authority_hash,
   'expiresAt':expires,'expiresMonotonic':mono+expires-wall,'bootId':self.ports.boot(),'lastWall':wall,'lastMonotonic':mono,'nextStage':0,'effects':[],'version':0,'incidentState':'OPEN','budgetReset':False})
 def record(self):
  row=self.journal.read();n=row['nextStage'];effects=row['effects'];stages=self.scope['stages'];wall,mono=self.clock()
  require(row['schema']=='ouf.installation-binding-native-journal.v1'and row['scopeHash']==digest(self.scope)
   and row['authorityHash']==self.action.authority_hash and row['budgetReset']is False
   and row['bootId']==self.ports.boot()and wall>=row['lastWall']and mono>=row['lastMonotonic']
   and type(n)is int and 0<=n<=len(stages)and len(effects)in(n,n+1)
   and [e['stage']for e in effects]==stages[:len(effects)]and all(e['state']=='APPLIED'for e in effects[:n])
   and(len(effects)==n or effects[-1]['state']=='CLAIMED')
   and all(e['intentHash']==digest({'planHash':digest(self.plan),'stage':e['stage']})for e in effects),'DURABLE_INSTALLATION_BINDING_HISTORY_DRIFT')
  return row
 def save(self,row,**values):
  wall,mono=self.clock();require(wall>=row['lastWall']and mono>=row['lastMonotonic'],'BINDING_ACTION_CLOCK_DRIFT')
  following={**row,**values,'version':row['version']+1,'lastWall':wall,'lastMonotonic':mono};self.journal.compare_and_save(row,following);return following
 def run(self):
  with self.journal.invocation():
   while True:
    row=self.record();self.action.guard(self.key,self.scope);wall,mono=self.clock()
    require(min(row['expiresAt']-wall,row['expiresMonotonic']-mono)>10,'INSTALLATION_BINDING_AUTHORITY_EXPIRED')
    n=row['nextStage']
    require(len(row['effects'])==n,'CLAIMED_BINDING_EFFECT_REQUIRES_RECONCILIATION_NO_REPLAY')
    if n==len(self.scope['stages']):
     if row['incidentState']!='RECOVERED':row=self.save(row,incidentState='RECOVERED')
     return row
    stage=self.scope['stages'][n];self.ports.guard_current(stage,row)
    effect={'stage':stage,'state':'CLAIMED','intentHash':digest({'planHash':digest(self.plan),'stage':stage})}
    row=self.save(row,effects=row['effects']+[effect])
    evidence=self.ports.apply(stage,row)
    self.action.guard(self.key,self.scope);self.ports.verify(stage,row,evidence)
    effects=copy.deepcopy(row['effects']);effects[-1].update(state='APPLIED',evidence=evidence)
    self.save(row,effects=effects,nextStage=n+1)
