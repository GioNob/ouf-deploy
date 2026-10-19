"""One owner secret-reference lifecycle. No key material, runtime or Gateway authority."""
import copy,hashlib,json,re,time
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
KIND='INGESTION_PROFILE_PUBLICATION_APPLY'
KEY='ingestionActiveProjectionPublication'
EXPORT='dd31d2b7de5ae66582275e5ac841584ff784065aa6e362ed0279d45fb6cdbc66'
OLD_PROJECTION='10b378c05f6ce38d46b8ba9d66a0fa1f9d5ceb0383975ca6c43ba604e9bf599d'
OWNER_CHECKSUM='66ab1adb9cbaf699100809568f06a7c0f4b97e63505fc8ea7fa6f9727342e5f9'
ROUTES='ed619aa9415b2e70f61689c3830b3fc89135bc9ab72fc90f24daeba1e7bed8c7'
OWNER_RESULT='7d3902327a9b3641129f4416b66324c4cf727d0e54708216f9df098388a15618'
STAGES={KIND:('VERIFY_INPUTS','PUBLISH_ACTIVE_PROJECTION','VERIFY_FINAL')}
FORBIDDEN=('automaticReplayAllowed','budgetReset','newHumanLoginAllowed','databaseMigrationAllowed','iamMutationAllowed',
 'grantChangesAllowed','containerLifecycleAllowed','sourceActivationAllowed','jobDispatchAllowed','publicMetadataChangesAllowed',
 'automaticRollbackAllowed','secretGenerationAllowed','gatewayRouteChangesAllowed','ownerMutationAllowed')
def scope_key(kind):require(kind==KIND,'ONLY_ACTIVE_PROJECTION_SCOPE_REQUIRED');return KEY

def scope(plan):
 require(type(plan)is dict and plan['schema']=='ouf.ingestion-active-projection-plan.v1'and plan['kind']==KIND
  and plan['maximumExecutionSeconds']==120 and plan['maximumEffectAttemptsPerStage']==1
  and all(plan[k]is False for k in FORBIDDEN),'EXACT_PROJECTION_ONLY_PLAN_REQUIRED')
 require(plan['ownerResultBinding']['sha256']==OWNER_RESULT and plan['projectionHash']==EXPORT
  and plan['expectedActive']['revision']==plan['expectedActive']['generation']==7
  and plan['expectedActive']['checksum']==OWNER_CHECKSUM
  and plan['projectionBinding']['sha256']==OLD_PROJECTION
  and plan['humanBinding']['retryProfile']['id']=='ouf.human.ingestion-owner-recovery288.v7'
  and plan['humanBinding']['retryProfile']['maximumAttempts']==288,'EXACT_OWNER7_EXPORT_AND_EXISTING_HUMAN_REQUIRED')
 require(len(plan['gateway']['beforeRoutes'])==82
  and digest(plan['gateway']['beforeRoutes'])==ROUTES,
  'ALL82_EXISTING_ROUTES_MUST_REMAIN_UNCHANGED')
 expected_logical=digest({'ownerResultHash':OWNER_RESULT,'oldProjectionHash':plan['projectionBinding']['sha256'],'newProjectionHash':EXPORT})
 require(plan['logicalRef']==expected_logical,'EXACT_PROJECTION_LOGICAL_SCOPE_REQUIRED')
 return validate_scope({'profile':'ouf.ingestion-active-projection-publication.v1','kind':KIND,'planHash':digest(plan),
  'logicalRef':plan['logicalRef'],'humanBinding':copy.deepcopy(plan['humanBinding']),'stages':list(STAGES[KIND]),
  'maximumExecutionSeconds':120,'maximumEffectAttemptsPerStage':1,'maximumActiveProjectionWrites':1,
  'maximumOwnerPosts':0,'maximumProjectionExports':0,'maximumGatewayPuts':0,
  'ownerResultHash':OWNER_RESULT,'projectionHash':EXPORT,**{k:False for k in FORBIDDEN}})

def validate_scope(value):
 keys={'profile','kind','planHash','logicalRef','humanBinding','stages','maximumExecutionSeconds','maximumEffectAttemptsPerStage',
  'maximumActiveProjectionWrites','maximumOwnerPosts','maximumProjectionExports','maximumGatewayPuts','ownerResultHash','projectionHash',*FORBIDDEN}
 require(type(value)is dict and set(value)==keys and value['profile']=='ouf.ingestion-active-projection-publication.v1'
  and value['kind']==KIND and value['stages']==list(STAGES[KIND])
  and [value[k]for k in('maximumExecutionSeconds','maximumEffectAttemptsPerStage','maximumActiveProjectionWrites','maximumOwnerPosts','maximumProjectionExports','maximumGatewayPuts')]==[120,1,1,0,0,0]
  and value['ownerResultHash']==OWNER_RESULT and value['projectionHash']==EXPORT
  and value['humanBinding']['retryProfile']['id']=='ouf.human.ingestion-owner-recovery288.v7'
  and value['humanBinding']['retryProfile']['maximumAttempts']==288
  and all(value[k]is False for k in FORBIDDEN)
  and all(type(value[k])is str and re.fullmatch('[0-9a-f]{64}',value[k])for k in('planHash','logicalRef')),
  'EXACT_FINITE_PROJECTION_SCOPE_REQUIRED')
 return copy.deepcopy(value)

class FiniteUpdate:
 def __init__(self,action,plan,ports,journal,clock=lambda:(time.time(),time.monotonic())):
  require(type(action)is AggregateAction and type(journal)is Journal,'REAL_SIGNED_ACTION_AND_PRIVATE_JOURNAL_REQUIRED')
  self.action,self.plan,self.ports,self.journal,self.clock=action,copy.deepcopy(plan),ports,journal,clock;self.scope=scope(plan);self.key=scope_key(plan['kind'])
 def initialize(self):
  wall,mono=self.clock();expires=json.loads(self.action.raw)['expiresAt']
  self.action.guard(self.key,self.scope);self.ports.guard_current('VERIFY_INPUTS',{'effects':[]})
  require(wall<expires<=wall+121,'FINITE_CURRENT_BINDING_AUTHORITY_REQUIRED')
  path=self.journal.root.parent/('ingestion-active-projection-'+self.scope['logicalRef']+'.claim.json')
  with protected_directory(path.parent)as directory:
   require(publish(directory,path.name,encoded({'context':str(self.journal.root),'scopeHash':digest(self.scope),'authorityHash':self.action.authority_hash,'automaticReplayAllowed':False,'budgetReset':False})),
    'LOGICAL_INSTALLATION_BINDING_ALREADY_CLAIMED')
  self.journal.initialize({'schema':'ouf.ingestion-active-projection-journal.v1','scopeHash':digest(self.scope),'authorityHash':self.action.authority_hash,
   'expiresAt':expires,'expiresMonotonic':mono+expires-wall,'bootId':self.ports.boot(),'lastWall':wall,'lastMonotonic':mono,'nextStage':0,'effects':[],'version':0,'incidentState':'OPEN','budgetReset':False})
 def record(self):
  row=self.journal.read();n=row['nextStage'];effects=row['effects'];stages=self.scope['stages'];wall,mono=self.clock()
  require(row['schema']=='ouf.ingestion-active-projection-journal.v1'and row['scopeHash']==digest(self.scope)
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
