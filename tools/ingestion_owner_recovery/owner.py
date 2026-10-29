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
KIND='INGESTION_OWNER_REFERENCE_APPLY'
KEY='ingestionOwnerReference'
CANDIDATE_HASH='66ab1adb9cbaf699100809568f06a7c0f4b97e63505fc8ea7fa6f9727342e5f9'
DRAFT_HASH='2b2e04e379209e365c8fcf2da8ac52141afed9d2034dc5534722c32cdfbb32ec'
ROUTES='ed619aa9415b2e70f61689c3830b3fc89135bc9ab72fc90f24daeba1e7bed8c7'
STAGES={KIND:('VERIFY_INPUTS','CREATE_REVISION','VALIDATE_ENVIRONMENT','ACTIVATE_EXPECTED','EXPORT_ACTIVE','VERIFY_FINAL')}
FORBIDDEN=('automaticReplayAllowed','budgetReset','newHumanLoginAllowed','databaseMigrationAllowed','iamMutationAllowed',
 'grantChangesAllowed','containerLifecycleAllowed','sourceActivationAllowed','jobDispatchAllowed','publicMetadataChangesAllowed',
 'automaticRollbackAllowed','secretGenerationAllowed','activeProjectionPublicationAllowed','gatewayRouteChangesAllowed')
def scope_key(kind):require(kind==KIND,'ONLY_INGESTION_OWNER_REFERENCE_SCOPE_REQUIRED');return KEY
def validate_scope(value):
 keys={'profile','kind','planHash','logicalRef','humanBinding','stages','maximumExecutionSeconds','maximumEffectAttemptsPerStage',
 'maximumOwnerPosts','maximumProjectionExports','maximumActiveProjectionWrites','maximumGatewayPuts','expectedActive','expectedActiveETag','candidatePayloadChecksum','draftPlanHash',*FORBIDDEN}
 require(type(value)is dict and set(value)==keys and value['kind']==KIND
  and value['profile']=='ouf.ingestion-read-owner-reference.v1'and value['stages']==list(STAGES[KIND])
  and value['maximumExecutionSeconds']==210 and value['maximumEffectAttemptsPerStage']==1
  and [value[k]for k in('maximumOwnerPosts','maximumProjectionExports','maximumActiveProjectionWrites','maximumGatewayPuts')]==[3,1,0,0]
  and value['candidatePayloadChecksum']==CANDIDATE_HASH and value['draftPlanHash']==DRAFT_HASH
  and value['humanBinding'].get('retryProfile',{}).get('id')=='ouf.human.ingestion-owner-recovery288.v7'
  and value['humanBinding']['retryProfile'].get('maximumAttempts')==288
  and all(value[k]is False for k in FORBIDDEN),'EXACT_FINITE_OWNER_REFERENCE_SCOPE_REQUIRED')
 require(all(type(value[k])is str and re.fullmatch('[0-9a-f]{64}',value[k])for k in('planHash','logicalRef'))
  and type(value['expectedActive'])is dict and set(value['expectedActive'])=={'installationId','revision','checksum','generation'}
  and value['expectedActiveETag']=='"'+str(value['expectedActive']['revision'])+':'+value['expectedActive']['checksum']+':'+str(value['expectedActive']['generation'])+'"','EXACT_STRONG_ACTIVE_OWNER_SCOPE_REQUIRED')
 return copy.deepcopy(value)
def scope(plan):
 from tools.installation_binding_plan.plan import canonical_owner
 require(type(plan)is dict and plan['kind']==KIND and plan['schema']=='ouf.ingestion-owner-reference-plan.v1'
  and plan['maximumExecutionSeconds']==210 and plan['maximumEffectAttemptsPerStage']==1
  and all(plan[k]is False for k in FORBIDDEN),'EXACT_OWNER_REFERENCE_ONLY_PLAN_REQUIRED')
 b=plan['bindingPlan'];candidate=b['candidatePayload'];source=b['sourcePayload'];ref=candidate['secrets']['references'].get('ingestionReadOwnerKey')
 require(canonical_owner(candidate)==b['candidatePayloadChecksum']==CANDIDATE_HASH
  and b['onlyChange']=='/secrets/references/ingestionReadOwnerKey'and b['addedBindings']=={}
  and type(ref)is str and ref==str(Path(plan['draftBinding']['path']).parent/'ingestion-read-owner.key')
  and plan['draftBinding']['sha256']==DRAFT_HASH and 'ingestionReadOwnerKey'not in source['secrets']['references']
  and source['secrets']['provider']==candidate['secrets']['provider']=='FILES','EXACT_DEDICATED_REFERENCE_DELTA_REQUIRED')
 restored=copy.deepcopy(candidate);del restored['secrets']['references']['ingestionReadOwnerKey']
 require(restored==source and canonical_owner(source)==b['expectedActive']['checksum']
  and b['expectedActive']['revision']==b['expectedActive']['generation']==6,'OWNER_PAYLOAD_OR_PREDECESSOR_DRIFT')
 require(plan['gateway']['beforeRoutes']==plan['gateway']['afterRoutes']and len(plan['gateway']['beforeRoutes'])==82
  and digest(plan['gateway']['beforeRoutes'])==ROUTES,'ALL82_GATEWAY_ROUTES_MUST_REMAIN_UNCHANGED')
 return validate_scope({'profile':'ouf.ingestion-read-owner-reference.v1','kind':KIND,'planHash':digest(plan),'logicalRef':plan['logicalRef'],
  'humanBinding':copy.deepcopy(plan['humanBinding']),'stages':list(STAGES[KIND]),'maximumExecutionSeconds':210,'maximumEffectAttemptsPerStage':1,
  'maximumOwnerPosts':3,'maximumProjectionExports':1,'maximumActiveProjectionWrites':0,'maximumGatewayPuts':0,
  'expectedActive':copy.deepcopy(b['expectedActive']),'expectedActiveETag':b['expectedActiveETag'],
  'candidatePayloadChecksum':CANDIDATE_HASH,'draftPlanHash':DRAFT_HASH,**{k:False for k in FORBIDDEN}})

class FiniteUpdate:
 def __init__(self,action,plan,ports,journal,clock=lambda:(time.time(),time.monotonic())):
  require(type(action)is AggregateAction and type(journal)is Journal,'REAL_SIGNED_ACTION_AND_PRIVATE_JOURNAL_REQUIRED')
  self.action,self.plan,self.ports,self.journal,self.clock=action,copy.deepcopy(plan),ports,journal,clock;self.scope=scope(plan);self.key=scope_key(plan['kind'])
 def initialize(self):
  wall,mono=self.clock();expires=json.loads(self.action.raw)['expiresAt']
  self.action.guard(self.key,self.scope);self.ports.guard_current('VERIFY_INPUTS',{'effects':[]})
  require(wall<expires<=wall+211,'FINITE_CURRENT_BINDING_AUTHORITY_REQUIRED')
  path=self.journal.root.parent/('ingestion-owner-reference-'+self.scope['logicalRef']+'.claim.json')
  with protected_directory(path.parent)as directory:
   require(publish(directory,path.name,encoded({'context':str(self.journal.root),'scopeHash':digest(self.scope),'authorityHash':self.action.authority_hash,'automaticReplayAllowed':False,'budgetReset':False})),
    'LOGICAL_INSTALLATION_BINDING_ALREADY_CLAIMED')
  self.journal.initialize({'schema':'ouf.ingestion-owner-reference-journal.v1','scopeHash':digest(self.scope),'authorityHash':self.action.authority_hash,
   'expiresAt':expires,'expiresMonotonic':mono+expires-wall,'bootId':self.ports.boot(),'lastWall':wall,'lastMonotonic':mono,'nextStage':0,'effects':[],'version':0,'incidentState':'OPEN','budgetReset':False})
 def record(self):
  row=self.journal.read();n=row['nextStage'];effects=row['effects'];stages=self.scope['stages'];wall,mono=self.clock()
  require(row['schema']=='ouf.ingestion-owner-reference-journal.v1'and row['scopeHash']==digest(self.scope)
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
