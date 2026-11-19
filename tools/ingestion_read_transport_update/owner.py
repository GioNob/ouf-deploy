"""Finite MCP-only routing update; no migration, metadata or policy writes."""
import copy,hashlib,json,re,time
from pathlib import Path
from tools.semantic_policy_token_owner.owner_installation import AggregateAction
from tools.semantic_lease_recovery.recovery_journal import Journal

OPERATIONS=('IMPORT_IMAGE','DISABLE_OLD_RESTART','STOP_OLD','DETACH_OLD_ENDPOINT','RENAME_OLD',
 'CREATE_REPLACEMENT','START_REPLACEMENT','READINESS','RESTORE_RESTART_POLICY')
STAGES=('VERIFY_INPUTS',)+tuple('mcp.'+s for s in OPERATIONS)+('VERIFY_FINAL',)
PROFILE='ouf.mcp-ingestion-read-transport-update.v1'
OLD_SOURCE='a79b139c7a26d64a584b0a432ebb8df8c32a52ed'
NEW_SOURCE='1f2c28d7abadae78680b040ba7b58be62ef85ee9'
OLD_MCP='c6fc3a462f4e1faf1e8121fee13ca445f7a3f7f1f39df65d738ea9cc1d4185f4'
FORBIDDEN=('automaticReplayAllowed','manualSqlMigrationAllowed','grantChangesAllowed','semanticDispatchAllowed',
 'automaticRollbackAllowed','identityDecisionsAllowed','profilePublicationAllowed','jobRetriesAllowed',
 'newHumanLoginAllowed','budgetReset','databaseMigrationAllowed','publicMetadataChangesAllowed','gatewayRouteChangesAllowed')
STAGE_WINDOW_SECONDS={name:210 if name.endswith('IMPORT_IMAGE')else 20 if name.endswith('READINESS')else 45 for name in STAGES}
class UpdateDenied(RuntimeError):pass
class UpdatePaused(RuntimeError):pass
def require(ok,reason):
 if not ok:raise UpdateDenied(reason)
def encoded(v):return json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def digest(v):return hashlib.sha256(encoded(v)).hexdigest()

def validate_scope(value):
 keys={'profile','planHash','logicalUpdateRef','privateReviewHash','stages','maximumExecutionSeconds',
  'maximumEffectAttemptsPerStage','maximumGatewayWrites','mcpMigrationsUnchanged','publicMetadataUnchanged',
  'deployedSourceCommit','candidateSourceCommit','oldContainerId','candidateImageId','humanBinding',*FORBIDDEN}
 require(type(value)is dict and set(value)==keys and value['profile']==PROFILE and value['stages']==list(STAGES)
  and value['maximumExecutionSeconds']==900 and value['maximumEffectAttemptsPerStage']==1
  and value['maximumGatewayWrites']==0 and value['mcpMigrationsUnchanged']is True
  and value['publicMetadataUnchanged']is True and all(value[k]is False for k in FORBIDDEN)
  and value['deployedSourceCommit']==OLD_SOURCE and value['candidateSourceCommit']==NEW_SOURCE
  and value['oldContainerId']==OLD_MCP and re.fullmatch('sha256:[0-9a-f]{64}',value['candidateImageId'])
  and all(re.fullmatch('[0-9a-f]{64}',value[k])for k in('planHash','logicalUpdateRef','privateReviewHash'))
  and type(value['humanBinding'])is dict,'EXACT_MCP_READ_TRANSPORT_SCOPE_REQUIRED')
 return value

def scope(plan):
 from image_custody import runtime_image_id
 require(type(plan)is dict and plan.get('schema')=='ouf.mcp-ingestion-read-transport-update-plan.v1'
  and set(plan.get('replacements',{}))=={'mcp'}and {'onboarding','udp','ingestion'}<=set(plan.get('unchangedApplications',{}))
  and 'mcp'not in plan['unchangedApplications']and len(plan['unchangedApplications'])<=8
  and plan.get('mcpMigrationsUnchanged')is True and plan.get('publicMetadataUnchanged')is True
  and plan.get('maximumExecutionSeconds')==900 and plan.get('maximumEffectAttemptsPerStage')==1
  and plan.get('maximumGatewayWrites')==0 and plan.get('databaseMigration')is None
  and all(plan.get(k)is False for k in FORBIDDEN),'EXACT_MCP_ONLY_UPDATE_PLAN_REQUIRED')
 gateway=plan['gateway']
 require(gateway['beforeRoutes']==gateway['afterRoutes']and gateway['additions']=={}
  and len(gateway['beforeRoutes'])==80,'EXISTING_EIGHTY_ROUTES_MUST_BE_UNCHANGED')
 row=plan['replacements']['mcp'];image=runtime_image_id(row['imageAudit'])
 require(row['oldRuntimeBinding']['containerId']==OLD_MCP and row['imageAudit']['sourceCommit']==NEW_SOURCE,
  'EXACT_INSTALLED_AND_CANDIDATE_MCP_REQUIRED')
 logical=digest({'oldContainerId':OLD_MCP,'candidateSourceCommit':NEW_SOURCE,'candidateImageId':image,'profile':PROFILE})
 require(plan['logicalUpdateRef']==logical,'LOGICAL_UPDATE_CHANGED')
 return validate_scope({'profile':PROFILE,'planHash':digest(plan),'logicalUpdateRef':logical,
  'privateReviewHash':plan['privateReviewBinding']['sha256'],'stages':list(STAGES),'maximumExecutionSeconds':900,
  'maximumEffectAttemptsPerStage':1,'maximumGatewayWrites':0,'mcpMigrationsUnchanged':True,'publicMetadataUnchanged':True,
  'deployedSourceCommit':OLD_SOURCE,'candidateSourceCommit':NEW_SOURCE,'oldContainerId':OLD_MCP,
  'candidateImageId':image,'humanBinding':copy.deepcopy(plan['humanBinding']),**{k:False for k in FORBIDDEN}})

class ReadinessUpdate:
 def __init__(self,action,journal,plan,ports,clock=lambda:(time.time(),time.monotonic())):
  require(type(action)is AggregateAction and type(journal)is Journal,'REAL_SIGNED_AUTHORITY_AND_CUSTODIED_JOURNAL_REQUIRED')
  from tools.ingestion_read_transport_update.native import NativePorts
  require(isinstance(ports,NativePorts)and ports.action is action and ports.plan==plan,'NATIVE_PORTS_BOUND_TO_SAME_AUTHORITY_REQUIRED')
  self.action,self.journal,self.plan,self.ports,self.clock=action,journal,copy.deepcopy(plan),ports,clock
  ports.journal=journal
  require(Path(self.plan['authorityDirectory'])==journal.root,'SAME_AUTHORITY_AND_JOURNAL_DIRECTORY_REQUIRED')
  self.scope=scope(self.plan);self.expires=json.loads(action.raw)['expiresAt']
 def guard(self):
  require(scope(self.plan)==self.scope,'UPDATE_PLAN_CHANGED')
  self.action.guard('mcpReadTransportUpdate',self.scope)
  wall,mono=self.clock();row=self.record()
  require(row['bootId']==self.ports.boot()and wall>=row['lastWall']and mono>=row['lastMonotonic']
   and wall<min(row['expiresAt'],self.expires)and mono<row['expiresMonotonic'],'UPDATE_AUTHORITY_OR_CLOCK_EXPIRED')
 def initialize(self):
  wall,mono=self.clock();remaining=min(900,self.expires-wall)
  require(remaining>0,'CURRENT_FINITE_UPDATE_AUTHORITY_REQUIRED')
  self.action.guard('mcpReadTransportUpdate',self.scope)
  self.ports.claim_logical_scope()
  self.journal.initialize({'schema':'ouf.mcp-ingestion-read-transport-update-journal.v1','scopeHash':digest(self.scope),
   'authorityHash':self.action.authority_hash,'bootId':self.ports.boot(),'version':0,'nextStage':0,'effects':[],
   'createdAt':wall,'expiresAt':wall+remaining,'expiresMonotonic':mono+remaining,'lastWall':wall,'lastMonotonic':mono,
   'readinessAttempts':0,'cumulativeReadinessAttempts':0,'nextReadAt':wall,'nextReadMonotonic':mono,'readinessState':'IDLE','budgetReset':False,
   'incidentState':'OPEN','applicationAcceptanceGranted':False})
 def record(self):
  row=self.journal.read();n=row.get('nextStage')
  require(row.get('schema')=='ouf.mcp-ingestion-read-transport-update-journal.v1'and row.get('scopeHash')==digest(self.scope)
   and row.get('authorityHash')==self.action.authority_hash and row.get('budgetReset')is False
   and type(n)is int and 0<=n<=len(STAGES)and len(row['effects'])in(n,n+1)
   and [e['stage']for e in row['effects']]==list(STAGES[:len(row['effects'])])
   and all(e['state']=='APPLIED'for e in row['effects'][:n])
   and (len(row['effects'])==n or row['effects'][-1]['state']=='CLAIMED')
   and type(row.get('readinessAttempts'))is int and 0<=row['readinessAttempts']<=128
   and type(row.get('cumulativeReadinessAttempts'))is int and row['readinessAttempts']<=row['cumulativeReadinessAttempts']<=128,
   'PERSISTENT_UPDATE_HISTORY_DRIFT')
  for effect in row['effects']:require(effect['intentHash']==digest({'planHash':self.scope['planHash'],'stage':effect['stage']}),'UPDATE_EFFECT_INTENT_DRIFT')
  return row
 def save(self,row,**changes):
  wall,mono=self.clock();following={**row,**changes,'version':row['version']+1,'lastWall':wall,'lastMonotonic':mono}
  self.journal.compare_and_save(row,following);return following
 def _applied(self,row,proof):
  require(type(proof)is dict and proof,'NATIVE_EFFECT_EVIDENCE_REQUIRED')
  effects=copy.deepcopy(row['effects']);effects[-1].update(state='APPLIED',evidence=proof)
  return self.save(row,effects=effects,nextStage=row['nextStage']+1)
 def _readiness(self,row,stage):
  wall,mono=self.clock()
  if row['readinessState']=='ATTEMPTING':raise UpdatePaused('READINESS_INTERRUPTED_RECONCILIATION_REQUIRED')
  if row['readinessState']=='EXHAUSTED'or row['cumulativeReadinessAttempts']>=128:raise UpdatePaused('READINESS_BUDGET_EXHAUSTED')
  if wall<row['nextReadAt']or mono<row['nextReadMonotonic']:raise UpdatePaused('READINESS_RETRY_WAIT')
  row=self.save(row,readinessState='ATTEMPTING',readinessAttempts=row['readinessAttempts']+1,cumulativeReadinessAttempts=row['cumulativeReadinessAttempts']+1)
  self.guard();self.ports.guard_current(stage)
  status,proof=self.ports.observe(stage);self.guard()
  if status=='APPLIED':
   proof={**proof,'readinessAttempts':row['readinessAttempts']};row=self.save(row,readinessState='IDLE',readinessAttempts=0,nextReadAt=self.clock()[0],nextReadMonotonic=self.clock()[1]);return self._applied(row,proof)
  require(status=='TRANSIENT','PERMANENT_READINESS_FAILURE')
  wall,mono=self.clock();attempt=row['readinessAttempts'];base=(5,15,60,300,900)[min(attempt-1,4)]
  jitter=int.from_bytes(hashlib.sha256((self.scope['planHash']+str(attempt)).encode()).digest()[:2],'big')/65535*.2
  delay=max(float(proof.get('retryAfterSeconds',0)),base*(1+jitter))
  require(0<delay<float('inf'),'BOUNDED_RETRY_AFTER_REQUIRED')
  state='EXHAUSTED'if row['cumulativeReadinessAttempts']>=128 or wall+delay>=row['expiresAt']or mono+delay>=row['expiresMonotonic']else'RETRY_WAIT'
  self.save(row,readinessState=state,nextReadAt=wall+delay,nextReadMonotonic=mono+delay)
  raise UpdatePaused('READINESS_'+state)
 def run(self):
  with self.journal.invocation():
   while True:
    self.guard();row=self.record();n=row['nextStage']
    if n==len(STAGES):
     if row['incidentState']!='RECOVERED':row=self.save(row,incidentState='RECOVERED')
     return {'complete':True,'applicationReady':True,'sourceActivationProven':False,'acceptanceGranted':False,'semanticDispatchPerformed':False,'journalVersion':row['version'],'databaseMigrationsPerformed':0,'publicMetadataChanged':False,'gatewayWrites':0,'nativeProfilePublished':False,'jobsRetried':0}
    stage=STAGES[n];self.ports.guard_current(stage)
    wall,mono=self.clock()
    if min(row['expiresAt']-wall,row['expiresMonotonic']-mono,self.expires-wall)<STAGE_WINDOW_SECONDS[stage]:
     raise UpdatePaused('INSUFFICIENT_AUTHORITY_WINDOW_FOR_STAGE')
    if stage.endswith('.READINESS')or stage=='VERIFY_FINAL':
     if len(row['effects'])==n:
      effect={'stage':stage,'state':'CLAIMED','intentHash':digest({'planHash':self.scope['planHash'],'stage':stage})}
      row=self.save(row,effects=row['effects']+[effect])
     self._readiness(row,stage);continue
    if len(row['effects'])!=n:raise UpdatePaused('CLAIMED_EFFECT_RECONCILIATION_REQUIRED')
    effect={'stage':stage,'state':'CLAIMED','intentHash':digest({'planHash':self.scope['planHash'],'stage':stage})}
    row=self.save(row,effects=row['effects']+[effect])
    self.guard();self.ports.guard_current(stage)
    self.ports.apply(stage)
    status,proof=self.ports.observe(stage);self.guard()
    require(status=='APPLIED','EFFECT_OUTCOME_REQUIRES_READ_ONLY_RECONCILIATION')
    self._applied(row,proof)
 def reconcile_claim(self):
  """Readback can close the existing claim; never repeats its effect."""
  with self.journal.invocation():
   self.guard();row=self.record();n=row['nextStage']
   require(n<len(STAGES)and len(row['effects'])==n+1,'EXISTING_EFFECT_CLAIM_REQUIRED')
   stage=STAGES[n];self.ports.guard_current(stage);status,proof=self.ports.observe(stage);self.guard()
   require(status=='APPLIED','EFFECT_STILL_UNPROVEN_NO_REPLAY')
   if stage.endswith('.READINESS'):row=self.save(row,readinessState='COMPLETE')
   self._applied(row,proof)
   return {'reconciledStage':stage,'effectReplayed':False,'acceptanceGranted':False}

