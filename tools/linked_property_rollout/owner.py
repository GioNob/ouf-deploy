"""Finite UDP/Onboarding update and exact additive Flyway migration.

No issuance, key generation, OAuth renewal, semantic dispatch or implicit replay.
Native ports are selected by the sealed entrypoint, never by a remote caller.
"""
import copy,hashlib,json,time
from pathlib import Path
from tools.semantic_policy_token_owner.owner_installation import AggregateAction
from tools.semantic_lease_recovery.recovery_journal import Journal

PREFIX=('IMPORT_IMAGE','DISABLE_OLD_RESTART','STOP_OLD')
SUFFIX=('DETACH_OLD_ENDPOINT','RENAME_OLD','CREATE_REPLACEMENT','START_REPLACEMENT','READINESS','RESTORE_RESTART_POLICY')
STAGES=('VERIFY_INPUTS',)+tuple(n+'.'+s for n in ('udp','onboarding') for s in PREFIX)+('BACKUP_UDP',)+tuple('udp.'+s for s in SUFFIX[:-1])+('VERIFY_MIGRATION','udp.RESTORE_RESTART_POLICY')+tuple('onboarding.'+s for s in SUFFIX)+('VERIFY_FINAL',)
PROFILE='ouf.linked-property-native-update.v1'
MIGRATION={'module':'udp','from':34,'to':35,'owner':'APPLICATION_FLYWAY','script':'V35__linked_property_reconciliation.sql','checksum':-376865285,'sha256':'d9937d14b53471ea718ea3ec91c8fc729a48f4e9fbe9bfd23f9673e718705c1f'}
STAGE_WINDOW_SECONDS={name:(210 if name.endswith('IMPORT_IMAGE') or name=='BACKUP_UDP' else 20 if name.endswith('READINESS') else 45) for name in STAGES}
class UpdateDenied(RuntimeError):pass
class UpdatePaused(RuntimeError):pass
def require(ok,reason):
 if not ok:raise UpdateDenied(reason)
def encoded(v):return json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def digest(v):return hashlib.sha256(encoded(v)).hexdigest()
def scope(plan):
 require(type(plan)is dict and plan.get('schema')=='ouf.linked-property-native-update-plan.v1'
  and set(plan.get('replacements',{}))=={'udp','onboarding'}
  and plan.get('maximumExecutionSeconds')==900 and plan.get('maximumEffectAttemptsPerStage')==1
  and plan.get('maximumGatewayWrites')==0 and plan.get('databaseMigration')==MIGRATION
  and plan.get('backupRequiredBeforeMigration')is True
  and all(plan.get(k)is False for k in ('automaticReplayAllowed','manualSqlMigrationAllowed','grantChangesAllowed','semanticDispatchAllowed','automaticRollbackAllowed','identityDecisionsAllowed','profilePublicationAllowed','jobRetriesAllowed')),
  'EXACT_LINKED_PROPERTY_MIGRATION_SCOPE_REQUIRED')
 require(plan['gateway']['afterRoutes']==plan['gateway']['beforeRoutes'],'GATEWAY_MUTATION_NOT_ALLOWED')
 require(plan['logicalUpdateRef']==digest({'retiredContainerIds':sorted(r['oldRuntimeBinding']['containerId'] for r in plan['replacements'].values()),'migration':MIGRATION}),'LOGICAL_UPDATE_CHANGED')
 return {'profile':PROFILE,'planHash':digest(plan),'logicalUpdateRef':plan['logicalUpdateRef'],
  'privateReviewHash':plan['privateReviewBinding']['sha256'],'stages':list(STAGES),'maximumExecutionSeconds':900,
  'maximumEffectAttemptsPerStage':1,'maximumGatewayWrites':0,'databaseMigration':copy.deepcopy(MIGRATION),
  'backupRequiredBeforeMigration':True, **{k:False for k in ('automaticReplayAllowed','manualSqlMigrationAllowed','grantChangesAllowed','semanticDispatchAllowed','automaticRollbackAllowed','identityDecisionsAllowed','profilePublicationAllowed','jobRetriesAllowed')}}

class ReadinessUpdate:
 def __init__(self,action,journal,plan,ports,clock=lambda:(time.time(),time.monotonic())):
  require(type(action)is AggregateAction and type(journal)is Journal,'REAL_SIGNED_AUTHORITY_AND_CUSTODIED_JOURNAL_REQUIRED')
  from tools.linked_property_rollout.native import NativePorts
  require(isinstance(ports,NativePorts)and ports.action is action and ports.plan==plan,'NATIVE_PORTS_BOUND_TO_SAME_AUTHORITY_REQUIRED')
  self.action,self.journal,self.plan,self.ports,self.clock=action,journal,copy.deepcopy(plan),ports,clock
  ports.journal=journal
  require(Path(self.plan['authorityDirectory'])==journal.root,'SAME_AUTHORITY_AND_JOURNAL_DIRECTORY_REQUIRED')
  self.scope=scope(self.plan);self.expires=json.loads(action.raw)['expiresAt']
 def guard(self):
  require(scope(self.plan)==self.scope,'UPDATE_PLAN_CHANGED')
  self.action.guard('linkedPropertyUpdate',self.scope)
  wall,mono=self.clock();row=self.record()
  require(row['bootId']==self.ports.boot()and wall>=row['lastWall']and mono>=row['lastMonotonic']
   and wall<min(row['expiresAt'],self.expires)and mono<row['expiresMonotonic'],'UPDATE_AUTHORITY_OR_CLOCK_EXPIRED')
 def initialize(self):
  wall,mono=self.clock();remaining=min(900,self.expires-wall)
  require(remaining>0,'CURRENT_FINITE_UPDATE_AUTHORITY_REQUIRED')
  self.action.guard('linkedPropertyUpdate',self.scope)
  self.ports.claim_logical_scope()
  self.journal.initialize({'schema':'ouf.linked-property-update-journal.v1','scopeHash':digest(self.scope),
   'authorityHash':self.action.authority_hash,'bootId':self.ports.boot(),'version':0,'nextStage':0,'effects':[],
   'createdAt':wall,'expiresAt':wall+remaining,'expiresMonotonic':mono+remaining,'lastWall':wall,'lastMonotonic':mono,
   'readinessAttempts':0,'nextReadAt':wall,'nextReadMonotonic':mono,'readinessState':'IDLE','budgetReset':False,
   'incidentState':'OPEN','applicationAcceptanceGranted':False})
 def record(self):
  row=self.journal.read();n=row.get('nextStage')
  require(row.get('schema')=='ouf.linked-property-update-journal.v1'and row.get('scopeHash')==digest(self.scope)
   and row.get('authorityHash')==self.action.authority_hash and row.get('budgetReset')is False
   and type(n)is int and 0<=n<=len(STAGES)and len(row['effects'])in(n,n+1)
   and [e['stage']for e in row['effects']]==list(STAGES[:len(row['effects'])])
   and all(e['state']=='APPLIED'for e in row['effects'][:n])
   and (len(row['effects'])==n or row['effects'][-1]['state']=='CLAIMED')
   and type(row.get('readinessAttempts'))is int and 0<=row['readinessAttempts']<=128,
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
  if row['readinessState']=='EXHAUSTED'or row['readinessAttempts']>=128:raise UpdatePaused('READINESS_BUDGET_EXHAUSTED')
  if wall<row['nextReadAt']or mono<row['nextReadMonotonic']:raise UpdatePaused('READINESS_RETRY_WAIT')
  row=self.save(row,readinessState='ATTEMPTING',readinessAttempts=row['readinessAttempts']+1)
  self.guard();self.ports.guard_current(stage)
  status,proof=self.ports.observe(stage);self.guard()
  if status=='APPLIED':
   proof={**proof,'readinessAttempts':row['readinessAttempts']};row=self.save(row,readinessState='IDLE',readinessAttempts=0,nextReadAt=self.clock()[0],nextReadMonotonic=self.clock()[1]);return self._applied(row,proof)
  require(status=='TRANSIENT','PERMANENT_READINESS_FAILURE')
  wall,mono=self.clock();attempt=row['readinessAttempts'];base=(5,15,60,300,900)[min(attempt-1,4)]
  jitter=int.from_bytes(hashlib.sha256((self.scope['planHash']+str(attempt)).encode()).digest()[:2],'big')/65535*.2
  delay=max(float(proof.get('retryAfterSeconds',0)),base*(1+jitter))
  require(0<delay<float('inf'),'BOUNDED_RETRY_AFTER_REQUIRED')
  state='EXHAUSTED'if attempt>=128 or wall+delay>=row['expiresAt']or mono+delay>=row['expiresMonotonic']else'RETRY_WAIT'
  self.save(row,readinessState=state,nextReadAt=wall+delay,nextReadMonotonic=mono+delay)
  raise UpdatePaused('READINESS_'+state)
 def run(self):
  with self.journal.invocation():
   while True:
    self.guard();row=self.record();n=row['nextStage']
    if n==len(STAGES):
     if row['incidentState']!='RECOVERED':row=self.save(row,incidentState='RECOVERED')
     return {'complete':True,'applicationReady':True,'sourceActivationProven':False,'acceptanceGranted':False,'semanticDispatchPerformed':False,'journalVersion':row['version'],'udpMigrationVersion':35,'nativeProfilePublished':False,'jobsRetried':0}
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
