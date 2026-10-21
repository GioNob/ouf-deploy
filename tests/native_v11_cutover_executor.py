"""Real original-manifest stopped creation through composed Executor.

Only CREATE_REPLACEMENT is a real native effect. Preceding phase history and
external authority/checkpoints are synthetic isolated fixtures, never grants.
No JVM, producer, database, network-rule, provider or target effect.
"""
import hashlib,json,os,time
from pathlib import Path
from cutover_executor import Executor
from creation_adapter import CreationAdapter
import transition_journal as tj

def qualify(engine,journal_module,root,manifest,receipt):
 request={'Image':manifest,'User':'10001:10001','HostConfig':{'NetworkMode':'none','ReadonlyRootfs':True,'CapDrop':['ALL'],'SecurityOpt':['no-new-privileges'],'RestartPolicy':{'Name':'no','MaximumRetryCount':0},'Memory':2147483648,'MemorySwap':2147483648,'NanoCpus':2000000000,'PidsLimit':512}}
 intents={p:{'syntheticFixturePhase':p} for p in tj.PHASES};intents['CREATE_REPLACEMENT']=request
 base=Path(__file__).resolve().parents[1]/'tools/semantic_application_cutover'
 source_hash=tj.digest({p:hashlib.sha256((base/p).read_bytes()).hexdigest() for p in ('cutover_executor.py','creation_adapter.py','engine_creation.py','transition_journal.py')})
 now=int(time.time());authority={'schema':'ouf.semantic-cutover-execution-authority.v1','issuedAt':now-1,'expiresAt':now+600,'creationRequestHash':tj.digest(request),'predecessorHistoryHash':'c'*64,'predecessorIncidentRef':'d'*64,'sourceClosureHash':source_hash,'phaseIntentHashes':{p:tj.digest(v) for p,v in intents.items()},'automaticReplayAllowed':False,'databaseRestoreAuthorized':False,'r12ReplayAuthorized':False,'newDistinctLeaseWorkerRequired':True}
 raw=json.dumps(authority,sort_keys=True,separators=(',',':')).encode();authority_hash=hashlib.sha256(raw).hexdigest()
 directory=root/'executor-creation-journal';directory.mkdir(mode=0o700)
 journal=journal_module.Journal(directory);initial=tj.Transition.initial(authority_hash,tj.digest(request),'c'*64,'d'*64);journal.initialize(initial)
 transition=tj.Transition(journal,initial['contextHash'])
 with transition.invocation():
  for phase in tj.PHASES[:4]:
   row=transition.begin(phase,tj.digest(intents[phase]),authority_hash,transition.read()['version'])
   transition.reconcile(phase,tj.digest(intents[phase]),'APPLIED',tj.digest({'syntheticPriorPhase':phase}),row['version'])
 def checkpoint(phase,point,row):return {'schema':'ouf.semantic-cutover-native-checkpoint.v1','phase':phase,'point':point,'journalVersion':row['version'],'intentHash':authority['phaseIntentHashes'][phase],'authorityHash':authority_hash,'sourceClosureHash':source_hash,'nativeEvidenceHash':tj.digest({'syntheticFixtureCheckpoint':True,'phase':phase,'point':point})}
 class NeverExecute:
  def apply(self,intent):raise AssertionError('UNQUALIFIED_PHASE_EXECUTED')
  def observe(self,intent):raise AssertionError('UNQUALIFIED_PHASE_OBSERVED')
 adapters={p:NeverExecute() for p in tj.PHASES};adapter=CreationAdapter(engine,transition,request);adapters['CREATE_REPLACEMENT']=adapter
 executor=Executor(transition,raw,lambda value:value==raw,checkpoint,adapters,intents)
 try:
  pid=os.fork()
  if pid==0:
   original=adapter.apply
   def crash_after_create(intent):original(intent);os._exit(71)
   adapter.apply=crash_after_create
   try:executor.run(5)
   except BaseException:os._exit(72)
   os._exit(73)
  _,status=os.waitpid(pid,0);assert os.waitstatus_to_exitcode(status)==71
  assert transition.read()['state']=='IN_FLIGHT'
  created=engine.inspect(transition);assert created['Image']==manifest and created['State']['Status']=='created' and created['State']['Pid']==0
  reopened=tj.Transition(journal_module.Journal(directory),initial['contextHash'])
  adapters['CREATE_REPLACEMENT']=CreationAdapter(engine,reopened,request)
  resumed=Executor(reopened,raw,lambda value:value==raw,checkpoint,adapters,intents)
  result=resumed.run(5);assert result['completedPhaseCount']==5 and result['status']=='ORDERED_PARTIAL_CHECKPOINT_NOT_RELEASE_ACCEPTANCE'
  assert engine.inspect(reopened)['Id']==created['Id'] and reopened.read()['state']=='READY'
  assert resumed.run(5)==result and engine.inspect(reopened)['Id']==created['Id']
  receipt.update(composedExecutorOriginalManifestCreationCrashReconciled=True,
   composedExecutorPartialCheckpointRepeatedWithoutEffect=True,
   executorAndCreationAdapterActualNativeBoundaryExercised=True,
   composedExecutorExternalAuthoritySyntheticFixtureOnly=True,
   targetCutoverExecutorQualified=False)
 finally:
  actual=engine.inspect(transition)
  if actual is not None:
   assert actual['State']['Status']=='created' and actual['State']['Pid']==0
   status,_=engine.request('DELETE','/v1.44/containers/'+actual['Id']);assert status==204
