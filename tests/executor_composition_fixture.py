"""Synthetic authority/other phases: shared composition harness, not a grant."""
import hashlib,json,tempfile,types
from pathlib import Path
from test_cutover_executor import j
from transition_journal import Transition,PHASES,digest
from native_evidence_store import NativeEvidenceStore
from cutover_executor import Executor

def compose(owner,phase,intent,factory):
    temp=tempfile.TemporaryDirectory();owner.addCleanup(temp.cleanup);root=Path(temp.name);root.chmod(0o700)
    directory=root/'journal';directory.mkdir(mode=0o700);evidence=root/'evidence';evidence.mkdir(mode=0o700)
    intents={p:{'syntheticFixture':p} for p in PHASES};intents[phase]=intent
    authority={'schema':'ouf.semantic-cutover-execution-authority.v1','issuedAt':100,'expiresAt':200,'creationRequestHash':'b'*64,'predecessorHistoryHash':'c'*64,'predecessorIncidentRef':'d'*64,'sourceClosureHash':'e'*64,'phaseIntentHashes':{p:digest(v) for p,v in intents.items()},'automaticReplayAllowed':False,'databaseRestoreAuthorized':False,'r12ReplayAuthorized':False,'newDistinctLeaseWorkerRequired':True}
    raw=json.dumps(authority,sort_keys=True,separators=(',',':')).encode();sha=hashlib.sha256(raw).hexdigest()
    journal=j.Journal(directory);initial=Transition.initial(sha,'b'*64,'c'*64,'d'*64);journal.initialize(initial);t=Transition(journal,initial['contextHash'])
    adapters={p:types.SimpleNamespace(apply=lambda value:None,observe=lambda value:('APPLIED',{'syntheticFixture':True})) for p in PHASES}
    store=NativeEvidenceStore(evidence);adapters[phase]=factory(t,store)
    def checkpoint(p,point,row):return {'schema':'ouf.semantic-cutover-native-checkpoint.v1','phase':p,'point':point,'journalVersion':row['version'],'intentHash':authority['phaseIntentHashes'][p],'authorityHash':sha,'sourceClosureHash':'e'*64,'nativeEvidenceHash':'f'*64}
    return Executor(t,raw,lambda value:value==raw,checkpoint,adapters,intents,lambda:150),store
