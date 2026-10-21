"""Real signed two-failure lineage, durable CAS and no replay of six effects."""
import copy,json,tempfile,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
import test_chatbot_cohort_paused_recovery as prior
from tools.chatbot_file_cohort import mounted_recovery as m,paused_recovery as p,postgrant_recovery as root
from tools.chatbot_file_cohort.plan import digest,PlanDenied
from tools.chatbot_file_cohort.review import REQUIRED_SCOPES
from tools.semantic_policy_token_owner.owner_installation import AggregateAction
from cutover_authority import CutoverAuthority
from cutover_executor import Executor
from transition_journal import Transition
from file_only_profile import PHASES
from tools.semantic_lease_recovery.bounded_recovery import Permanent

class MountedSuccessor(unittest.TestCase):
    def setUp(self):
        h=prior.SignedPausedSuccessor();self.addCleanup(h.doCleanups);h.setUp();self.h=h;self.f=h.f;self.profile=h.profile
        old=h.successor()
        def fail(intent):raise Permanent('AUTHORITY_EXPIRED')
        old.adapters['ATTEST_NEW_OCI_PEER'].apply=fail
        with self.assertRaises(Permanent):old.run()
        self.old=old;self.row=old.t.read();self.assertEqual(self.row['version'],15)
        self.preserved={str(x):x.read_bytes()for x in(h.old.t.journal.record,old.t.journal.record)}
        for name,value in(('AUTHORITY',old.authority_hash),('TRANSITION_HASH',digest(self.row))):
            override=patch.object(m,name,value);override.start();self.addCleanup(override.stop)
        self.prepared={'postGrantRecovery':h.proof,'registry':{'creationRequest':self.profile.request,'intents':h.intents}}
        m.validate_boundary(self.row,self.prepared)
        self.proof={'profile':m.PROFILE,'predecessorAuthorityHash':root.AUTHORITY,'pausedPredecessorAuthorityHash':m.AUTHORITY,
            'predecessorTransitionHash':digest(self.row),'transitionContextHash':self.row['contextHash'],
            'appliedPrefixHash':digest(self.row['effects'][:6]),'failedUnsignedIntentHash':digest(self.row['effects'][6]),
            'previousReprocessingMarkerHash':digest(self.row['governedUnsignedReprocessing']),'recordBindings':[]}
        self.intents=copy.deepcopy(h.intents);self.intents['ATTEST_NEW_OCI_PEER']={'correctLifetimeWitnessSource':True}
        hashes={k:digest(v)for k,v in self.intents.items()}
        self.scope={'postGrantRecovery':self.proof,'creationRequestHash':self.row['creationRequestHash'],
            'executionProfileHash':self.profile.sha256,'sourceClosureHash':'9'*64,'phaseIntentHashes':hashes}
        a=json.loads(self.f.authority);a.update(sourceClosureHash='9'*64,phaseIntentHashes=hashes)
        a.update({key:{'fixtureScope':key}for key in REQUIRED_SCOPES});a['applicationRegistryCutover']=self.scope
        self.f.expected['sourceClosureHash']='9'*64;self.f.authority=prior.fixture.crypto.encoded(a)
        self.f.approval.update(sourceClosureHash='9'*64,executionAuthorityHash=prior.fixture.crypto.sha(self.f.authority),approvalRef='NEW_SIGNED_MOUNT_LIFETIME_BUDGET')
        self.f.write(self.f.mandate,prior.fixture.crypto.encoded(self.f.approval));self.f.approved=prior.fixture.crypto.sha(self.f.mandate.read_bytes())
        for role in self.f.grant['roles']:self.f.sign(role)
        gate=CutoverAuthority(self.f.verifier,self.f.binding(self.f.mandate),self.f.approved,self.f.context,self.f.expected,self.f.clock,execution_profile=self.profile)
        self.action=AggregateAction(gate,self.f.authority,'9'*64)
        self.paths={name:str(self.f.root/('mount-successor-'+name))for name in('transition','evidence','before','retirementBefore')}
        for path in self.paths.values():Path(path).mkdir(mode=0o700)
        self.previous={'transition':self.row,'prepared':self.prepared,'payloads':h.previous['payloads']}
    def successor(self):
        with patch.object(m,'retained_bindings'):
            journal=m.seed_registry(self.previous,self.paths,self.action,self.scope)
        transition=Transition(journal,self.old.t.context,execution_profile=self.profile)
        adapters=copy.copy(self.old.adapters)
        adapters['ATTEST_NEW_OCI_PEER']=SimpleNamespace(apply=lambda intent:self.h.calls.append('ATTEST_NEW_OCI_PEER'),
            observe=lambda intent:('APPLIED',{'syntheticNativeAttestation':True}))
        def checkpoint(phase,point,row):return {'schema':'ouf.semantic-cutover-native-checkpoint.v1','phase':phase,'point':point,
            'journalVersion':row['version'],'intentHash':digest(self.intents[phase]),'authorityHash':self.action.authority_hash,
            'sourceClosureHash':self.action.closure,'nativeEvidenceHash':'f'*64}
        return Executor(transition,self.action.raw,self.action.authority,checkpoint,adapters,self.intents,self.f.clock,
            aggregate_action=self.action,aggregate_scope=self.scope)
    def unchanged(self):
        for path,data in self.preserved.items():self.assertEqual(Path(path).read_bytes(),data)
    def test_both_failed_intents_and_six_effects_survive_new_signed_seventh_phase(self):
        before=list(self.h.calls);new=self.successor();new.run();current=new.t.read()
        self.assertEqual(self.h.calls[len(before):],list(PHASES[6:]));self.assertEqual(self.h.calls.count('CREATE_REPLACEMENT'),1)
        self.assertEqual(self.h.calls.count('STAGE_PAUSED_REPLACEMENT'),1)
        self.assertEqual(current['effects'][:6],self.row['effects'][:6]);marker=current['governedUnsignedReprocessing']
        self.assertEqual(marker['failedIntent'],self.row['effects'][6]);self.assertEqual(marker['previousReprocessing'],self.row['governedUnsignedReprocessing'])
        self.unchanged();before=list(self.h.calls);new.run();self.assertEqual(self.h.calls,before)
    def test_tamper_to_either_failed_intent_or_prefix_or_new_authority_denies(self):
        new=self.successor();row=new.t.read()
        for key in('newFailed','oldFailed','prefix','authority'):
            bad=copy.deepcopy(row);marker=bad['governedUnsignedReprocessing']
            if key=='newFailed':marker['failedIntent']['intentHash']='e'*64
            if key=='oldFailed':marker['previousReprocessing']['failedIntent']['intentHash']='e'*64
            if key=='prefix':bad['effects'][5]['nativeEvidenceHash']='e'*64
            if key=='authority':marker['newAuthorityHash']='e'*64
            with self.subTest(key=key),self.assertRaises(PlanDenied):m.verify_successor_transition(bad,self.scope,self.action.authority_hash)
        self.unchanged()
    def test_revoked_current_human_denies_before_seed_or_native_effect(self):
        self.f.mandate.write_bytes(b'{}');before=list(self.h.calls)
        with self.assertRaises(Exception):self.successor()
        self.assertEqual(list(Path(self.paths['transition']).iterdir()),[]);self.assertEqual(self.h.calls,before);self.unchanged()
    def test_proposed_successor_keeps_previous_bytes_and_refuses_same_or_changed_prefix_intent(self):
        new=m.successor_seed(self.previous,self.proof,self.action.authority_hash,self.intents)
        self.assertEqual(new['version'],16);self.assertEqual(new['nextPhase'],6)
        for changed in(False,True):
            intents=copy.deepcopy(self.prepared['registry']['intents'])
            if changed:intents['CREATE_REPLACEMENT']={'mustNotReplay':True}
            with self.subTest(changed=changed),self.assertRaises(PlanDenied):m.successor_seed(self.previous,self.proof,self.action.authority_hash,intents)
        self.unchanged()

class MountedFence(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory(dir=prior.bootstrap.ROOT);self.addCleanup(temp.cleanup);self.root=Path(temp.name);self.root.chmod(0o700)
        for target,name,value in((root.evidence,'PARENT',self.root),(m,'retained_bindings',lambda proof:None)):
            override=patch.object(target,name,value);override.start();self.addCleanup(override.stop)
        self.old={root.CLAIM:b'ORIGINAL_CLAIM',p.CLAIM:b'PAUSED_CLAIM'}
        for name,data in self.old.items():(self.root/name).write_bytes(data)
        self.proof={'profile':m.PROFILE,'recordBindings':[],'newBudget':{'priorControlledGrantAttempts':3}}
        self.action=SimpleNamespace(raw=root.encoded({'applicationRegistryCutover':{'postGrantRecovery':self.proof}}),authority_hash='e'*64,guard=lambda *a:True)
    def test_fixed_third_claim_preserves_old_claims_and_denies_duplicate_relaunch_and_inode_swap(self):
        with root.ContinuationFence(self.action,self.proof)as fence:
            self.assertTrue(fence.guard())
            with self.assertRaises(FileExistsError):
                with root.ContinuationFence(self.action,self.proof):pass
            path=self.root/m.CLAIM;data=path.read_bytes();path.rename(self.root/'retained-claim');path.write_bytes(data);path.chmod(0o600)
            with self.assertRaises(PlanDenied):fence.guard()
        with self.assertRaises(FileExistsError):
            with root.ContinuationFence(self.action,self.proof):pass
        for name,data in self.old.items():self.assertEqual((self.root/name).read_bytes(),data)

if __name__=='__main__':unittest.main()
