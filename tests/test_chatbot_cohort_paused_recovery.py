"""Unsigned changed-intent reprocessing; old checkpoints never reset/replay."""
import copy,json,tempfile,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
import test_chatbot_cohort_containers as bootstrap
import test_file_only_cutover as fixture
from tools.chatbot_file_cohort import paused_recovery as p
from tools.chatbot_file_cohort import postgrant_recovery as original
from tools.chatbot_file_cohort.plan import PlanDenied,digest
from tools.semantic_lease_recovery.recovery_journal import Journal
from tools.semantic_policy_token_owner.owner_installation import AggregateAction
from tools.chatbot_file_cohort.review import REQUIRED_SCOPES
from cutover_authority import CutoverAuthority
from cutover_executor import Executor
from transition_journal import Transition
from file_only_profile import PHASES

class PausedBoundary(unittest.TestCase):
    def fixture(self):
        intents={phase:{'fixture':phase}for phase in PHASES}
        row={'schema':'ouf.semantic-cutover-journal.v2','version':13,'state':'IN_FLIGHT','nextPhase':6,
            'transitionAuthorityEvidenceHash':original.AUTHORITY,'databaseMayHaveChanged':False,
            'applicationWritesMayHaveOccurred':True,'automaticReplayAllowed':False,'preMigrationRestoreAllowed':False,
            'effects':[{'phase':phase,'intentHash':digest(intents[phase]),'authorityEvidenceHash':original.AUTHORITY if i<5 else p.AUTHORITY,
                'state':'APPLIED'if i<6 else'IN_FLIGHT',**({'nativeEvidenceHash':str(i+1)*64}if i<6 else{})}for i,phase in enumerate(PHASES[:7])]}
        return row,intents
    def test_exact_six_effects_and_unsigned_attempt_are_preserved(self):
        row,intents=self.fixture();before=copy.deepcopy(row)
        self.assertEqual(p.validate_boundary(row,intents),row);self.assertEqual(row,before)
    def test_unknown_effect_changed_prefix_and_database_boundary_are_denied(self):
        row,intents=self.fixture()
        for name in('stage','effect','db','writes','version','count','intent','authority'):
            bad=copy.deepcopy(row)
            if name=='stage':bad['effects'][5]['state']='IN_FLIGHT'
            if name=='effect':bad['effects'][6]['state']='APPLIED'
            if name=='db':bad['databaseMayHaveChanged']=True
            if name=='writes':bad['applicationWritesMayHaveOccurred']=False
            if name=='version':bad['version']=14
            if name=='count':bad['effects'].pop()
            if name=='intent':bad['effects'][2]['intentHash']='e'*64
            if name=='authority':bad['effects'][5]['authorityEvidenceHash']=original.AUTHORITY
            with self.subTest(name=name),self.assertRaises(PlanDenied):p.validate_boundary(bad,intents)
    def test_node_issuance_claim_or_accepted_receipt_denies_reprocessing(self):
        with tempfile.TemporaryDirectory(dir=bootstrap.ROOT)as d:
            root=Path(d);root.chmod(0o700);node=root/'node';node.mkdir(mode=0o700);store=root/'evidence';store.mkdir(mode=0o700)
            (node/'frame-policy.json').write_bytes(b'{}')
            previous={'prepared':{'registry':{'directoryPlan':{'node':str(node),'evidence':str(store)}}}}
            p.unsigned_node(previous)
            for target in(node/'attestation-issuance-claim.json',store/'ATTEST_NEW_OCI_PEER.json'):
                target.write_bytes(b'{}')
                with self.assertRaises(PlanDenied):p.unsigned_node(previous)
                target.unlink()
    def test_new_recipe_uses_only_reviewed_inputs_and_independent_ci_seal(self):
        import test_file_only_preparation as inputs
        template,launch,context,args,request=inputs.Preparation().gated_frame()
        request['HostConfig']['Binds']=[row.split(':')[0]+':'+target+':ro'for row,target in zip(request['HostConfig']['Binds'],p.MOUNT_TARGETS)]
        registry={'creationRequest':request,'nodeRecipe':{'template':template,'launch':launch,
            'imageConfigurationHash':p.IMAGE_CONFIG,'expectedRootfsSeal':copy.deepcopy(p.ORIGINAL_SEAL)},
            'imageAudit':{'configSha256':p.IMAGE_CONFIG,'sourceCommit':p.CI_WITNESS['moduleSource']}}
        before=copy.deepcopy(registry);recipe=p.proposed_recipe(registry)
        self.assertEqual(registry,before);self.assertEqual(recipe['expectedRootfsSeal'],p.ROOTFS_SEAL)
        bad=copy.deepcopy(registry);bad['creationRequest']['HostConfig']['Binds'][0]='/source:/run/another-profile:ro'
        with self.assertRaises(PlanDenied):p.proposed_recipe(bad)
        bad=copy.deepcopy(registry);bad['imageAudit']['configSha256']='e'*64
        with self.assertRaises(PlanDenied):p.proposed_recipe(bad)

class SignedPausedSuccessor(unittest.TestCase):
    """Real dual-role signatures and durable journals; native effects fixtures."""
    def setUp(self):
        h=fixture.FileOnlyCutover();self.addCleanup(h.doCleanups)
        self.f,self.profile,self.old,self.calls=h.fixture()
        def fail_unsigned(intent):raise ValueError('fixture unsigned complete OCI failure')
        self.old.adapters['ATTEST_NEW_OCI_PEER'].apply=fail_unsigned
        with self.assertRaises(ValueError):self.old.run()
        row=self.old.t.read();self.assertEqual(row['version'],13);self.assertEqual(row['nextPhase'],6)
        self.original_bytes=self.old.t.journal.record.read_bytes();self.row=row
        for module,name,value in[(original,'AUTHORITY',self.old.authority_hash),(p,'AUTHORITY',self.old.authority_hash),(p,'TRANSITION_HASH',digest(row))]:
            override=patch.object(module,name,value);override.start();self.addCleanup(override.stop)
        self.proof={'profile':p.PROFILE,'predecessorAuthorityHash':self.old.authority_hash,'pausedPredecessorAuthorityHash':self.old.authority_hash,
            'predecessorTransitionHash':digest(row),'transitionContextHash':row['contextHash'],'appliedPrefixHash':digest(row['effects'][:6]),
            'failedUnsignedIntentHash':digest(row['effects'][6]),'recordBindings':[]}
        self.intents=copy.deepcopy(self.old.intents);self.intents['ATTEST_NEW_OCI_PEER']={'newIndependentExpectedInputs':True}
        hashes={k:digest(v)for k,v in self.intents.items()}
        self.scope={'postGrantRecovery':self.proof,'creationRequestHash':row['creationRequestHash'],
            'executionProfileHash':self.profile.sha256,'sourceClosureHash':'8'*64,'phaseIntentHashes':hashes}
        authority=json.loads(self.f.authority);authority.update(sourceClosureHash='8'*64,phaseIntentHashes=hashes)
        authority.update({key:{'fixtureScope':key}for key in REQUIRED_SCOPES});authority['applicationRegistryCutover']=self.scope
        self.f.expected['sourceClosureHash']='8'*64;self.f.authority=fixture.crypto.encoded(authority)
        self.f.approval.update(sourceClosureHash='8'*64,executionAuthorityHash=fixture.crypto.sha(self.f.authority),approvalRef='NEW_EXACT_UNSIGNED_REPROCESSING')
        self.f.write(self.f.mandate,fixture.crypto.encoded(self.f.approval));self.f.approved=fixture.crypto.sha(self.f.mandate.read_bytes())
        for role in self.f.grant['roles']:self.f.sign(role)
        gate=CutoverAuthority(self.f.verifier,self.f.binding(self.f.mandate),self.f.approved,self.f.context,self.f.expected,self.f.clock,execution_profile=self.profile)
        self.action=AggregateAction(gate,self.f.authority,'8'*64)
        self.paths={name:str(self.f.root/('paused-successor-'+name))for name in('transition','evidence','before','retirementBefore')}
        for path in self.paths.values():Path(path).mkdir(mode=0o700)
        self.previous={'transition':row,'prepared':{'registry':{'intents':self.old.intents}},
            'payloads':{'evidence':{phase:{'syntheticPhase':phase}for phase in PHASES[:6]},'before':{},'retirementBefore':{}}}
    def successor(self):
        # Fixed host ancestry/absence proof has its own negative tests. This
        # fixture covers signed scope, real seed CAS/history and Executor.
        with patch.object(p,'retained_bindings'):
            journal=p.seed_registry(self.previous,self.paths,self.action,self.scope)
        t=Transition(journal,self.old.t.context,execution_profile=self.profile)
        adapters=copy.copy(self.old.adapters)
        adapters['ATTEST_NEW_OCI_PEER']=SimpleNamespace(apply=lambda intent:self.calls.append('ATTEST_NEW_OCI_PEER'),
            observe=lambda intent:('APPLIED',{'fixtureSignedNativeAttestation':True}))
        def checkpoint(phase,point,row):return {'schema':'ouf.semantic-cutover-native-checkpoint.v1','phase':phase,'point':point,
            'journalVersion':row['version'],'intentHash':digest(self.intents[phase]),'authorityHash':self.action.authority_hash,
            'sourceClosureHash':self.action.closure,'nativeEvidenceHash':'f'*64}
        return Executor(t,self.action.raw,self.action.authority,checkpoint,adapters,self.intents,self.f.clock,
            aggregate_action=self.action,aggregate_scope=self.scope)
    def test_new_signed_intent_starts_at_seventh_phase_and_does_not_replay_create_or_stage(self):
        before=list(self.calls);successor=self.successor();receipt=successor.run()
        self.assertEqual(self.calls[:len(before)],before);self.assertEqual(self.calls[len(before):],list(PHASES[6:]))
        self.assertEqual(self.calls.count('CREATE_REPLACEMENT'),1);self.assertEqual(self.calls.count('STAGE_PAUSED_REPLACEMENT'),1)
        self.assertEqual(self.old.t.journal.record.read_bytes(),self.original_bytes)
        current=successor.t.read();self.assertEqual(current['effects'][:6],self.row['effects'][:6])
        self.assertEqual(current['governedUnsignedReprocessing']['failedIntent'],self.row['effects'][6])
        self.assertFalse(receipt['releaseAcceptance']);before=list(self.calls);successor.run();self.assertEqual(self.calls,before)
    def test_revocation_denies_before_new_journal_or_any_native_effect(self):
        self.f.mandate.write_bytes(b'{}');before=list(self.calls)
        with self.assertRaises(Exception):self.successor()
        self.assertEqual(list(Path(self.paths['transition']).iterdir()),[]);self.assertEqual(self.calls,before)
    def test_marker_or_applied_prefix_change_is_rejected(self):
        successor=self.successor();row=successor.t.read()
        for name in('marker','prefix','authority'):
            bad=copy.deepcopy(row)
            if name=='marker':bad['governedUnsignedReprocessing']['failedIntent']['intentHash']='e'*64
            if name=='prefix':bad['effects'][5]['nativeEvidenceHash']='e'*64
            if name=='authority':bad['governedUnsignedReprocessing']['newAuthorityHash']='e'*64
            with self.subTest(name=name),self.assertRaises(PlanDenied):p.verify_successor_transition(bad,self.scope,self.action.authority_hash)

class PausedContinuationFence(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory(dir=bootstrap.ROOT);self.addCleanup(temp.cleanup)
        self.root=Path(temp.name);self.root.chmod(0o700)
        override=patch.object(original.evidence,'PARENT',self.root);override.start();self.addCleanup(override.stop)
        override=patch.object(p,'retained_bindings');override.start();self.addCleanup(override.stop)
        (self.root/original.CLAIM).write_bytes(b'OLD_CONSUMED_CLAIM_MUST_REMAIN')
        self.proof={'profile':p.PROFILE,'recordBindings':[],'newBudget':{'priorControlledGrantAttempts':2}}
        self.action=SimpleNamespace(raw=original.encoded({'applicationRegistryCutover':{'postGrantRecovery':self.proof}}),
            authority_hash='e'*64,guard=lambda key,scope:True)
    def test_new_fixed_fence_keeps_old_claim_and_denies_second_operator_and_relaunch(self):
        before=(self.root/original.CLAIM).read_bytes()
        with original.ContinuationFence(self.action,self.proof)as fence:
            self.assertTrue(fence.guard())
            with self.assertRaises(FileExistsError):
                with original.ContinuationFence(self.action,self.proof):pass
        with self.assertRaises(FileExistsError):
            with original.ContinuationFence(self.action,self.proof):pass
        self.assertEqual((self.root/original.CLAIM).read_bytes(),before)
        current=json.loads((self.root/p.CLAIM).read_bytes());self.assertEqual(current['priorControlledGrantAttempts'],2)
    def test_replaced_identical_claim_inode_does_not_allow_stale_worker(self):
        with original.ContinuationFence(self.action,self.proof)as fence:
            path=self.root/p.CLAIM;raw=path.read_bytes();path.rename(self.root/'retained-old-claim');path.write_bytes(raw);path.chmod(0o600)
            with self.assertRaises(PlanDenied):fence.guard()

if __name__=='__main__':unittest.main()
