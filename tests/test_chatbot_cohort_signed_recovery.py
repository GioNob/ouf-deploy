"""Real Ed25519/Journal/Executor; native effects are explicit synthetic fixtures."""
import copy,json,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
import test_chatbot_cohort_mounted_recovery as prior
from tools.chatbot_file_cohort import signed_recovery as s,postgrant_recovery as root
from tools.chatbot_file_cohort.plan import digest
from tools.chatbot_file_cohort.review import REQUIRED_SCOPES
from tools.semantic_policy_token_owner.owner_installation import AggregateAction
from cutover_authority import CutoverAuthority
from cutover_executor import Executor
from transition_journal import Transition
from file_only_profile import PHASES

class SignedAdmissionSuccessor(unittest.TestCase):
    def setUp(self):
        h=prior.MountedSuccessor();self.addCleanup(h.doCleanups);h.setUp();self.h=h;self.f=h.f;self.profile=h.profile
        old=h.successor();checkpoint=old.checkpoint
        def fail(phase,point,row):
            if phase=='ADMIT_MIGRATION'and point=='BEFORE_NATIVE_EFFECT':raise ValueError('CURRENT_ATTESTATION_PHASE_AND_CREATION_SCOPE_REQUIRED')
            return checkpoint(phase,point,row)
        old.checkpoint=fail
        with self.assertRaisesRegex(ValueError,'CURRENT_ATTESTATION_PHASE'):old.run()
        self.old=old;self.row=old.t.read();self.assertEqual(self.row['version'],19);self.assertEqual(self.row['nextPhase'],7)
        self.preserved={**h.preserved,str(old.t.journal.record):old.t.journal.record.read_bytes()}
        for name,value in(('AUTHORITY',old.authority_hash),('TRANSITION_HASH',digest(self.row))):
            override=patch.object(s,name,value);override.start();self.addCleanup(override.stop)
        self.prepared={'postGrantRecovery':h.proof,'registry':{'creationRequest':self.profile.request,'intents':h.intents}}
        s.validate_boundary(self.row,self.prepared)
        self.proof={'profile':s.PROFILE,'predecessorAuthorityHash':root.AUTHORITY,'pausedPredecessorAuthorityHash':s.AUTHORITY,
            'predecessorTransitionHash':digest(self.row),'transitionContextHash':self.row['contextHash'],'appliedPrefixHash':digest(self.row['effects'][:6]),
            'previousAcceptedAttestationHash':digest(self.row['effects'][6]),'failedMigrationIntentHash':digest(self.row['effects'][7]),
            'previousReprocessingMarkerHash':digest(self.row['governedUnsignedReprocessing']),'recordBindings':[]}
        self.intents=copy.deepcopy(h.intents);self.intents['ATTEST_NEW_OCI_PEER']={'correctRetainedCheckpointSource':True}
        self.scope={'postGrantRecovery':self.proof,'creationRequestHash':self.row['creationRequestHash'],'executionProfileHash':self.profile.sha256,
            'sourceClosureHash':'6'*64,'phaseIntentHashes':{k:digest(v)for k,v in self.intents.items()}}
        authority=json.loads(self.f.authority);authority.update(sourceClosureHash='6'*64,phaseIntentHashes=self.scope['phaseIntentHashes'])
        authority.update({key:{'fixtureScope':key}for key in REQUIRED_SCOPES});authority['applicationRegistryCutover']=self.scope
        self.f.expected['sourceClosureHash']='6'*64;self.f.authority=prior.prior.fixture.crypto.encoded(authority)
        self.f.approval.update(sourceClosureHash='6'*64,executionAuthorityHash=prior.prior.fixture.crypto.sha(self.f.authority),approvalRef='NEW_SIGNED_ADMISSION_REPROCESSING')
        self.f.write(self.f.mandate,prior.prior.fixture.crypto.encoded(self.f.approval));self.f.approved=prior.prior.fixture.crypto.sha(self.f.mandate.read_bytes())
        for role in self.f.grant['roles']:self.f.sign(role)
        gate=CutoverAuthority(self.f.verifier,self.f.binding(self.f.mandate),self.f.approved,self.f.context,self.f.expected,self.f.clock,execution_profile=self.profile)
        self.action=AggregateAction(gate,self.f.authority,'6'*64)
        self.paths={name:str(self.f.root/('signed-successor-'+name))for name in('transition','evidence','before','retirementBefore')}
        for path in self.paths.values():Path(path).mkdir(mode=0o700)
        self.previous={'transition':self.row,'prepared':self.prepared,'payloads':h.previous['payloads']}
    def successor(self,deny_fence=False):
        with patch.object(s,'retained_bindings'):
            journal=s.seed_registry(self.previous,self.paths,self.action,self.scope)
        t=Transition(journal,self.old.t.context,execution_profile=self.profile)
        adapters=copy.copy(self.old.adapters)
        adapters['ATTEST_NEW_OCI_PEER']=SimpleNamespace(apply=lambda _:self.h.h.calls.append('ATTEST_NEW_OCI_PEER'),observe=lambda _:('APPLIED',{'syntheticFreshAttestation':True}))
        def checkpoint(phase,point,row):
            if deny_fence and phase=='ADMIT_MIGRATION'and point=='BEFORE_NATIVE_EFFECT':raise ValueError('CURRENT_DATABASE_FENCE_LOST')
            return {'schema':'ouf.semantic-cutover-native-checkpoint.v1','phase':phase,'point':point,'journalVersion':row['version'],
                'intentHash':digest(self.intents[phase]),'authorityHash':self.action.authority_hash,'sourceClosureHash':self.action.closure,'nativeEvidenceHash':'f'*64}
        return Executor(t,self.action.raw,self.action.authority,checkpoint,adapters,self.intents,self.f.clock,aggregate_action=self.action,aggregate_scope=self.scope)
    def unchanged(self):
        for path,data in self.preserved.items():self.assertEqual(Path(path).read_bytes(),data)
    def test_signed_attestation_and_pending_intent_are_archived_without_database_flag_reset(self):
        before=list(self.h.h.calls);new=self.successor();new.run();row=new.t.read();m=row['governedSignedAttestationReprocessing']
        self.assertTrue(row['databaseMayHaveChanged']);self.assertFalse(row['preMigrationRestoreAllowed'])
        self.assertEqual(row['effects'][:6],self.row['effects'][:6]);self.assertEqual(m['previousAcceptedAttestation'],self.row['effects'][6])
        self.assertEqual(m['failedMigrationIntent'],self.row['effects'][7]);self.assertEqual(m['previousReprocessing'],self.row['governedUnsignedReprocessing'])
        self.assertEqual(self.h.h.calls[len(before):],list(PHASES[6:]));self.assertEqual(self.h.h.calls.count('CREATE_REPLACEMENT'),1)
        self.assertEqual(self.h.h.calls.count('STAGE_PAUSED_REPLACEMENT'),1);self.unchanged()
    def test_changed_previous_acceptance_pending_intent_flag_or_new_authority_is_denied(self):
        seed=s.successor_seed(self.previous,self.proof,self.action.authority_hash,self.intents)
        for drift in('accepted','migration','oldMarker','database','newAuthority'):
            row=copy.deepcopy(seed);m=row['governedSignedAttestationReprocessing']
            if drift=='accepted':m['previousAcceptedAttestation']['nativeEvidenceHash']='f'*64
            if drift=='migration':m['failedMigrationIntent']['intentHash']='f'*64
            if drift=='oldMarker':m['previousReprocessing']['proofHash']='f'*64
            if drift=='database':row['databaseMayHaveChanged']=False
            if drift=='newAuthority':m['newAuthorityHash']='f'*64
            with self.subTest(drift=drift),self.assertRaises(Exception):s.verify_successor_transition(row,self.scope,self.action.authority_hash)
        self.unchanged()
    def test_lost_fence_stops_before_new_admission_effect(self):
        before=self.h.h.calls.count('ADMIT_MIGRATION');new=self.successor(deny_fence=True)
        with self.assertRaisesRegex(ValueError,'CURRENT_DATABASE_FENCE_LOST'):new.run()
        self.assertEqual(self.h.h.calls.count('ADMIT_MIGRATION'),before);self.assertTrue(new.t.read()['databaseMayHaveChanged']);self.unchanged()
    def test_duplicate_seed_is_consumed_and_cannot_replay(self):
        new=self.successor();before=new.t.journal.record.read_bytes()
        with self.assertRaisesRegex(Exception,'ALREADY_CONSUMED'):self.successor()
        self.assertEqual(new.t.journal.record.read_bytes(),before);self.unchanged()
    def test_revoked_new_human_cannot_seed_or_replay(self):
        self.f.mandate.write_bytes(b'{}')
        with self.assertRaises(Exception):self.successor()
        self.assertEqual(list(Path(self.paths['transition']).iterdir()),[]);self.unchanged()
    def test_other_boundary_or_changed_consumed_migration_intent_is_denied(self):
        for drift in('version','cursor','applied','database','intent'):
            row=copy.deepcopy(self.row);intents=copy.deepcopy(self.intents)
            if drift=='version':row['version']=18
            if drift=='cursor':row['nextPhase']=8
            if drift=='applied':row['effects'][6]['state']='IN_FLIGHT'
            if drift=='database':row['databaseMayHaveChanged']=False
            if drift=='intent':intents['ADMIT_MIGRATION']={'other':'database'}
            with self.subTest(drift=drift),self.assertRaises(Exception):s.successor_seed({**self.previous,'transition':row},self.proof,self.action.authority_hash,intents)
        self.unchanged()

if __name__=='__main__':unittest.main()
