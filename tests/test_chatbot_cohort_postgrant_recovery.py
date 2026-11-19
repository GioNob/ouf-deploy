"""Post-grant history invariants; synthetic target records, no VPS effects."""
import copy
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import test_chatbot_cohort_containers as bootstrap
from tools.chatbot_file_cohort import postgrant_recovery as p
from tools.chatbot_file_cohort.plan import digest,PlanDenied
from file_only_profile import PHASES


def fixture():
    intents={phase:{'syntheticIntent':phase}for phase in PHASES}
    effects=[{'phase':phase,'intentHash':digest(intents[phase]),'authorityEvidenceHash':p.AUTHORITY,
        'state':'APPLIED' if n<4 else 'IN_FLIGHT',**({'nativeEvidenceHash':str(n+1)*64}if n<4 else {})}
        for n,phase in enumerate(PHASES[:5])]
    row={'schema':'ouf.semantic-cutover-journal.v2','contextHash':'c'*64,'version':9,'state':'IN_FLIGHT',
        'nextPhase':4,'transitionAuthorityEvidenceHash':p.AUTHORITY,'creationRequestHash':digest(intents['CREATE_REPLACEMENT']),
        'effects':effects,'databaseMayHaveChanged':False,'applicationWritesMayHaveOccurred':False,
        'automaticReplayAllowed':False,'preMigrationRestoreAllowed':False}
    proof={'profile':p.PROFILE,'predecessorAuthorityHash':p.AUTHORITY,'predecessorTransitionHash':p.TRANSITION_HASH,
        'createdContainerId':p.CREATED_ID,'transitionContextHash':row['contextHash'],'appliedPrefixHash':digest(effects[:4])}
    return row,intents,{'creationRequestHash':row['creationRequestHash'],'postGrantRecovery':proof}


class PostGrantHistory(unittest.TestCase):
    def test_accepts_only_four_applied_and_one_consumed_create_without_rewriting(self):
        row,intents,scope=fixture();before=copy.deepcopy(row)
        self.assertEqual(p.validate_cutover_seed(row,intents),row)
        self.assertTrue(p.verify_successor_transition(row,scope,'f'*64));self.assertEqual(row,before)
    def test_missing_unknown_or_rewritten_prefix_is_not_adopted(self):
        original,intents,scope=fixture()
        for kind in ('next','flag','version','prefix','create','intent','authority','missing'):
            row=copy.deepcopy(original)
            if kind=='next':row['nextPhase']=3
            if kind=='flag':row['databaseMayHaveChanged']=True
            if kind=='version':row['version']=10
            if kind=='prefix':row['effects'][0]['state']='IN_FLIGHT'
            if kind=='create':row['effects'][4]['state']='APPLIED'
            if kind=='intent':row['effects'][3]['intentHash']='f'*64
            if kind=='authority':row['effects'][1]['authorityEvidenceHash']='f'*64
            if kind=='missing':row['effects'].pop(0)
            with self.subTest(kind=kind),self.assertRaises(PlanDenied):p.validate_cutover_seed(row,intents)
    def test_successor_effects_require_current_authority_and_keep_original_create_claim(self):
        row,intents,scope=fixture();row['effects'][4]['state']='APPLIED';row['nextPhase']=5
        row['effects'].append({'phase':'STAGE_PAUSED_REPLACEMENT','state':'IN_FLIGHT','authorityEvidenceHash':'f'*64})
        self.assertTrue(p.verify_successor_transition(row,scope,'f'*64))
        for position in (0,4,5):
            bad=copy.deepcopy(row);bad['effects'][position]['authorityEvidenceHash']='e'*64
            with self.subTest(position=position),self.assertRaises(PlanDenied):p.verify_successor_transition(bad,scope,'f'*64)
    def worker(self):
        first={'operation':'1'*64,'scopeHash':'2'*64,'state':'TOKEN_PUBLISHED_NOT_RUNTIME_ACCEPTED',
            'attemptSlotsConsumed':1,'gapRemainsOpen':True,'historicalAccountingReconciled':False,'legacyHistoricalGrantAttempts':None}
        session={'predecessorFirstGrantOperation':first['operation'],'predecessorFirstGrantScopeHash':first['scopeHash']}
        worker={'state':'CANCELLED','attempts':0,'controlledPredecessorGrantAttempts':1,'controlledCumulativeGrantAttempts':1,
            'workerSessionHash':digest(session),'firstGrantReceiptHash':digest(first)}
        admission={'state':'BLOCKED'}
        completed={'state':'OWNER_READY_FOR_FINITE_WORKER_NOT_APPLICATION_ACCEPTED','firstGrantReceiptHash':digest(first),
            'workerSessionScopeHash':digest(session)}
        return first,worker,admission,session,completed
    def test_spent_first_grant_is_history_and_cancelled_worker_is_not_resumed(self):
        args=self.worker();before=copy.deepcopy(args);result=p.validate_worker_seed(*args)
        self.assertEqual(result['controlledCumulativeGrantAttempts'],1);self.assertEqual(args,before)
    def test_any_prior_renewal_active_admission_or_ambiguous_handoff_blocks(self):
        for kind in ('spent','active','attempt','cumulative','admission','receipt','handoff'):
            first,worker,admission,session,completed=self.worker()
            if kind=='spent':first['attemptSlotsConsumed']=0
            if kind=='active':worker['state']='ACTIVE'
            if kind=='attempt':worker['attempts']=1
            if kind=='cumulative':worker['controlledCumulativeGrantAttempts']=2
            if kind=='admission':admission['state']='ACTIVE'
            if kind=='receipt':worker['firstGrantReceiptHash']='f'*64
            if kind=='handoff':completed['state']='RESERVED_OUTCOME_UNPROVEN'
            with self.subTest(kind=kind),self.assertRaises(PlanDenied):p.validate_worker_seed(first,worker,admission,session,completed)
    def test_changed_old_authority_or_different_container_never_uses_generic_successor(self):
        row,intents,original=fixture()
        for field in ('predecessorAuthorityHash','createdContainerId','predecessorTransitionHash','appliedPrefixHash'):
            scope=copy.deepcopy(original);scope['postGrantRecovery'][field]='f'*64
            with self.subTest(field=field),self.assertRaises(PlanDenied):p.verify_successor_transition(row,scope,'f'*64)


class PersistentContinuationFence(unittest.TestCase):
    """Real O_EXCL/flock and sealed files; authorization itself is a fixture."""
    def setUp(self):
        temporary=tempfile.TemporaryDirectory(dir=bootstrap.ROOT,prefix='postgrant-fence-')
        self.addCleanup(temporary.cleanup);self.root=Path(temporary.name);self.root.chmod(0o700)
        parent=patch.object(p.evidence,'PARENT',self.root);parent.start();self.addCleanup(parent.stop)
        self.proof={'profile':p.PROFILE,'recordBindings':[]}
        self.action=SimpleNamespace(raw=p.encoded({'applicationRegistryCutover':{'postGrantRecovery':self.proof}}),
            authority_hash='e'*64,guard=lambda key,scope:True)

    def test_different_operator_and_later_invocation_cannot_reserve_again(self):
        with p.ContinuationFence(self.action,self.proof)as first:
            self.assertTrue(first.guard())
            with self.assertRaises(FileExistsError):
                with p.ContinuationFence(self.action,self.proof):pass
        before=(self.root/p.CLAIM).read_bytes()
        with self.assertRaises(FileExistsError):
            with p.ContinuationFence(self.action,self.proof):pass
        self.assertEqual((self.root/p.CLAIM).read_bytes(),before)

    def test_same_bytes_at_replaced_inode_do_not_authorize_stale_invocation(self):
        with p.ContinuationFence(self.action,self.proof)as first:
            path=self.root/p.CLAIM;raw=path.read_bytes();path.rename(self.root/'preserved-original-claim')
            path.write_bytes(raw);path.chmod(0o600)
            with self.assertRaisesRegex(PlanDenied,'IDENTITY_DRIFT'):first.guard()

    def test_different_unsigned_proof_cannot_consume_global_claim(self):
        with self.assertRaisesRegex(PlanDenied,'SIGNED_POSTGRANT'):
            with p.ContinuationFence(self.action,{**self.proof,'changed':True}):pass
        self.assertFalse((self.root/p.CLAIM).exists())


if __name__=='__main__':unittest.main()
