"""New real dual-role authority over copied history; phase effects are fixtures.

The predecessor CREATE has already executed and lost its ACK. Its journal and
native evidence are preserved, while the successor can only observe that phase.
"""
import copy
import json
from pathlib import Path
import unittest
from unittest.mock import patch

import test_chatbot_cohort_containers as bootstrap
import test_file_only_cutover as fixture
from cutover_authority import CutoverAuthority
from cutover_executor import Executor
from transition_journal import Transition,digest
from tools.semantic_lease_recovery.recovery_journal import Journal
from tools.semantic_policy_token_owner.owner_installation import AggregateAction
from tools.chatbot_file_cohort import postgrant_recovery as p
from tools.chatbot_file_cohort.review import REQUIRED_SCOPES


class SignedSuccessor(unittest.TestCase):
    def setUp(self):
        harness=fixture.FileOnlyCutover();self.addCleanup(harness.doCleanups)
        self.f,self.profile,self.old,self.calls=harness.fixture()
        native=self.old.adapters['CREATE_REPLACEMENT'].apply
        def lost_ack(intent):native(intent);raise OSError('synthetic ACK lost after CREATE')
        self.old.adapters['CREATE_REPLACEMENT'].apply=lost_ack
        with self.assertRaises(OSError):self.old.run()
        self.old_bytes=self.old.t.journal.record.read_bytes();row=self.old.t.read()
        self.assertEqual(row['version'],9);self.assertEqual(row['nextPhase'],4)
        proof={'profile':p.PROFILE,'predecessorAuthorityHash':self.old.authority_hash,
            'predecessorTransitionHash':digest(row),'createdContainerId':'c'*64,
            'transitionContextHash':row['contextHash'],'appliedPrefixHash':digest(row['effects'][:4]),
            'recordBindings':[{'path':str(self.old.t.journal.record),'sha256':fixture.crypto.sha(self.old_bytes)}]}
        for name,value in (('AUTHORITY',self.old.authority_hash),('TRANSITION_HASH',digest(row)),('CREATED_ID','c'*64)):
            override=patch.object(p,name,value);override.start();self.addCleanup(override.stop)
        self.scope={'postGrantRecovery':proof,'creationRequestHash':digest(self.profile.request),
            'executionProfileHash':self.profile.sha256,'sourceClosureHash':'8'*64,
            'phaseIntentHashes':copy.deepcopy(self.old.intent_hashes)}
        authority=json.loads(self.f.authority);authority['sourceClosureHash']='8'*64
        authority.update({key:{'syntheticUnexecutedScope':key}for key in REQUIRED_SCOPES})
        authority['applicationRegistryCutover']=self.scope
        self.f.expected['sourceClosureHash']='8'*64;self.f.authority=fixture.crypto.encoded(authority)
        self.f.approval.update(sourceClosureHash='8'*64,executionAuthorityHash=fixture.crypto.sha(self.f.authority),
            approvalRef='NEW_EXACT_POSTGRANT_SYNTHETIC_REVIEW')
        self.f.write(self.f.mandate,fixture.crypto.encoded(self.f.approval));self.f.approved=fixture.crypto.sha(self.f.mandate.read_bytes())
        for role in self.f.grant['roles']:self.f.sign(role)
        gate=CutoverAuthority(self.f.verifier,self.f.binding(self.f.mandate),self.f.approved,self.f.context,
            self.f.expected,self.f.clock,execution_profile=self.profile)
        self.action=AggregateAction(gate,self.f.authority,'8'*64)
        self.paths={name:str(self.f.root/('successor-'+name))for name in ('transition','evidence','before','retirementBefore')}
        for path in self.paths.values():Path(path).mkdir(mode=0o700)
        self.predecessor={'transition':row,'prepared':{'registry':{'intents':self.old.intents}},
            'payloads':{'evidence':{phase:{'syntheticPhase':phase}for phase in self.old.phases[:4]},
                'before':{'QUIESCE_PRODUCERS':{'syntheticOriginalAuthorization':True}},
                'retirementBefore':{'STOP_REVOKE_OLD_LEASE':{'syntheticOriginalRetirement':True}}}}

    def successor(self):
        journal=p.seed_registry(self.predecessor,self.paths,self.action,self.scope)
        transition=Transition(journal,self.old.t.context,execution_profile=self.profile)
        def checkpoint(phase,point,row):
            return {'schema':'ouf.semantic-cutover-native-checkpoint.v1','phase':phase,'point':point,
                'journalVersion':row['version'],'intentHash':self.old.intent_hashes[phase],
                'authorityHash':self.action.authority_hash,'sourceClosureHash':self.action.closure,'nativeEvidenceHash':'f'*64}
        return Executor(transition,self.action.raw,self.action.authority,checkpoint,self.old.adapters,
            self.old.intents,self.f.clock,aggregate_action=self.action,aggregate_scope=self.scope)

    def test_fresh_signed_action_observes_create_once_then_applies_only_later_phases(self):
        successor=self.successor();result=successor.run()
        self.assertEqual(self.calls,list(self.old.phases))
        self.assertEqual(self.calls.count('CREATE_REPLACEMENT'),1)
        self.assertEqual(self.old.t.journal.record.read_bytes(),self.old_bytes)
        row=successor.t.read();self.assertEqual(row['state'],'COMPLETED')
        self.assertEqual(row['effects'][:4],self.predecessor['transition']['effects'][:4])
        self.assertEqual(row['effects'][4]['authorityEvidenceHash'],self.old.authority_hash)
        self.assertTrue(all(e['authorityEvidenceHash']==self.action.authority_hash for e in row['effects'][5:]))
        before=list(self.calls);successor.run();self.assertEqual(self.calls,before)
        self.assertFalse(result['releaseAcceptance'])

    def test_ambiguous_native_create_observation_cannot_replay_or_start_later_phase(self):
        successor=self.successor();successor.adapters['CREATE_REPLACEMENT'].observe=lambda intent:('UNKNOWN',{'synthetic':'ambiguous'})
        before=list(self.calls)
        with self.assertRaises(Exception):successor.run()
        self.assertEqual(self.calls,before);self.assertEqual(successor.t.read()['nextPhase'],4)
        self.assertEqual(self.old.t.journal.record.read_bytes(),self.old_bytes)

    def test_new_human_revocation_denies_before_copy_or_reconciliation(self):
        self.f.mandate.write_bytes(b'{}')
        with self.assertRaises(Exception):self.successor()
        self.assertEqual(list(Path(self.paths['transition']).iterdir()),[])
        self.assertEqual(self.old.t.journal.record.read_bytes(),self.old_bytes)


if __name__=='__main__':unittest.main()
