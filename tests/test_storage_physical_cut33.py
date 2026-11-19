import copy
import importlib.util
from pathlib import Path
import unittest
import tempfile
from types import SimpleNamespace
from unittest.mock import patch
from test_storage_coordinated33_lab import ledger

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('physical_cut33',ROOT/'scripts/run-storage-physical-cut33-lab.py')
joint=importlib.util.module_from_spec(spec);spec.loader.exec_module(joint)
SEGMENT='000000010000000000000004'

class PhysicalCutTests(unittest.TestCase):
    def fixture(self):
        base={'backup_label':{'bytes':4,'sha256':'a'*64}}
        wal={SEGMENT:{'bytes':16*1024*1024,'sha256':'b'*64}}
        cold={'config/s3.json':{'bytes':80,'sha256':'c'*64}}
        state=ledger()
        cut={'schema':joint.SCHEMA,'targetName':joint.TARGET,'targetLsn':'0/4000040',
             'targetWalSegment':SEGMENT,'timeline':1,'sourceSystemIdentifier':'12345',
             'lockSha256':joint.common.LOCK_SHA,'cohortReceiptSha256':joint.common.COHORT_SHA,
             'baseIndexSha256':joint.common.sha(joint.encoded(base)),
             'walIndexSha256':joint.common.sha(joint.encoded(wal)),
             'coldIndexSha256':joint.common.sha(joint.encoded(cold)),
             'ledgerSha256':joint.common.sha(joint.encoded(state)),
             'readOnlyConfigSha256':'c'*64,'sourcePostgresStopped':True,
             'sourceStorageStoppedAndWithheld':True}
        return cut,base,wal,cold,state
    def test_bound_quiesced_cut_accepts_exact_components(self):
        self.assertTrue(joint.validate_cut(*self.fixture()))
    def test_component_from_another_backup_is_rejected(self):
        for position in (1,2,3):
            args=self.fixture();next(iter(args[position].values()))['sha256']='d'*64
            with self.assertRaisesRegex(RuntimeError,'BOUND_BACKUP_COMPONENT'):joint.validate_cut(*args)
    def test_missing_or_already_in_base_target_segment_is_rejected(self):
        args=self.fixture();args[2].clear()
        with self.assertRaisesRegex(RuntimeError,'POST_BASE_TARGET_WAL'):joint.validate_cut(*args)
        args=self.fixture();args[1]['pg_wal/'+SEGMENT]=args[2][SEGMENT]
        with self.assertRaisesRegex(RuntimeError,'POST_BASE_TARGET_WAL'):joint.validate_cut(*args)
    def test_running_source_or_unwithheld_storage_blocks_restore(self):
        for field in ('sourcePostgresStopped','sourceStorageStoppedAndWithheld'):
            args=self.fixture();args[0][field]=False
            with self.assertRaisesRegex(RuntimeError,'SOURCES_STOPPED'):joint.validate_cut(*args)
    def test_wrong_target_timeline_or_generation_rejected(self):
        for field,value in [('targetName','other'),('timeline',2),('lockSha256','0'*64),('cohortReceiptSha256','0'*64)]:
            args=self.fixture();args[0][field]=value
            with self.assertRaises(RuntimeError):joint.validate_cut(*args)
    def test_pending_intent_prevents_physical_cut(self):
        args=self.fixture();args[-1]['intents'][1]['state']='PENDING'
        with self.assertRaisesRegex(RuntimeError,'TERMINAL_INTENTS'):joint.validate_cut(*args)
    def test_frozen_ledger_or_readonly_config_cannot_be_substituted(self):
        for field in ('ledgerSha256','readOnlyConfigSha256'):
            args=self.fixture();args[0][field]='0'*64
            with self.assertRaises(RuntimeError):joint.validate_cut(*args)
    def restored(self):
        state=ledger()
        return [state,copy.deepcopy(state),'12345','12345','cut','f',
                [{'name':SEGMENT,'status':'COPIED','sha256':'b'*64}],SEGMENT,'b'*64]
    def test_physical_clone_preserves_ledger_and_cluster_identity(self):
        joint.validate_restored(*self.restored())
    def test_end_of_wal_or_pre_target_readiness_is_rejected(self):
        for index,value in [(4,'after-cut'),(4,'base'),(5,'t')]:
            args=self.restored();args[index]=value
            with self.assertRaisesRegex(RuntimeError,'EXACT_NAMED_TARGET'):joint.validate_restored(*args)
    def test_unrelated_cluster_cannot_qualify_as_physical_restore(self):
        args=self.restored();args[3]='54321'
        with self.assertRaisesRegex(RuntimeError,'SAME_PHYSICAL_CLUSTER'):joint.validate_restored(*args)
    def test_claimed_wal_without_exact_read_is_rejected(self):
        for rows in ([],[{'name':SEGMENT,'status':'MISSING'}],[{'name':SEGMENT,'status':'COPIED','sha256':'d'*64}]):
            args=self.restored();args[6]=rows
            with self.assertRaisesRegex(RuntimeError,'ACTUAL_POST_BASE_WAL'):joint.validate_restored(*args)
    def test_rewritten_valid_history_is_rejected(self):
        args=self.restored()
        for row in args[1]['events']:row['sequence']+=100
        with self.assertRaisesRegex(RuntimeError,'EXACT_ACK_FENCE_HISTORY'):joint.validate_restored(*args)


class SqlReadinessTests(unittest.TestCase):
    def run_probe(self,codes):
        temporary=tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup)
        proof=Path(temporary.name)
        destination=SimpleNamespace(binary=lambda name:Path('/fixture')/name,socket=Path('/private/socket'))
        with patch.object(joint.pitr,'command',side_effect=[SimpleNamespace(returncode=n) for n in codes]) as command, patch.object(joint.time,'sleep'), patch.object(joint.time,'monotonic',return_value=0):
            try:
                result=joint.await_sql_ready(destination,proof)
            finally:self.calls=command.call_count
        return result
    def test_rejecting_and_no_response_are_not_sql_readiness(self):
        result=self.run_probe([1,2,0])
        self.assertEqual([x['returnCode'] for x in result],[1,2,0])
        self.assertEqual(self.calls,3)
    def test_invalid_probe_is_permanent_and_not_retried(self):
        with self.assertRaisesRegex(RuntimeError,'PERMANENT_READINESS'):self.run_probe([3,0])
        self.assertEqual(self.calls,1)
    def test_readiness_budget_is_finite(self):
        with self.assertRaisesRegex(RuntimeError,'SQL_READINESS_BUDGET'):self.run_probe([1]*60)
        self.assertEqual(self.calls,60)

if __name__=='__main__':unittest.main()
