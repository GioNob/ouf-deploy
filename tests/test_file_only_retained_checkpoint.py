"""Actual owner call path; native builder stops after the real binding gate.

Authority/native payloads are synthetic here. Native Docker binding and scoped
signature acceptance have separate tests; this is not full node qualification.
"""
import copy,sys,unittest
from pathlib import Path
from unittest.mock import Mock,patch
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'tests'),str(ROOT/'tools/semantic_application_cutover'),str(ROOT)]
import test_file_only_preparation  # Established complete component import roots.
import test_paused_workload_binding as fixture
import file_only_node_owner as node
from transition_journal import digest

class NativeBuilderReached(Exception):pass

class RetainedOwnerWiring(unittest.TestCase):
    def owner(self,cursor):
        b,state,row,receipt,intent=fixture.Binding().retained_fixture(cursor)
        owner=node.FileOnlyNodeOwner.__new__(node.FileOnlyNodeOwner)
        owner.intent={'fixture':'exact-attestation'};owner.intent_hash=digest(owner.intent)
        receipt['intentHash']=owner.intent_hash
        row['effects'][6].update(intentHash=owner.intent_hash,nativeEvidenceHash=digest(receipt))
        owner.current=Mock(return_value=copy.deepcopy(row));owner.adapter=None
        owner.recipe={'observationSeconds':30,'observationConfiguration':{}}
        owner.engine,owner.transition,owner.request,owner.store=b.engine,b.transition,{'Image':'sha256:'+'a'*64},b.store
        return owner,row,state
    def test_actual_verify_retained_selects_retained_binding_before_both_successor_effects(self):
        for cursor in(7,8):
            owner,row,state=self.owner(cursor)
            with patch.object(node,'NodeObservation',side_effect=NativeBuilderReached)as builder:
                with self.assertRaises(NativeBuilderReached):owner.verify_retained()
                builder.assert_called_once()
            owner.current.assert_called_once_with(owner.intent,True)
    def test_changed_or_unpaused_process_is_denied_before_native_builder_or_signing(self):
        for drift in('unpause','pid','restart'):
            owner,row,state=self.owner(7)
            if drift=='unpause':state['State'].update(Paused=False,Status='running')
            if drift=='pid':state['State']['Pid']+=1
            if drift=='restart':state['RestartCount']=1
            with patch.object(node,'NodeObservation')as builder:
                with self.assertRaises(ValueError):owner.verify_retained()
                builder.assert_not_called()
    def test_current_journal_change_after_owner_guard_denies_before_native_builder(self):
        owner,row,state=self.owner(8);row['version']+=1
        with patch.object(node,'NodeObservation')as builder:
            with self.assertRaisesRegex(ValueError,'CURRENT_RETAINED_PAUSED_CHECKPOINT'):owner.verify_retained()
            builder.assert_not_called()

if __name__=='__main__':unittest.main()
