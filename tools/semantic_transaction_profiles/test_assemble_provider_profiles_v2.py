"""Pure v2 portability, exact producer/journal bindings and legacy immutability."""
import sys,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT))
import test_assemble_provider_profiles as legacy
from tools.semantic_transaction_profiles.assemble_provider_profiles_v2 import assemble_profiles,AssemblyDenied,digest,encoded

class ProfilesV2(unittest.TestCase):
    def setUp(self):
        self.case=legacy.ProfilesTest();self.case.setUp()
    def test_selected_parent_is_bound_in_broker_node_and_both_initial_journals(self):
        inputs=self.case.inputs();inputs['runtime_parents']=['/private/installation/runtime']
        files=assemble_profiles(**inputs);broker=files['broker.json']
        self.assertEqual(broker['runtimeRootParent'],'/private/installation/runtime')
        self.assertEqual(files['attestation-producer.json']['runtimeRootParents'],inputs['runtime_parents'])
        for name in ('broker-state.json','deployment.json'):
            self.assertEqual(files[name]['configurationHash'],digest(encoded(broker)))
    def test_multiple_parents_require_explicit_selection_inside_approved_set(self):
        inputs=self.case.inputs();inputs['runtime_parents']=['/private/runtime-a','/private/runtime-b']
        with self.assertRaisesRegex(AssemblyDenied,'UNAMBIGUOUS_BROKER_RUNTIME_PARENT'):assemble_profiles(**inputs)
        with self.assertRaisesRegex(AssemblyDenied,'OUTSIDE_APPROVED_NODE_PARENTS'):
            assemble_profiles(**inputs,broker_runtime_root_parent='/run')
        files=assemble_profiles(**inputs,broker_runtime_root_parent='/private/runtime-b')
        self.assertEqual(files['broker.json']['runtimeRootParent'],'/private/runtime-b')
    def test_existing_run_selection_keeps_all_legacy_output_bytes_exact(self):
        inputs=self.case.inputs()
        self.assertEqual(assemble_profiles(**inputs),legacy.assemble_profiles(**inputs))
    def test_invalid_parent_paths_are_refused_before_any_source_assembly(self):
        for parents in ([],['/'],['relative'],['/private/../run'],['/run','/run']):
            inputs=self.case.inputs();inputs['runtime_parents']=parents
            with self.assertRaisesRegex(AssemblyDenied,'APPROVED_RUNTIME_PARENTS'):assemble_profiles(**inputs)

if __name__=='__main__':unittest.main()
