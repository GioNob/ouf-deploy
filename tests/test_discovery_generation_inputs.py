import copy
import importlib.util
import json
from pathlib import Path
import stat
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('generation_inputs',ROOT/'scripts/prepare-discovery-generation-inputs-20261109.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)


def fixture():
    old={'kernel':{'fixture':'kernel'},'dns':{'fixture':'dns'},'commonLockFile':'/run/guard.lock',
         'journalFile':'/old/journal.json','binding':{'transactionId':'a'*64,'configurationHash':'b'*64,'leaseStructureHash':'c'*64}}
    new=copy.deepcopy(old);new['journalFile']='/new/journal.json';new['binding']['transactionId']='d'*64
    template={k:None for k in m.TEMPLATE_FIELDS}
    template.update(schema='ouf.semantic-admission-preparer-template.v1',**m.owner_selection(old),
        candidate={'containerId':'1'*64,'transactionId':'2'*64,'transport':{'peer':{'containerId':'3'*64}}})
    return old,new,template


class GenerationInputs(unittest.TestCase):
    def test_completed_boot_receipt_matches_producer_bytes(self):
        r=json.loads((ROOT/'evidence/discovery-successor-boot-bound-operator-20261109.json').read_bytes())
        raw=m.encoded(r);self.assertEqual(1434,len(raw));m.verify_boot_result(raw)
        for key in r:
            modified=dict(r);modified.pop(key)
            with self.subTest(key=key),self.assertRaisesRegex(RuntimeError,'EXACT_COMPLETED_BOOT_RECEIPT_REQUIRED'):
                m.verify_boot_result(m.encoded(modified))

    def test_pinned_dependency_closure_loads_without_running_controller(self):
        b=m.boot_module();c=b.dependency();self.assertEqual(13,len(b.helper_pins(c)))

    def test_separate_unsigned_selection_preserves_history_and_marks_identities(self):
        old,new,t=fixture();retained=copy.deepcopy((old,new,t))
        out=m.prepare_role('adapter','1'*64,t,old,new)
        self.assertEqual(retained,(old,new,t));self.assertEqual(t,out['historicalTemplate'])
        self.assertEqual(m.owner_selection(new),out['successorCoordination'])
        self.assertEqual(['/candidate/containerId','/candidate/transactionId','/candidate/transport/peer/containerId',
                          '/coordinationBinding/transactionId'],out['historicalIdentityPaths'])
        self.assertFalse(out['runtimeConfigurationProduced']);self.assertFalse(out['startAuthorized'])
        self.assertFalse(out['historicalIdentityReuseAllowed']);self.assertEqual(0,out['signaturesProduced'])
        out['historicalTemplate']['candidate']['containerId']='foreign';self.assertEqual('1'*64,t['candidate']['containerId'])

    def test_unknown_fields_and_wrong_cid_refused(self):
        old,new,t=fixture();t['unknown']=True
        with self.assertRaisesRegex(RuntimeError,'EXACT_PREPARER_TEMPLATE_REQUIRED'):m.prepare_role('adapter','1'*64,t,old,new)
        del t['unknown'];t['candidate']['containerId']='9'*64
        with self.assertRaisesRegex(RuntimeError,'BOUND_HISTORICAL_CANDIDATE_REQUIRED'):m.prepare_role('adapter','1'*64,t,old,new)

    def test_mixed_historical_coordinator_refused(self):
        old,new,t=fixture();t['coordinationBinding']=copy.deepcopy(new['binding'])
        with self.assertRaisesRegex(RuntimeError,'HISTORICAL_COORDINATOR_TEMPLATE_MISMATCH'):
            m.prepare_role('southbound','1'*64,t,old,new)

    def test_kernel_dns_lock_or_reused_generation_refused(self):
        for key in ('kernel','dns','commonLockFile','journalFile','binding'):
            old,new,t=fixture()
            if key in ('journalFile','binding'):new[key]=old[key]
            else:new[key]='foreign'
            with self.subTest(key=key),self.assertRaisesRegex(RuntimeError,'EXACT_SUCCESSOR_COORDINATION_DELTA_REQUIRED'):
                m.prepare_role('adapter','1'*64,t,old,new)

    def test_real_create_only_private_publication_and_replay_denial(self):
        b=m.boot_module();c=b.dependency();old,new,t=fixture()
        roles={r:m.prepare_role(r,'1'*64,t,old,new) for r in ('adapter','southbound')}
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);hashes=m.write_inputs(c.p.save,root,{'state':'UNSIGNED_INPUTS_ONLY'},roles)
            self.assertEqual(3,len(hashes));before={p:p.read_bytes() for p in root.iterdir()}
            for p,raw in before.items():
                self.assertEqual(0o600,stat.S_IMODE(p.stat().st_mode));self.assertEqual(m.sha(raw),hashes[p.name])
            with self.assertRaises(FileExistsError):m.write_inputs(c.p.save,root,{},roles)
            self.assertEqual(before,{p:p.read_bytes() for p in root.iterdir()})

    def test_partial_publication_is_preserved(self):
        b=m.boot_module();c=b.dependency();old,new,t=fixture()
        roles={r:m.prepare_role(r,'1'*64,t,old,new) for r in ('adapter','southbound')}
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);calls=[]
            def write(path,raw):
                calls.append(path)
                if len(calls)==2:raise OSError('simulated failure')
                c.p.save(path,raw)
            with self.assertRaises(OSError):m.write_inputs(write,root,{},roles)
            self.assertEqual(['adapter-inputs.private.json'],[p.name for p in root.iterdir()])
            self.assertEqual(m.encoded(roles['adapter']),(root/'adapter-inputs.private.json').read_bytes())


if __name__=='__main__':unittest.main()
