import copy
import importlib.util
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('all_crash33', ROOT / 'scripts/run-storage-generation33-lateral-isolation.py')
lab = importlib.util.module_from_spec(spec); spec.loader.exec_module(lab)


class AllCrashTests(unittest.TestCase):
    def snapshots(self):
        before = {r: {'Id': r, 'RestartCount': 0, 'State': {'Running': True, 'StartedAt': 'initial',
                  'OOMKilled': False, 'Error': '', 'ExitCode': 0}} for r in lab.ROLES}
        killed = {r: copy.deepcopy(before[r]) for r in lab.SERVICES}
        for item in killed.values(): item['State'].update(Running=False, ExitCode=137)
        return before, killed

    def test_every_service_must_be_non_oom_sigkill(self):
        before, killed = self.snapshots(); lab.validate_all_killed(before, killed)
        for role in lab.SERVICES:
            for field, value in [('Running', True), ('ExitCode', 0), ('OOMKilled', True)]:
                bad = copy.deepcopy(killed); bad[role]['State'][field] = value
                with self.subTest(role=role,field=field), self.assertRaises(ValueError): lab.validate_all_killed(before,bad)

    def test_partial_extra_and_duplicate_killed_sets_are_rejected(self):
        before, killed = self.snapshots()
        for bad in ({k:v for k,v in killed.items() if k!='s3'}, {**killed,'client':before['client']},
                    {**killed,'s3':killed['filer']}):
            with self.assertRaises(ValueError): lab.validate_all_killed(before,bad)

    def test_all_four_services_are_replaced_but_client_retained(self):
        before,_=self.snapshots();after=copy.deepcopy(before)
        for role in lab.SERVICES:after[role]['Id']='new-'+role
        lab.validate_retained_roles(before,after,'all')
        for role in lab.SERVICES:
            bad=copy.deepcopy(after);bad[role]['Id']=before[role]['Id']
            with self.assertRaises(ValueError):lab.validate_retained_roles(before,bad,'all')
        for field in ('Id','RestartCount'):
            bad=copy.deepcopy(after);bad['client'][field]='different' if field=='Id' else 1
            with self.assertRaises(ValueError):lab.validate_retained_roles(before,bad,'all')

    def test_replacement_namespaces_cannot_reuse_old_host_or_each_other(self):
        old={r:'old-'+r for r in lab.ROLES};new={r:'new-'+r for r in lab.SERVICES}
        lab.validate_replacement_namespaces(old,new,'host')
        for value in ('host',old['client'],old['master'],new['volume']):
            bad={**new,'master':value}
            with self.assertRaises(ValueError):lab.validate_replacement_namespaces(old,bad,'host')
        with self.assertRaises(ValueError):lab.validate_replacement_namespaces(old,{'master':'new'},'host')

    def gates(self,root):
        result={r:root/r for r in lab.SERVICES}
        for p in result.values():p.mkdir()
        return result

    def test_all_gates_release_only_with_fresh_valid_directories(self):
        with tempfile.TemporaryDirectory() as temp:
            gates=self.gates(Path(temp));lab.release_replacement_gates(gates)
            self.assertTrue(all((p/'open').read_bytes()==b'READY\n' for p in gates.values()))

    def test_bad_last_gate_prevents_any_earlier_gate_release(self):
        with tempfile.TemporaryDirectory() as temp:
            gates=self.gates(Path(temp));(gates['s3']/'open').write_text('stale')
            with self.assertRaises(ValueError):lab.release_replacement_gates(gates)
            self.assertTrue(all(not (gates[r]/'open').exists() for r in ('master','volume','filer')))

    def test_symlink_and_missing_gate_prevent_global_release(self):
        for symlink in (False,True):
            with tempfile.TemporaryDirectory() as temp:
                root=Path(temp);gates=self.gates(root);gates['s3'].rmdir()
                if symlink:gates['s3'].symlink_to(gates['master'],target_is_directory=True)
                with self.assertRaises(ValueError):lab.release_replacement_gates(gates)
                self.assertFalse((gates['master']/'open').exists())

    def test_partial_or_client_gate_set_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            gates=self.gates(Path(temp))
            for bad in ({'master':gates['master'],'volume':gates['volume']},{'client':gates['s3']}):
                with self.assertRaises(ValueError):lab.release_replacement_gates(bad)
            self.assertTrue(all(not (p/'open').exists() for p in gates.values()))

    def test_all_crash_cannot_be_combined_with_single_role_modes(self):
        for other in ('crash_volume','crash_filer','crash_master'):
            with self.assertRaisesRegex(ValueError,'ONE_CRASH_ROLE'):
                lab.run(None,None,None,None,crash_all=True,**{other:True})

    def test_each_replacement_preserves_its_storage_and_readonly_configuration(self):
        for role in lab.SERVICES:
            args=lab.container_argv('image','new-'+role,'net',Path('/fixture'),Path('/config'),
                                    Path('/binary'),role,Path('/gates')/role)
            self.assertIn('type=bind,src=/fixture/'+role+',dst=/data',args)
            self.assertIn('type=bind,src=/config,dst=/config,readonly',args)
            self.assertIn('type=bind,src=/gates/'+role+',dst=/gate,readonly',args)
            self.assertEqual(lab.IPS[role],args[args.index('--ip')+1])
            self.assertNotIn('--privileged',args)


if __name__=='__main__':unittest.main()
