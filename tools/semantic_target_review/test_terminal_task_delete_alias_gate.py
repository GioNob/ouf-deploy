"""Negative maintenance boundaries; fixtures confer no target authority."""
import importlib.util
from pathlib import Path
import unittest
spec=importlib.util.spec_from_file_location('gate',Path(__file__).with_name('terminal_task_delete_alias_gate.py'))
gate=importlib.util.module_from_spec(spec);spec.loader.exec_module(gate)
A='a'*64;B='b'*64;ROOT='/run/explicit-runc-root'
class Tests(unittest.TestCase):
    def test_delete_exact_pair_without_force(self):
        self.assertEqual(gate.parse_delete(['--root',ROOT,'--log','/run/explicit/log.json','--log-format','json','delete',A],{A:{},B:{}},ROOT),A)
    def test_no_start_create_kill_force_exec_wrong_cid_or_root(self):
        for argv in (['--root',ROOT,'start',A],['--root',ROOT,'create',A],['--root',ROOT,'kill',A,'9'],
            ['--root',ROOT,'delete','--force',A],['--root',ROOT,'delete','c'*64],['--root','/run/other','delete',A],
            ['--root',ROOT,'exec',A],['--root',ROOT,'delete',A,'extra'],['--root',ROOT,'--root',ROOT,'delete',A]):
            with self.subTest(argv=argv),self.assertRaises(gate.Denied):gate.parse_delete(argv,{A:{},B:{}},ROOT)
    def test_native_entry_or_live_pid_or_state_directory_denies(self):
        cfg={'tasks':{A:{'pid':101},B:{'pid':102}},'runtimeRoot':ROOT}
        gate.absent(cfg,[],lambda _:False)
        gate.absent(cfg,None,lambda _:False)
        for rows,predicate in (([{'id':A,'status':'stopped'}],lambda _:False),([],lambda p:p=='/proc/102'),([],lambda p:p==ROOT+'/'+A)):
            with self.assertRaises(gate.Denied):gate.absent(cfg,rows,predicate)
class AliasTests(unittest.TestCase):
    def test_exact_alias_acceptance_other_alias_and_retarget_denied(self):
        import tempfile
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);canonical=root/'state';canonical.mkdir()
            alias=root/'observed';alias.symlink_to(canonical,target_is_directory=True)
            other=root/'unobserved';other.symlink_to(canonical,target_is_directory=True)
            cfg={'runtimeArgumentRoot':str(alias),'runtimeRoot':str(canonical)}
            gate.validate_root_binding(cfg)
            self.assertEqual(gate.parse_delete(['--root',str(alias),'delete',A],(A,B),str(alias)),A)
            for supplied in (str(other),str(canonical)):
                with self.assertRaises(gate.Denied):gate.parse_delete(['--root',supplied,'delete',A],(A,B),str(alias))
            alias.unlink();elsewhere=root/'elsewhere';elsewhere.mkdir();alias.symlink_to(elsewhere)
            with self.assertRaises(gate.Denied):gate.validate_root_binding(cfg)
    def test_parent_traversal_denied(self):
        with self.assertRaises(gate.Denied):gate.validate_root_binding({'runtimeArgumentRoot':'/run/../run/x','runtimeRoot':'/run/x'})
if __name__=='__main__':unittest.main()
