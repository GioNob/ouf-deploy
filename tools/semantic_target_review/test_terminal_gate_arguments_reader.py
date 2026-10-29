import ast,importlib.util,json,tempfile,unittest
from pathlib import Path
spec=importlib.util.spec_from_file_location('reader',Path(__file__).with_name('read_terminal_gate_arguments.py'))
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
gate_spec=importlib.util.spec_from_file_location('gate',Path(__file__).with_name('terminal_task_delete_gate.py'))
g=importlib.util.module_from_spec(gate_spec);gate_spec.loader.exec_module(g)
class Tests(unittest.TestCase):
    def test_root_alias_reproduces_lexical_denial_without_delete(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temporary:
            root=Path(temporary);real=root/'real';real.mkdir();(real/'moby').mkdir();alias=root/'alias';alias.symlink_to(real,target_is_directory=True)
            _,supplied,argv=m.reconstruct({'root':str(alias),'binary_name':str(m.WRAPPER)},Path('/run/fixed/bundle'),m.S)
            expected=str(real/'moby');projection=m.root_projection(supplied,expected)
            self.assertFalse(projection['lexicallyEqual']);self.assertTrue(projection['canonicallyEqual'])
            with self.assertRaisesRegex(g.Denied,'EXACT_RETAINED_RUNTIME_ROOT_REQUIRED'):g.parse_delete(argv,{m.S:{},m.A:{}},expected)
    def test_exact_root_passes_pure_gate_and_systemd_flag_preserved(self):
        _,supplied,argv=m.reconstruct({'root':'/run/retained','binary_name':str(m.WRAPPER),'systemd_cgroup':True},Path('/run/fixed/bundle'),m.S)
        self.assertIn('--systemd-cgroup',argv);self.assertEqual(g.parse_delete(argv,{m.S:{},m.A:{}},supplied),m.S)
    def test_missing_ambiguous_relative_root_and_nonboolean_options_denied(self):
        for options in ({'binary_name':str(m.WRAPPER)},{'root':'/run/a','Root':'/run/a','binary_name':str(m.WRAPPER)},{'root':'relative','binary_name':str(m.WRAPPER)},{'root':'/run/a','binary_name':str(m.WRAPPER),'systemd_cgroup':'false'}):
            with self.assertRaises(m.Denied):m.reconstruct(options,Path('/run/fixed/bundle'),m.S)
    def test_private_roots_are_only_hashed_in_projection(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temporary:
            out=json.dumps(m.root_projection(temporary,temporary));self.assertNotIn(temporary,out)
    def test_no_gate_acknowledgement_and_only_native_list_command(self):
        tree=ast.parse(Path(m.__file__).read_text())
        attrs={n.func.attr for n in ast.walk(tree) if isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute)}
        self.assertFalse(attrs & {'write_bytes','write_text','chmod','mkdir','unlink','replace','rename','acknowledge','publish','kill','terminate','Popen'})
        subscripts={n.value for n in ast.walk(tree) if isinstance(n,ast.Constant) and isinstance(n.value,str)}
        self.assertNotIn('acknowledge',subscripts)
        run=[n for n in ast.walk(tree) if isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute) and n.func.attr=='run']
        self.assertEqual(len(run),1);self.assertIn("'list', '--format', 'json'",ast.unparse(run[0]));self.assertNotIn("'delete'",ast.unparse(run[0]))
if __name__=='__main__':unittest.main()
