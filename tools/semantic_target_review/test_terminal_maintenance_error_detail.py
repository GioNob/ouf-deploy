import ast,importlib.util,json,stat,unittest
from pathlib import Path
from types import SimpleNamespace
spec=importlib.util.spec_from_file_location('reader',Path(__file__).with_name('read_terminal_maintenance_error_detail.py'))
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class Tests(unittest.TestCase):
    def test_root_readable_log_modes_without_widening_to_writable_files(self):
        for mode in (0o600,0o640,0o644):m.validate_log_info(SimpleNamespace(st_mode=stat.S_IFREG|mode,st_uid=0,st_gid=0,st_nlink=1,st_size=100))
        for changes in ({'st_mode':stat.S_IFREG|0o666},{'st_mode':stat.S_IFLNK|0o600},{'st_uid':10006},{'st_nlink':2},{'st_size':131073}):
            value={'st_mode':stat.S_IFREG|0o644,'st_uid':0,'st_gid':0,'st_nlink':1,'st_size':100};value.update(changes)
            with self.assertRaises(m.Denied):m.validate_log_info(SimpleNamespace(**value))
    def test_parse_quoted_daemon_error_then_redact(self):
        value=m.error_fields('time="2026-10-09" msg="delete task" error="failed to delete task: unable to retrieve OCI runtime error /private/secret KEY=SECRET no such file or directory"')
        self.assertIn('unable to retrieve OCI runtime error',value['recognizedPhrases'])
        self.assertIn('no such file or directory',value['recognizedPhrases'])
        self.assertIn('failed to delete task',value['error']['publicStructure'])
        self.assertNotIn('/private/secret',json.dumps(value));self.assertNotIn('SECRET',json.dumps(value))
    def test_runc_error_history_is_bounded_and_drops_extra_fields(self):
        raw=b'\n'.join(json.dumps({'level':'error','msg':'failed delete /secret/KEY','time':'2026-10-09T13:24:00Z','private':'SECRET'}).encode() for _ in range(10))
        value=m.json_log(raw);self.assertEqual(value['errorCount'],10);self.assertEqual(len(value['errorRecords']),8)
        self.assertNotIn('SECRET',json.dumps(value));self.assertNotIn('/secret',json.dumps(value))
        self.assertEqual(value['errorRecords'][0]['time'],'2026-10-09T13:24:00Z')
    def test_non_json_and_wrong_time_are_not_printed_raw(self):
        value=m.json_log(b'PRIVATE_SECRET\n'+json.dumps({'level':'error','msg':'failed','time':'PRIVATE_SECRET'}).encode())
        self.assertEqual(value['invalidLineCount'],1);self.assertNotIn('PRIVATE_SECRET',json.dumps(value))
    def test_only_journal_read_no_lifecycle_and_no_file_mutation(self):
        tree=ast.parse(Path(m.__file__).read_text())
        attrs={n.func.attr for n in ast.walk(tree) if isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute)}
        self.assertFalse(attrs & {'write_bytes','write_text','chmod','mkdir','unlink','replace','rename','acknowledge','publish','kill','terminate','Popen'})
        run=[n for n in ast.walk(tree) if isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute) and n.func.attr=='run']
        self.assertEqual(len(run),1);self.assertIn("'--lines=500'",ast.unparse(run[0]));self.assertIn("'--no-pager'",ast.unparse(run[0]))
if __name__=='__main__':unittest.main()
