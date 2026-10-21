"""CI-only read projection/boundary checks; never target authority."""
import ast,copy,importlib.util,unittest
from pathlib import Path
from unittest.mock import patch
spec=importlib.util.spec_from_file_location('r6reader',Path(__file__).with_name('read_r6_terminal_state.py'))
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class Tests(unittest.TestCase):
    def test_present_absent_and_malformed_task_inventory(self):
        cid='a'*64
        self.assertEqual(m.requested_tasks(b'TASK PID STATUS\nunrelated 9 RUNNING\n',{cid}),{})
        row=m.requested_tasks(('TASK PID STATUS\n'+cid+' 23 STOPPED\n').encode(),{cid})[cid]
        self.assertEqual(row,{'taskPresent':True,'pid':23,'status':'STOPPED'})
        for raw in (b'',b'invalid header\n',b'TASK PID STATUS\nx invalid STOPPED\n',('TASK PID STATUS\n'+cid+' 1 STOPPED\n'+cid+' 2 STOPPED\n').encode()):
            with self.assertRaises(AssertionError):m.requested_tasks(raw,{cid})
    def test_stopped_task_does_not_imply_process_absence(self):
        row={'taskPresent':True,'pid':23,'status':'STOPPED'};before=copy.deepcopy(row)
        for present in (True,False):
            with patch.object(m.Path,'exists',return_value=present):
                self.assertEqual(m.process_review(row)['taskPidPresent'],present)
        self.assertEqual(row,before)
        with patch.object(m.Path,'exists',side_effect=AssertionError('must not infer pid')):
            self.assertFalse(m.process_review({'taskPresent':False,'pid':None})['taskPidPresent'])
    def test_no_write_signing_or_lifecycle_dispatch(self):
        source=Path(m.__file__).read_text();tree=ast.parse(source)
        forbidden={'execute_transaction','issue_role_authority','operate','publish','publish_once','replace','unlink','chmod','mkdir','makedirs','write','fchmod','fsync','kill'}
        for node in ast.walk(tree):
            if isinstance(node,ast.Call):
                name=node.func.id if isinstance(node.func,ast.Name) else node.func.attr if isinstance(node.func,ast.Attribute) else ''
                self.assertNotIn(name,forbidden)
            if isinstance(node,ast.Attribute):self.assertNotIn(node.attr,{'O_WRONLY','O_CREAT','O_TRUNC'})
        for text in ("['tasks','delete'","['start'","155oj3tc","1687816","1722506"):
            self.assertNotIn(text,source)
if __name__=='__main__':unittest.main()
