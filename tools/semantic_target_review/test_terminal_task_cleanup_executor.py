"""Inert approval boundary and exact wrapper restoration with actual files."""
import contextlib,copy,importlib.util,io,json,tempfile,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
spec=importlib.util.spec_from_file_location('executor',Path(__file__).with_name('execute_terminal_task_cleanup.py'))
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class Tests(unittest.TestCase):
    def test_pending_approval_denies_before_source_or_target_access(self):
        with contextlib.redirect_stdout(io.StringIO()) as out:
            code=m.main('not-approved','/does/not/exist','/does/not/exist')
        value=json.loads(out.getvalue().split('=',1)[1]);self.assertEqual(code,1)
        self.assertEqual(value['reason'],'EXPLICIT_TERMINAL_CLEANUP_APPROVAL_REQUIRED')
        self.assertEqual(value['taskDeleteRequests'],0);self.assertFalse(value['doNotRerunApply'])
    def test_two_hour_approval_denies_before_target_reads_outside_window(self):
        self.assertEqual(m.APPROVAL_WINDOW_SECONDS,7200)
        for offset in (-1,7200,7201):
            with self.subTest(offset=offset),patch.object(m.time,'time',return_value=m.APPROVED_AT+offset),patch.object(m,'load') as loader,contextlib.redirect_stdout(io.StringIO()) as out:
                code=m.main(m.APPROVAL_REF,'/not-a-target-reader','/not-a-target-gate')
            value=json.loads(out.getvalue().split('=',1)[1])
            self.assertEqual(code,1);loader.assert_not_called()
            self.assertEqual(value['reason'],'LIVE_HUMAN_MAINTENANCE_APPROVAL_REQUIRED')
            self.assertEqual(value['taskDeleteRequests'],0);self.assertFalse(value['doNotRerunApply'])
    def test_explicit_two_hour_approval_accepts_second_hour_before_reader(self):
        for offset in (0,3599,3600,7199):
            with self.subTest(offset=offset),patch.object(m.time,'time',return_value=m.APPROVED_AT+offset),patch.object(m.os,'geteuid',return_value=0),patch.object(m.sys,'flags',SimpleNamespace(isolated=True)),patch.object(m.sys,'dont_write_bytecode',True),patch.object(m,'load',side_effect=m.Denied('TEST_READER_BOUNDARY')) as loader,contextlib.redirect_stdout(io.StringIO()) as out:
                code=m.main(m.APPROVAL_REF,'/not-a-target-reader','/not-a-target-gate')
            value=json.loads(out.getvalue().split('=',1)[1])
            self.assertEqual(code,1);loader.assert_called_once()
            self.assertEqual(value['reason'],'TEST_READER_BOUNDARY')
            self.assertEqual(value['taskDeleteRequests'],0);self.assertFalse(value['doNotRerunApply'])
    def test_exact_terminal_review_and_shim_generation(self):
        facts={'status':'R5_TERMINAL_REVIEW_CAPTURED','allRecordedTaskPidsAbsent':True,'containerdVersions':{'Client':'v2.3.5','Server':'v2.3.5'},'installedWrapperHash':m.WRAPPER_SHA,'nativeEmptyGuardObservation':{'providerSetsEmpty':True},'terminalTaskReview':{}}
        for cid,(pid,ticks,argv) in m.EXPECTED_SHIMS.items():facts['terminalTaskReview'][cid]={'shims':[{'pid':pid,'startTicks':ticks,'argvHash':argv,'executableHash':'e873923a2d5361f14494a8434543b5bb218aa15736b1ac5bb73dbce5ac9ea1cb'}]}
        m.validate_review(facts)
        changed=copy.deepcopy(facts);changed['terminalTaskReview'][m.A]['shims'][0]['startTicks']+=1
        with self.assertRaises(m.Denied):m.validate_review(changed)
        facts['allRecordedTaskPidsAbsent']=False
        with self.assertRaises(m.Denied):m.validate_review(facts)
    def test_real_file_cas_and_exact_restoration(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temporary:
            root=Path(temporary);wrapper=root/'runtime';wrapper.write_bytes(b'original');wrapper.chmod(0o755)
            prior=m.WRAPPER;m.WRAPPER=wrapper
            try:
                entry={'read':lambda p,*_:Path(p).read_bytes()}
                m.replace_wrapper(entry,b'original',b'delete-only',root/'stage')
                self.assertEqual(wrapper.read_bytes(),b'delete-only')
                with self.assertRaises(m.Denied):m.replace_wrapper(entry,b'wrong',b'unsafe',root/'unused')
                self.assertFalse((root/'unused').exists())
                m.replace_wrapper(entry,b'delete-only',b'original',root/'restore')
                self.assertEqual(wrapper.read_bytes(),b'original')
            finally:m.WRAPPER=prior
if __name__=='__main__':unittest.main()
