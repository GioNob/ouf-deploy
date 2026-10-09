"""Inert approval boundary and exact wrapper restoration with actual files."""
import contextlib,copy,importlib.util,io,json,tempfile,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
spec=importlib.util.spec_from_file_location('executor',Path(__file__).with_name('execute_terminal_alias_recovery.py'))
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class Tests(unittest.TestCase):
    def test_pending_approval_denies_before_source_or_target_access(self):
        with contextlib.redirect_stdout(io.StringIO()) as out:
            code=m.main('not-approved','/does/not/exist','/does/not/exist','/does/not/exist')
        value=json.loads(out.getvalue().split('=',1)[1]);self.assertEqual(code,1)
        self.assertEqual(value['reason'],'EXPLICIT_TERMINAL_CLEANUP_APPROVAL_REQUIRED')
        self.assertEqual(value['taskDeleteRequests'],0);self.assertFalse(value['doNotRerunApply'])
    def test_absolute_deadline_denies_before_target_access(self):
        for now in (1791552017,m.APPROVAL_EXPIRES_AT,m.APPROVAL_EXPIRES_AT+1):
            with patch.object(m,'APPROVAL_REF','DISPOSABLE_TEST_APPROVAL'),patch.object(m,'APPROVED_AT',1791552018),patch.object(m.time,'time',return_value=now),patch.object(m,'load') as loader,contextlib.redirect_stdout(io.StringIO()) as out:
                self.assertEqual(m.main('DISPOSABLE_TEST_APPROVAL','x','x','x'),1)
            loader.assert_not_called()
            self.assertEqual(json.loads(out.getvalue().split('=',1)[1])['reason'],'LIVE_HUMAN_MAINTENANCE_APPROVAL_REQUIRED')
    def test_failed_claim_and_all_evidence_are_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            base=Path(directory);context=base/'context';context.mkdir();evidence=base/'evidence';evidence.mkdir()
            window={'tasks':{m.S:{'pid':1687816},m.A:{'pid':1722506}}}
            raw=m.encoded(window);(evidence/'window.json').write_bytes(raw)
            claim={'approvalRef':'OUF_TERMINAL_TASK_CLEANUP_HUMAN_APPROVAL_20261009_152018','approvedAt':1791552018,'evidenceDirectory':str(evidence),'windowHash':m.sha(raw),'tasks':window['tasks']}
            claim_path=context/'terminal-task-cleanup-claim.json';claim_path.write_bytes(m.encoded(claim))
            (evidence/'maintenance-result.json').write_bytes(m.encoded({'status':'BLOCKED','reason':'TERMINAL_TASK_DELETE_UNPROVEN','taskDeleteRequests':1,'doNotRerunApply':True,'wrapperRestored':True}))
            (evidence/'gate.py').write_bytes(b'old evidence')
            before={p:p.read_bytes() for p in [claim_path,*evidence.iterdir()]}
            entry={'read':lambda p,*_:Path(p).read_bytes(),'parse':json.loads}
            with patch.object(m,'CONTEXT',context),patch.object(m,'EVIDENCE',evidence):
                frozen=m.retain_failed_attempt(entry)
                self.assertEqual(len(frozen),len(before))
                self.assertEqual(before,{p:p.read_bytes() for p in before})
                changed=claim.copy();changed['approvedAt']+=1;claim_path.write_bytes(m.encoded(changed))
                with self.assertRaises(m.Denied):m.retain_failed_attempt(entry)
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
