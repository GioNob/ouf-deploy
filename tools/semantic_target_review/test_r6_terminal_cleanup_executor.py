"""R6 scoped cleanup boundaries; disposable fixtures do not grant target authority."""
import contextlib,copy,importlib.util,io,json,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
spec=importlib.util.spec_from_file_location('r6cleanup',Path(__file__).with_name('execute_r6_terminal_cleanup.py'))
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class Tests(unittest.TestCase):
    def facts(self):
        v={'status':'R6_TERMINAL_REVIEW_CAPTURED','allRecordedTaskPidsAbsent':True,
           'containerdVersions':{'Client':'v2.3.5','Server':'v2.3.5'},'installedWrapperHash':m.WRAPPER_SHA,
           'nativeEmptyGuardObservation':{'providerSetsEmpty':True,'lockInodePreserved':True,'configurationHash':m.OWNER_SHA,'candidateStateHashes':dict(m.STATES)},
           'containerdRequestedTasks':{},'requestedEntriesAtRetainedRoot':{},'terminalTaskReview':{}}
        for cid,(pid,metadata) in m.TASKS.items():
            v['containerdRequestedTasks'][cid]={'taskPresent':True,'status':'STOPPED','pid':pid,'containerMetadataHash':metadata,'runtimeKind':'io.containerd.runc.v2'}
            v['requestedEntriesAtRetainedRoot'][cid]={'entryPresent':False}
            p,t,a=m.EXPECTED_SHIMS[cid]
            v['terminalTaskReview'][cid]={'shims':[{'pid':p,'startTicks':t,'argvHash':a,'executableHash':'e873923a2d5361f14494a8434543b5bb218aa15736b1ac5bb73dbce5ac9ea1cb'}]}
        return v
    def test_pending_and_expired_approval_deny_before_target_access(self):
        for ref,approved,expires,now in [('PENDING_R6_TERMINAL_CLEANUP_APPROVAL',None,None,1),('DISPOSABLE_TEST',5,8,8),('DISPOSABLE_TEST',5,8,4)]:
            with patch.object(m,'APPROVAL_REF',ref),patch.object(m,'APPROVED_AT',approved),patch.object(m,'APPROVAL_EXPIRES_AT',expires),patch.object(m.time,'time',return_value=now),patch.object(m,'load') as loader,contextlib.redirect_stdout(io.StringIO()) as out:
                self.assertEqual(m.main(ref,'x','x','x'),1)
            loader.assert_not_called()
            v=json.loads(out.getvalue().split('=',1)[1]);self.assertEqual(v['taskDeleteRequests'],0);self.assertFalse(v['doNotRerunApply'])
    def test_exact_task_and_shim_generations_guard_and_pid_absence(self):
        v=self.facts();before=copy.deepcopy(v);m.validate_review(v);self.assertEqual(v,before)
        cases=[]
        for field,bad in [('pid',1),('status','RUNNING'),('taskPresent',False),('containerMetadataHash','0'*64)]:
            c=copy.deepcopy(v);c['containerdRequestedTasks'][m.A][field]=bad;cases.append(c)
        c=copy.deepcopy(v);c['terminalTaskReview'][m.S]['shims'][0]['startTicks']+=1;cases.append(c)
        c=copy.deepcopy(v);c['allRecordedTaskPidsAbsent']=False;cases.append(c)
        c=copy.deepcopy(v);c['nativeEmptyGuardObservation']['candidateStateHashes'][m.A]='0'*64;cases.append(c)
        c=copy.deepcopy(v);c['requestedEntriesAtRetainedRoot'][m.S]['entryPresent']=True;cases.append(c)
        for c in cases:
            with self.assertRaises(m.Denied):m.validate_review(c)
    def test_real_wrapper_cas_and_restoration(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as directory:
            root=Path(directory);wrapper=root/'runtime';wrapper.write_bytes(b'original');wrapper.chmod(0o755)
            entry={'read':lambda p,*_:Path(p).read_bytes()}
            with patch.object(m,'WRAPPER',wrapper):
                m.replace_wrapper(entry,b'original',b'delete-only',root/'stage')
                with self.assertRaises(m.Denied):m.replace_wrapper(entry,b'wrong',b'unsafe',root/'unused')
                self.assertFalse((root/'unused').exists())
                m.replace_wrapper(entry,b'delete-only',b'original',root/'restore')
                self.assertEqual(wrapper.read_bytes(),b'original')
    def test_claim_and_denial_preserved_without_replay(self):
        with tempfile.TemporaryDirectory() as directory:
            context=Path(directory)/'context';context.mkdir();root=Path(directory)/'output';root.mkdir()
            names={'execution-claim.json':{'outputRoot':str(root)},'human-approval-binding.json':{},'execution-configuration.json':{}}
            for n,v in names.items():(context/n).write_bytes(m.encoded(v))
            raw=b'retained denial'
            for n in ('cohort-activation-denial.json','runtime-switch-claim.json','runtime-switch-receipt.json','cohort-activation-claim.json','installation-receipt.json'):(root/n).write_bytes(raw)
            before={p:p.read_bytes() for p in [*context.iterdir(),*root.iterdir()]}
            digest=m.sha
            # Only this disposable denial stands in for the exact target digest.
            with patch.object(m,'CONTEXT',context),patch.object(m,'ROOT',root),patch.object(m,'sha',side_effect=lambda b:'a87bc84ef93af80fb8bd871daae77979604eea9ab77fa352ceca35e828c0bf3d' if b==raw else digest(b)):
                frozen=m.retain_failed_attempt({'read':lambda p,*_:Path(p).read_bytes(),'parse':json.loads})
            self.assertEqual(len(frozen),len(before));self.assertEqual(before,{p:p.read_bytes() for p in before})
if __name__=='__main__':unittest.main()
