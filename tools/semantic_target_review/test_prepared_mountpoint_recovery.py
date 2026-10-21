"""R8 approval boundaries and maintenance failure handling, no native target."""
import copy
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import types
import unittest
from unittest.mock import patch

import execute_prepared_mountpoint_recovery as recovery

ROOT=Path(__file__).resolve().parents[2]


class PreparedRecoveryTest(unittest.TestCase):
    def setUp(self):
        self.scope=json.loads((ROOT/'evidence/provider-r8-mountpoint-recovery-scope-20261009.json').read_bytes())
        self.receipt=json.loads((ROOT/'evidence/provider-r7-rootfs-target-20261009.json').read_bytes())['receipt']
        self.temp=tempfile.TemporaryDirectory(dir=os.environ.get('OUF_TRANSACTION_TEST_ROOT',Path.cwd()))
        self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)

    def test_inert_executor_refuses_old_or_invented_approvals_before_any_io(self):
        for ref in ('invented','OUF_PROVIDER_AUDITED_RECOVERY_APPROVED_20261009T191942_CEST_R7'):
            result=subprocess.run([sys.executable,'-I','-B',str(ROOT/'tools/semantic_target_review/execute_prepared_mountpoint_recovery.py'),ref,str(self.root)],
                stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=5)
            self.assertEqual(result.returncode,1)
            value=json.loads(result.stdout.decode().split('=',1)[1])
            self.assertEqual(value['reason'],'EXPLICIT_PREPARED_ROOTFS_APPROVAL_REQUIRED')
            self.assertEqual(value['taskDeleteRequests'],0);self.assertEqual(value['privateKeysRead'],0)
        self.assertEqual(list(self.root.iterdir()),[])

    def test_actual_receipt_matches_fixed_scope_but_new_pid_seal_or_wrapper_is_rejected(self):
        recovery.validate_fresh(self.scope,self.receipt)
        for edit in ('pid','seal','wrapper','native'):
            value=copy.deepcopy(self.receipt);cid=self.scope['roles']['adapter']['containerId']
            if edit=='pid':value['containerdRequestedTasks'][cid]['pid']+=1
            elif edit=='seal':value['roles']['adapter']['currentV1Seal']['sha256']='0'*64
            elif edit=='wrapper':value['installedWrapperHash']='0'*64
            else:value['requestedNativeEntries'][cid]=[{'status':'created','pid':1}]
            with self.assertRaises(ValueError):recovery.validate_fresh(self.scope,value)

    def test_mandates_require_fresh_approval_and_exact_inputs_and_preserve_new_seals(self):
        scope=copy.deepcopy(self.scope);records={role:{'ci':b'CI_ONLY'} for role in scope['roles']}
        for role in records:scope['roles'][role]['inputHashes']={'ci':recovery.sha(b'CI_ONLY')}
        now=1791570000;before=copy.deepcopy(scope)
        with patch.multiple(recovery,APPROVAL_REF='CI_ONLY_R8',APPROVED_AT=now,APPROVAL_EXPIRES_AT=now+60):
            value=recovery.build_mandates(scope,records,now,'CI_ONLY_R8')
            self.assertEqual(scope,before)
            for role in value:
                self.assertEqual(value[role]['runtimeSeal'],scope['roles'][role]['runtimeSeal'])
                self.assertEqual(value[role]['expiresAt'],now+240)
            for when in (now-1,now+60):
                with self.assertRaisesRegex(ValueError,'LIVE_PREPARED_ROOTFS'):
                    recovery.build_mandates(scope,records,when,'CI_ONLY_R8')
            records['adapter']['ci']=b'changed'
            with self.assertRaisesRegex(ValueError,'INPUTS_CHANGED'):
                recovery.build_mandates(scope,records,now,'CI_ONLY_R8')

    def maintenance_fixture(self,fail_second=False):
        scope=copy.deepcopy(self.scope);fresh=copy.deepcopy(self.receipt);now=int(time.time())
        context=self.root/'new-context';context.mkdir();wrapper=self.root/'wrapper';wrapper.write_bytes(b'original-wrapper')
        lock=self.root/'lock';lock.touch();output=self.root/'prior-output'
        runtime_root='/ci/retained-root';fresh['runtimeRootHash']=recovery.sha(runtime_root.encode())
        scope['priorWrapperHash']=recovery.sha(wrapper.read_bytes())
        cids=[scope['roles'][r]['containerId'] for r in ('southbound','adapter')]
        private={};options={};metadata={};shim_bytes={};native_calls=[];remaining=set(cids)
        def put(path,value):private[str(path)]=recovery.encoded(value)
        for cid in cids:
            put(output/'registry'/cid/'adapter.json',{'runtimeRoot':runtime_root})
            path=Path('/run/containerd/io.containerd.runtime.v2.task/moby')/cid
            for name in ('options.json','runtime'):
                private[str(path/name)]=b'CI_OPTIONS';options[str(path/name)]=recovery.sha(b'CI_OPTIONS')
            metadata[cid]=recovery.encoded({'ID':cid})
            scope['tasks'][cid]['containerMetadataHash']=recovery.sha(metadata[cid])
            scope['tasks'][cid]['pid']=2147483646 if cid==cids[0] else 2147483647
            shim=scope['shims'][cid]['shims'][0];shim_bytes[str(shim['pid'])]=b'CI_SHIM'
            shim['argvHash']=recovery.sha(b'CI_SHIM')
        put(self.root/'template',{'candidate':{'runtimeBinding':{'path':'/ci/runc','sha256':'0'*64}}})
        put(self.root/'pointer',{'receiptFile':str(self.root/'guard/receipt.json'),'receiptHash':'0'*64})
        put(self.root/'guard/coordinated-configuration.json',{'commonLockFile':str(lock)})
        cfg={'recordsByRole':{'adapter':{'preparerTemplate':{'path':str(self.root/'template')}}},
            'guardPointerBinding':{'path':str(self.root/'pointer')},'pythonBinding':{'path':'/ci/python','sha256':'0'*64},'commandBindings':{}}
        def read(path,executable=False):return wrapper.read_bytes() if Path(path)==wrapper else private[str(path)]
        entry={'read':read,'parse':json.loads,'bound':lambda binding:read(binding['path'])}
        def publish(path,raw):Path(path).write_bytes(raw)
        def replace(entry,expected,new,stage):
            self.assertEqual(wrapper.read_bytes(),expected);wrapper.write_bytes(new)
        helpers={'cleanup':{'retained_alias':lambda *args:('/ci/alias',options),'replace_wrapper':replace},
            'gate':{'validate_root_binding':lambda window:None},'arguments':{},'gateRaw':b'CI_INERT_GATE'}
        original_read=Path.read_bytes
        def process_bytes(path):
            if str(path).startswith('/proc/'):
                pid=path.parent.name;cid=next(c for c in cids if str(scope['shims'][c]['shims'][0]['pid'])==pid)
                if path.name=='cmdline':return b'CI_SHIM'
                return b'0 (shim) '+b' '.join([b'0']*19+[str(scope['shims'][cid]['shims'][0]['startTicks']).encode()])
            return original_read(path)
        def readlink(path):
            pid=Path(path).parent.name;cid=next(c for c in cids if str(scope['shims'][c]['shims'][0]['pid'])==pid)
            return '/run/containerd/io.containerd.runtime.v2.task/moby/'+cid
        def run(argv,**kwargs):
            args=argv[5:];native_calls.append(args);code=0
            if args[:2]==['containers','info']:raw=metadata[args[2]]
            elif args==['tasks','list']:
                raw=('TASK PID STATUS\n'+''.join(c+' '+str(scope['tasks'][c]['pid'])+' STOPPED\n' for c in cids if c in remaining)).encode()
            else:
                self.assertEqual(args[:2],['tasks','delete']);self.assertEqual(len(args),3)
                cid=args[2];raw=b''
                if fail_second and cid==cids[1]:code=1
                else:remaining.remove(cid)
            kwargs['stdout'].write(raw);kwargs['stderr'].write(b'CI_FAILURE' if code else b'')
            return types.SimpleNamespace(returncode=code)
        module=types.ModuleType('transaction_guard_observation');module.executable_binding=lambda binding:binding
        module.observe_locked=lambda *args:copy.deepcopy(fresh['nativeEmptyGuardObservation'])
        with contextlib.ExitStack() as stack:
            stack.enter_context(patch.multiple(recovery,NEW_CONTEXT=context,OUTPUT=output,WRAPPER=wrapper,
                APPROVAL_REF='CI_ONLY_R8',APPROVED_AT=now-1,APPROVAL_EXPIRES_AT=now+600,
                REPORT={'taskDeleteRequests':0,'containerLifecycleOperations':0}))
            stack.enter_context(patch.dict(sys.modules,{'transaction_guard_observation':module}))
            stack.enter_context(patch.object(recovery.subprocess,'run',side_effect=run))
            stack.enter_context(patch.object(Path,'read_bytes',process_bytes))
            stack.enter_context(patch.object(recovery.os,'readlink',side_effect=readlink))
            with contextlib.redirect_stdout(io.StringIO()):
                if fail_second:
                    with self.assertRaisesRegex(ValueError,'TERMINAL_TASK_DELETE_FAILED'):
                        recovery.cleanup_pair(entry,cfg,scope,fresh,helpers,{},publish)
                else:recovery.cleanup_pair(entry,cfg,scope,fresh,helpers,{},publish)
            self.assertTrue(recovery.REPORT['maintenanceWrapperRestored'])
            self.assertEqual(recovery.REPORT['taskDeleteRequests'],2)
            self.assertEqual(wrapper.read_bytes(),b'original-wrapper')
            self.assertEqual(len(remaining),1 if fail_second else 0)
            self.assertTrue(all(args[:2] in (['containers','info'],['tasks','list'],['tasks','delete']) for args in native_calls))

    def test_exact_two_terminal_deletions_restore_wrapper_and_preserve_containers(self):self.maintenance_fixture()
    def test_second_delete_failure_restores_wrapper_and_never_retries(self):self.maintenance_fixture(True)


if __name__=='__main__':unittest.main()
