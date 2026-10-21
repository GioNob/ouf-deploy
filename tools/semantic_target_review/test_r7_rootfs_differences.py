"""R7 reader checks; disposable files/processes are never target observations."""
import copy
import builtins
import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

import read_r7_rootfs_differences as reader
from test_audited_provider_recovery import package_inputs,build,recovery

ROOT=Path(__file__).resolve().parents[2]


class R7RootfsReaderTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory(dir=os.environ.get('OUF_TRANSACTION_TEST_ROOT',Path.cwd()))
        cls.root=Path(cls.temp.name);cls.root.chmod(0o700)
        cls.built=build(*package_inputs())
        cls.package=cls.root/'source';cls.package.mkdir(mode=0o700)
        recovery.install_package(cls.package,cls.built['files'])
        cls.saved_modules=dict(sys.modules)
        entry={'__name__':'read_test_sources','__file__':str(cls.package/'provider_transaction_intake.py')}
        exec(compile(cls.built['files']['provider_transaction_intake.py'],entry['__file__'],'exec'),entry)
        entry['load'](cls.package)
        cls.sealer=staticmethod(sys.modules['tools.semantic_provider_node_observation'].rootfs_seal)

    @classmethod
    def tearDownClass(cls):
        for name in list(sys.modules):
            if name not in cls.saved_modules:sys.modules.pop(name,None)
        sys.modules.update(cls.saved_modules)
        cls.temp.cleanup()

    def test_fixed_scope_is_the_recorded_consumed_r7_package_and_receipt(self):
        value=json.loads((ROOT/'evidence/provider-r7-target-denial-20261009.json').read_text())
        self.assertEqual(reader.sha(reader.encoded(value['receipt'])),reader.OPERATOR_DENIAL)
        self.assertEqual(value['receipt']['evidenceDirectory'],str(reader.OUTPUT))
        self.assertEqual(value['receipt']['contextDirectory'],str(reader.CONTEXT))
        self.assertEqual(self.built['entryHash'],reader.R7_ENTRY)
        self.assertEqual(self.built['sourceClosureHash'],reader.CLOSURE)
        self.assertEqual(set(reader.ROLE_IDS.values()),set(value['receipt']['candidateObservations']))

    def test_actual_v1_sealer_retains_new_mount_entries_content_and_metadata_changes(self):
        with tempfile.TemporaryDirectory(dir=self.root) as directory:
            root=Path(directory);root.chmod(0o755)
            (root/'program').write_bytes(b'original')
            (root/'link').symlink_to('/private/example-do-not-print')
            limits={'maxEntries':100,'maxBytes':10000,'maxDepth':8}
            encoded_before=self.sealer.__globals__['encoded']
            original,left=reader.entries(self.sealer,root,limits)
            self.assertEqual(original,self.sealer(root,limits,reader.ReadBudget()))
            (root/'new-bind').mkdir();(root/'new-bind/token').touch()
            (root/'program').write_bytes(b'different')
            (root/'program').chmod(0o600)
            current,right=reader.entries(self.sealer,root,limits)
            self.assertNotEqual(original,current)
            self.assertIs(self.sealer.__globals__['encoded'],encoded_before)
            oci={'mounts':[{'destination':'/new-bind/token'}],'process':{'cwd':'/'}}
            result=reader.differences(left,right,oci)
            self.assertEqual(result['unexpectedDeclaredMountOrCwdEntries'],2)
            self.assertEqual(result['fieldCounts']['sha256'],1)
            self.assertEqual(result['fieldCounts']['mode'],1)
            printed=reader.encoded(result)
            for secret in (b'original',b'different"',b'example-do-not-print',right['program']['sha256'].encode()):
                self.assertNotIn(secret,printed)
            self.assertFalse(result['acceptanceGranted'])

    def test_diagnostic_normalization_never_changes_v1_records_or_file_security_fields(self):
        records={'':{'path':'','kind':'directory','mode':0o700,'uid':0,'gid':0,'links':5,'xattrs':{}},
            'file':{'path':'file','kind':'file','mode':0o600,'uid':1,'gid':2,'links':2,'size':4,'sha256':'a'*64,'xattrs':{'user.secret':'deadbeef'}}}
        before=copy.deepcopy(records)
        expected=reader.image_view(records,True)
        self.assertEqual(records,before)
        self.assertEqual(expected['']['mode'],0o755)
        self.assertNotIn('links',expected[''])
        self.assertEqual(expected['file'],records['file'])
        for field,value in [('links',1),('mode',0o644),('uid',0),('sha256','b'*64),('xattrs',{})]:
            altered=copy.deepcopy(expected);altered['file'][field]=value
            self.assertNotEqual(reader.image_digest(expected),reader.image_digest(altered))

    def test_mount_inventory_rejects_private_descendants_and_ambiguous_or_foreign_mount(self):
        root='/var/lib/docker/rootfs/overlayfs/test'
        row='1 0 0:1 / '+root+' rw - overlay overlay rw\n'
        self.assertEqual(reader.mount_rows(row.encode(),root),[{'mountId':1,'filesystem':'overlay'}])
        self.assertEqual(reader.mount_rows(b'1 0 0:1 / / rw - ext4 disk rw\n',root),[])
        for suffix in ('/secret','/secret\\040name'):
            with self.assertRaisesRegex(ValueError,'PRIVATE_SUBMOUNT'):
                reader.mount_rows((row+'2 1 0:2 / '+root+suffix+' rw - tmpfs private rw\n').encode(),root)
        with self.assertRaisesRegex(ValueError,'AMBIGUOUS'):
            reader.mount_rows((row+row).encode(),root)
        with self.assertRaisesRegex(ValueError,'EXACT_OVERLAY'):
            reader.mount_rows(row.replace('overlay overlay','ext4 disk').encode(),root)

    def test_mounted_stopped_view_does_not_export_and_detects_mount_change(self):
        with patch.object(reader,'current_mount',return_value=[{'mountId':1,'filesystem':'overlay'}]),patch.object(reader.subprocess,'Popen') as spawn:
            with reader.stopped_view('docker','config','cid','root',{}) as root:self.assertEqual(root,'root')
            spawn.assert_not_called()
        with patch.object(reader,'current_mount',side_effect=[[{'mountId':1}],[{'mountId':2}]]):
            with self.assertRaisesRegex(ValueError,'MOUNT_CHANGED'):
                with reader.stopped_view('docker','config','cid','root',{}):pass

    def test_stopped_export_holds_pipe_then_drains_without_unpack_or_container_operation(self):
        original=subprocess.Popen;processes=[];calls=[]
        def spawn(argv,**kwargs):
            calls.append(argv)
            p=original([sys.executable,'-c','import os; data=b"x"*1048576; os.write(1,data)'],**kwargs)
            processes.append(p);return p
        def mounts(root):return [{'mountId':1,'filesystem':'overlay'}] if processes and processes[0].poll() is None else []
        report={'stoppedContainerExports':0}
        with patch.object(reader.subprocess,'Popen',side_effect=spawn),patch.object(reader,'current_mount',side_effect=mounts):
            with reader.stopped_view('/fixed/docker','/fixed/config','exact-cid','/fixed/root',report):
                self.assertIsNone(processes[0].poll())
        self.assertEqual(processes[0].returncode,0)
        self.assertEqual(calls,[['/fixed/docker','--host','unix:///var/run/docker.sock','--config','/fixed/config','export','exact-cid']])
        self.assertEqual(report['stoppedContainerExports'],1)

    def test_task_parser_retains_only_requested_terminal_pids_and_rejects_duplicates(self):
        cid=reader.ROLE_IDS['adapter']
        value=reader.task_rows(('TASK PID STATUS\nother 1 RUNNING\n'+cid+' 2147483647 STOPPED\n').encode())
        self.assertEqual(set(value),set(reader.ROLE_IDS.values()))
        self.assertEqual(value[cid]['status'],'STOPPED')
        self.assertFalse(value[cid]['taskPidPresent'])
        self.assertFalse(value[reader.ROLE_IDS['southbound']]['taskPresent'])
        with self.assertRaisesRegex(ValueError,'DUPLICATE_TASK'):
            reader.task_rows(('TASK PID STATUS\n'+cid+' 0 STOPPED\n'+cid+' 0 STOPPED\n').encode())

    def test_complete_reader_with_real_sealed_loader_and_synthetic_native_reads(self):
        """Exercise private JSON shape/custody and every phase; no Docker target."""
        base=self.root/'full-read';base.mkdir(mode=0o700)
        original=base/'original';original.mkdir(mode=0o700)
        context=base/'context';context.mkdir(mode=0o700)
        output=base/'output';output.mkdir(mode=0o700)
        offline=base/'offline';offline.mkdir(mode=0o700)
        package=base/'semantic-provider-v2-transaction-source-audited-ci';package.mkdir(mode=0o700)
        recovery.install_package(package,self.built['files'])
        def private(path,value,raw=False):
            path.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
            path.write_bytes(value if raw else reader.encoded(value));path.chmod(0o600)
            return {'path':str(path),'sha256':reader.sha(path.read_bytes())}
        entry_raw=(ROOT/'tools/semantic_transaction_profiles/provider_transaction_intake.py').read_bytes()
        private(original/'provider_transaction_intake.py',entry_raw,True)
        wrapper=base/'wrapper';private(wrapper,b'CI_ONLY_NO_EXECUTION',True);wrapper.chmod(0o700)
        private(output/'runtime-switch-receipt.json',{'installedWrapperHash':reader.sha(wrapper.read_bytes())})
        lock=base/'lock';private(lock,b'',True)
        owner=private(base/'guard/coordinated-configuration.json',{'commonLockFile':str(lock)})
        pointer=private(base/'guard-pointer.json',{'receiptFile':str(base/'guard/receipt.json'),'receiptHash':'0'*64})
        from authenticate_provider_transaction import TARGETS
        limits={'maxEntries':100,'maxBytes':10000,'maxDepth':8}
        seals={};image_seals={};actual_roots={};records={};denial={'doNotRerunApply':True,
            'evidenceDirectory':str(output),'candidateObservations':{},'retainedPhaseDiagnostics':{}}
        runtime_root='/run/ci-reader-only'
        for role,cid in reader.ROLE_IDS.items():
            low=offline/role/'bundle/rootfs';low.mkdir(mode=0o755,parents=True);low.chmod(0o755)
            (low/'program').write_bytes(b'CI_IMAGE')
            seal,left=reader.entries(self.sealer,low,limits);seals[role]=seal['sha256']
            image_seals[role]=reader.image_digest(reader.image_view(left,True))
            private(offline/role/'expected-docker-rootfs.json',{'rootfsLimits':limits,'rootfsSeal':seal,
                'manifestDigest':TARGETS[role]['imageManifestDigest'],'configDigest':TARGETS[role]['imageConfigDigest']})
            current=base/(role+'-current');current.mkdir(mode=0o755);current.chmod(0o755)
            (current/'program').write_bytes(b'CI_IMAGE');(current/'runtime-created').mkdir()
            actual_roots[str(Path('/var/lib/docker/rootfs/overlayfs')/cid)]=current
            oci={'root':{'path':str(Path('/var/lib/docker/rootfs/overlayfs')/cid)},
                'mounts':[{'destination':'/runtime-created'}],'process':{'cwd':'/'}}
            records[role]={'framePolicy':private(base/(role+'-policy.json'),{'expectedOci':oci}),
                'preparerTemplate':private(base/(role+'-template.json'),{'candidate':{'runtimeBinding':{'path':'/usr/bin/runc','sha256':'0'*64}}})}
            root=output/'registry'/cid
            journal=private(root/'adapter.json',{'runtimeRoot':runtime_root,'state':'DELETING'})
            private(root/'broker-state.json',{'state':'PREPARING'});private(root/'deployment.json',{'state':'CREATED'})
            private(root/'bundle/config.json',oci)
            auth=private(root/'live-authorization.json',{'rootfsSeal':TARGETS[role]['runtimeSeal']})
            private(root/'attestation-producer.json',{'liveAcceptanceAuthorizationPath':auth['path']})
            denial['candidateObservations'][cid]={'adapterJournalHash':journal['sha256'],'stateHash':role+'-state'}
        denied=private(context/'operator-denial.json',denial)
        cfg={'outputRoot':str(output),'recordsByRole':records,'guardPointerBinding':pointer,
            'commandBindings':{'docker':{'path':'/usr/bin/docker','sha256':'0'*64}}}
        configuration=private(context/'execution-configuration.json',cfg)
        private(context/'human-approval-binding.json',{'approvalRef':'OUF_PROVIDER_AUDITED_RECOVERY_APPROVED_20261009T191942_CEST_R7',
            'sourceClosureHash':reader.CLOSURE,'configurationHash':configuration['sha256'],'sourcePackage':str(package)})
        guard={'candidateStateHashes':{cid:v['stateHash'] for cid,v in denial['candidateObservations'].items()},'providerSetsEmpty':True}
        def exec_sources(code,space):
            builtins.exec(code,space)
            if space['__name__']=='r7_read_only_entry':
                real=space['read']
                space['read']=lambda path,executable=False:real(wrapper if str(path)=='/usr/local/sbin/ouf-semantic-admitted-v2' else path,executable)
            if space['__name__']=='r7_sealed_sources':
                real=space['load']
                def load(package):
                    result=real(package);module=sys.modules['transaction_guard_observation']
                    module.executable_binding=lambda binding:binding
                    module.observe_locked=lambda *args:copy.deepcopy(guard)
                    return result
                space['load']=load
        calls=[]
        def run(argv,**kwargs):
            calls.append(argv)
            if argv[0]=='/usr/bin/docker':
                self.assertIn('inspect',argv);cid=argv[-1]
                target=next(v for v in TARGETS.values() if v['containerId']==cid)
                raw=reader.encoded({'id':cid,'image':target['imageManifestDigest'],'runtime':'ouf-semantic-admitted-v2',
                    'state':{'Status':'created','Running':False,'Pid':0,'StartedAt':'0001-01-01T00:00:00Z'}})
            elif argv[0]=='/usr/bin/ctr':
                if argv[-2:]==['tasks','list']:raw=b'TASK PID STATUS\n'
                else:
                    self.assertEqual(argv[-3:-1],['containers','info'])
                    raw=reader.encoded({'ID':argv[-1],'Runtime':{'Name':'io.containerd.runc.v2'}})
            else:
                self.assertEqual(argv,['/usr/bin/runc','--root',runtime_root,'list','--format','json']);raw=b'null'
            kwargs['stdout'].write(raw);kwargs['stdout'].flush()
            return types.SimpleNamespace(returncode=0)
        original_entries=reader.entries
        def mapped_entries(sealer,path,limits):return original_entries(sealer,actual_roots.get(str(path),path),limits)
        with contextlib.ExitStack() as stack:
            changes={'BASE':base,'ORIGINAL':original,'CONTEXT':context,'OUTPUT':output,'OFFLINE':offline,
                'ORIGINAL_ENTRY':reader.sha(entry_raw),'OPERATOR_DENIAL':denied['sha256'],
                'OWNER':owner['sha256'],'OFFLINE_SEALS':seals,'IMAGE_SEALS':image_seals,
                'RUNTIME_ROOT_HASH':reader.sha(runtime_root.encode()),'PHASE':'CI_READ','DIAGNOSTIC':None,
                'sys':types.SimpleNamespace(flags=types.SimpleNamespace(isolated=1),dont_write_bytecode=True,argv=['reader.py'])}
            for name,value in changes.items():stack.enter_context(patch.object(reader,name,value))
            stack.enter_context(patch.dict(reader.__dict__,{'exec':exec_sources}))
            stack.enter_context(patch.object(reader.subprocess,'run',side_effect=run))
            spawn=stack.enter_context(patch.object(reader.subprocess,'Popen'))
            stack.enter_context(patch.object(reader,'process_metadata',return_value={cid:[] for cid in reader.ROLE_IDS.values()}))
            stack.enter_context(patch.object(reader,'current_mount',return_value=[{'mountId':1,'filesystem':'overlay'}]))
            stack.enter_context(patch.object(reader,'entries',side_effect=mapped_entries))
            stdout=io.StringIO()
            with contextlib.redirect_stdout(stdout):exit_code=reader.main()
            self.assertEqual(exit_code,0,stdout.getvalue())
            spawn.assert_not_called()
            record=json.loads(stdout.getvalue().split('OUF_R7_ROOTFS_READ_ONLY=',1)[1])
            self.assertFalse(record['startAuthorized'])
            self.assertFalse(record['cleanupAuthorized'])
            self.assertEqual(record['containerLifecycleOperations'],0)
            self.assertTrue(record['retainedEvidencePreserved'])
            self.assertEqual(set(record['roles']),{'adapter','southbound'})
            self.assertTrue(all(v['imageDifferences']['unexpectedDeclaredMountOrCwdEntries']==1 for v in record['roles'].values()))
            self.assertTrue((Path(record['evidenceDirectory'])/'diagnosis.json').is_file())


if __name__=='__main__':unittest.main()
