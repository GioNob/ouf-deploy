"""Read-only boundaries and retained one-use outcome checks; no target authority."""
import ast,copy,importlib.util,json,subprocess,unittest
from pathlib import Path
from unittest.mock import patch
spec=importlib.util.spec_from_file_location('reader',Path(__file__).with_name('read_post_terminal_admission_preflight.py'))
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class Tests(unittest.TestCase):
    def fixture(self):
        success={'schema':'ouf.semantic-terminal-alias-recovery.v1',
            'status':'TWO_TERMINAL_TASKS_REMOVED_ALIAS_RECOVERY_CONTAINERS_PRESERVED',
            'taskDeleteRequests':2,'wrapperRestored':True,'priorJournalsPreserved':True,
            'doNotRerunApply':True,'evidenceDirectory':str(m.MAINTENANCE),
            'dockerStartRequests':0,'providerCalls':0,'privateKeysRead':0,'signaturesIssued':0,
            'automaticRetryPerformed':False,'startAuthorized':False,
            'postMaintenanceEmptyGuard':{'providerSetsEmpty':True,'lockInodePreserved':True,
                'candidateStateHashes':dict(m.STATES),'configurationHash':m.OWNER_SHA}}
        claim={'schema':'ouf.semantic-terminal-alias-recovery-claim.v1','approvalRef':m.APPROVAL,
            'approvedAt':1791554865,'evidenceDirectory':str(m.MAINTENANCE),
            'retainedWrapperHash':m.WRAPPER_SHA,'tasks':{m.S:{'pid':1687816},m.A:{'pid':1722506}}}
        return success,claim
    def test_success_does_not_convert_to_start_authority(self):
        result,claim=self.fixture();before=copy.deepcopy((result,claim));m.validate_success(result,claim)
        self.assertEqual((result,claim),before)
        for field,bad in [('wrapperRestored',False),('priorJournalsPreserved',False),('taskDeleteRequests',1),('startAuthorized',True)]:
            changed=copy.deepcopy(result);changed[field]=bad
            with self.assertRaises(m.Denied):m.validate_success(changed,claim)
    def test_claim_or_guard_generation_drift_denied(self):
        result,claim=self.fixture()
        for field,bad in [('approvalRef','old'),('approvedAt',1791554864),('evidenceDirectory','/elsewhere'),('retainedWrapperHash','0'*64)]:
            changed=copy.deepcopy(claim);changed[field]=bad
            with self.assertRaises(m.Denied):m.validate_success(result,changed)
        result['postMaintenanceEmptyGuard']['candidateStateHashes'][m.A]='0'*64
        with self.assertRaises(m.Denied):m.validate_success(result,claim)
    def test_frozen_paths_exclude_keys_and_traversal(self):
        for p in (m.ROOT/'source/scripts/runtime.py',m.FAILED/'window.json',m.CONTEXT/'terminal-task-cleanup-claim.json'):
            self.assertTrue(m.allowed_frozen_path(str(p)))
        for p in ('/etc/ouf/keys/private.pem',str(m.ROOT/'../elsewhere'),str(m.CONTEXT/'execution-claim.json'),str(m.MAINTENANCE/'gate.py'),'relative'):
            self.assertFalse(m.allowed_frozen_path(p))
    def test_task_reappearance_and_bad_inventory_denied(self):
        m.absent_tasks(b'TASK PID STATUS\nunrelated 1 RUNNING\n')
        for raw in (b'',b'wrong header\n',f'TASK PID STATUS\n{m.S} 5 STOPPED\n'.encode(),b'TASK PID STATUS\nunrelated invalid STOPPED\n'):
            with self.assertRaises(m.Denied):m.absent_tasks(raw)
    def publication_fixture(self):
        manifest=json.loads((Path(__file__).resolve().parent.parent/'semantic_transaction_profiles/intake-source-closure.json').read_text())
        expected={p.removeprefix('source/'):h for p,h in manifest['sourceHashes'].items() if p.startswith('source/') or p=='frame-observer.py'}
        expected['scripts/semantic_provider_deployment_broker.py']='3069c3dbbb959d8e8d423f5fc0c22db65aa4a50e2ba1874ad26ccd3a928af0cf'
        expected['scripts/semantic_provider_docker_runtime.py']='7894d0e942642d1daa5ae2e29c85cd7f0584b7cd285c539cab3ae624bab0bba9'
        files={str(m.ROOT/'source'/name):h for name,h in expected.items()}
        files.update({str(m.ROOT/'fixture-records'/str(i)):'0'*64 for i in range(81-len(files))})
        encode=lambda v:json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
        return {'fileHashes':files},dict(files),set(expected),encode,manifest
    def test_actual_sealed_manifest_30_published_sources_not_39_intake_files(self):
        receipt,frozen,names,encode,manifest=self.publication_fixture()
        self.assertEqual(len(manifest['sourceHashes']),39);self.assertEqual(len(names),30)
        observed=m.published_closure(receipt,frozen,names,encode)
        self.assertEqual(observed['sourceClosureHash'],m.CLOSURE_SHA)
        self.assertEqual(observed['publishedSourceCount'],30)
    def test_source_hash_or_name_drift_denied(self):
        receipt,frozen,names,encode,_=self.publication_fixture()
        for change in ('hash','missing','extra'):
            changed=copy.deepcopy(receipt)
            path=str(m.ROOT/'source/frame-observer.py')
            if change=='hash':changed['fileHashes'][path]='0'*64
            if change=='missing':changed['fileHashes'].pop(path)
            if change=='extra':changed['fileHashes'][str(m.ROOT/'source/utility/unreviewed.py')]='0'*64
            with self.assertRaises(m.Denied):m.published_closure(changed,frozen,names,encode)
    def test_source_frozen_digest_mismatch_denied(self):
        receipt,frozen,names,encode,_=self.publication_fixture()
        frozen[str(m.ROOT/'source/frame-observer.py')]='0'*64
        with self.assertRaisesRegex(m.Denied,'PUBLISHED_SOURCE_NOT_FROZEN'):m.published_closure(receipt,frozen,names,encode)
    def test_publication_escape_denied(self):
        receipt,frozen,names,encode,_=self.publication_fixture()
        receipt['fileHashes']['/etc/ouf/keys/private.pem']='0'*64
        with self.assertRaisesRegex(m.Denied,'PUBLICATION_PATH_OR_HASH_DRIFT'):m.published_closure(receipt,frozen,names,encode)
    def test_native_reader_checks_custody_and_never_delegates_stderr(self):
        binding={'path':'/pinned/ctr','sha256':'a'*64};args=['--address','/run/containerd/containerd.sock','--namespace','moby','tasks','list']
        with patch.object(m.subprocess,'run',return_value=subprocess.CompletedProcess([],0,b'TASK PID STATUS\n',b'private')) as run:
            self.assertEqual(m.run_read(binding,args,lambda _:('same',)),b'TASK PID STATUS\n')
            self.assertEqual(run.call_args.args[0],[binding['path'],*args])
            self.assertEqual(run.call_args.kwargs['stderr'],subprocess.DEVNULL)
        with patch.object(m.subprocess,'run',return_value=subprocess.CompletedProcess([],0,b'',b'')):
            identities=iter([('old',),('changed',)])
            with self.assertRaisesRegex(m.Denied,'NATIVE_READ_EXECUTABLE_DRIFT'):m.run_read(binding,args,lambda _:next(identities))
    def test_static_no_mutation_or_lifecycle_dispatch(self):
        source=Path(m.__file__).read_text();tree=ast.parse(source)
        forbidden={'execute_transaction','issue_role_authority','operate','publish','publish_once','replace','unlink','chmod','mkdir','makedirs','write','fchmod','fsync'}
        for n in ast.walk(tree):
            if isinstance(n,ast.Call):
                name=n.func.id if isinstance(n.func,ast.Name) else n.func.attr if isinstance(n.func,ast.Attribute) else ''
                self.assertNotIn(name,forbidden)
            if isinstance(n,ast.Attribute):self.assertNotIn(n.attr,{'O_WRONLY','O_CREAT','O_TRUNC'})
        self.assertNotIn("['tasks','delete'",source);self.assertNotIn("['start'",source)
if __name__=='__main__':unittest.main()
