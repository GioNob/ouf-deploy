"""Coherent sealed package and failure boundaries; no target execution."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parent
PROFILES=HERE.parent/'semantic_transaction_profiles'
sys.path.insert(0,str(PROFILES))
from build_audited_source_package import build,REPLACEMENTS,encoded,sha
import execute_audited_provider_recovery as recovery


def package_inputs():
    fixture=PROFILES/'fixtures/original-intake-v1'
    manifest=(fixture/'intake-source-closure.json').read_bytes()
    files={}
    for name in json.loads(manifest)['sourceHashes']:
        if name.startswith('source/'):
            path=PROFILES.parent/'semantic_cohort_admission/cohort-draft'/name.removeprefix('source/')
        elif name in REPLACEMENTS:path=fixture/(Path(name).name+'.txt')
        elif name=='frame-observer.py' or name=='utility/compile_creation_frame_policy.py':
            path=PROFILES.parent/'semantic_frame_compiler'/Path(name).name
        else:path=PROFILES/Path(name).name
        files[name]=path.read_bytes()
    return manifest,files,{n:(PROFILES/Path(n).name).read_bytes() for n in REPLACEMENTS},(PROFILES/'provider_transaction_intake.py').read_bytes()


class AuditedRecoveryTest(unittest.TestCase):
    def setUp(self):
        self.assertEqual(os.geteuid(),0)
        self.temp=tempfile.TemporaryDirectory(dir=os.environ.get('OUF_TRANSACTION_TEST_ROOT',Path.cwd()))
        self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name);self.root.chmod(0o700)
        self.scope=json.loads((PROFILES.parents[1]/'evidence/provider-audited-recovery-scope-20261009.json').read_bytes())

    def test_actual_original_package_builds_and_loads_as_one_isolated_sealed_package(self):
        values=package_inputs();before=copy.deepcopy(values)
        built=build(*values)
        for k in ('entryHash','manifestHash','sourceClosureHash','changedRuntimeFiles','changedUtilities'):
            self.assertEqual(built[k],self.scope['package'][k])
        self.assertEqual(values,before)
        package=self.root/'source-package';package.mkdir(mode=0o700)
        recovery.install_package(package,built['files'])
        code="""import json,sys,pathlib
p=pathlib.Path(sys.argv[1]);entry={'__name__':'sealed_test','__file__':str(p/'provider_transaction_intake.py')}
exec(compile((p/'provider_transaction_intake.py').read_bytes(),entry['__file__'],'exec'),entry)
sources,observer=entry['load'](p)
import guarded_runtime_switch,publish_provider_transaction,authenticated_runtime_switch
print(json.dumps({'sourceCount':len(sources),'observerHash':entry['digest'](observer),
    'sourceClosureHash':entry['digest'](entry['encoded']({**{k:entry['digest'](v) for k,v in sources.items()},'frame-observer.py':entry['digest'](observer)})),
    'publisherModule':publish_provider_transaction.__file__,'signaturesCreated':(p/'issued-signatures').exists()}))
"""
        result=subprocess.run([sys.executable,'-I','-B','-c',code,str(package)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10)
        self.assertEqual(result.returncode,0,result.stderr.decode())
        value=json.loads(result.stdout)
        self.assertEqual(value['sourceCount'],29)
        self.assertEqual(value['sourceClosureHash'],built['sourceClosureHash'])
        self.assertEqual(value['publisherModule'],str(package/'utility/publish_provider_transaction.py'))
        self.assertFalse(value['signaturesCreated'])

    def test_tampered_old_or_replacement_bytes_fail_before_any_publication(self):
        manifest,original,replacements,entry=package_inputs()
        altered=dict(original);altered['frame-observer.py']+=b'\n'
        with self.assertRaisesRegex(ValueError,'ORIGINAL_INTAKE_SOURCE_DRIFT'):build(manifest,altered,replacements,entry)
        altered=dict(replacements);altered['utility/publish_provider_transaction.py']+=b'\n'
        with self.assertRaisesRegex(ValueError,'EXACT_REVIEWED_PUBLICATION_UTILITIES_REQUIRED'):build(manifest,original,altered,entry)
        self.assertEqual(list(self.root.iterdir()),[])

    def test_inert_cli_cannot_run_with_old_or_invented_approval(self):
        result=subprocess.run([sys.executable,'-I','-B',str(HERE/'execute_audited_provider_recovery.py'),
            'old-approval',str(self.root)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=5)
        self.assertEqual(result.returncode,1)
        report=json.loads(result.stdout.decode().split('=',1)[1])
        self.assertEqual(report['reason'],'EXPLICIT_AUDITED_RECOVERY_APPROVAL_REQUIRED')
        self.assertEqual(report['privateKeysRead'],0)
        self.assertEqual(report['containerLifecycleOperations'],0)
        self.assertEqual(list(self.root.iterdir()),[])

    def test_cleanup_receipt_is_exact_and_consumed_claim_is_not_start_authority(self):
        record=json.loads((PROFILES.parents[1]/'evidence/provider-r6-terminal-cleanup-target-success-20261009.json').read_text())['receipt']
        window={'approvalRef':'OUF_R6_TERMINAL_CLEANUP_APPROVED_20261009T174356_CEST',
                'tasks':{cid:{'pid':pid} for cid,pid in recovery.TASK_PIDS.items()}}
        claim={'schema':'ouf.semantic-r6-terminal-cleanup-claim.v1',**window,'approvedAt':1791560636,
               'evidenceDirectory':str(recovery.MAINTENANCE),'retainedWrapperHash':recovery.WRAPPER_SHA,
               'windowHash':sha(encoded(window))}
        recovery.validate_cleanup(record,claim,window)
        altered=copy.deepcopy(record);altered['wrapperRestored']=False
        with self.assertRaisesRegex(recovery.Denied,'EXACT_SUCCESSFUL_R6_CLEANUP_REQUIRED'):
            recovery.validate_cleanup(altered,claim,window)
        with self.assertRaisesRegex(recovery.Denied,'EXPLICIT_AUDITED_RECOVERY_APPROVAL_REQUIRED'):
            recovery.build_mandates(self.scope,{},1791562000,claim['approvalRef'])

    def test_current_task_presence_and_malformed_inventory_are_refused(self):
        recovery.absent_tasks(b'TASK PID STATUS\n')
        recovery.absent_tasks(b'TASK PID STATUS\nother 99 RUNNING\n')
        with self.assertRaisesRegex(recovery.Denied,'RESIDUAL_TASK_REQUIRES_SEPARATE_RECOVERY'):
            recovery.absent_tasks(('TASK PID STATUS\n'+recovery.A+' 99 STOPPED\n').encode())
        with self.assertRaisesRegex(recovery.Denied,'EXACT_TASK_INVENTORY_ROW_REQUIRED'):
            recovery.absent_tasks(b'TASK PID STATUS\ninvalid\n')

    def test_complete_reviewed_delta_hashes_and_no_path_escape(self):
        for name,wanted in recovery.DELTA_FILES.items():
            path=PROFILES.parents[1]/'evidence/provider-audited-recovery-scope-20261009.json' if name=='scope.json' else PROFILES/name
            raw=path.read_bytes();self.assertEqual(sha(raw),wanted);(self.root/name).write_bytes(raw)
        self.assertEqual(len(recovery.download_bytes(self.root)),8)
        (self.root/'scope.json').write_bytes(b'{}')
        with self.assertRaisesRegex(recovery.Denied,'REVIEWED_DOWNLOAD_HASH_DRIFT'):recovery.download_bytes(self.root)
        self.assertFalse(recovery.confined(str(recovery.OUTPUT/'../foreign'),recovery.OUTPUT))
        self.assertFalse(recovery.confined(str(recovery.OUTPUT),recovery.OUTPUT))

    def test_diagnostics_project_only_bounded_symbolic_reasons_and_keep_both_roles(self):
        for cid in (recovery.A,recovery.S):
            directory=self.root/'registry'/cid;directory.mkdir(parents=True)
            (directory/'attestation-producer-denial-attestation.json').write_text(json.dumps({
                'reason':'NODE_APPROVED_ROOTFS_DRIFT','exceptionPoints':[]}))
        report=recovery.collected_diagnostics(self.root)
        self.assertEqual(len(report),2)
        path=self.root/'registry'/recovery.A/'attestation-producer-denial-attestation.json'
        path.write_text(json.dumps({'reason':'private-secret','exceptionPoints':[]}))
        report=recovery.collected_diagnostics(self.root)
        self.assertNotIn('private-secret',json.dumps(report))
        self.assertEqual(report['adapter/attestation-producer-denial-attestation.json']['status'],'DIAGNOSIS_UNREADABLE')

    def test_main_prekey_pipeline_loads_coherent_package_and_hands_off_once(self):
        # Control-flow integration only. The separate native job consumes actual
        # issued records and starts disposable Docker through the production broker.
        from contextlib import ExitStack
        from test_authenticated_transaction import AuthenticatedTransactionTest
        fixture=AuthenticatedTransactionTest();fixture.setUp();self.addCleanup(fixture.doCleanups)
        manifest,original,replacements,reviewed_entry=package_inputs()
        retained=self.root/'retained-source';retained.mkdir(mode=0o700)
        original_entry=reviewed_entry.replace(b'9ecd16cd04d86c68947b127e845cde7f5fc4170eaf02a9043989f3bf4409bf67',
                                            recovery.MANIFEST_SHA.encode())
        recovery.install_package(retained,{**original,'intake-source-closure.json':manifest,
                                           'provider_transaction_intake.py':original_entry})
        context=self.root/'old-context';context.mkdir(mode=0o700)
        output=self.root/'old-output';maintenance=self.root/'cleanup'
        scope=copy.deepcopy(self.scope)
        scope.update(priorContext=str(context),priorOutput=str(output),successfulCleanup=str(maintenance))
        records={role:{name:raw for name,raw in values.items() if name in {
            'template','launch','context','framePolicy','preparerTemplate','deploymentConstraints','provenanceEvidence','dependencyEvidence'}}
            for role,values in fixture.records.items()}
        bindings={}
        for role,values in records.items():
            bindings[role]={};scope['roles'][role]['inputHashes']={name:sha(raw) for name,raw in values.items()}
            for name,raw in values.items():
                path=context/(role+'-'+name+'.json');recovery.publish(path,raw)
                bindings[role][name]={'path':str(path),'sha256':sha(raw)}
        download=self.root/'download';download.mkdir(mode=0o700);pins={}
        for name in recovery.DELTA_FILES:
            raw=encoded(scope) if name=='scope.json' else (PROFILES/name).read_bytes()
            (download/name).write_bytes(raw);pins[name]=sha(raw)
        frozen={str(context/(role+'-context.json')):sha(values['context']) for role,values in records.items()}
        calls=[];actual_definitions=recovery.definitions
        def definitions(name,raw,path):
            value=actual_definitions(name,raw,path)
            if name=='audited_current_entry':
                def handoff(package,configuration,expected_hash,sources,observer):
                    cfg=json.loads(configuration.read_bytes())
                    self.assertEqual(sha(configuration.read_bytes()),expected_hash)
                    self.assertEqual(cfg['recordsByRole'],bindings)
                    self.assertEqual(sha(encoded({**{n:sha(v) for n,v in sources.items()},'frame-observer.py':sha(observer)})),scope['package']['sourceClosureHash'])
                    self.assertNotEqual(package,context)
                    self.assertFalse((package/'execution-claim.json').exists())
                    self.assertEqual(set(cfg['mandatesByRole']),{'adapter','southbound'})
                    for role,binding in cfg['mandatesByRole'].items():
                        mandate=json.loads(Path(binding['path']).read_bytes())
                        self.assertEqual(mandate['inputHashes'],scope['roles'][role]['inputHashes'])
                        self.assertEqual(mandate['sourceClosureHash'],scope['package']['sourceClosureHash'])
                    calls.append(cfg)
                    return {'status':'CI_HANDOFF_ONLY','notReleaseAcceptance':True}
                value['execute_transaction']=handoff
            return value
        now=int(__import__('time').time())
        with ExitStack() as stack:
            for name,value in {'BASE':self.root,'PACKAGE':retained,'CONTEXT':context,'OUTPUT':output,
                'MAINTENANCE':maintenance,'CLAIM_PATH':self.root/'recovery-claim.json',
                'ENTRY_SHA':sha(original_entry),'DELTA_FILES':pins,'APPROVAL_REF':'DISPOSABLE_CI_ONLY',
                'APPROVED_AT':now-1,'APPROVAL_EXPIRES_AT':now+300,'NEW_CONTEXT':None,'NEW_OUTPUT':None}.items():
                stack.enter_context(patch.object(recovery,name,value))
            stack.enter_context(patch.object(recovery.sys,'flags',types.SimpleNamespace(**{**{k:getattr(sys.flags,k) for k in dir(sys.flags) if not k.startswith('_')},'isolated':1})))
            stack.enter_context(patch.object(recovery.sys,'dont_write_bytecode',True))
            stack.enter_context(patch.object(recovery,'retain',return_value=({'recordsByRole':bindings,'outputRoot':str(output)},frozen)))
            stack.enter_context(patch.object(recovery,'native_preflight',return_value={'CI_ONLY':True}))
            stack.enter_context(patch.object(recovery,'definitions',side_effect=definitions))
            result=recovery.main('DISPOSABLE_CI_ONLY',str(download))
            self.assertEqual(result['status'],'CI_HANDOFF_ONLY');self.assertEqual(len(calls),1)
            recovery.ensure_preserved({'read':lambda p:Path(p).read_bytes()},frozen)
            with self.assertRaisesRegex(recovery.Denied,'DO_NOT_REPLAY_AUDITED_PROVIDER_RECOVERY'):
                recovery.main('DISPOSABLE_CI_ONLY',str(download))


if __name__=='__main__':unittest.main()
