"""New selection uses the real postboot producer; unchanged SQL/native tests reused."""
import ast
import copy
import hashlib
import importlib.util
import os
import subprocess
from pathlib import Path
import unittest
from unittest.mock import patch
import test_ingestion_db_preflight as legacy

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('db_postboot',ROOT/'scripts/read-ingestion-db-postboot-preflight-20261020.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
legacy.m=m
ReadContract=legacy.ReadContract

if 'OUF_TEST_ROOT' in os.environ:
    import test_ingestion_db_preflight_native as native
    native.m=m
    NativeDatabase=native.NativeDatabase


class PostbootSelection(legacy.RetainedSelection):
    def setUp(self):
        super().setUp()
        self.original['databasePlan']['postgresRuntimeBinding'].update(imageId='b'*64,pid=1)
        self.original['cohortPlan']['databasePlanHash']=m.digest(self.original['databasePlan'])
        before={n:{'Id':n,'Image':'image','Config':{'Labels':{'org.opencontainers.image.revision':'source'}},
                   'State':{'Running':True,'Paused':False,'Restarting':False},'HostConfig':{}}
                for n in ('onboarding','mcp','udp')}
        historical={'schema':'ouf.source-revision-private-inputs.v1','runtimeAuthorityIssued':False,
            'readyForExecution':False,'packageRootCustodyProven':True,'engine':copy.deepcopy(self.engine),
            'beforeApplications':before,'selection':{'currentApplications':{n:{'imageId':'image','sourceCommit':'source'}for n in before}},
            'databasePlan':copy.deepcopy(self.original['databasePlan']),'unchangedApplications':{},
            'retainedReplacements':{n:{'request':{'HostConfig':{}}}for n in ('onboarding','mcp')},
            'candidates':{},'gatewayPackage':{},'gateway':{}}
        spec=importlib.util.spec_from_file_location('actual_postboot_policy',ROOT/'scripts/source-revision-postboot-policy.py')
        policy=importlib.util.module_from_spec(spec);spec.loader.exec_module(policy)
        pg={'Id':'a'*64,'Image':'b'*64,'State':{'Running':True}}
        projected,self.current,proof=policy.project(self.original,historical,{**before,'a'*64:pg},self.engine,{},
            lambda _:dict(self.original['databasePlan']['postgresRuntimeBinding'],pid=2),lambda _:None,lambda *_:{})
        self.original.clear();self.original.update(projected)
        self.case['originalBinding']['sha256']=m.digest(self.original)
        original_binding={'path':str(m.POSTBOOT/'current-original-preparation.json'),'sha256':m.digest(self.original)}
        self.current['postbootReconciliation']={**proof,'currentOriginalPreparationBinding':original_binding}
        self.result={'schema':'ouf.source-revision-postboot-preparation-result.v1','contextPath':str(m.POSTBOOT_RESULT.parent),
            'runtimeAuthorityIssued':False,'readyForExecution':False,'hostCompletionReadbackProven':True,
            'postbootSuccessorPrepared':True,'nativePlanCompilationProven':True,'effectiveFlywayConfigurationProven':True,
            'currentOriginalPreparationBinding':original_binding,
            'preparedInputsBinding':{'path':str(m.POSTBOOT/'postboot-private-inputs.json'),'sha256':m.digest(self.current)}}
        self.values[str(m.POSTBOOT_RESULT)]=self.result
        self.values[str(m.POSTBOOT/'postboot-private-inputs.json')]=self.current
        self.package['fileHashes']['case.json']=m.digest(self.case)
        self.package['executionPins']['caseSha256']=m.digest(self.case)
        self.values[str(m.CONTEXT/'runtime.claim.json')]['packageHash']=m.digest(self.package)
        patches=patch.multiple(m,POSTBOOT_ORIGINAL_HASH=m.digest(self.original),
            POSTBOOT_INPUTS_HASH=m.digest(self.current),POSTBOOT_RESULT_HASH=m.digest(self.result))
        patches.start();self.addCleanup(patches.stop)

    def test_actual_postboot_pair_accepts_only_sealed_successor_despite_historical_hash(self):
        self.assertNotEqual(m.digest(self.original['databasePlan']),self.original['cohortPlan']['databasePlanHash'])
        chosen=m.selection(self.parse)
        self.assertEqual(chosen['postgres']['pid'],2)
        self.assertEqual(chosen['user'],'ingestion_role')
        self.assertIn(str(m.POSTBOOT_RESULT),self.reads)
        self.assertIn(str(m.POSTBOOT/'postboot-private-inputs.json'),self.reads)

    def test_recomputing_historical_cohort_hash_cannot_bypass_whole_document_pin(self):
        self.original['cohortPlan']['databasePlanHash']=m.digest(self.original['databasePlan'])
        with self.assertRaisesRegex(m.Denied,'EXACT_WHOLE_POSTBOOT_ORIGINAL_REQUIRED'):
            m.selection(self.parse)

    def test_private_pair_hash_drift_is_denied(self):
        self.current['databasePlan']['modules'][2]['database']='foreign_db'
        with self.assertRaisesRegex(m.Denied,'EXACT_SEALED_POSTBOOT_PRIVATE_INPUTS_REQUIRED'):
            m.selection(self.parse)

    def test_independently_pinned_but_inconsistent_pair_is_denied(self):
        self.current['databasePlan']['modules'][2]['database']='foreign_db'
        self.result['preparedInputsBinding']['sha256']=m.digest(self.current)
        with patch.multiple(m,POSTBOOT_INPUTS_HASH=m.digest(self.current),POSTBOOT_RESULT_HASH=m.digest(self.result)):
            with self.assertRaisesRegex(m.Denied,'EXACT_POSTBOOT_DATABASE_PAIR_REQUIRED'):
                m.selection(self.parse)

    def test_historical_authority_is_not_reused_as_read_permission(self):
        self.current['postbootReconciliation']['historicalAuthorityReused']=True
        self.result['preparedInputsBinding']['sha256']=m.digest(self.current)
        with patch.multiple(m,POSTBOOT_INPUTS_HASH=m.digest(self.current),POSTBOOT_RESULT_HASH=m.digest(self.result)):
            with self.assertRaisesRegex(m.Denied,'EXACT_RETAINED_POSTBOOT_PROVENANCE_REQUIRED'):
                m.selection(self.parse)

    def test_completed_preparation_receipt_drift_is_denied(self):
        self.result['readyForExecution']=True
        with self.assertRaisesRegex(m.Denied,'EXACT_COMPLETED_POSTBOOT_PREPARATION_REQUIRED'):
            m.selection(self.parse)


class PreservedReadContract(unittest.TestCase):
    def test_delivery_checks_exact_blob_and_hash_before_sudo(self):
        path=ROOT/'scripts/launch-ingestion-db-postboot-preflight-20261020.sh'
        delivery=path.read_text()
        raw=(ROOT/'scripts/read-ingestion-db-postboot-preflight-20261020.py').read_bytes()
        blob=hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()
        self.assertIn('git/blobs/'+blob,delivery)
        self.assertIn(hashlib.sha256(raw).hexdigest(),delivery)
        self.assertLess(delivery.index('sha256sum -c -'),delivery.index('sudo /usr/bin/python3'))
        self.assertLess(delivery.index('ouf-gh-2.102.0.PNoFbF'),delivery.index('command -v gh'))
        self.assertIn('-I -B -S',delivery)
        self.assertIn('os.O_NOFOLLOW',delivery)
        subprocess.run(['bash','-n',str(path)],check=True)

    def test_log_and_stop_exit_code_are_preserved(self):
        delivery=(ROOT/'scripts/launch-ingestion-db-postboot-preflight-20261020.sh').read_text()
        body=delivery[delivery.index('ouf_report_log()'):delivery.index('"$ouf_gh" api')]
        result=subprocess.run(['bash','-c','ouf_read=/fixture/retained\n'+body+'\nexit 7'],capture_output=True)
        self.assertEqual(result.returncode,7)
        self.assertIn(b'/fixture/retained/read.log',result.stdout)
        self.assertNotIn('rm -',delivery)

    def test_production_postboot_hashes_are_exact_release_pins(self):
        self.assertEqual(m.POSTBOOT_ORIGINAL_HASH,'b3988d964a3c60b06b17952863f4fc62fc9a8f1626ced82bfb864721eb7b740a')
        self.assertEqual(m.POSTBOOT_INPUTS_HASH,'1ab309f747d2e0c70b3a284258ea0f2100d51bc149ef9c2ae2b55b73f3871c62')
        self.assertEqual(m.POSTBOOT_RESULT_HASH,'3eb2fd4fff1048accdb954322faa58979bb490250c8535c1dd8512253e603587')

    def test_sql_and_native_effect_adapter_are_unchanged(self):
        old=ast.parse((ROOT/'scripts/read-ingestion-db-preflight-20261020.py').read_text())
        new=ast.parse((ROOT/'scripts/read-ingestion-db-postboot-preflight-20261020.py').read_text())
        nodes=lambda t:{n.name:ast.dump(n)for n in t.body if isinstance(n,(ast.FunctionDef,ast.ClassDef))}
        a,b=nodes(old),nodes(new)
        for name in ('EngineReader','runtime','read','verify_executable','native_arguments','bounded_command','analyze','selected_config_matches'):
            self.assertEqual(a[name],b[name],name)
        old_spec=importlib.util.spec_from_file_location('original_db_reader',ROOT/'scripts/read-ingestion-db-preflight-20261020.py')
        old_module=importlib.util.module_from_spec(old_spec);old_spec.loader.exec_module(old_module)
        self.assertEqual(old_module.SQL,m.SQL)
        self.assertEqual(old_module.MANIFEST,m.MANIFEST)


if __name__=='__main__':unittest.main()
