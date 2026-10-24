"""Metadata-only reconciliation; histories/runtime rows are synthetic fixtures.

Native tests use actual root-custodied socket inodes/aliases and /proc identity,
never Docker/SQL/network requests. They do not prove target Engine continuity.
"""
import copy
import importlib.util
import json
import os
from pathlib import Path
import socket
import stat
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[3]if Path(__file__).parent.name=='tests'else Path(__file__).parent

def module(name,path):
    spec=importlib.util.spec_from_file_location(name,path);value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value

def file(repo,local):
    path=ROOT/repo;return path if path.exists()else ROOT/local

c=module('engine_metadata_reconciliation',file('scripts/reconcile-onboarding-engine-metadata-20261024.py','reconcile-onboarding-engine-metadata-20261024.py'))
d=module('stopped_db_definitions',file('scripts/read-onboarding-finite-database-20261024.py','read-onboarding-finite-database-20261024.py'))
m=module('metadata_dependencies',file('scripts/prepare-onboarding-finite-session-inputs-20261024.py','prepare-onboarding-finite-session-inputs-20261024.py'))
r=module('sealed_dependencies',file('scripts/repair-registry-network-projection-20261024.py','repair.py'))
r.CAPSULE=str(file('releases/semantic-registry-checkpoint-successor-20261023.py','capsule.py'));r.load_legacy()
from tools.ingestion_readiness_patch_execution import runtime_bindings,database_read


def private(path,value):
    body=m.encoded(value);path.write_bytes(body);path.chmod(0o400);return m.sha(body)


def binding(path='/protected/engine.sock',inode=100):return {'socketPath':path,'socketBinding':[1,inode,0,0,0o600]}


def view(path='/protected/engine.sock',retained=True):
    return {'present':True,'canonicalPath':path,'observedSocketBinding':[1,100,0,0,0o600],
        'selectedPathIsCanonical':True,'retainedSocketBindingMatchesObserved':retained}


class Guards(unittest.TestCase):
    def test_exact_metadata_shapes_and_closed_comparison_fields(self):
        left=binding();right=binding('/other/engine.sock',101)
        row=c.difference(left,right)
        self.assertEqual(row['changedFields'],['socketBinding','socketPath'])
        self.assertEqual(row['socketBindingChanges'],['inode'])
        for value in ({**left,'url':'private'},binding('https://private'),binding('/protected/../engine.sock'),
                      {'socketPath':'/x','socketBinding':[1,2,False,0,0o600]}):
            with self.assertRaises(c.Stop):c.validate_engine(value)

    def test_path_alias_classification_preserves_original_profiles(self):
        engines={'prepared':binding('/alias/engine.sock'),'plan':binding('/alias/engine.sock'),'current':binding()}
        original=copy.deepcopy(engines);views={k:view()for k in engines}
        row=c.classify(engines,views)
        self.assertEqual(row['classification'],'PATH_ALIAS_ONLY_SAME_CURRENT_SOCKET')
        self.assertTrue(row['failedComparisonReproduced']);self.assertEqual(engines,original)
        self.assertFalse(row['engineApiIdentityProvenByThisReader'])

    def test_stale_pin_different_plan_and_missing_old_path_never_grant_runtime(self):
        engines={'prepared':binding(inode=99),'plan':binding(inode=99),'current':binding()}
        views={'prepared':view(retained=False),'plan':view(retained=False),'current':view()}
        row=c.classify(engines,views)
        self.assertEqual(row['classification'],'HISTORICAL_SOCKET_BINDING_DIFFERS_FROM_CURRENT')
        engines['plan']=binding(inode=98)
        self.assertEqual(c.classify(engines,views)['classification'],'HISTORICAL_PREPARED_AND_PLAN_ENGINE_DIFFER')
        engines['plan']=engines['prepared'];views['prepared']=views['plan']={'present':False,'status':'ABSENT'}
        self.assertEqual(c.classify(engines,views)['classification'],'ENGINE_METADATA_DIFFERENCE_REQUIRES_REVIEW')
        views['current']=view(retained=False)
        with self.assertRaisesRegex(c.Stop,'CURRENT_CAPTURED_SOCKET'):c.classify(engines,views)

    def test_non_reproduced_guard_does_not_become_acceptance(self):
        engines={k:binding()for k in('prepared','plan','current')}
        result=c.classify(engines,{k:view()for k in engines})
        self.assertEqual(result['classification'],'STOP_NOT_REPRODUCED_FROM_RETAINED_METADATA')
        self.assertFalse(result['failedComparisonReproduced'])
        self.assertTrue(result['metadataClassificationDoesNotAuthorizeReplacement'])

    def test_mount_encoding_observed_both_ways_without_rewriting_retained_hash(self):
        actual={'Id':'a'*64,'Image':'sha256:'+'b'*64,'State':{'Pid':123,'StartedAt':'fixture'},
            'Config':{},'HostConfig':{},'NetworkSettings':{},'Mounts':[{'Destination':'/z'},{'Destination':'/a'}]}
        old=runtime_bindings.observed(actual,runtime_bindings.SORTED);before=copy.deepcopy(old)
        report=c.runtime_comparison(old,actual,runtime_bindings)
        self.assertEqual(report['native']['changedFields'],['mountsHash']);self.assertTrue(report['sortedMounts']['equal'])
        self.assertEqual(old,before)

    def test_resolver_policy_copies_original_caller_files_without_host_fallback(self):
        from tools.semantic_registry_recovery_execution import caller_lookup
        self.assertEqual(caller_lookup.POLICY['mode'],'COPIED_CALLER_FILES_PRIVATE_MOUNTS_V1')
        self.assertFalse(caller_lookup.POLICY['hostResolverFallbackAllowed'])
        self.assertEqual(caller_lookup.VIEWS,('resolv.conf','hosts','nsswitch.conf'))
        self.assertIn("v['lookup'][name].encode('ascii')",caller_lookup.CHILD_SETUP)


@unittest.skipUnless(os.environ.get('OUF_NATIVE_ENGINE_METADATA')=='1','isolated root /proc and Unix filesystem runner required')
class Native(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(dir=ROOT);self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name);self.root.chmod(0o700)
        (self.root/'run').mkdir(mode=0o700);(self.root/'alias').symlink_to(self.root/'run',target_is_directory=True)
        self.path=self.root/'run/engine.sock';self.server=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
        self.server.bind(str(self.path));self.path.chmod(0o600);self.server.listen(1);self.server.setblocking(False)
        self.addCleanup(self.server.close);s=self.path.stat()
        self.current={'socketPath':str(self.path),'socketBinding':[s.st_dev,s.st_ino,s.st_uid,s.st_gid,0o600]}
        self.historical={**self.current,'socketPath':str(self.root/'alias/engine.sock')}

    def test_actual_socket_alias_missing_path_and_pin_drift_without_connection(self):
        alias=c.socket_view(self.historical);current=c.socket_view(self.current)
        self.assertEqual(alias['canonicalPath'],current['canonicalPath'])
        self.assertTrue(alias['retainedSocketBindingMatchesObserved']);self.assertFalse(alias['selectedPathIsCanonical'])
        self.assertTrue(current['selectedPathIsCanonical'])
        missing={**self.current,'socketPath':str(self.root/'missing.sock')}
        self.assertFalse(c.socket_view(missing)['present'])
        drift=copy.deepcopy(self.current);drift['socketBinding'][1]+=1
        self.assertFalse(c.socket_view(drift)['retainedSocketBindingMatchesObserved'])
        with self.assertRaises(BlockingIOError):self.server.accept()
        self.path.chmod(0o666)
        with self.assertRaises(c.Stop):c.socket_view(self.current)

    def test_actual_files_proc_and_exclusive_claim_never_invoke_engine_sql_or_old_entry(self):
        package=self.root/'package';package.mkdir(mode=0o700);capture=package/'input-preparation-v1';capture.mkdir(mode=0o700)
        base=self.root/'base';base.mkdir(mode=0o700);owner=self.root/'owner';owner.mkdir(mode=0o700)
        actual={'Image':'sha256:'+'b'*64,'State':{'Pid':os.getpid(),'StartedAt':'synthetic-history',
            'Running':True,'Paused':False,'Restarting':False,'Dead':False,'OOMKilled':False,'Error':''},
            'Config':{'Env':['SECRET_FIXTURE=never-print-this']},'HostConfig':{},'NetworkSettings':{},'Mounts':[],
            'RestartCount':0}
        observations={};references={};current={};processes={}
        for name,cid in [('onboarding','a'*64),('postgres','b'*64)]:
            row={**actual,'Id':cid};observations[name]=row
            path=capture/(name+'.json');references[name]={'path':str(path),'sha256':private(path,row)}
            current[name]=runtime_bindings.observed(row,runtime_bindings.NATIVE);processes[name]=m.process(row)
        inputs={'schema':'ouf.onboarding-finite-session-private-inputs.v1','kind':'INPUTS_NOT_EXECUTABLE_AUTHORITY',
            'targetApplyAuthorized':False,'automaticReplayAllowed':False,'budgetReset':False,
            'bootId':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'retainedFacts':[],
            'engineBinding':self.current,'runtimeObservations':references,'currentBindings':current,'currentProcessIdentities':processes}
        ip=capture/'inputs.json';ih=private(ip,inputs)
        private(capture/'complete.json',{'complete':True,'privateInputsHash':ih,'engineGetAttempts':14,'currentCohortStable':True})
        prepared={'engine':self.historical,'databasePlan':{'postgresRuntimeBinding':runtime_bindings.observed(observations['postgres'],runtime_bindings.NATIVE)}}
        pp=base/'prepared.json';ph=private(pp,{'prepared':prepared})
        br={'scopes':{'finiteActionProcess':{'bundle':{'path':str(pp),'sha256':ph}}},'privateInputHashes':{'preparedInputs':c.digest(prepared)}}
        bh=private(base/'review.json',br)
        plan={'engine':self.historical};private(owner/'execution-plan.json',plan)
        stages=['FIXTURE_'+str(i)for i in range(10)]+['VERIFY_FINAL'];scope={'planHash':c.digest(plan),'stages':stages}
        review={'scopes':{'onboardingAuditUpdate':scope}};rh=private(owner/'review.json',review)
        effects=[{'stage':name,'state':'APPLIED'}for name in stages]
        effects[-1]['evidence']={'applications':{'onboarding':{'runtimeBinding':runtime_bindings.observed(observations['onboarding'],runtime_bindings.SORTED)}}}
        private(owner/'recovery.json',{'scopeHash':c.digest(scope),'incidentState':'RECOVERED','version':29,'nextStage':11,'effects':effects})
        old={p:p.read_bytes()for folder in(base,owner,capture)for p in folder.iterdir()}
        pins={'INPUT':str(ip),'INPUT_HASH':ih,'BASE':str(base),'BASE_REVIEW':bh,'OWNER':str(owner),'OWNER_REVIEW':rh}
        with patch.multiple(d,**pins),patch.object(m,'PACKAGE',str(package)),\
             patch.object(m.Engine,'get',side_effect=AssertionError('NO_ENGINE_GET')),\
             patch.object(database_read,'bounded_read',side_effect=AssertionError('NO_SQL')),\
             patch.object(d,'prepare',side_effect=AssertionError('NO_OLD_ENTRY')),\
             patch.object(d,'query',side_effect=AssertionError('NO_SQL_COMPOSITION')),\
             patch.object(subprocess,'Popen',side_effect=AssertionError('NO_SUBPROCESS')),\
             patch.object(socket,'socket',side_effect=AssertionError('NO_CONNECTION')):
            result=c.prepare(d,m,r)
            self.assertEqual(result['classification'],'PATH_ALIAS_ONLY_SAME_CURRENT_SOCKET')
            self.assertTrue(result['failedComparisonReproduced']);self.assertEqual(result['engineConnections'],0)
            self.assertEqual(result['engineGetAttempts'],0);self.assertEqual(result['sqlSessionAttempts'],0)
            self.assertFalse(result['newSqlAttemptAuthorized']);self.assertFalse(result['newBindingAcceptedForRuntime'])
            self.assertFalse(result['priorScopeState']['databaseScopeExists'])
            self.assertTrue(all(v['matchesCaptured']for v in result['capturedProcessPins'].values()))
            self.assertTrue(result['historicalVsCapturedRuntime']['onboarding']['sortedMounts']['equal'])
            self.assertTrue(result['historicalVsCapturedRuntime']['postgres']['native']['equal'])
            public=json.dumps(result);self.assertNotIn('never-print-this',public);self.assertNotIn(str(self.path),public)
            bundle=json.loads((package/c.SCOPE/'reconciliation.json').read_bytes())
            self.assertEqual(result['privateReconciliationHash'],c.digest(bundle))
            self.assertTrue(all(stat.S_IMODE(p.stat().st_mode)==0o400 for p in (package/c.SCOPE).iterdir()))
            with self.assertRaisesRegex(c.Stop,'ALREADY_CLAIMED'):c.prepare(d,m,r)
        self.assertEqual(old,{p:p.read_bytes()for p in old})
        with self.assertRaises(BlockingIOError):self.server.accept()

if __name__=='__main__':unittest.main()
