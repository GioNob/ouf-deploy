import ast
import copy
import hashlib
import importlib.util
import json
import subprocess
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('selection_reconcile', ROOT/'scripts/reconcile-ingestion-db-selection-20261020.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class SelectionReconcile(unittest.TestCase):
    def setUp(self):
        self.engine = {'socketPath':'/run/fixture.sock','socketBinding':[1,2,0,0,0o600]}
        self.db = {'schema':'ouf.chatbot-cohort-database-plan.v1',
                   'postgresRuntimeBinding':{'containerId':'a'*64,'imageId':'b'*64,'pid':1}}
        self.original = {'schema':'ouf.chatbot-file-cohort-prepared-inputs.v1',
            'engine':copy.deepcopy(self.engine),'databasePlan':copy.deepcopy(self.db),
            'cohortPlan':{'databasePlanHash':m.digest(self.db)}}
        self.case = {'humanBinding':{'sessionDirectory':'/NEVER_OPEN/HUMAN'},
                     'originalBinding':{'path':'/retained/original.json','sha256':m.digest(self.original)}}
        self.package = {'sourceCommit':m.SOURCE,'closure':{'declaration':{'moduleCount':244}},
            'fileHashes':{'case.json':m.digest(self.case)},'executionPins':{'caseSha256':m.digest(self.case)}}
        self.review = {'sourceClosureHash':m.digest(self.package['closure'])}
        self.values = {str(m.OWNER/'execution-plan.json'):{'engine':self.engine,'humanBinding':self.case['humanBinding']},
            str(m.OWNER/'update-result.json'):{'complete':True,'planHash':m.OWNER_PLAN},
            str(m.CONTEXT/'package.json'):self.package,str(m.CONTEXT/'review.json'):self.review,
            str(m.CONTEXT/'decision.json'):{'reviewHash':m.digest(self.review)},
            str(m.CONTEXT/'runtime.claim.json'):{'packageHash':m.digest(self.package),'automaticReplayAllowed':False},
            str(m.CONTEXT/'case.json'):self.case,'/retained/original.json':self.original}

    def parse(self,path,expected=None):
        if str(path)==self.case['originalBinding']['path']:
            self.assertEqual(expected,self.case['originalBinding']['sha256'])
        return copy.deepcopy(self.values[str(path)])

    def test_all_three_predicates_are_separate_observations(self):
        facts=m.inspect_selection(self.parse)
        self.assertTrue(facts['allOriginalPreflightSelectionPredicatesMatch'])
        for field in ('schema','engine','databasePlan'):
            with self.subTest(field=field):
                saved=copy.deepcopy(self.original[field])
                if field=='schema':self.original[field]='unknown-private-value'
                elif field=='engine':self.original[field]['socketBinding'][1]=3
                else:self.original[field]['postgresRuntimeBinding']['pid']=2
                facts=m.inspect_selection(self.parse)
                self.assertEqual(sum(facts['checks'].values()),2)
                self.assertNotIn('unknown-private-value',json.dumps(facts))
                self.original[field]=saved

    def test_real_postboot_project_preserves_historical_cohort_hash(self):
        spec=importlib.util.spec_from_file_location('postboot_policy',ROOT/'scripts/source-revision-postboot-policy.py')
        policy=importlib.util.module_from_spec(spec);spec.loader.exec_module(policy)
        before={n:{'Id':n,'Image':'image','Config':{'Labels':{'org.opencontainers.image.revision':'source'}},
                   'State':{'Running':True,'Paused':False,'Restarting':False},'HostConfig':{}}
                for n in ('onboarding','mcp','udp')}
        historical={'schema':'ouf.source-revision-private-inputs.v1','runtimeAuthorityIssued':False,
            'readyForExecution':False,'packageRootCustodyProven':True,'engine':self.engine,
            'beforeApplications':before,'selection':{'currentApplications':{n:{'imageId':'image','sourceCommit':'source'}for n in before}},
            'databasePlan':self.db,'unchangedApplications':{},'retainedReplacements':{n:{'request':{'HostConfig':{}}}for n in ('onboarding','mcp')},
            'candidates':{},'gatewayPackage':{},'gateway':{}}
        pg={'Id':'a'*64,'Image':'b'*64,'State':{'Running':True}}
        projected,_,_=policy.project(self.original,historical,{**before,'a'*64:pg},self.engine,{},
            lambda _:dict(self.db['postgresRuntimeBinding'],pid=2),lambda _:None,lambda *_:{})
        self.assertEqual(projected['cohortPlan'],self.original['cohortPlan'])
        self.original.clear();self.original.update(projected)
        facts=m.inspect_selection(self.parse)
        self.assertFalse(facts['checks']['originalDatabasePlanMatchesCohortHash'])
        self.assertTrue(facts['checks']['originalEngineMatchesCompletedOwner7'])

    def test_case_binding_drift_stops_before_original_read(self):
        self.case['originalBinding']['path']='/foreign'
        with self.assertRaisesRegex(m.Denied,'EXACT_COMPLETED_CASE_REQUIRED'):
            m.inspect_selection(self.parse)

    def test_stable_documents_are_rechecked_without_runtime_access(self):
        reads=[]
        def reader(path,expected=None):
            raw=m.encoded(self.values[str(path)])
            if expected and str(path) not in (str(m.OWNER/'execution-plan.json'),str(m.OWNER/'update-result.json')):
                self.assertEqual(m.sha(raw),expected)
            reads.append(str(path));return raw,[1,2,3]
        result=m.reconcile(reader)
        self.assertTrue(result['retainedSelectionRechecked'])
        self.assertEqual(len(reads),16)
        for field in ('engineGetRequests','databaseCalls','oauthRequests','journalWrites'):
            self.assertEqual(result[field],0)
        self.assertFalse(result['databaseAdmissionProven'])
        self.assertFalse(result['runtimeAuthorityIssued'])
        self.assertFalse(any('NEVER_OPEN' in p for p in reads))

    def test_metadata_change_during_recheck_blocks(self):
        counts={}
        def reader(path,expected=None):
            key=str(path);counts[key]=counts.get(key,0)+1
            return m.encoded(self.values[key]),[counts[key]]
        with self.assertRaisesRegex(m.Denied,'RETAINED_SELECTION_CHANGED'):
            m.reconcile(reader)

    def test_no_runtime_process_network_or_writing_calls(self):
        tree=ast.parse((ROOT/'scripts/reconcile-ingestion-db-selection-20261020.py').read_text())
        calls={ast.unparse(n.func)for n in ast.walk(tree)if isinstance(n,ast.Call)}
        for forbidden in ('exec','eval','subprocess.run','socket.socket','os.replace','os.unlink','os.chmod','os.chown','os.mkdir'):
            self.assertNotIn(forbidden,calls)
        opens=[n for n in ast.walk(tree)if isinstance(n,ast.Call)and ast.unparse(n.func)=='os.open']
        self.assertTrue(opens)
        for node in opens:
            flags=ast.unparse(node.args[1])
            self.assertIn('os.O_RDONLY',flags)
            self.assertIn('os.O_NOFOLLOW',flags)

    def test_delivery_checks_immutable_reader_before_sudo(self):
        source=(ROOT/'scripts/reconcile-ingestion-db-selection-20261020.py').read_bytes()
        blob=hashlib.sha1(b'blob '+str(len(source)).encode()+b'\0'+source).hexdigest()
        path=ROOT/'scripts/launch-ingestion-db-selection-reconcile-20261020.sh'
        launcher=path.read_text()
        self.assertIn('git/blobs/'+blob,launcher)
        self.assertIn(hashlib.sha256(source).hexdigest(),launcher)
        self.assertLess(launcher.index('sha256sum -c -'),launcher.index('sudo /usr/bin/python3'))
        self.assertLess(launcher.index('ouf-gh-2.102.0.PNoFbF'),launcher.index('command -v gh'))
        self.assertIn('-I -B -S',launcher)
        subprocess.run(['bash','-n',str(path)],check=True)

    def test_delivery_keeps_log_and_original_stop_exit_code(self):
        launcher=(ROOT/'scripts/launch-ingestion-db-selection-reconcile-20261020.sh').read_text()
        body=launcher[launcher.index('ouf_report_log()'):launcher.index('"$ouf_gh" api')]
        result=subprocess.run(['bash','-c','ouf_read=/fixture/retained\n'+body+'\nexit 7'],capture_output=True)
        self.assertEqual(result.returncode,7)
        self.assertIn(b'/fixture/retained/read.log',result.stdout)
        self.assertNotIn('rm -',launcher)


if __name__=='__main__':unittest.main()
