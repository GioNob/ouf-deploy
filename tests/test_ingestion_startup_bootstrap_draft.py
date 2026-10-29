import ast
import copy
import hashlib
import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
PATH=ROOT/'scripts/prepare-ingestion-startup-bootstrap-draft-20261020.py'
spec=importlib.util.spec_from_file_location('bootstrap_draft',PATH)
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)


class BootstrapDraft(unittest.TestCase):
    def setUp(self):
        config={'Entrypoint':['java','-jar','/app/app.jar'],'Cmd':[],'Env':['OUF_ING_DB_PASSWORD=fixture-not-for-output']}
        self.actual={name:{'Id':key*64,'Image':'sha256:'+key*64,'State':{'Running':True,'Pid':2,'StartedAt':'fixture'},
            'Config':copy.deepcopy(config),'HostConfig':{},'Mounts':[],'NetworkSettings':{}}for name,key in [('ingestion','a'),('gateway','b')]}
        payload={'secrets':{'references':{'ingestionReadOwnerKey':'/retained/key'}}}
        self.owner={'bindingPlan':{'candidatePayloadChecksum':'c'*64,'candidatePayload':payload},
                    'currentApplications':{n:m.runtime(v)for n,v in self.actual.items()}}
        routes={k:{}for k in ['mcp-ingestion-status','mcp-ingestion-history',*[str(n)for n in range(80)]]}
        after=copy.deepcopy(routes)
        for n in ('status','history'):after['mcp-ingestion-'+n]={'fixtureReceipt':True}
        self.draft={'owner':{'candidatePayloadChecksum':'c'*64,'candidatePayload':copy.deepcopy(payload)},
            'gateway':{'beforeRoutes':routes,'afterRoutes':after,'retainedOtherRoutes':80,'maximumPutRequests':2},
            'runtime':{'ingestion':{'environmentAdditions':{'OUF_ING_GATEWAY_READ_ENABLED':'true'},
                'readOnlyBindAddition':{'Source':'/retained/key','Destination':'/run/secrets/key','RW':False}}}}
        p=patch.object(m,'ROUTES',m.digest(routes));p.start();self.addCleanup(p.stop)

    def compile(self):return m.compile_draft(self.owner,self.draft,self.actual)

    def rebind_fixture(self):self.owner['currentApplications']={n:m.runtime(v)for n,v in self.actual.items()}

    def test_exact_two_bootstraps_form_only_private_unauthorized_draft(self):
        plan=self.compile()
        self.assertEqual(plan['ingestion']['bootstrapCmd'],list(m.FLAGS))
        self.assertEqual(plan['ingestion']['startupEnvironmentAddition'],{'SPRING_FLYWAY_ENABLED':'false'})
        self.assertFalse(plan['runtimeAuthorityIssued'])
        self.assertFalse(plan['gateway']['referenceValueResolved'])
        self.assertEqual(len(plan['unprovenGates']),6)
        self.assertNotIn('fixture-not-for-output',m.encoded(plan).decode())
        self.assertFalse(plan['newLoginAllowed'])
        self.assertFalse(plan['databaseMigrationAllowed'])

    def test_runtime_generation_drift_blocks(self):
        self.actual['gateway']['State']['Pid']=4
        with self.assertRaisesRegex(m.Denied,'CURRENT_INGESTION_OR_GATEWAY_GENERATION_DRIFT'):self.compile()

    def test_published_owner_reference_cannot_be_substituted(self):
        self.draft['runtime']['ingestion']['readOnlyBindAddition']['Source']='/foreign/key'
        with self.assertRaisesRegex(m.Denied,'EXACT_ALREADY_PUBLISHED_OWNER_KEY_REFERENCE_REQUIRED'):self.compile()

    def test_each_existing_owner_environment_collision_blocks(self):
        for module,key in [('gateway','OUF_INGESTION_READ_OWNER_KEY'),('ingestion','OUF_ING_GATEWAY_READ_ENABLED')]:
            with self.subTest(module=module):
                self.actual[module]['Config']['Env'].append(key+'=existing')
                self.rebind_fixture()
                with self.assertRaises(m.Denied):self.compile()
                self.actual[module]['Config']['Env'].pop()

    def test_third_route_change_blocks(self):
        self.draft['gateway']['afterRoutes']['3']={'unexpected':True}
        with self.assertRaisesRegex(m.Denied,'EXACT80_OTHER_ROUTES_MUST_BE_PRESERVED'):self.compile()

    def test_runtime_sql_oauth_and_mutation_paths_are_absent(self):
        text=PATH.read_text();tree=ast.parse(text)
        calls={ast.unparse(n.func)for n in ast.walk(tree)if isinstance(n,ast.Call)}
        self.assertFalse({'exec','eval','subprocess.run','os.execv','os.replace','os.unlink','os.chown'}&calls)
        for bad in ('psql','BEGIN READ ONLY','human-access.jwt','start_refresh','authenticate('):self.assertNotIn(bad,text)
        requests=[n for n in ast.walk(tree)if isinstance(n,ast.Call)and ast.unparse(n.func)=='connection.request']
        self.assertEqual(len(requests),1);self.assertEqual(ast.literal_eval(requests[0].args[0]),'GET')
        self.assertIn('os.O_EXCL',ast.unparse(next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='write_new')))

    def test_existing_delivery_pins_reader_before_sudo_and_retains_stop_log(self):
        path=ROOT/'scripts/launch-ingestion-startup-bootstrap-draft-20261020.sh'
        delivery=path.read_text();raw=PATH.read_bytes()
        self.assertIn(hashlib.sha256(raw).hexdigest(),delivery)
        blob=hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()
        self.assertIn('git/blobs/'+blob,delivery)
        self.assertLess(delivery.index('sha256sum -c -'),delivery.index('sudo /usr/bin/python3'))
        self.assertLess(delivery.index('ouf-gh-2.102.0.PNoFbF'),delivery.index('command -v gh'))
        subprocess.run(['bash','-n',str(path)],check=True)
        body=delivery[delivery.index('ouf_report_log()'):delivery.index('"$ouf_gh" api')]
        result=subprocess.run(['bash','-c','ouf_read=/retained\n'+body+'\nexit 7'],capture_output=True)
        self.assertEqual(result.returncode,7);self.assertIn(b'/retained/read.log',result.stdout)


if 'OUF_TEST_ROOT' in os.environ:
    class PrivateDraftCustody(unittest.TestCase):
        def test_exclusive_private_write_readback_and_no_clobber(self):
            with tempfile.TemporaryDirectory(prefix='startup-draft-fixture-',dir=os.environ['OUF_TEST_ROOT'])as root:
                path=Path(root)/'draft.json';value={'schema':'fixture','runtimeAuthorityIssued':False}
                m.write_new(path,value)
                before=m.read(path)[1]
                with self.assertRaises(FileExistsError):m.write_new(path,{'changed':True})
                self.assertEqual(m.parsed(path),value);self.assertEqual(m.read(path)[1],before)


if __name__=='__main__':unittest.main()
