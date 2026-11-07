"""Early composition contract; no Engine, namespace, kernel or manager effects."""
import copy,json,sys,types,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tests')]
import test_m2_provider_profiles as providers
from fixtures.m2_admitted_provider_sealed_worker_native import review,bind_review
from tools.m2_discovery_installation_profile import lease_materialization as materialization
from tools.m2_discovery_installation_profile.provider_materialized_admission import admission_scope
from fixtures.m2_publication_read_diagnostics import capture,after_failure_status


class PublicationDiagnostics(unittest.TestCase):
    def fixture(self):
        counts=[]
        def journal():counts.append('journal');return {'state':'LEASE_UPDATING','leaseAuthorized':False,'private':'PRIVATE_SENTINEL'}
        def sets(configuration):counts.append('sets');return {('inet',0):{'PRIVATE_ADDRESS':12},('bridge',0):{'PRIVATE_ADDRESS':12}}
        c=types.SimpleNamespace(journal=journal,configuration={'providerFlows':[{}]},
            owner=types.SimpleNamespace(backend=types.SimpleNamespace(read_sets=sets)))
        return c,counts
    def test_exact_failed_read_state_is_captured_without_private_data_or_extra_reads(self):
        c,counts=self.fixture();before=c.journal;sets=c.owner.backend.read_sets;logs=[]
        error=ValueError('PRIVATE_EXCEPTION_SENTINEL')
        def actual(owner,path,identity):
            owner.journal();owner.owner.backend.read_sets(owner.configuration);raise error
        with self.assertRaises(ValueError) as caught:capture(actual,c,'UNPRINTED_PATH',[],logs.append)
        self.assertIs(caught.exception,error);self.assertEqual(counts,['journal','sets'])
        self.assertIs(c.journal,before);self.assertIs(c.owner.backend.read_sets,sets)
        self.assertNotIn('PRIVATE',logs[0]);self.assertNotIn('UNPRINTED',logs[0])
        value=json.loads(logs[0].split('=',1)[1]);self.assertEqual(value['events'][0],
            {'kind':'coordination','state':'LEASE_UPDATING','leaseAuthorized':False})
        self.assertTrue(value['events'][1]['exactExpectedKeys'])
    def test_success_is_unchanged_and_emits_no_new_report(self):
        c,counts=self.fixture();logs=[]
        self.assertEqual(capture(lambda *args:'SAME_RESULT',c,'unused',[],logs.append),'SAME_RESULT')
        self.assertEqual(counts,[]);self.assertEqual(logs,[])
    def test_failed_diagnostic_emitter_cannot_replace_the_original_denial(self):
        c,counts=self.fixture();error=ValueError('ORIGINAL_DENIAL')
        def actual(*args):raise error
        def emit(value):raise RuntimeError('UNRELATED_OUTPUT_ERROR')
        with self.assertRaises(ValueError) as caught:capture(actual,c,'unused',[],emit)
        self.assertIs(caught.exception,error);self.assertEqual(counts,[])

    def test_after_failure_log_read_is_bounded_and_emits_only_valid_minimized_status(self):
        calls=[];logs=[]
        v={'state':'ACTIVE','reason':'RENEWED','attempts':1,'renewals':16,'incidentRef':'a'*64,
            'ready':True,'live':True,'applicationReady':False,'runtimeAuthorityIssued':False}
        invalid={**v,'private':'PRIVATE_SENTINEL'}
        raw=('PRIVATE_NATIVE_LOG\nOUF_DISCOVERY_LEASE_WORKER_STATUS='+json.dumps(invalid)+
            '\nOUF_DISCOVERY_LEASE_WORKER_STATUS='+json.dumps(v)+'\n').encode()
        def read(args,**options):
            calls.append((args,options));return types.SimpleNamespace(returncode=0,stdout=raw)
        after_failure_status('ouf-admitted-worker-fixture.service',logs.append,read)
        self.assertEqual(len(calls),1);self.assertEqual(calls[0][1]['timeout'],2)
        self.assertIn('--lines=64',calls[0][0]);self.assertEqual(calls[0][0][0],'/usr/bin/journalctl')
        self.assertNotIn('PRIVATE',logs[0]);self.assertNotIn('a'*64,logs[0])
        value=json.loads(logs[0].split('=',1)[1]);self.assertEqual(value['status'],'CAPTURED')
        self.assertEqual(value['records'],[{k:v[k] for k in ('state','reason','attempts','renewals','ready','live')}])
        self.assertIn('NOT_ATOMIC',value['timing'])

    def test_after_failure_unavailable_reader_or_emitter_never_changes_original_failure(self):
        def read(*args,**kwargs):raise TimeoutError('PRIVATE_COMMAND_ERROR')
        logs=[];after_failure_status('ouf-admitted-worker-fixture.service',logs.append,read)
        self.assertEqual(json.loads(logs[0].split('=',1)[1])['status'],'UNAVAILABLE')
        self.assertNotIn('PRIVATE',logs[0])
        def emit(value):raise RuntimeError('PRIVATE_EMITTER_ERROR')
        after_failure_status('ouf-admitted-worker-fixture.service',emit,read)
        calls=[]
        after_failure_status('unowned.service',logs.append,lambda *a,**k:calls.append(a))
        self.assertEqual(calls,[])

    def test_after_failure_oversized_log_and_duplicate_or_authorized_rows_are_denied(self):
        prefix='OUF_DISCOVERY_LEASE_WORKER_STATUS='
        v={'state':'ACTIVE','reason':'RENEWED','attempts':1,'renewals':1,'incidentRef':'a'*64,
            'ready':True,'live':True,'applicationReady':False,'runtimeAuthorityIssued':True}
        for raw in (b'x'*65537,(prefix+'{"state":"ACTIVE","state":"BLOCKED"}').encode(),
            (prefix+json.dumps(v)).encode()):
            logs=[]
            after_failure_status('ouf-admitted-worker-fixture.service',logs.append,
                lambda *a,**k:types.SimpleNamespace(returncode=0,stdout=raw))
            self.assertEqual(json.loads(logs[0].split('=',1)[1])['records'],[])

class EarlyReview(unittest.TestCase):
    def test_same_provider_and_registry_inputs_are_bound_before_cids_or_worker_ledger_exist(self):
        fixture=providers.Profiles();self.addCleanup(fixture.doCleanups)
        issuer,window,auth,_,_,options,_=fixture.fixture()
        root=auth.root/'joint-worker-case';root.mkdir(mode=0o700)
        profile=copy.deepcopy(issuer.scope);prep=profile['preparerTemplate']
        kernel=root/'provider-kernel';kernel.mkdir(mode=0o700)
        prep['lockFile']=str(kernel/'kernel.lock')
        auth.write(Path(prep['lockFile']),b'')
        prep['coordinationBinding']['configurationHash']=materialization.digest(prep['kernel'])
        template,setup=review(auth,root,issuer.template,profile,window.request)
        provider=admission_scope(template,issuer.template,issuer.creation.scope,profile)
        scope_hash=bind_review(auth,setup,provider)
        materialization.paired_native_inputs(template,profile,window.request,
            [*materialization.inode(prep['lockFile']),0,1,1])
        self.assertEqual(scope_hash,materialization.digest(setup['start']))
        self.assertFalse(Path(template['configurationTemplate']['commonInvocationLock']).exists())
        self.assertFalse(Path(template['configurationTemplate']['ledgerRoot']).exists())
        self.assertFalse(Path(template['installationRoot']).exists())
        self.assertEqual(template['recipeTemplate']['kernel'],prep['kernel'])
        self.assertEqual(template['recipeTemplate']['dns'],prep['dns'])
        self.assertEqual(template['expectedImages']['registry'],window.request['Image'])
        self.assertEqual(template['expectedImages']['provider'],issuer.template['expectedImageId'])
        self.assertIn(str(auth.key),template['signingKeyPaths'])

if __name__=='__main__':unittest.main()
