"""Signed eleven-phase orchestration, real HTTP, fixture Docker/PostgreSQL.

These tests verify channel/transition semantics, not target deployment evidence.
"""
import copy,json,sys,threading,types,unittest
from http.server import BaseHTTPRequestHandler,HTTPServer
from pathlib import Path
from unittest import mock
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'tests'),str(ROOT/'tools/semantic_application_cutover'),str(ROOT/'tools/semantic_database_cutover')]
import test_file_only_cutover as profile_fixture
import application_verification_adapter as app
from application_verification_adapter import ApplicationReadinessChannel,ApplicationVerificationAdapter
from producer_release_adapter import ProducerReleaseAdapter
from native_evidence_store import NativeEvidenceStore
from engine_creation import Engine
from transition_journal import digest
from cutover_executor import CutoverDenied

class Owners(unittest.TestCase):
    def fixture(self,release=False,retire_all=False):
        state={'http':200,'health':{'status':'UP'},'db':{'name':'semantic','oid':44,'allowConnections':True},
            'migrations':[{'version':'1','type':'SQL','script':'V1__fixture.sql','checksum':123,'success':True}]}
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(state['http']);self.end_headers();self.wfile.write(json.dumps(state['health']).encode())
            def log_message(self,*args):pass
        server=HTTPServer(('127.0.0.1',0),Handler);thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        self.addCleanup(server.server_close);self.addCleanup(server.shutdown)
        scope={'databaseContainerId':'c'*64,'databaseUser':'postgres','database':'semantic','databaseOid':44,
            'flywaySchema':'ouf_sem','flywayHistoryHash':digest(state['migrations']),'health':{'address':'127.0.0.1','port':server.server_port,'path':'/actuator/health/readiness','timeoutSeconds':1}}
        channel=ApplicationReadinessChannel(scope)
        class Pg:
            def __init__(self,*args):state['dbConnections']=state.get('dbConnections',0)+1
            def query(self,expression,**kwargs):
                if 'flyway_schema_history' in expression:
                    if '"ouf_sem".flyway_schema_history' not in expression:raise AssertionError('fixture requires actual Registry schema')
                    return copy.deepcopy(state['migrations'])
                return copy.deepcopy(state['db'])
            def close(self):pass
        patch=mock.patch.object(app,'Psql',Pg);patch.start();self.addCleanup(patch.stop)
        request,_=profile_fixture.inputs();request_hash=digest(request)
        verification={'creationRequestHash':request_hash,'readinessScopeHash':channel.scope_hash,'priorReleaseEvidencePhase':'START_REPLACEMENT'}
        overrides={'VERIFY_APPLICATION':verification}
        producers={};pins=[];hosts={};networks={}
        for index in (1,2):
            cid=str(index)*64;host={'RestartPolicy':{'Name':'unless-stopped','MaximumRetryCount':0}}
            network={'Networks':{'bridge':{'NetworkID':'e'*64,'IPAddress':'10.1.0.'+str(index),'MacAddress':'02:42:00:00:00:0'+str(index)}}}
            original={'Id':cid,'Image':'sha256:'+'d'*64,'Config':{'fixture':index},'HostConfig':copy.deepcopy(host),'Mounts':[],
                'NetworkSettings':copy.deepcopy(network),'State':{'Pid':100+index,'StartedAt':'2026-10-14T00:00:00Z','Running':True,'Paused':False,'Status':'running'},'RestartCount':0}
            pins.append(Engine.runtime_binding(original));hosts[cid]=host;networks[cid]=network
            original['HostConfig']['RestartPolicy']={'Name':'no','MaximumRetryCount':0}
            original['State'].update(Pid=0,Running=False,Status='exited',FinishedAt='2026-10-14T01:00:00Z',Error='');producers[cid]=original
        quiescence={'producerBindings':pins,'initialHostConfigs':hosts,'initialNetworkSettings':networks,
            'quiescentRestartPolicy':{'Name':'no','MaximumRetryCount':0},'stopTimeoutSeconds':1}
        release_intent={'creationRequestHash':request_hash,'quiescenceIntentHash':digest(quiescence),'retiredContainerIds':['1'*64],
            'cohortReviewHash':'9'*64,
            'releaseProducerIds':['2'*64],'restartPolicies':{'2'*64:hosts['2'*64]['RestartPolicy']}}
        if retire_all:release_intent.update(retiredContainerIds=['1'*64,'2'*64],releaseProducerIds=[],restartPolicies={})
        if release:overrides.update(QUIESCE_PRODUCERS=quiescence,RELEASE_PRODUCERS=release_intent)
        fixture=profile_fixture.FileOnlyCutover();f,p,e,calls=fixture.fixture(overrides);self.addCleanup(fixture.doCleanups)
        directory=f.root/'native';directory.mkdir(mode=0o700);store=NativeEvidenceStore(directory)
        before=f.root/'before';before.mkdir(mode=0o700);before_store=NativeEvidenceStore(before)
        actual={'Id':'f'*64,'Name':'/'+Engine.name(e.t),'Image':request['Image'],'Config':{k:v for k,v in request.items() if k not in ('HostConfig','NetworkingConfig')},
            'HostConfig':copy.deepcopy(request['HostConfig']),'Mounts':[],'NetworkSettings':{'Networks':{'bridge':{'IPAddress':'127.0.0.1'}}},
            'State':{'Pid':999,'StartedAt':'2026-10-14T02:00:00Z','Running':True,'Paused':False,'Status':'running'},'RestartCount':0}
        engine=Engine.__new__(Engine);engine.inspect=lambda t:copy.deepcopy(actual);mutations=[]
        def native(method,path,body=None):
            cid=path.split('/')[3];value=producers[cid]
            if method=='GET':return 200,copy.deepcopy(value)
            mutations.append((cid,path.rsplit('/',1)[-1]))
            if path.endswith('/update'):value['HostConfig']['RestartPolicy']=copy.deepcopy(body['RestartPolicy']);return 200,None
            if path.endswith('/start'):
                value['State'].update(Pid=200,Running=True,Status='running',StartedAt='2026-10-14T03:00:00Z');return 204,None
            raise AssertionError(path)
        engine.request=native
        def observation(phase,value):store.publish(phase,value);return 'APPLIED',value
        e.adapters['START_REPLACEMENT'].observe=lambda i:observation('START_REPLACEMENT',Engine.runtime_binding(actual))
        e.adapters['VERIFY_APPLICATION']=ApplicationVerificationAdapter(engine,e.t,request,verification,store,channel,lambda point:None)
        if release:
            e.adapters['QUIESCE_PRODUCERS'].observe=lambda i:observation('QUIESCE_PRODUCERS',{'fixtureStopped':True})
            e.adapters['RELEASE_PRODUCERS']=ProducerReleaseAdapter(engine,e.t,request,release_intent,quiescence,store,before_store,channel,lambda point:None)
        return e,state,actual,producers,mutations
    def test_real_http_and_exact_database_history_verify_without_mutation(self):
        e,state,actual,producers,mutations=self.fixture();e.run(10)
        self.assertEqual(e.t.read()['nextPhase'],10);self.assertEqual(mutations,[]);self.assertGreater(state['dbConnections'],0)
    def test_not_ready_remains_consumed_and_later_read_reconciles(self):
        e,state,actual,producers,mutations=self.fixture();state['http']=503
        with self.assertRaises(CutoverDenied):e.run(10)
        self.assertEqual(e.t.read()['state'],'IN_FLIGHT');state['http']=200;e.run(10)
        self.assertEqual(e.t.read()['nextPhase'],10);self.assertEqual(mutations,[])
    def test_wrong_database_failed_schema_and_changed_generation_block_release(self):
        for kind in ('database','migration','generation','health'):
            e,state,actual,producers,mutations=self.fixture();e.run(9)
            if kind=='database':state['db']['oid']+=1
            if kind=='migration':state['migrations'][0]['success']=False
            if kind=='generation':actual['State']['Pid']+=1
            if kind=='health':state['health']['status']='DOWN'
            with self.assertRaises(ValueError):e.run(10)
            self.assertEqual(mutations,[])
    def test_restart_other_producer_keeps_old_registry_retired_and_reconciles_crash(self):
        e,state,actual,producers,mutations=self.fixture(release=True);adapter=e.adapters['RELEASE_PRODUCERS'];original=adapter.apply
        def crash(i):original(i);raise RuntimeError('fixture crash after independent producer start')
        adapter.apply=crash
        with self.assertRaises(RuntimeError):e.run()
        self.assertEqual(mutations,[('2'*64,'update'),('2'*64,'start')]);self.assertFalse(producers['1'*64]['State']['Running'])
        adapter.apply=lambda i:self.fail('consumed producer release replayed');e.run();e.run()
        self.assertEqual(e.t.read()['state'],'COMPLETED');self.assertEqual(len(mutations),2)
    def test_unknown_partial_start_is_never_retransmitted(self):
        e,state,actual,producers,mutations=self.fixture(release=True);adapter=e.adapters['RELEASE_PRODUCERS'];native=adapter.engine.request
        def fail(method,path,body=None):
            if path.endswith('/start'):raise TimeoutError('fixture before unknown start acknowledgement')
            return native(method,path,body)
        adapter.engine.request=fail
        with self.assertRaises(TimeoutError):e.run()
        adapter.engine.request=native
        with self.assertRaises(CutoverDenied):e.run()
        self.assertEqual(mutations,[('2'*64,'update')]);self.assertEqual(e.t.read()['state'],'IN_FLIGHT')
    def test_old_registry_restart_blocks_release(self):
        e,state,actual,producers,mutations=self.fixture(release=True);e.run(10);producers['1'*64]['State']['Running']=True
        with self.assertRaises(ValueError):e.run()
        self.assertEqual(mutations,[])
    def test_replaced_cohort_generations_are_never_restarted(self):
        e,state,actual,producers,mutations=self.fixture(release=True,retire_all=True);e.run()
        self.assertEqual(mutations,[]);self.assertTrue(all(not v['State']['Running'] for v in producers.values()))
        self.assertEqual(e.t.read()['state'],'COMPLETED')

if __name__=='__main__':unittest.main()
