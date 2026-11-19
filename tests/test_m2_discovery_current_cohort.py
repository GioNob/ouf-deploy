"""Real parent Ed25519 and local Unix Engine peer; cohort leaves are modeled.

No Docker lifecycle, SQL, TLS, IAM, lease, target admission or E2E is exercised.
"""
import copy,http.server,json,os,socketserver,sys,threading,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tests')]+[str(ROOT/'tools'/p) for p in
    ('semantic_application_cutover','semantic_frame_compiler','semantic_database_cutover','semantic_policy_token_owner',
     'semantic_lease_recovery','semantic_transaction_profiles','semantic_cohort_admission/cohort-draft')]
import test_m2_discovery_parent_authority as crypto
from tools.m2_discovery_installation_profile import current_cohort as m


def pin(pid):return {'pid':pid,'startTicks':pid*10,'namespaces':{'net':[1,2],'mnt':[1,3]}}
def fixture():
    peers={}
    for i,role in enumerate(sorted(m.ROLES),1):
        name='/ouf-'+('gateway-operational-owner' if role=='gateway-owner' else role)
        if role=='semantic':name='/ouf-semantic-cutover-'+'a'*64
        peers[role]={'name':name,'runtimeBinding':{'containerId':format(i,'064x'),'imageId':'sha256:'+'b'*64,
            'pid':100+i,'startedAt':'fixture-only','configHash':'c'*64,'hostConfigHash':'d'*64,
            'mountsHash':'e'*64,'networkSettingsHash':'f'*64},'processPin':pin(100+i)}
    return {'schema':m.INPUT_SCHEMA,'sourceClosureHash':'a'*64,'installationInputsHash':'b'*64,
        'desiredProfileHash':'c'*64,'cohortManifestHash':'d'*64,'bootId':'11111111-1111-1111-1111-111111111111',
        'engineBinding':{'socketPath':'/run/fixture.sock','socketBinding':[1,2,0,0,0o600],
            'peerCredentials':[9,0,0],'startTicks':90},'rootProcessPins':{'pid1':pin(1),'engine':pin(9)},'peers':peers}


class Cohort(unittest.TestCase):
    setUp=crypto.Parent.setUp
    native=crypto.Parent.native
    write=crypto.Parent.write
    binding=crypto.Parent.binding
    sign=crypto.Parent.sign
    authority=crypto.Parent.fixture

    def owner(self,quiesced=None):
        inputs=fixture();component={k:inputs[k] for k in ('sourceClosureHash','installationInputsHash','desiredProfileHash')}
        component.update(gatewayRuntime={'schema':'explicit.gateway.fixture'},mcp={'schema':'explicit.mcp.fixture'})
        component['currentAdmission']={'schema':'ouf.discovery-current-cohort-review-requirements.v1',
            'cohortManifestHash':inputs['cohortManifestHash'],'registryCreationRequestHash':'9'*64,
            'gatewayRuntimeHash':m.digest(component['gatewayRuntime']),'mcpComponentHash':m.digest(component['mcp']),
            'requiredProofs':list(m.REQUIRED_PROOFS),'mustBeCurrentAtExecution':True,'historicalEvidenceSufficient':False}
        self.review['components']['cohortInstallation']=component
        old=copy.deepcopy(self.review);self.review=m.bind_runtime_review(self.review,inputs);parent=self.authority(seconds=300)
        selected=object.__new__(m.DiscoverySelectedRuntime);engine=object.__new__(m.Engine)
        selected.images=SimpleNamespace(parent=parent,component=self.review['components']['cohortInstallation'],engine=engine)
        selected.guard=lambda:parent.guard('cohortInstallation',selected.images.component) # modeled native owner lineage
        row={'state':'READY','nextPhase':12,'version':42}
        def held(expected=None):
            self.assertTrue(expected is None or row==expected);return copy.deepcopy(row)
        selected.held=held
        ids={r:v['runtimeBinding']['containerId'] for r,v in inputs['peers'].items()}
        app=SimpleNamespace(request_hash='9'*64,intents={'RELEASE_OLD_ENDPOINT':{'containerId':ids['semantic']},
            'QUIESCE_PRODUCERS':{'producerBindings':[] if quiesced is None else [{'containerId':ids[quiesced]}]}})
        selected.installation=SimpleNamespace(application=app)
        selected.mcp=SimpleNamespace(plan={'replacement':{'oldRuntimeBinding':{'containerId':ids['mcp']}}})
        selected.gateway=SimpleNamespace(plan={'oldRuntimeBinding':{'containerId':ids['apisix']}})
        return m.CurrentCohortRuntime(selected,inputs),parent,old

    def test_new_review_binds_runtime_inputs_and_preserves_old_review(self):
        owner,parent,old=self.owner()
        self.assertEqual(old['components']['cohortInstallation']['currentAdmission']['schema'],
            'ouf.discovery-current-cohort-review-requirements.v1')
        self.assertEqual(parent.review['components']['cohortInstallation']['currentAdmission']['nativeRuntimeInputsHash'],owner.input_hash)
        self.assertNotEqual(m.review_scope(old)['reviewHash'],parent.scope['reviewHash'])

    def test_unbound_input_drift_and_signature_revocation_are_denied(self):
        owner,parent,_=self.owner();owner.inputs['peers']['onboarding']['processPin']['startTicks']+=1
        with self.assertRaises(ValueError):owner.guard()
        owner.inputs['peers']['onboarding']['processPin']['startTicks']-=1
        (self.signatures/(parent.sha+'.FINAL_DEPLOYMENT_APPROVAL.json')).unlink()
        with self.assertRaises((OSError,ValueError)):owner.guard()

    def test_onboarding_quiescence_is_rejected_before_any_engine_read(self):
        with self.assertRaisesRegex(ValueError,'CONTROL_PLANE_MUST_REMAIN_REACHABLE'):self.owner('onboarding')

    def test_only_exact_thirteen_names_generations_and_root_engine_are_reviewable(self):
        original=fixture()
        def check(change):
            bad=copy.deepcopy(original);change(bad)
            with self.assertRaises(ValueError):m.validate_inputs(bad)
        check(lambda i:i['peers'].pop('minio'))
        check(lambda i:i['peers']['onboarding'].update(name='/ouf-unreviewed'))
        check(lambda i:i['peers']['minio']['runtimeBinding'].update(containerId=i['peers']['caddy']['runtimeBinding']['containerId']))
        check(lambda i:i['engineBinding'].update(peerCredentials=[9,1000,0]))
        check(lambda i:i['rootProcessPins']['engine'].update(startTicks=91))
        check(lambda i:i['peers']['onboarding']['processPin']['namespaces'].update(net=[True,2]))

    def native_server(self):
        path=self.root/'e.sock';seen=[]
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(handler):
                seen.append((handler.command,handler.path));raw=b'{"nativeUnixPeerFixture":true}'
                handler.send_response(200);handler.send_header('Content-Length',str(len(raw)));handler.end_headers();handler.wfile.write(raw)
            def log_message(*a):pass
        server=socketserver.UnixStreamServer(str(path),Handler);path.chmod(0o600)
        thread=threading.Thread(target=lambda:server.serve_forever(poll_interval=.02),daemon=True);thread.start()
        self.addCleanup(lambda:(server.shutdown(),server.server_close(),thread.join(timeout=2)))
        process=m.process_pin(os.getpid());s=path.stat();socket_binding=[s.st_dev,s.st_ino,s.st_uid,s.st_gid,0o600]
        engine=m.Engine(str(path),tuple(socket_binding))
        binding={'socketPath':str(path),'socketBinding':socket_binding,'peerCredentials':[os.getpid(),0,0],
            'startTicks':process['startTicks']}
        ids=[v['runtimeBinding']['containerId'] for v in fixture()['peers'].values()]
        return m.CurrentCohortEngine(engine,binding,ids,m.ObservationBudget(30)),ids,seen

    def test_real_unix_socket_peer_gets_are_bounded_to_twenty_six(self):
        reader,ids,seen=self.native_server()
        for _ in range(2):
            for cid in ids:self.assertEqual(reader.get(cid),{'nativeUnixPeerFixture':True})
        with self.assertRaisesRegex(ValueError,'ALLOWLIST'):reader.get(ids[0])
        self.assertEqual(len(seen),26);self.assertEqual({method for method,_ in seen},{'GET'})

    def test_wrong_engine_peer_and_unlisted_path_never_return_a_positive_read(self):
        reader,ids,seen=self.native_server()
        with self.assertRaisesRegex(ValueError,'ALLOWLIST'):reader.get('f'*64)
        self.assertEqual(seen,[])
        reader.binding['peerCredentials'][1]=123
        with self.assertRaisesRegex(ValueError,'PEER_CREDENTIALS_CHANGED'):reader.get(ids[0])
        self.assertEqual(seen,[])

    def observe_fixture(self,owner,mutate=None):
        peers=owner.inputs['peers'];actual={};selected={}
        for role,p in peers.items():
            row={'Id':p['runtimeBinding']['containerId'],'Image':p['runtimeBinding']['imageId'],'Config':{},'HostConfig':{},
                'Mounts':[],'NetworkSettings':{},'Name':p['name'],'RestartCount':0,
                'State':{'Pid':p['runtimeBinding']['pid'],'StartedAt':'fixture-only','Running':True,'Paused':False,'Restarting':False,'Status':'running'}}
            # Keep independently signed retained configuration hashes equal to the modeled fixture's actual metadata.
            actual[role]=row
            if role in m.REPLACED:
                selected[role]=m.Engine.runtime_binding(row)
        class Reader:
            def __init__(reader,*a):reader.reads=0
            def get(reader,cid):
                reader.reads+=1
                if mutate:mutate(reader.reads,actual)
                return copy.deepcopy(next(v for v in actual.values() if v['Id']==cid))
        with patch.object(owner,'roots'),patch.object(owner,'selected_now',return_value=selected), \
             patch.object(m,'CurrentCohortEngine',Reader),patch.object(m,'process_pin',side_effect=pin):
            return owner.observe()

    def test_current_runtime_roster_requires_two_matching_native_passes(self):
        owner,parent,_=self.owner()
        # Rebind synthetic reviewed hashes before issuing a NEW fixture parent, never mutate authenticated scope.
        inputs=copy.deepcopy(owner.inputs)
        for p in inputs['peers'].values():
            for k in ('configHash','hostConfigHash','networkSettingsHash'):p['runtimeBinding'][k]=m.digest({})
            p['runtimeBinding']['mountsHash']=m.digest([])
        old=copy.deepcopy(self.review);old['components']['cohortInstallation']['currentAdmission']=copy.deepcopy(
            self.review['components']['cohortInstallation']['currentAdmission']['requirements'])
        self.review=m.bind_runtime_review(old,inputs);parent=self.authority(seconds=300)
        owner.selected.images.parent=parent;owner.selected.images.component=self.review['components']['cohortInstallation']
        owner.selected.guard=lambda:parent.guard('cohortInstallation',owner.selected.images.component)
        owner=m.CurrentCohortRuntime(owner.selected,inputs)
        proof=self.observe_fixture(owner)
        self.assertEqual((proof['peerCount'],proof['engineGets']),(13,26));self.assertTrue(proof['currentRuntimeRosterObserved'])
        for field in ('fullCohortProven','tlsIamDatabaseLeaseAdmissionProvenHere','producerReleaseDispatched','runtimeAuthorityIssued','releaseAcceptance'):
            self.assertIs(proof[field],False)
        def drift(count,actual):
            if count==14:actual['onboarding']['State']['Paused']=True
        with self.assertRaisesRegex(ValueError,'RUNNING_GENERATION_CHANGED'):self.observe_fixture(owner,drift)

if __name__=='__main__':unittest.main()
