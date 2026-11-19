import copy
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
def module(name,p):
    spec=importlib.util.spec_from_file_location(name,p);value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value
m=module('live_reader',ROOT/'reader.py')


class Tests(unittest.TestCase):
    def setUp(self):
        previous=module('composition_fixture',ROOT.parent/'semantic_registry_recovery_composition/tests/test_compose.py')
        fixture=previous.Tests();fixture.setUp()
        self.inputs=fixture.inputs;self.gateway=fixture.gateway;self.registry=fixture.registry
        self.case=json.loads((ROOT/'case.json').read_text());self.nid='e'*64
        self.route={'id':'fixture-semantic-resolve','uri':m.OPERATION,'methods':['GET'],'status':1,
                    'upstream':{'nodes':{'192.0.2.21:8080':1}}}
        self.routes={self.route['id']:self.route}
        self.request=self.inputs['registryInputs']['creationRequest']={'Image':fixture.iid,'Env':['PORT=8080'],
            'NetworkingConfig':{'EndpointsConfig':{'fixture':{'NetworkID':self.nid,'IPAMConfig':{'IPv4Address':'192.0.2.21'}}}}}
        self.gateway['NetworkSettings']={'Networks':{'fixture':{'NetworkID':self.nid}}}
        proposal=self.inputs['proposal'];proposal['gatewayBinding']['networkSettingsHash']=m.digest(self.gateway['NetworkSettings'])
        self.network={'Id':self.nid,'Driver':'bridge','EnableIPv6':False,'Containers':{}}
        self.profile={'config':{'path':'/fixture/config','sha256':'a'*64,'metadata':[]},'adminKey':{'fixture':'secret'}}
        self.gateway['Mounts']=[{'Destination':'/usr/local/apisix/conf/config.yaml','Source':'/fixture/config','Type':'bind','RW':False}]
        root=self.case['patchContext']
        self.packet={'routeDraft':{'afterRoutes':copy.deepcopy(self.routes)},'retainedGatewayConfig':copy.deepcopy(self.profile['config'])}
        self.review={'executionReview':{'stages':[{}]*12,'packetBinding':{'path':root+'/packet.json','sha256':m.digest(self.packet)},
                                      'gatewayTransportProfile':self.profile}}
        self.journal={'nextStage':12,'effects':[{'state':'APPLIED'}]*12}
        proposal.update(retainedPatchReviewHash=m.digest(self.review),retainedPatchJournalHash=m.digest(self.journal))
        self.case['inputsHash']=m.digest(self.inputs)
        self.composition={'inputsHash':self.case['inputsHash'],'runtimeAuthorityIssued':False,'targetApplyAuthorized':False}
        self.case['compositionHash']=m.digest(self.composition)
        self.files={self.case['inputsPath']:self.inputs,self.case['compositionPath']:self.composition,
            root+'/review.json':self.review,root+'/recovery.json':self.journal,root+'/packet.json':self.packet}

    def run_reader(self,drift=None):
        sequence=[self.gateway,self.registry,self.network,self.network,self.registry,self.gateway]
        if drift:sequence[drift[0]]=copy.deepcopy(sequence[drift[0]]);drift[1](sequence[drift[0]])
        self.paths=[]
        def get(engine,p):
            self.paths.append(p);engine.calls+=1;return m.encoded(sequence[engine.calls-1])
        with patch.object(m,'private_json',lambda p:(self.files[p],m.encoded(self.files[p]))),\
             patch.object(m.BaseEngine,'get',get),patch.object(m,'admin_routes',return_value=self.routes) as admin:
            result=m.run(self.case);self.assertEqual(admin.call_count,1);return result

    def test_full_read_correlates_current_target_with_stopped_reviewed_registry(self):
        result=self.run_reader()
        self.assertEqual(result['finding'],'LIVE_ADMIN_ROUTE_TARGETS_STOPPED_REVIEWED_REGISTRY_WITH_NO_NETWORK_ENDPOINT')
        self.assertEqual((result['engineGets'],result['adminGets']),(6,1))
        self.assertFalse(result['rootCauseEstablished']);self.assertFalse(result['dataPlaneRequestReproduced'])
        self.assertNotIn('192.0.2',json.dumps(result));self.assertNotIn('fixture-semantic',json.dumps(result))
        self.assertEqual(result['credentialFileReadOperations'],4)

    def test_changed_live_target_is_reported_without_selecting_a_replacement(self):
        self.route['upstream']['nodes']={'192.0.2.99:8080':1}
        result=self.run_reader()
        self.assertEqual(result['finding'],'LIVE_ADMIN_ROUTE_TARGET_DIFFERS_FROM_REVIEWED_REGISTRY')
        self.assertFalse(result['currentRouteEqualsRetainedSemanticRoute'])

    def test_endpoint_held_by_other_container_is_not_called_absent(self):
        self.network['Containers']={'f'*64:{'IPv4Address':'192.0.2.21/24'}}
        result=self.run_reader()
        self.assertEqual(result['currentTargetEndpointCount'],1)
        self.assertFalse(result['currentTargetEndpointIsReviewedRegistry'])
        self.assertEqual(result['finding'],'LIVE_ADMIN_ROUTE_TARGET_REQUIRES_FURTHER_RECONCILIATION')

    def test_network_drift_and_gateway_generation_changes_stop(self):
        for i,change in ((3,lambda r:r.update(Driver='other')),(5,lambda r:r['State'].update(Pid=99))):
            with self.subTest(i=i),self.assertRaises(m.Stop):self.run_reader((i,change))

    def test_wrong_private_hash_stops_before_admin_read(self):
        self.case['inputsHash']='0'*64
        with patch.object(m,'admin_routes',side_effect=AssertionError('no request')):
            with self.assertRaisesRegex(m.Stop,'EXACT_PRIVATE_INPUT_HASH_REQUIRED'):self.run_reader()

    def test_invalid_case_path_is_rejected_before_open(self):
        self.case['inputsPath']='/etc/credential.json'
        with patch.object(m,'private_json',side_effect=AssertionError('no open')):
            with self.assertRaisesRegex(m.Stop,'EXACT_RETAINED_DIAGNOSTIC_INPUT_PATH_REQUIRED'):m.run(self.case)

    def test_ambiguous_indirect_and_discovered_routes_stop(self):
        for change in ('duplicate','indirect','discovery','multiple'):
            routes=copy.deepcopy(self.routes)
            row=next(iter(routes.values()))
            if change=='duplicate':routes['other']={**row,'id':'other'}
            if change=='indirect':row['upstream_id']='id'
            if change=='discovery':row['upstream']['discovery_type']='dns'
            if change=='multiple':row['upstream']['nodes']['192.0.2.22:8080']=1
            with self.subTest(change=change),self.assertRaises(m.Stop):m.selected_route(routes)

    def test_route_map_normalization_matches_producer_contract(self):
        routes=m.route_map([{'value':{'value':{**self.route,'create_time':1,'update_time':2}}}])
        self.assertEqual(routes,self.routes)
        with self.assertRaises(m.Stop):m.route_map([self.route,self.route])

    def test_read_only_child_literal_denies_put_before_namespace_or_socket(self):
        # The exact sealed child used on target exits before setns for a mutation.
        import subprocess,sys
        result=subprocess.run([sys.executable,'-I','-B','-S','-c',m.CHILD_SOURCE,'0'],
            input=m.encoded({'method':'PUT','path':'/apisix/admin/routes','body':{},'key':'X'*32,'host':'127.0.0.1','port':9180}),
            capture_output=True,timeout=3)
        self.assertNotEqual(result.returncode,0);self.assertEqual(result.stdout,b'')

    def test_admin_request_uses_only_private_stdin_and_one_get(self):
        profile={'schema':'ouf.ingestion-rollout-gateway-transport.v1','endpoint':{'host':'127.0.0.1','port':9180},
            'pythonExecutable':{'path':'/usr/bin/python3','sha256':'a'*64},'config':{'name':'config'},'adminKey':{'name':'key'}}
        class Child:
            returncode=0
            stdin=None;stdout=None
            def communicate(child,request,timeout):
                self.sent=m.decode(request)
                return m.encoded({'status':200,'body':{'total':1,'list':[self.route]},'retryAfter':''}),b''
            def poll(child):return 0
            def wait(child,timeout):return 0
        import types
        info=types.SimpleNamespace(st_dev=1,st_ino=2)
        config=b'deployment:\n  admin:\n    admin_key:\n'
        def private(binding):return config if binding['name']=='config' else b'PRIVATE_KEY_VALUE_123456789'
        with patch.object(m,'verify_program'),patch.object(m,'read',side_effect=private),\
             patch.object(m,'process_ticks',return_value=42),patch.object(m.os,'open',return_value=9),\
             patch.object(m.os,'close'),patch.object(m.os,'stat',return_value=info),patch.object(m.os,'fstat',return_value=info),\
             patch.object(m.subprocess,'Popen',return_value=Child()) as launch:
            result=m.admin_routes(profile,self.gateway)
        self.assertEqual(result,self.routes);self.assertEqual(launch.call_count,1)
        self.assertEqual((self.sent['method'],self.sent['path'],self.sent['body']),('GET','/apisix/admin/routes',None))
        self.assertNotIn('PRIVATE_KEY',repr(launch.call_args))

    def test_budget_and_paths_rejected_before_engine_socket(self):
        engine=m.Engine({},'a'*64,'b'*64,'c'*64)
        for p,calls in (('/v1.44/containers/json',0),(engine.network_path,6)):
            engine.calls=calls
            with patch.object(engine,'check',side_effect=AssertionError('no socket')):
                with self.assertRaises(m.Stop):engine.get(p)

    def test_error_redaction(self):
        self.assertNotIn('PRIVATE_KEY',json.dumps(m.stopped(RuntimeError('PRIVATE_KEY'))))


if __name__=='__main__':unittest.main()
