"""Prepare an exact private correction; never issue authority or write routes."""
import ast,copy,importlib.util,json,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('upstream_prepare',ROOT/'scripts/prepare-chatbot-semantic-upstream-repair-20261016.py')
r=importlib.util.module_from_spec(spec);spec.loader.exec_module(r)
class Preparation(unittest.TestCase):
    def fixture(self):
        def route(name):return {'id':name,'uri':'/internal/capabilities/v1/execute/semantic/'+name,
            'upstream':{'scheme':'http','nodes':{'old-registry:8080':1}},'plugins':{'fixed':{'value':'unchanged'}}}
        routes={v:route(v)for v in ('search','get')};routes['unrelated']={'id':'unrelated','uri':'/preserved','upstream':{'nodes':{'other:8080':1}}}
        plan={'upstreamBindings':{'ouf-semantic-registry':{'alias':'old-registry','port':8080,'networkId':'network'}},'proposedRoutes':routes}
        registry={'Name':'/current-registry','NetworkSettings':{'Networks':{'selected':{'NetworkID':'network','IPAddress':'127.0.0.1'}}}}
        request={'NetworkingConfig':{'EndpointsConfig':{'selected':{'NetworkID':'network','IPAMConfig':{'IPv4Address':'127.0.0.1'}}}}}
        return plan,registry,request
    def test_only_selected_registry_nodes_change_and_every_other_field_is_preserved(self):
        plan,registry,request=self.fixture();saved=copy.deepcopy(plan)
        from unittest.mock import patch
        with patch.object(r,'runtime_pin',return_value={'containerId':'current'}):result=r.compile_binding_repair(plan,registry,request)
        self.assertEqual(plan,saved);self.assertEqual(len(result['changes']),2)
        self.assertEqual(result['proposedRoutes']['unrelated'],saved['proposedRoutes']['unrelated'])
        for row in result['changes']:
            normalized=copy.deepcopy(row['after']);normalized['upstream']['nodes']=row['before']['upstream']['nodes']
            self.assertEqual(normalized,row['before']);self.assertEqual(row['after']['upstream']['nodes'],{'127.0.0.1:8080':1})
        for name in ('runtimeAuthorityIssued','databaseRestoreAuthorized','serviceLifecycleAuthorized','newGrantAuthorized','automaticWriteReplayAllowed','budgetReset'):
            self.assertFalse(result[name])
    def test_missing_reviewed_binding_blocks(self):
        plan,registry,request=self.fixture();plan['upstreamBindings']={}
        with self.assertRaisesRegex(r.ReadDenied,'RETAINED_REVIEWED'):r.compile_binding_repair(plan,registry,request)
    def test_same_name_and_collision_block(self):
        plan,registry,request=self.fixture();plan['upstreamBindings']['ouf-semantic-registry']['alias']='127.0.0.1'
        with self.assertRaisesRegex(r.ReadDenied,'DISTINCT_CURRENT'):r.compile_binding_repair(plan,registry,request)
        plan['upstreamBindings']['ouf-semantic-registry']['alias']='old-registry';plan['proposedRoutes']['get']['upstream']['nodes']['127.0.0.1:8080']=1
        with self.assertRaisesRegex(r.ReadDenied,'NODE_COLLISION'):r.compile_binding_repair(plan,registry,request)
    def test_wrong_semantic_selector_blocks(self):
        plan,registry,request=self.fixture();plan['proposedRoutes']['get']['uri']='/not-semantic-get'
        with self.assertRaisesRegex(r.ReadDenied,'SEMANTIC_BINDINGS_NOT_INCLUDED'):r.compile_binding_repair(plan,registry,request)
    def test_http_remains_get_only_and_old_native_transport_is_identical(self):
        source=Path(r.__file__).read_text();old=ast.parse((ROOT/'scripts/read-chatbot-semantic-upstream-20261016.py').read_text());new=ast.parse(source)
        for name in ('engine_get','gateway_read','gateway_check','transport_binding','resolver_selection'):
            a=next(x for x in old.body if isinstance(x,ast.FunctionDef)and x.name==name)
            b=next(x for x in new.body if isinstance(x,ast.FunctionDef)and x.name==name)
            self.assertEqual(ast.dump(a),ast.dump(b))
        for text in (source,r.GET_CHILD,r.DNS_CHILD):
            for node in ast.walk(ast.parse(text)):
                if isinstance(node,ast.Call)and isinstance(node.func,ast.Attribute)and node.func.attr=='request':
                    self.assertEqual(ast.literal_eval(node.args[0]),'GET')
        self.assertNotIn('APPROVO',source);self.assertNotIn('ExistingEd25519Signer',source)
    def test_static_address_must_match_both_reviewed_request_and_current_network(self):
        plan,registry,request=self.fixture();request['NetworkingConfig']['EndpointsConfig']['selected']['IPAMConfig']['IPv4Address']='127.0.0.2'
        with self.assertRaisesRegex(r.ReadDenied,'STATIC_REGISTRY_ADDRESS_DRIFT'):r.compile_binding_repair(plan,registry,request)
    def test_native_updated_dns_child_retains_dns_and_tcp_qualification(self):
        spec=importlib.util.spec_from_file_location('previous_upstream_native_test',ROOT/'tests/test_gateway_semantic_upstream_readback.py')
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        from unittest.mock import patch
        instance=module.SemanticUpstream('test_native_dns_and_tcp_child_classifies_match_without_returning_addresses')
        try:
            with patch.object(module.r,'DNS_CHILD',r.DNS_CHILD):
                instance.test_native_dns_and_tcp_child_classifies_match_without_returning_addresses()
        finally:instance.doCleanups()
if __name__=='__main__':unittest.main()
