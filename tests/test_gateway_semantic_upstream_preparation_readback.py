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
        plan={'upstreamBindings':{'ouf-semantic-registry':{'alias':'old-registry','port':8080}},'proposedRoutes':routes}
        registry={'Name':'/current-registry'}
        return plan,registry
    def test_only_selected_registry_nodes_change_and_every_other_field_is_preserved(self):
        plan,registry=self.fixture();saved=copy.deepcopy(plan)
        from unittest.mock import patch
        with patch.object(r,'runtime_pin',return_value={'containerId':'current'}):result=r.compile_binding_repair(plan,registry)
        self.assertEqual(plan,saved);self.assertEqual(len(result['changes']),2)
        self.assertEqual(result['proposedRoutes']['unrelated'],saved['proposedRoutes']['unrelated'])
        for row in result['changes']:
            normalized=copy.deepcopy(row['after']);normalized['upstream']['nodes']=row['before']['upstream']['nodes']
            self.assertEqual(normalized,row['before']);self.assertEqual(row['after']['upstream']['nodes'],{'current-registry:8080':1})
        for name in ('runtimeAuthorityIssued','databaseRestoreAuthorized','serviceLifecycleAuthorized','newGrantAuthorized','automaticWriteReplayAllowed','budgetReset'):
            self.assertFalse(result[name])
    def test_missing_reviewed_binding_blocks(self):
        plan,registry=self.fixture();plan['upstreamBindings']={}
        with self.assertRaisesRegex(r.ReadDenied,'RETAINED_REVIEWED'):r.compile_binding_repair(plan,registry)
    def test_same_name_and_collision_block(self):
        plan,registry=self.fixture();registry['Name']='/old-registry'
        with self.assertRaisesRegex(r.ReadDenied,'DISTINCT_CURRENT'):r.compile_binding_repair(plan,registry)
        registry['Name']='/current-registry';plan['proposedRoutes']['get']['upstream']['nodes']['current-registry:8080']=1
        with self.assertRaisesRegex(r.ReadDenied,'NODE_COLLISION'):r.compile_binding_repair(plan,registry)
    def test_wrong_semantic_selector_blocks(self):
        plan,registry=self.fixture();plan['proposedRoutes']['get']['uri']='/not-semantic-get'
        with self.assertRaisesRegex(r.ReadDenied,'SEMANTIC_BINDINGS_NOT_INCLUDED'):r.compile_binding_repair(plan,registry)
    def test_http_remains_get_only_and_old_native_transport_is_identical(self):
        source=Path(r.__file__).read_text();old=ast.parse((ROOT/'scripts/read-chatbot-semantic-upstream-20261016.py').read_text());new=ast.parse(source)
        for name in ('engine_get','gateway_read','gateway_check','transport_binding','upstream_metadata','resolver_selection'):
            a=next(x for x in old.body if isinstance(x,ast.FunctionDef)and x.name==name)
            b=next(x for x in new.body if isinstance(x,ast.FunctionDef)and x.name==name)
            self.assertEqual(ast.dump(a),ast.dump(b))
        for text in (source,r.GET_CHILD,r.DNS_CHILD):
            for node in ast.walk(ast.parse(text)):
                if isinstance(node,ast.Call)and isinstance(node.func,ast.Attribute)and node.func.attr=='request':
                    self.assertEqual(ast.literal_eval(node.args[0]),'GET')
        self.assertNotIn('APPROVO',source);self.assertNotIn('ExistingEd25519Signer',source)
if __name__=='__main__':unittest.main()
