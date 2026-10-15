"""Real pure compiler bodies, byte custody and diagnostic privacy; no VPS I/O."""
import base64, contextlib, copy, hashlib, importlib.util, io, json, os
from pathlib import Path
import tempfile, unittest
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('paused_node_reader',ROOT/'scripts/read-chatbot-paused-node-20261015.py')
r=importlib.util.module_from_spec(spec);spec.loader.exec_module(r)

class Reader(unittest.TestCase):
    def sources(self):
        return {name:base64.b64encode((ROOT/'tools/semantic_cohort_admission/cohort-draft/tools'/(name.split('.')[-1]+'.py')).read_bytes()).decode()for name in r.PINS}
    def fixture(self):
        cfg={'commands':{'ip':{'path':'/pinned/ip'},'nsenter':{'path':'/pinned/nsenter'}},'candidate':{'networkBindings':[
            {'interface':'eth0','bridge':'br-fixture','mac':'02:42:aa:bb:cc:07','ipv4':'10.44.0.7','workloadRef':'fixture','bindingRef':'fixture-binding'}],
            'transport':[{'purpose':'IDENTITY','authorityRef':'fixture-authority','source':'10.44.0.7','destination':'10.55.0.9','protocol':'tcp','port':443,'peerIngress':{'kind':'HOST','ifindex':0}}],
            'tableName':'fixture_registry'}}
        p={'registry':{'nodeRecipe':{'observationConfiguration':cfg,'transactionId':'a'*64}}}
        child={'ifname':'eth0','ifindex':2,'link_index':55,'address':'02:42:aa:bb:cc:07','addr_info':[{'family':'inet','local':'10.44.0.7'}]}
        host={'ifindex':55,'ifname':'vethfixture','link_index':2,'master':'br-fixture'}
        oci={'linux':{'namespaces':[{'type':'network'}]}}
        def command(binding,args):return copy.deepcopy([host]if'link'in args else[child])
        return p,{'State':{'Pid':123}},oci,command
    def probe(self,p,n,oci,cmd):
        output=io.StringIO()
        with contextlib.redirect_stdout(output),patch.object(r,'proc_generation',return_value={'networkNamespaceInode':99}),patch.object(r,'command',side_effect=cmd),patch.object(r.socket,'if_indextoname',return_value='vethfixture'):
            result=r.network_probe(p,n,oci,'/approved/bundle',self.sources())
        return result,[json.loads(line)for line in output.getvalue().splitlines()]
    def test_actual_frozen_pure_admission_and_materializer_pass(self):
        p,n,oci,cmd=self.fixture();before=copy.deepcopy(p)
        result,rows=self.probe(p,n,oci,cmd)
        self.assertIsNone(result);self.assertEqual(rows[0]['status'],'PASS');self.assertEqual(p,before)
    def test_value_error_static_literal_is_visible_without_runtime_values(self):
        p,n,oci,cmd=self.fixture();p['registry']['nodeRecipe']['observationConfiguration']['candidate']['tableName']='DO_NOT_PRINT_PRIVATE_VALUE!'
        result,rows=self.probe(p,n,oci,cmd)
        self.assertEqual(result,'safe explicit kernel binding required');self.assertEqual(rows[0]['errorClass'],'ValueError')
        self.assertNotIn('DO_NOT_PRINT',json.dumps(rows));self.assertTrue(rows[0]['locations'])
    def test_changed_pinned_source_is_denied_before_execution(self):
        sources=self.sources();key=next(iter(sources));sources[key]=base64.b64encode(b'raise RuntimeError("MUST_NOT_EXECUTE")').decode()
        with self.assertRaisesRegex(r.ReadDenied,'PURE_SOURCE_PIN_DRIFT'):r.pure_network(sources)
    def test_namespace_or_link_drift_at_end_is_denied(self):
        p,n,oci,cmd=self.fixture();count=0
        def changed(binding,args):
            nonlocal count
            count+=1;value=cmd(binding,args)
            if count>2:value[0]['ifindex']=9876
            return value
        with self.assertRaisesRegex(r.ReadDenied,'NETWORK_PROBE_INPUT_OR_GENERATION_DRIFT'):self.probe(p,n,oci,changed)
    def test_dynamic_native_exception_message_is_never_printed(self):
        p,n,oci,cmd=self.fixture()
        def secret(*a):raise ValueError('DO_NOT_PRINT_PRIVATE_VALUE')
        ns,allow=r.pure_network(self.sources());ns['live_profile']=secret
        with patch.object(r,'pure_network',return_value=(ns,allow)):
            result,rows=self.probe(p,n,oci,cmd)
        self.assertIsNone(result);self.assertIsNone(rows[0]['sourceLiteralReason']);self.assertNotIn('DO_NOT_PRINT',json.dumps(rows))
    @unittest.skipUnless(os.geteuid()==0,'root custody fixture')
    def test_real_private_file_bound_symlink_and_hardlink_denial(self):
        with tempfile.TemporaryDirectory(dir=ROOT)as d:
            path=Path(d)/'record.json';path.write_bytes(b'{"state":"CANCELLED"}');path.chmod(0o600)
            self.assertEqual(r.read(path),{'state':'CANCELLED'})
            with self.assertRaisesRegex(r.ReadDenied,'PRIVATE_BOUNDED_RECORD_REQUIRED'):r.read(path,1)
            other=Path(d)/'link';os.link(path,other)
            with self.assertRaisesRegex(r.ReadDenied,'PRIVATE_BOUNDED_RECORD_REQUIRED'):r.read(path)
            other.unlink();other.symlink_to(path)
            with self.assertRaisesRegex(r.ReadDenied,'EXACT_READ_PATH_REQUIRED'):r.read(other)
    def test_projection_rejects_arbitrary_text(self):
        self.assertEqual(r.projection({'state':'CANCELLED','attempts':1,'secret':'HIDDEN'}),{'state':'CANCELLED','attempts':1})
        with self.assertRaises(r.ReadDenied):r.projection({'state':'secret value'})

if __name__=='__main__':unittest.main()
