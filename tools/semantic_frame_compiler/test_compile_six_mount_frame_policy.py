"""Independent declared inputs, never observed OCI or target authority."""
import copy,unittest
import ast,hashlib,sys,types
from pathlib import Path
if 'review_semantic_oci_policy' not in sys.modules:
    # Same pinned reviewer used by existing compiler/native fixtures; parse
    # literal source only, never execute the frame-observer wrapper.
    tree=ast.parse(Path(__file__).with_name('frame-observer.py').read_text())
    sources=next(ast.literal_eval(n.value) for n in tree.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='SOURCES' for t in n.targets))
    source=sources['review_semantic_oci_policy']
    assert hashlib.sha256(source.encode()).hexdigest()=='d35123954e91fc463a3ad78cedeeb2284c0106c22de48780e1128178c72a4eb6'
    reviewer=types.ModuleType('review_semantic_oci_policy')
    exec(compile(source,'<pinned-compiler-fixture-reviewer>','exec'),reviewer.__dict__)
    sys.modules[reviewer.__name__]=reviewer
# Existing fixture setUp reads the separately pinned schema next to its module.
tree=ast.parse(Path(__file__).with_name('frame-observer.py').read_text())
schema=next(ast.literal_eval(n.value) for n in tree.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='SCHEMA_BYTES' for t in n.targets))
assert hashlib.sha256(schema).hexdigest()=='d8f2196b2f0e22c448942d46e25a775d4ffc7284b72435e04633ec9cb08b5368'
schema_path=Path(__file__).with_name('semantic_oci_shape_schema.json')
if not schema_path.exists():schema_path.write_bytes(schema)
assert schema_path.read_bytes()==schema
import test_compile_projected_frame_policy as previous
from compile_six_mount_frame_policy import compile_policy,compilation_receipt,Denied

class SixCompiler(unittest.TestCase):
    def setUp(self):
        f=previous.ProjectedCompiler();f.setUp()
        self.template,self.launch,self.context,self.tree=f.template,f.launch,f.context,f.tree
        self.key={'source':'/approved/original-key','target':'/run/original-key','readOnly':True,'uid':10001,'gid':10001,'mode':0o400,'maxBytes':4096,'sha256':'f'*64}
        self.launch['sources'].append(self.key)
        self.token={'source':'/approved/token-root','target':'/run/token-root','fileName':'token.jwt','gid':10001,'directoryDevice':1,'directoryInode':2,'ownerBindingHash':'a'*64,'maxBytes':16384,'minimumRemainingSeconds':30}
        binds=[{k:s[k] for k in ('source','target','readOnly')} for s in self.launch['sources']]
        binds+=[{k:self.tree[k] for k in ('source','target','readOnly')},{k:self.token[k] for k in ('source','target')}|{'readOnly':True}]
        self.launch['manifest']['mounts']=binds
        for item in (binds[3],binds[5]):
            self.template['expectedOci']['mounts'].append({'type':'bind','source':item['source'],'destination':item['target'],'options':['rbind','rprivate','ro']})
    def compile(self):
        return compile_policy(self.template,self.launch,self.context,configtree=self.tree,renewable_token=self.token,delegation_key_metadata_hash='b'*64)
    def test_independent_six_mount_compile_preserves_inputs_and_grants_nothing(self):
        original=copy.deepcopy((self.template,self.launch,self.context,self.token))
        result=self.compile()
        self.assertEqual(result['schema'],'ouf.semantic-configured-six-mount-frame-policy.v1')
        self.assertEqual(len(result['manifest']['mounts']),6);self.assertEqual(len(result['sources']),4)
        self.assertEqual(result['delegationKeyMetadataHash'],'b'*64)
        self.assertEqual(original,(self.template,self.launch,self.context,self.token))
        receipt=compilation_receipt(self.template,self.launch,self.context,result)
        self.assertFalse(receipt['observedOciUsed']);self.assertFalse(receipt['inputsAuthenticated'])
        self.assertFalse(receipt['acceptanceGranted']);self.assertEqual(receipt['signaturesIssued'],0)
    def test_root_owner_profile_and_static_key_drift_are_denied(self):
        for name,value in [('gid',0),('directoryInode',0),('ownerBindingHash','bad'),('fileName','../token'),('maxBytes',16385)]:
            saved=self.token[name];self.token[name]=value
            with self.assertRaises(Denied):self.compile()
            self.token[name]=saved
        self.key['mode']=0o600
        with self.assertRaises(Denied):self.compile()
    def test_rw_shared_missing_and_shadow_token_mount_are_denied(self):
        mount=self.template['expectedOci']['mounts'][-1];saved=copy.deepcopy(mount)
        for options in (['rbind','rw'],['rbind','ro','rshared']):
            mount['options']=options
            with self.assertRaises(Denied):self.compile()
        mount.clear();mount.update(saved);self.token['target']='/run/private-configtree/token'
        with self.assertRaises(Denied):self.compile()
    def test_original_launch_and_template_identity_cannot_be_silently_changed(self):
        self.launch['startup']['args']=['unapproved']
        with self.assertRaises(Denied):self.compile()
    def test_actual_oci_cannot_be_used_as_template(self):
        compiled=self.compile();self.template['expectedOci']=compiled['expectedOci']
        with self.assertRaises(Denied):self.compile()

if __name__=='__main__':unittest.main()
