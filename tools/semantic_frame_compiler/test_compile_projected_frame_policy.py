"""Independent synthetic template compilation; no native/target approval."""
import copy,unittest
import test_compile_creation_frame_policy as fixture_module
from compile_projected_frame_policy import compile_policy,Denied

class ProjectedCompiler(unittest.TestCase):
    def setUp(self):
        fixture=fixture_module.CompilerTests();fixture.setUp();self.template=fixture.template;self.launch=fixture.launch;self.context=fixture.context
        self.launch['startup']['uid']=self.launch['startup']['gid']=10001
        self.launch['manifest']['user']='10001:10001'
        self.template['expectedOci']['process']['user']={'uid':10001,'gid':10001}
        for s in self.launch['sources']:s['uid']=s['gid']=10001
        for i in range(2):
            source={'source':'/approved/role-'+str(i)+'.json','target':'/run/role-'+str(i)+'.json','readOnly':True}
            self.launch['manifest']['mounts'].append(source)
            self.launch['sources'].append({**source,'uid':10001,'gid':10001,'mode':0o400,'maxBytes':4096,'sha256':'d'*64})
            self.template['expectedOci']['mounts'].append({'type':'bind','source':source['source'],'destination':source['target'],'options':['rbind','rprivate','ro']})
        self.tree={'source':'/approved/private-configtree','target':'/run/private-configtree','readOnly':True,'uid':10001,'gid':10001,
                   'directoryMode':0o500,'fileName':'OUF_SEM_DB_PASSWORD','fileMode':0o400,'maxBytes':4096,'sha256':'e'*64}
        self.launch['manifest']['mounts'].append({k:self.tree[k] for k in ('source','target','readOnly')})
        self.template['expectedOci']['mounts'].append({'type':'bind','source':self.tree['source'],'destination':self.tree['target'],'options':['rbind','rprivate','ro']})
    def compile(self):return compile_policy(self.template,self.launch,self.context,configtree=self.tree)
    def test_compiles_four_input_policy_without_observed_oci_or_authority(self):
        result=self.compile();self.assertEqual(result['schema'],'ouf.semantic-configured-projected-frame-policy.v1')
        self.assertEqual(len(result['sources']),3);self.assertEqual(result['configtree'],self.tree)
        self.assertEqual(result['expectedOci']['process']['user']['uid'],10001)
        self.assertEqual(self.template['expectedOci']['root']['path'],'$OUF_ROOTFS')
    def test_directory_privilege_path_bound_hash_and_permission_drift_denied(self):
        for field,value in [('directoryMode',0o700),('fileMode',0o600),('uid',0),('readOnly',False),('fileName','../PASSWORD'),('maxBytes',1048577),('sha256','bad')]:
            original=self.tree[field];self.tree[field]=value
            with self.assertRaises(Denied):self.compile()
            self.tree[field]=original
    def test_missing_extra_or_changed_mount_cannot_pass_directory_policy(self):
        original=copy.deepcopy(self.launch)
        self.launch['sources'].pop()
        with self.assertRaises(Denied):self.compile()
        self.launch=original;self.launch['manifest']['mounts'][-1]['target']='/different'
        with self.assertRaises(Denied):self.compile()
    def test_recursive_writable_or_shared_directory_bind_denied(self):
        mount=self.template['expectedOci']['mounts'][-1]
        for options in (['rbind','rw'],['rbind','ro','rshared']):
            mount['options']=options
            with self.assertRaises(Denied):self.compile()

if __name__=='__main__':unittest.main()
