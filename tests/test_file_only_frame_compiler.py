import copy,sys,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'tests'),str(ROOT/'tools/semantic_application_cutover'),str(ROOT/'tools/semantic_frame_compiler')]
from test_file_only_cutover import inputs
from file_only_profile import FileOnlyProfile
from compile_file_only_frame_policy import compile_policy

class FourMountCompiler(unittest.TestCase):
    def fixture(self):
        request,db=inputs();profile=FileOnlyProfile(request,db)
        files=[{'source':'/fixture/delegation.key','target':'/run/ouf/delegation.key','readOnly':True,'uid':10001,'gid':10001,'mode':0o400,'maxBytes':64,'sha256':'d'*64},
            {'source':'/fixture/proposal.key','target':'/run/ouf/proposal.key','readOnly':True,'uid':0,'gid':10001,'mode':0o440,'maxBytes':64,'sha256':'e'*64}]
        token={'source':'/fixture/token','target':'/run/ouf/policy','fileName':'token','gid':10001,'directoryDevice':1,'directoryInode':2,
            'ownerBindingHash':'f'*64,'maxBytes':8192,'minimumRemainingSeconds':30}
        bindings=[{k:v[k] for k in ('source','target','readOnly')} for v in files]
        bindings+=[{k:db[k] for k in ('source','target','readOnly')},{k:token[k] for k in ('source','target')}|{'readOnly':True}]
        startup={'uid':10001,'gid':10001,'umask':None,'cwd':'/app','args':request['Entrypoint'], 'env':request['Env']+['HOSTNAME=$OUF_HOSTNAME']}
        launch={'schema':'ouf.semantic-creation-frame-launch.v1','startup':startup,'sources':files,
            'manifest':{'user':'10001:10001','readOnlyRoot':False,'memoryBytes':123456,'pidsLimit':128,'mounts':bindings}}
        mounts=[{'type':'bind','destination':b['target'],'source':b['source'],'options':['rbind','rprivate','ro']} for b in bindings]
        mounts+=[{'type':'bind','destination':target,'source':source,'options':['rbind','rprivate','ro']}
            for target,source in (('/etc/hosts','$OUF_HOSTS'),('/etc/hostname','$OUF_HOSTNAME_FILE'),('/etc/resolv.conf','$OUF_RESOLV'))]
        template={'schema':'ouf.semantic-creation-frame-template.v1','approvedHooks':{},'expectedOci':{'hostname':'$OUF_HOSTNAME',
            'root':{'path':'$OUF_ROOTFS','readonly':False},'process':{'user':{'uid':10001,'gid':10001},'args':startup['args'],'cwd':'/app','env':startup['env']},
            'mounts':mounts,'linux':{'cgroupsPath':'$OUF_CGROUPS','namespaces':[{'type':'network','path':'$OUF_NETWORK_NAMESPACE'}],
                'resources':{'memory':{'limit':123456,'swap':123456},'pids':{'limit':128}}}}}
        context={'schema':'ouf.semantic-docker-frame-context.v1','containerId':'a'*64,'bundleParent':'/run/docker/bundles',
            'metadataParent':'/var/lib/docker/containers','networkNamespaceParent':'/run/docker/netns','networkNamespaceName':'b'*12,
            'cgroupDriver':'systemd','storageParent':'/var/lib/docker','rootfsPath':'/var/lib/docker/overlay/merged'}
        args={'execution_profile':profile,'renewable_token':token,'delegation_key_metadata_hash':'c'*64,'proposal_receipt_key':files[1]|{'metadataHash':'8'*64}}
        return template,launch,context,args
    def test_preserves_independent_template_and_uses_exact_four_inputs(self):
        t,l,c,a=self.fixture();before=copy.deepcopy((t,l,c));result=compile_policy(t,l,c,**a)
        self.assertEqual((t,l,c),before);self.assertEqual(len(result['manifest']['mounts']),4)
        self.assertEqual(result['executionProfileHash'],a['execution_profile'].sha256)
        self.assertEqual([m['destination'] for m in result['expectedOci']['mounts']],[m['destination'] for m in t['expectedOci']['mounts']])
        self.assertEqual(result['sources'],l['sources']);self.assertNotIn('$OUF_',str(result))
    def test_flags_inherited_environment_mount_shadow_or_wrong_key_rejected(self):
        for kind in ('env','readonly','shadow','key','owner'):
            t,l,c,a=self.fixture()
            if kind=='env':l['startup']['env'].append('JAVA_TOOL_OPTIONS=-Doverride=true')
            if kind=='readonly':t['expectedOci']['mounts'][3]['options']=['rw']
            if kind=='shadow':a['renewable_token']['target']='/run/db/token'
            if kind=='key':a['proposal_receipt_key']['uid']=10001
            if kind=='owner':a['renewable_token']['ownerBindingHash']='invalid'
            with self.assertRaises(ValueError):compile_policy(t,l,c,**a)
    def test_no_policy_can_be_derived_from_foreign_or_extra_context(self):
        t,l,c,a=self.fixture();c['observedOci']=t['expectedOci']
        with self.assertRaises(ValueError):compile_policy(t,l,c,**a)
    def test_future_output_is_explicit_proposal_and_cannot_mix_invented_inode(self):
        t,l,c,a=self.fixture();token=a['renewable_token']
        token.pop('directoryDevice');token.pop('directoryInode');token['directoryCustodyScopeHash']='7'*64
        result=compile_policy(t,l,c,**a)
        self.assertEqual(result['schema'],'ouf.semantic-configured-file-only-four-mount-frame-policy.v2-proposal')
        self.assertNotIn('directoryInode',result['renewableToken'])
        token['directoryInode']=1
        with self.assertRaisesRegex(ValueError,'EXACT_FILE_ONLY_RENEWABLE_TOKEN'):compile_policy(t,l,c,**a)

if __name__=='__main__':unittest.main()
