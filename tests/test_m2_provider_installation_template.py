"""Pure independent provider expectations; no native or application admission."""
import copy,json,sys,types,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tools/semantic_frame_compiler'),str(ROOT/'tools/semantic_cohort_admission/cohort-draft')]
from tools.m2_discovery_installation_profile import provider_installation_template as m

def inputs():
    baseline=json.loads((ROOT/'tools/semantic_frame_compiler/containerd-overlayfs-southbound.json').read_text())
    f=types.SimpleNamespace(template=baseline['template'],launch=baseline['launch'],context={
        'schema':'ouf.semantic-docker-frame-context.v1','containerId':'a'*64,
        'bundleParent':'/fixture/bundles','metadataParent':'/fixture/storage/containers',
        'networkNamespaceParent':'/fixture/netns','networkNamespaceName':None,
        'cgroupDriver':'systemd','storageParent':'/fixture/storage','rootfsPath':'/fixture/bundles/'+'a'*64+'/rootfs'})
    s=f.launch['startup'];man=f.launch['manifest']
    own={'interface':'eth0','bridge':'brfixture','mac':'02:00:00:00:01:01','ipv4':'10.77.0.2',
        'workloadRef':'provider-fixture','bindingRef':'provider-nic'}
    peer={**own,'mac':'02:00:00:00:01:02','ipv4':'10.77.0.3','workloadRef':'registry-fixture','bindingRef':'registry-nic'}
    request={'Image':'sha256:'+'6'*64,'User':man['user'],'Entrypoint':s['args'],'Cmd':[],
        'Env':[v for v in s['env'] if not v.startswith('HOSTNAME=')],'WorkingDir':s['cwd'],
        'HostConfig':{'Runtime':'ouf-fixture-admitted','NetworkMode':'fixture-network',
            'RestartPolicy':{'Name':'no','MaximumRetryCount':0},'CapDrop':['ALL'],'SecurityOpt':['no-new-privileges:true'],
            'ReadonlyRootfs':man['readOnlyRoot'],'Memory':man['memoryBytes'],'MemorySwap':man['memoryBytes'],
            'PidsLimit':man['pidsLimit'],'Mounts':[{'Type':'bind','Source':v['source'],'Target':v['target'],'ReadOnly':True} for v in man['mounts']]},
        'NetworkingConfig':{'EndpointsConfig':{'fixture-network':{'MacAddress':own['mac'],'IPAMConfig':{'IPv4Address':own['ipv4']}}}}}
    context={k:v for k,v in f.context.items() if k not in {'schema','containerId','rootfsPath'}}
    context.update(schema='ouf.discovery-provider-docker-context-template.v1',networkNamespaceName=None,rootfsLayout='bundle-rootfs-v1')
    flow={'purpose':'GATEWAY_ADAPTER','authorityRef':'fixture-infrastructure','source':own['ipv4'],'destination':peer['ipv4'],
        'protocol':'tcp','port':9443,'peerIngress':{'kind':'CREATED_CANDIDATE','bindingRef':peer['bindingRef'],
            'declaration':{'containerId':m.CID_SLOT,'applicationHash':m.APP_SLOT,'networkBindings':[peer]}}}
    return dict(source_closure_hash='a'*64,qualified_package_hash='b'*64,image_configuration_hash='c'*64,
        expected_rootfs_seal={'schema':'ouf.semantic-rootfs-seal.v1','sha256':'d'*64,'entries':10,'bytes':128},
        request=request,frame_template=f.template,launch=f.launch,docker_context_template=context,
        network_bindings=[own],transport_template=[flow],table_name='fixture_provider',
        runtime_binding={'path':'/usr/bin/runc','sha256':'e'*64})

class Template(unittest.TestCase):
    def test_invalid_transport_contract_is_rejected_before_native_allocation_or_signing(self):
        for change in ({'purpose':'REGISTRY_DEPENDENCY'},{'protocol':'udp'},{'port':0},{'source':'10.77.0.99'}):
            options=inputs();options['transport_template'][0].update(change)
            with self.assertRaises(ValueError):m.template(**options)
    def test_static_review_predates_both_identities_and_materialization_grants_nothing(self):
        opts=inputs();before=copy.deepcopy(opts);t=m.template(**opts)
        self.assertEqual(opts,before);self.assertEqual(m.recompile(t),t)
        result=m.materialize(t,'1'*64,{'containerId':'2'*64,'applicationHash':'3'*64})
        self.assertEqual(result['applicationHash'],m.digest(result['framePolicy']['expectedOci']))
        self.assertTrue(all(result[k] is False for k in m.FALSE_FACTS))
        self.assertEqual(result['framePolicy']['expectedOci']['linux']['cgroupsPath'],'system.slice:docker:'+'1'*64)
        self.assertNotIn('observedOci',result)
    def test_recipe_and_worker_profile_remain_static_when_new_identities_change(self):
        t=m.template(**inputs());profile=m.expected_node_profile(t)
        a=m.materialize(t,'1'*64,{'containerId':'2'*64,'applicationHash':'3'*64})
        b=m.materialize(t,'4'*64,{'containerId':'5'*64,'applicationHash':'6'*64})
        self.assertEqual(a['independentNodeProfile'],profile);self.assertEqual(a['nodeRecipe'],b['nodeRecipe'])
        self.assertNotEqual(a['applicationHash'],b['applicationHash']);self.assertNotEqual(a['artifactHash'],b['artifactHash'])
        self.assertNotEqual(a['transportHash'],b['transportHash'])
    def test_same_inputs_compile_repeatably_without_mutation(self):
        t=m.template(**inputs());before=copy.deepcopy(t);r={'containerId':'2'*64,'applicationHash':'3'*64}
        self.assertEqual(m.materialize(t,'1'*64,r),m.materialize(t,'1'*64,r));self.assertEqual(t,before)
    def test_actual_oci_is_not_an_accepted_template_or_materialization_input(self):
        t=m.template(**inputs());t['observedOci']={}
        with self.assertRaisesRegex(ValueError,'EXACT_PROVIDER_INSTALLATION_TEMPLATE'):m.recompile(t)
        with self.assertRaises(TypeError):m.materialize(m.template(**inputs()),'1'*64,{},observed_oci={})
    def test_foreign_launch_or_source_mount_cannot_be_blessed_by_template(self):
        for key in ('args','env','mount'):
            o=inputs()
            if key=='args':o['launch']['startup']['args']=['/bin/sh']
            elif key=='env':o['request']['Env'].append('UNREVIEWED=true')
            else:o['request']['HostConfig']['Mounts'][0]['Source']='/foreign/private'
            with self.assertRaises(ValueError):m.template(**o)
    def test_old_concrete_registry_identity_cannot_replace_closed_slots(self):
        o=inputs();o['transport_template'][0]['peerIngress']['declaration']['containerId']='f'*64
        with self.assertRaisesRegex(ValueError,'ONLY_OWNED_REGISTRY_PEER_SLOTS'):m.template(**o)
    def test_substitution_outside_peer_identity_fields_is_denied(self):
        o=inputs();o['transport_template'][0]['authorityRef']=m.CID_SLOT
        with self.assertRaisesRegex(ValueError,'LATE_BINDING_OUTSIDE_CLOSED'):m.template(**o)
    def test_provider_and_registry_cannot_be_the_same_candidate(self):
        t=m.template(**inputs())
        with self.assertRaisesRegex(ValueError,'DISTINCT_PROVIDER_AND_REGISTRY'):m.materialize(t,'1'*64,{'containerId':'1'*64,'applicationHash':'2'*64})
    def test_unknown_or_unbounded_late_bindings_are_denied(self):
        t=m.template(**inputs())
        for registry in ({'containerId':'2'*64,'applicationHash':'3'*64,'pid':123},{'containerId':'2'*64,'applicationHash':'x'*64}):
            with self.assertRaisesRegex(ValueError,'EXACT_REGISTRY_PEER_IDENTITY'):m.materialize(t,'1'*64,registry)
    def test_stopped_predecessor_namespace_cannot_be_reused(self):
        o=inputs();o['docker_context_template']['networkNamespaceName']='a'*12
        with self.assertRaisesRegex(ValueError,'NEW_PROVIDER_PRIVATE_OCI_NAMESPACE'):m.template(**o)
    def test_runtime_fallback_and_automatic_restart_are_denied(self):
        for change in ({'Runtime':'runc'},{'RestartPolicy':{'Name':'always','MaximumRetryCount':0}}, {'CapAdd':['SYS_ADMIN']}):
            o=inputs();o['request']['HostConfig'].update(change)
            with self.assertRaisesRegex(ValueError,'NAMED_ADMITTED_PROVIDER_RUNTIME'):m.template(**o)
    def test_requested_allocation_must_equal_reviewed_native_binding(self):
        o=inputs();o['request']['NetworkingConfig']['EndpointsConfig']['fixture-network']['MacAddress']='02:00:00:00:ff:ff'
        with self.assertRaisesRegex(ValueError,'EXACT_NEW_PROVIDER_NETWORK_ALLOCATION'):m.template(**o)
    def test_runtime_rootfs_seal_is_not_replaced_by_image_or_portable_digest(self):
        o=inputs();t=m.template(**o);recipe=m.node_recipe(t)
        self.assertEqual(recipe['expectedRootfsSeal'],o['expected_rootfs_seal'])
        self.assertEqual(set(recipe),m.RECIPE_FIELDS)
        o['expected_rootfs_seal']['bytes']=-1
        with self.assertRaisesRegex(ValueError,'RUNTIME_ROOTFS_SEAL'):m.template(**o)
    def test_all_nonidentity_expectations_remain_bound_by_static_recipe(self):
        t=m.template(**inputs());a=m.node_recipe(t)
        for field in ('imageConfigurationHash','qualifiedPackageHash','sourceClosureHash'):
            changed=copy.deepcopy(t);changed[field]='f'*64;self.assertNotEqual(m.node_recipe(changed),a)

if __name__=='__main__':unittest.main()
