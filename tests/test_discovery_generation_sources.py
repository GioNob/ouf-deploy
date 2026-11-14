import copy
import importlib.util
import json
from pathlib import Path
import types
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
def load(name,path):
    s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
m=load('generation_sources',ROOT/'scripts/read-discovery-generation-sources-20261109.py')
compiler=load('frame_compiler',ROOT/'tools/semantic_frame_compiler/compile_creation_frame_policy.py')


def fixture():
    files={};recipes={};inputs={};cfg={'registryRoot':'/etc/ouf/fixture/registry','candidates':{}};source_bindings={}
    def put(path,value):
        raw=m.encoded(value);files[str(path)]=raw;return {'path':str(path),'sha256':m.sha(raw)}
    for i,role in enumerate(('adapter','southbound')):
        cid=str(i+1)*64;root=Path(cfg['registryRoot'])/cid
        nic={'interface':'eth0','bridge':'oufsp-int','mac':'02:00:00:00:00:01','ipv4':'172.21.0.3',
             'workloadRef':'fixture','bindingRef':'fixture-nic'}
        candidate={'containerId':cid,'transactionId':'fixture-transaction','networkBindings':[nic],
            'transport':[{'purpose':'WORKLOAD_GATEWAY','authorityRef':'PRIVATE_AUTHORITY_SENTINEL',
                'source':'172.21.0.2','destination':'172.21.0.3','protocol':'tcp','port':443,
                'peerIngress':{'kind':'CREATED_CANDIDATE','bindingRef':'fixture-nic',
                    'declaration':{'containerId':str(2-i)*64,'applicationHash':'e'*64,'networkBindings':[nic]}}}],
            'tableName':'fixture_transport','runtimeBinding':{'path':'/usr/bin/runc','sha256':'f'*64}}
        template={'candidate':candidate}
        template_binding=put(root/'preparer-template.json',template)
        baseline=json.loads((ROOT/'tools/semantic_frame_compiler'/('containerd-overlayfs-'+role+'.json')).read_bytes())
        baseline['launch']['startup']['env'].append('SECRET=PRIVATE_ENV_SENTINEL')
        baseline['template']['expectedOci']['process']['env'].append('SECRET=PRIVATE_ENV_SENTINEL')
        context={'schema':'ouf.semantic-docker-frame-context.v1','containerId':cid,
            'bundleParent':'/run/docker/containerd/daemon/io.containerd.runtime.v2.task/moby',
            'metadataParent':'/var/lib/docker/containers','networkNamespaceParent':'/run/docker/netns',
            'networkNamespaceName':None,'cgroupDriver':'systemd','rootfsPath':'/var/lib/docker/rootfs/overlayfs/'+cid,
            'storageParent':'/var/lib/docker'}
        policy=compiler.compile_policy(baseline['template'],baseline['launch'],context)
        documents={'launch':baseline['launch'],'template':baseline['template'],'context':context,'policy':policy}
        recipes[role]={}
        for name,value in documents.items():
            path=(m.LAUNCH_ROOT if name=='launch' else m.FRAME_ROOT)/(role+'.'+name+'.json')
            recipes[role][name]=put(path,value)['sha256']
        installed=copy.deepcopy(policy);installed['expectedOci']['process']['env'][-1]='SECRET=PRIVATE_CHANGED_SENTINEL'
        policy_binding=put(root/'frame-policy.json',installed)
        put(root/'live-authorization.json',{'containerId':cid,'rootfsSeal':{'schema':'ouf.semantic-rootfs-seal.v1',
            'sha256':'a'*64,'entries':101,'bytes':2000},'signature':'PRIVATE_SIGNATURE_SENTINEL'})
        node={'schema':'ouf.semantic-node-attestor.v4','creationFrameObserverBinding':{'configuration':policy_binding},
            'liveAcceptanceAuthorizationPath':str(root/'live-authorization.json'),
            'signingKeyBinding':{'path':'/etc/ouf/DO_NOT_READ_SIGNING_KEY','sha256':'9'*64}}
        node_binding=put(root/'attestation-producer.json',node)
        broker_binding=put(root/'broker.json',{'preparerTemplate':template_binding,
            'producers':{'attestation':{'configuration':node_binding}}})
        cfg['candidates'][cid]={'admissionConfiguration':broker_binding['path'],
                              'admissionConfigurationHash':broker_binding['sha256']}
        source_bindings.update({b['path']:b['sha256'] for b in (template_binding,broker_binding)})
        inputs[role]={'schema':'ouf.discovery-role-generation-inputs.v1','role':role,'state':'UNSIGNED_INPUTS_ONLY',
            'runtimeConfigurationProduced':False,'historicalTemplate':template}
    cfg_binding=put('/etc/ouf/fixture/runtime.json',cfg);source_bindings[cfg_binding['path']]=cfg_binding['sha256']
    pointer=put('/etc/ouf/coordinated-boot-installation.json',{'fixture':'pointer'})
    plan={'schema':'ouf.discovery-generation-input-plan.v1','state':'UNSIGNED_INPUTS_ONLY','authorityIssued':False,
          'runtimeConfigurationProduced':False,'activePointerSha256':pointer['sha256'],'sourceBindings':source_bindings}
    input_hashes={role+'-inputs.private.json':put(m.ROOT/(role+'-inputs.private.json'),value)['sha256']
                  for role,value in inputs.items()}
    input_hashes['generation-plan.private.json']=put(m.ROOT/'generation-plan.private.json',plan)['sha256']
    receipt={'status':'DISCOVERY_GENERATION_INPUTS_PREPARED','phase':'COMPLETE','preparationDirectory':str(m.ROOT),
             'fileHashes':input_hashes}
    result_sha=put(m.RESULT,receipt)['sha256']
    claim=Path('/var/lib/ouf-storage-migration/discovery-generation-inputs-20261109')
    put(claim/'complete.json',receipt)
    p=types.SimpleNamespace(CLAIM=claim);b=types.SimpleNamespace(POINTER=Path(pointer['path']))
    c=types.SimpleNamespace(l=types.SimpleNamespace(CONFIG_SHA=cfg_binding['sha256']))
    return files,recipes,inputs,cfg,p,b,c,result_sha,input_hashes


class SourceRead(unittest.TestCase):
    def test_actual_operator_receipt_and_compiler_byte_pins(self):
        r=json.loads((ROOT/'evidence/discovery-generation-inputs-prepared-operator-20261109.json').read_bytes())
        raw=m.encoded(r);self.assertEqual(1383,len(raw));self.assertEqual(m.RESULT_SHA,m.sha(raw))
        self.assertEqual(m.INPUT_HASHES,r['fileHashes'])
        self.assertEqual(m.COMPILER_SHA,m.sha((ROOT/'tools/semantic_frame_compiler'/m.COMPILER).read_bytes()))

    def run_fixture(self,change=None):
        files,recipes,inputs,cfg,p,b,c,result_sha,input_hashes=fixture();calls=[]
        if change:change(files,recipes,inputs,cfg)
        def read(path):calls.append(str(path));return files[str(path)]
        docs=m.Documents(read,json.loads)
        with patch.object(m,'RECIPES',recipes),patch.object(m,'RESULT_SHA',result_sha),patch.object(m,'INPUT_HASHES',input_hashes):
            roles=m.collect(p,b,c,compiler,docs)
        return roles,files,calls,docs

    def test_full_two_role_lineage_recompiles_and_does_not_expose_values(self):
        roles,files,calls,docs=self.run_fixture()
        out=json.dumps(roles)
        for secret in ('PRIVATE_ENV_SENTINEL','PRIVATE_CHANGED_SENTINEL','PRIVATE_SIGNATURE_SENTINEL','PRIVATE_AUTHORITY_SENTINEL'):
            self.assertNotIn(secret,out)
        self.assertEqual(2,len(roles))
        for role,row in roles.items():
            self.assertTrue(row['independentRecipeRecompiled']);self.assertFalse(row['originalDraftMatchesInstalledPolicy'])
            self.assertEqual(['/expectedOci/process/env/2'],row['originalDraftDifferencePaths'])
            self.assertFalse(row['signaturesVerified']);self.assertFalse(row['historicalAuthorityReused'])
        self.assertFalse(any('DO_NOT_READ' in p for p in calls))
        self.assertFalse(any('/root/ouf-frame-compiler-' in p for p in calls))
        self.assertTrue(all(calls.count(p)>=2 for p in docs.original))

    def test_input_drift_is_rejected_before_role_sources_are_read(self):
        files,_,_,_,p,b,c,result_sha,input_hashes=fixture();calls=[]
        files[str(m.ROOT/'adapter-inputs.private.json')]+=b' '
        def read(path):calls.append(str(path));return files[str(path)]
        with patch.object(m,'RESULT_SHA',result_sha),patch.object(m,'INPUT_HASHES',input_hashes):
            with self.assertRaisesRegex(RuntimeError,'SEALED_METADATA_HASH_CHANGED'):
                m.collect(p,b,c,compiler,m.Documents(read,json.loads))
        self.assertFalse(any(str(m.FRAME_ROOT) in p for p in calls))

    def test_recompilation_failure_is_not_relabelled_as_pass(self):
        def changed(files,recipes,inputs,cfg):
            path=str(m.FRAME_ROOT/'adapter.policy.json');value=json.loads(files[path]);value['expectedOci']['process']['cwd']='/wrong'
            files[path]=m.encoded(value);recipes['adapter']['policy']=m.sha(files[path])
        with self.assertRaisesRegex(RuntimeError,'INDEPENDENT_RECIPE_RECOMPILATION_FAILED'):self.run_fixture(changed)

    def test_original_recipe_context_must_name_historical_cid(self):
        def changed(files,recipes,inputs,cfg):
            path=str(m.FRAME_ROOT/'adapter.context.json');value=json.loads(files[path]);value['containerId']='9'*64
            files[path]=m.encoded(value);recipes['adapter']['context']=m.sha(files[path])
        with self.assertRaisesRegex(RuntimeError,'HISTORICAL_RECIPE_CID_CHANGED'):self.run_fixture(changed)

    def test_full_v1_seal_cannot_be_replaced_with_portable_image_digest(self):
        def changed(files,recipes,inputs,cfg):
            path=cfg['registryRoot']+'/'+'1'*64+'/live-authorization.json';value=json.loads(files[path])
            value['rootfsSeal']['schema']='portable-image-seal';files[path]=m.encoded(value)
        with self.assertRaisesRegex(RuntimeError,'HISTORICAL_FULL_V1_SEAL_REQUIRED'):self.run_fixture(changed)

    def test_drift_after_read_is_rejected(self):
        _,files,_,docs=self.run_fixture();path=next(iter(docs.original));files[path]+=b' '
        with self.assertRaisesRegex(RuntimeError,'METADATA_CHANGED_DURING_READ'):docs.recheck()

    def test_unsafe_paths_and_arbitrary_bindings_are_rejected(self):
        calls=[];docs=m.Documents(lambda p:calls.append(p),json.loads)
        for path in ('/etc/ouf/../shadow','/root/private','relative.json'):
            with self.subTest(path=path),self.assertRaisesRegex(RuntimeError,'EXACT_METADATA_PATH_REQUIRED'):docs.raw(path)
        with self.assertRaisesRegex(RuntimeError,'EXACT_METADATA_BINDING_REQUIRED'):docs.binding({'path':'/etc/ouf/a','sha256':'a'*64,'key':True})
        self.assertEqual([],calls)

    def test_unknown_candidate_fields_and_invalid_mac_do_not_escape(self):
        _,_,inputs,_,_,_,_,_,_=fixture();candidate=inputs['adapter']['historicalTemplate']['candidate']
        for key,value in (('secret','PRIVATE_SENTINEL'),):
            other=copy.deepcopy(candidate);other[key]=value
            with self.assertRaisesRegex(RuntimeError,'EXACT_CANDIDATE_METADATA_REQUIRED'):m.candidate_summary(other)
        for mac in ('','00:00:00:00:00:00','01:00:00:00:00:01',None):
            other=copy.deepcopy(candidate);other['networkBindings'][0]['mac']=mac
            with self.subTest(mac=mac),self.assertRaisesRegex(RuntimeError,'EXACT_ENDPOINT_MAC_REQUIRED'):m.candidate_summary(other)

    def test_duplicate_peers_cannot_hide_different_expectations(self):
        _,_,inputs,_,_,_,_,_,_=fixture();candidate=inputs['adapter']['historicalTemplate']['candidate']
        flow=copy.deepcopy(candidate['transport'][0]);flow['peerIngress']['declaration']['applicationHash']='9'*64
        candidate['transport'].append(flow)
        with self.assertRaisesRegex(RuntimeError,'INCONSISTENT_HISTORICAL_PEER'):m.candidate_summary(candidate)

    def test_legacy_peer_indices_are_reported_as_historical_without_resolution(self):
        _,_,inputs,_,_,_,_,_,_=fixture();candidate=inputs['southbound']['historicalTemplate']['candidate']
        candidate['transport'][0]['peerIngress']={'kind':'BRIDGE_PORT','ifindex':217}
        result=m.candidate_summary(candidate)
        self.assertEqual([],result['peers'])
        self.assertEqual({'kind':'BRIDGE_PORT','ifindex':217},result['transport'][0]['peerIngress'])
        candidate['transport'][0]['peerIngress']['ifindex']=True
        with self.assertRaisesRegex(RuntimeError,'EXACT_HISTORICAL_PEER_INDEX_REQUIRED'):m.candidate_summary(candidate)


if __name__=='__main__':unittest.main()
