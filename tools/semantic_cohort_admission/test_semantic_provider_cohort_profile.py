"""Draft integration checks; no command execution, signing or target start."""
import ast
import copy
import importlib
import importlib.util
import json
from pathlib import Path
import sys
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).parent / 'cohort-draft'
package = types.ModuleType('tools')
package.__path__ = [str(ROOT / 'tools')]
sys.modules['tools'] = package
from tools.semantic_provider_deployment_admission import live_profile, application_hash, transport_hash
from tools.semantic_provider_preexec import PreexecDenied
from tools.semantic_provider_peer_bindings import digest
from tools.semantic_provider_peer_bindings import await_peers,PeerNotReady
import tools.semantic_provider_node_observation as node

spec=importlib.util.spec_from_file_location('cohort_driver',ROOT/'scripts'/'semantic_provider_preexec_hook.py')
driver=importlib.util.module_from_spec(spec);spec.loader.exec_module(driver)

NIC = {'interface':'oufint0','bridge':'oufsp-int','mac':'02:42:ac:15:00:02',
       'ipv4':'172.21.0.2','workloadRef':'southbound','bindingRef':'southbound-internal'}
PEER = {'containerId':'a'*64,'applicationHash':digest({'fixture':'sealed-peer-oci'}),'networkBindings':[NIC]}
FLOW = {'purpose':'GATEWAY_ADAPTER','authorityRef':'ci-infrastructure','source':'172.21.0.2',
        'destination':'172.21.0.3','protocol':'tcp','port':9443,
        'peerIngress':{'kind':'CREATED_CANDIDATE','declaration':PEER,'bindingRef':NIC['bindingRef']}}
OCI = {'linux':{'namespaces':[{'type':'network'}]},'process':{'args':['fixture-only']}}
OWN = {**NIC,'mac':'02:42:ac:15:00:03','ipv4':'172.21.0.3','workloadRef':'adapter','bindingRef':'adapter-internal'}
CHILD = {'ifname':'oufint0','address':OWN['mac'],'ifindex':2,'link_index':21,
         'addr_info':[{'family':'inet','local':OWN['ipv4']}]}
HOST = {'ifname':'vethadapter','ifindex':21,'link_index':2,'master':'oufsp-int'}
SNAPSHOT = {'containerId':PEER['containerId'],'applicationHash':PEER['applicationHash'],
            'generation':{'pid':123,'startTicks':40,'namespaceInode':900},
            'bindings':[{**NIC,'childIfindex':3,'hostIfindex':20,'hostInterface':'vethsouth'}]}

class Tests(unittest.TestCase):
    def candidate(self):
        return {'applicationHash':application_hash(OCI),'containerId':'b'*64,'transactionId':'c'*64,
                'bundlePath':'/root/fixture/bundle','networkBindings':[OWN],'transport':[copy.deepcopy(FLOW)],
                'tableName':'fixture_cohort'}
    def profile(self,candidate,snapshots=None):
        return live_profile(candidate,OCI,'/proc/123/ns/net',900,[CHILD],[HOST],snapshots)
    def test_symbolic_transport_is_not_materialized_without_independent_observation(self):
        with self.assertRaisesRegex(PreexecDenied,'INDEPENDENT_PEER_OBSERVATION_REQUIRED'):
            self.profile(self.candidate())
    def test_kernel_profile_resolves_peer_but_signed_transport_stays_unchanged(self):
        candidate=self.candidate();before=transport_hash(candidate)
        profile=self.profile(candidate,{PEER['containerId']:SNAPSHOT})
        self.assertEqual(profile['policy']['flows'][0]['peerIngress'],{'kind':'BRIDGE_PORT','ifindex':20})
        self.assertEqual(transport_hash(candidate),before)
        self.assertEqual(candidate['transport'][0]['peerIngress']['kind'],'CREATED_CANDIDATE')
    def test_changed_peer_oci_is_rejected_before_profile(self):
        changed=copy.deepcopy(SNAPSHOT);changed['applicationHash']='0'*64
        with self.assertRaisesRegex(ValueError,'PEER_SNAPSHOT_SCOPE_DRIFT'):
            self.profile(self.candidate(),{PEER['containerId']:changed})
    def test_legacy_numeric_transport_keeps_existing_profile(self):
        candidate=self.candidate();candidate['transport'][0]['peerIngress']={'kind':'HOST','ifindex':0}
        profile=self.profile(candidate)
        self.assertEqual(profile['policy']['flows'],candidate['transport'])
    def test_closed_loaders_have_peer_module_before_admission(self):
        checked=0
        for script in (ROOT/'scripts').glob('*.py'):
            tree=ast.parse(script.read_text())
            assignments=[x for x in tree.body if isinstance(x,ast.Assign) and
                any(isinstance(t,ast.Name) and t.id=='MODULES' for t in x.targets)]
            if not assignments:continue
            names=ast.literal_eval(assignments[0].value)
            if 'semantic_provider_deployment_admission' not in names:continue
            self.assertLess(names.index('semantic_provider_peer_bindings'),names.index('semantic_provider_deployment_admission'))
            for name in names:
                self.assertTrue((ROOT/'tools'/(name+'.py')).is_file(),name)
                importlib.import_module('tools.'+name)
            checked+=1
        self.assertGreaterEqual(checked,5)
    def test_preparer_and_v6_driver_have_matching_executable_source_closures(self):
        def modules(script,schema):
            tree=ast.parse((ROOT/'scripts'/script).read_text());env={'cfg':{'schema':schema},'value':{'schema':schema}}
            base=next(x.value for x in tree.body if isinstance(x,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='MODULES' for t in x.targets))
            env['MODULES']=ast.literal_eval(base)
            load=next(x for x in tree.body if isinstance(x,ast.FunctionDef) and x.name=='load')
            def assignment(statement):
                if isinstance(statement,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='modules' for t in statement.targets):
                    env['modules']=eval(compile(ast.Expression(statement.value),'<closed-loader>','eval'),{'__builtins__':{}},env)
            for statement in load.body:
                assignment(statement)
                if isinstance(statement,ast.If) and any(isinstance(x,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='modules' for t in x.targets) for x in statement.body):
                    if eval(compile(ast.Expression(statement.test),'<closed-loader>','eval'),{'__builtins__':{}},env):
                        for child in statement.body:assignment(child)
            return env['modules']
        preparer=modules('semantic_provider_admission_preparer.py','ouf.semantic-admission-preparer.v3')
        gate=modules('semantic_provider_preexec_hook.py','ouf.semantic-preexec-driver.v6')
        self.assertEqual(preparer,gate)
        originals={key:value for key,value in sys.modules.items() if key=='tools' or key.startswith('tools.')}
        try:
            for key in originals:sys.modules.pop(key)
            package=types.ModuleType('tools');package.__path__=[];sys.modules['tools']=package
            for name in gate:
                full='tools.'+name;module=types.ModuleType(full);module.__package__='tools'
                module.__file__=str(ROOT/'tools'/(name+'.py'));sys.modules[full]=module;setattr(package,name,module)
                exec(compile(Path(module.__file__).read_bytes(),module.__file__,'exec'),module.__dict__)
        finally:
            for key in list(sys.modules):
                if key=='tools' or key.startswith('tools.'):sys.modules.pop(key)
            sys.modules.update(originals)
    def node_fixture(self,peer_bundle='/root/fixture/bundles/peer'):
        namespace='/proc/111/ns/net'
        inode=900
        oci=copy.deepcopy(OCI);oci['linux']['namespaces'][0]['path']=namespace;oci['root']={'path':'/root/fixture/rootfs'}
        candidate=self.candidate();candidate['applicationHash']=digest(oci)
        peer_oci={'fixture':'sealed-peer-oci'}
        state={'id':'b'*64,'status':'created','pid':111,'bundle':'/root/fixture/bundles/current'}
        peer_state={'id':'a'*64,'status':'created','pid':222,'bundle':peer_bundle}
        cfg={'runtimeRootParents':['/root/fixture'],'bundleParents':['/root/fixture/bundles'],
             'runtimeBinding':{'path':'/usr/bin/runc','sha256':'d'*64},
             'commands':{'ip':{'path':'/usr/bin/ip','sha256':'e'*64},'nsenter':{'path':'/usr/bin/nsenter','sha256':'f'*64}},
             'candidate':{k:candidate[k] for k in ('networkBindings','transport','tableName')},'rootfsLimits':{}}
        class Budget:
            def check(self):pass
        observer=node.NodeObservation(cfg,Budget())
        def run(binding,args,limit=131072):
            if args[0]=='--root':value=state if args[-1]=='b'*64 else peer_state
            elif args[0].startswith('--net='):
                value=[{**CHILD,'ifindex':3,'link_index':20,'address':NIC['mac'],
                       'addr_info':[{'family':'inet','local':NIC['ipv4']}]}] if '/222/' in args[0] else [CHILD]
            else:value=[HOST] if args[-1]=='vethadapter' else [{'ifname':'vethsouth','ifindex':20,'link_index':3,'master':NIC['bridge']}]
            return json.dumps(value).encode()
        observer.run=run
        request={'containerId':'b'*64,'transactionId':'c'*64,'applicationHash':digest(oci),
                 'transportHash':transport_hash(candidate),'generation':{'pid':111,'startTicks':40,'namespaceInode':inode}}
        journal={'runtimeRoot':'/root/fixture/runtime','bundleHash':digest(oci)}
        reads=[]
        def reader(path):
            reads.append(str(path))
            return json.dumps(oci if '/current/' in str(path) else peer_oci).encode()
        return observer,request,journal,reader,reads
    def observe(self,fixture,peer_ticks=50):
        observer,request,journal,reader,_=fixture
        def generation(_,pid):
            return request['generation'] if pid==111 else {'pid':222,'startTicks':peer_ticks,'namespaceInode':901}
        with patch.object(node,'ancestors'),patch.object(node,'program'),patch.object(node,'rootfs_seal',return_value={'sha256':'0'*64}),\
             patch.object(node.Path,'stat',return_value=types.SimpleNamespace(st_ino=900)),\
             patch.object(node.NativeBackend,'generation',generation),\
             patch.object(node.socket,'if_indextoname',side_effect=lambda index:'vethadapter' if index==21 else 'vethsouth'):
            return observer.observe(request,journal,reader)
    def test_node_observes_real_collector_and_retains_peer_generation_for_signing_recheck(self):
        fixture=self.node_fixture();observed=self.observe(fixture)
        self.assertEqual(observed['peerObservations']['a'*64]['generation']['startTicks'],50)
        self.assertIn('/root/fixture/bundles/peer/config.json',fixture[-1])
        self.assertNotEqual(observed,self.observe(fixture,peer_ticks=51))
    def test_node_refuses_peer_bundle_outside_approved_parents_before_private_read(self):
        fixture=self.node_fixture('/root/unapproved/peer')
        with self.assertRaisesRegex(PreexecDenied,'NODE_PEER_BUNDLE_OUTSIDE_APPROVAL'):self.observe(fixture)
        self.assertNotIn('/root/unapproved/peer/config.json',fixture[-1])
    def driver_fixture(self):
        fixture=self.node_fixture();observed=self.observe(fixture)
        candidate=self.candidate();candidate['applicationHash']=fixture[1]['applicationHash']
        profile=self.profile(self.candidate(),observed['peerObservations'])
        policy={k:candidate[k] for k in ('networkBindings','transport','tableName')}
        value={'profile':profile,'authorityScope':{'transportHash':digest(policy)},
               'runtimeBinding':{**fixture[0].cfg['runtimeBinding'],'root':fixture[2]['runtimeRoot'],'containerId':'b'*64},
               'commands':{'ip':'/usr/bin/ip','nsenter':'/usr/bin/nsenter'},
               'peerBinding':{'declaredPolicy':policy,'observations':observed['peerObservations'],
                              'commandBindings':fixture[0].cfg['commands']}}
        return fixture,value
    def driver_check(self,fixture,value,peer_ticks=50):
        class Budget:
            def check(self):pass
        with patch.object(node.socket,'if_indextoname',return_value='vethsouth'):
            return driver.verify_peers(value,Budget(),fixture[3],fixture[0].run,
                lambda pid:{'pid':222,'startTicks':peer_ticks,'namespaceInode':901})
    def test_final_driver_recollects_peer_before_any_release(self):
        fixture,value=self.driver_fixture();fixture[-1].clear()
        self.driver_check(fixture,value)
        self.assertEqual(fixture[-1],['/root/fixture/bundles/peer/config.json']*2)
    def test_final_driver_rejects_replaced_peer_generation(self):
        fixture,value=self.driver_fixture()
        with self.assertRaisesRegex(RuntimeError,'PEER_GENERATION_OR_LINK_CHANGED'):
            self.driver_check(fixture,value,peer_ticks=51)
    def test_final_driver_rejects_transport_scope_drift_before_read(self):
        fixture,value=self.driver_fixture();fixture[-1].clear()
        value['authorityScope']['transportHash']='0'*64
        with self.assertRaisesRegex(RuntimeError,'PEER_DRIVER_TRANSPORT_SCOPE_DRIFT'):self.driver_check(fixture,value)
        self.assertFalse(fixture[-1])
    def test_final_driver_rejects_resolved_kernel_policy_drift(self):
        fixture,value=self.driver_fixture();value['profile']['policy']['flows'][0]['peerIngress']['ifindex']=99
        with self.assertRaisesRegex(RuntimeError,'PEER_KERNEL_PROFILE_DRIFT'):self.driver_check(fixture,value)
    def test_cohort_barrier_waits_only_for_explicit_not_ready(self):
        class Budget:
            def check(self):pass
            def remaining(self,maximum):return maximum
        calls=[];pauses=[]
        def probe(peer):
            calls.append(peer['containerId'])
            if len(calls)==1:raise PeerNotReady()
            return SNAPSHOT
        observed=await_peers([PEER],probe,Budget(),pause=pauses.append)
        self.assertEqual(observed,{PEER['containerId']:SNAPSHOT});self.assertEqual(pauses,[0.1])
    def test_cohort_barrier_does_not_retry_identity_drift(self):
        class Budget:
            def check(self):pass
        def probe(_):raise ValueError('PEER_COMPLETE_OCI_DRIFT')
        with self.assertRaisesRegex(ValueError,'PEER_COMPLETE_OCI_DRIFT'):
            await_peers([PEER],probe,Budget(),pause=lambda _:self.fail('identity drift was retried'))
    def test_cohort_barrier_does_not_return_ready_when_deadline_expires(self):
        class Budget:
            def check(self):pass
            def remaining(self,_):raise RuntimeError('DEADLINE_EXPIRED')
        def probe(_):raise PeerNotReady()
        with self.assertRaisesRegex(RuntimeError,'DEADLINE_EXPIRED'):await_peers([PEER],probe,Budget(),pause=lambda _:None)

if __name__=='__main__':unittest.main()
