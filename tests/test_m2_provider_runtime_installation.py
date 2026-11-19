"""Actual wrapper CAS/flock/crypto/files; Engine/nft/node acceptance modeled."""
import copy,hashlib,json,os,sys,types,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tests'),str(ROOT/'tools/semantic_transaction_profiles')]
import test_m2_provider_profiles as profiles
import test_m2_provider_materialized_admission as admissions
import test_m2_discovery_lease_installation_template as workers
from tools.m2_discovery_installation_profile import provider_runtime_installation as m
from tools.semantic_provider_lease_nft import structure_hash
from guarded_runtime_switch import TransactionDenied

class Runtime(unittest.TestCase):
    def fixture(self,*,lost=False,sequenced=False):
        if not Path('/proc/self/ns/net').exists():
            # The local sandbox exposes no proc namespace. CI observes real proc;
            # these substitutions are native leaves, never native proof.
            self.enterContext(patch.object(m,'host_namespace',return_value=123))
            self.enterContext(patch.object(m,'process_namespace',return_value=types.SimpleNamespace(st_dev=1,st_ino=123)))
            self.enterContext(patch.object(m.NativeBackend,'generation',return_value={'pid':os.getpid(),'startTicks':42,'namespaceInode':123}))
        true=Path('/usr/bin/true').resolve();runtime={'path':str(true),'sha256':hashlib.sha256(true.read_bytes()).hexdigest()}
        base=profiles.Profiles();old,w,auth,state,calls,opts,*_=base.fixture(runtime_binding=runtime)
        self.addCleanup(base.doCleanups)
        prep=opts['preparer_template'];prep['hostNetworkNamespace']=m.host_namespace()
        tables={family:{'nftables':[{'set':{'family':family,'table':prep['kernel']['tableName'],
            'name':'provider_0','type':'ipv4_addr','flags':['timeout'],'elem':[]}}]} for family in ('inet','bridge')}
        prep['coordinationBinding']['leaseStructureHash']=structure_hash(tables)
        auth.write(Path(prep['coordinationJournal']),m.encoded({'schema':'ouf.semantic-lease-coordination.v1',
            **prep['coordinationBinding'],'state':'QUIESCED','leaseAuthorized':False,'startAuthorized':False,'leaseAddresses':[[]]}))
        auth.write(Path(prep['lockFile']),b'')
        scope=profiles.m.profile_scope(old.template,old.creation.scope,**opts)
        c,r,s,p,o=workers.Template().fixture();o['source_closure_hash']=old.template['sourceClosureHash']
        o['expected_images']['provider']=old.template['expectedImageId']
        o['expected_node_profiles']['provider']=profiles.m.templates.expected_node_profile(old.template)
        o['signing_key_paths']=[str(auth.key)]
        c['verification']['context']={k:auth.context[k] for k in ('installationRef','entityRef','attestorRef')}
        lease=workers.m.template(c,r,p,**o)
        admission=admissions.m.admission_scope(lease,old.template,old.creation.scope,scope)
        wrappers=auth.root/'wrappers';wrappers.mkdir(mode=0o700);wrapper=wrappers/'ouf-provider'
        wrapper.write_bytes(m.wrapper_bytes(scope['pythonBinding']['path'],scope['sourceRoot'],scope['priorRuntimeConfigurationBinding']['path']))
        wrapper.chmod(0o755)
        self.enterContext(patch.object(m,'WRAPPER_DIRECTORIES',frozenset((str(wrappers),))))
        rs=m.runtime_scope(scope,wrapper_binding=auth.binding(wrapper),common_lock_identity=list(m.custody(prep['lockFile'],0o600)[1]))
        component={'schema':'ouf.discovery-composed-provider-installation-scope.v1','creation':old.creation.scope,
            'installation':rs,'admission':admission}
        if sequenced:
            from tools.m2_discovery_installation_profile.provider_creation import provider_sequence_scope
            sequence=auth.root/'provider-sequence';sequence.mkdir(mode=0o700)
            component.update(schema='ouf.discovery-composed-provider-installation-scope.v2',
                sequence=provider_sequence_scope(old.creation.scope,rs,admission,journal_directory=sequence))
        auth.review['components']['providerInstallation']=component;parent=auth.fixture();w.parent=parent;w.parent_hash=parent.sha
        creation=m.ProviderCreation(parent=parent,window=w,template=old.template,journal_directory=old.creation.root,installation_component=component)
        issuer=m.ProviderInitialIssuer(creation=creation,scope=scope,signers=old.signers)
        pub=m.ProviderProfilePublication(issuer);reader=m.MaterializedProviderAdmission(publication=pub,lease_template=lease)
        backend=m.NftBackend([prep['commands']['nft']],prep['kernel'],prep['coordinationBinding']['leaseStructureHash'],5)
        self.enterContext(patch.object(backend,'run',side_effect=lambda args,**kw:json.dumps(tables[args[3]])))
        journal=m.PrivateJournal(Path(prep['coordinationJournal']))
        coordinator=m.Coordinator(m.LeaseOwner(prep['kernel'],prep['dns'],backend),prep['coordinationBinding'],
            lambda:m.hold_common_lock(Path(prep['lockFile'])),journal.read,journal.write)
        owner=m.ProviderRuntimeInstallation(publication=pub,admission=reader,scope=rs,coordinator=coordinator)
        old_request=creation.engine.request
        def request(method,path,body=None):
            if path=='/v1.44/info':
                return 200,{'ServerVersion':'29.8.1','Driver':'overlayfs','CgroupDriver':'systemd',
                    'Runtimes':{creation.template['creationRequest']['HostConfig']['Runtime']:{'path':str(wrapper),'runtimeArgs':[]}}}
            if method=='POST' and path.endswith('/start'):
                # A runtime/preparer must obtain this same inode. Holding it over
                # Docker's start would deadlock; actual nonblocking flock proves release.
                with m.hold_common_lock(Path(prep['lockFile'])):pass
                calls.append((method,path,None));state['native']['State'].update(Status='running',Running=True,Pid=os.getpid())
                admissions.Admission().admit(reader,auth,m.NativeBackend.generation(None,os.getpid()))
                if lost:raise TimeoutError('CI_LOST_START_REPLY')
                return 204,None
            return old_request(method,path,body)
        creation.engine.request=request
        return owner,w,auth,state,calls,tables,wrapper
    def prepare(self,owner):
        owner.creation.create_once();owner.issuer.issue_once();owner.publication.apply()
    def test_real_atomic_switch_and_single_start_release_lock_before_runtime(self):
        owner,w,auth,state,calls,tables,wrapper=self.fixture();prior=wrapper.read_bytes()
        with w.peer_window():
            self.prepare(owner);self.assertEqual(owner.switch_once()['status'],'WRAPPER_SWITCHED')
            self.assertNotEqual(wrapper.read_bytes(),prior);self.assertEqual(owner.observe_switch()[0],'APPLIED')
            owner.start_once();self.assertEqual(owner.observe_started()[0],'APPLIED')
            with self.assertRaises((ValueError,RuntimeError)):owner.start_once()
        self.assertEqual(owner.observe_started()[0],'APPLIED')
        self.assertEqual([p for method,p,_ in calls if method=='POST'],[
            '/v1.44/containers/create?name='+owner.creation.name,'/v1.44/containers/'+'9'*64+'/start'])
        self.assertFalse(owner.observe_started()[1]['applicationReadinessProven'])
    def test_lost_start_reply_reconciles_after_gate_closure_without_retransmission(self):
        owner,w,auth,state,calls,*_=self.fixture(lost=True)
        with self.assertRaises(TimeoutError):
            with w.peer_window():self.prepare(owner);owner.switch_once();owner.start_once()
        count=len(calls);self.assertEqual(owner.observe_started()[0],'APPLIED')
        self.assertTrue(all(method=='GET' for method,_,_ in calls[count:]))
        self.assertEqual(sum(method=='POST' and p.endswith('/start') for method,p,_ in calls),1)
    def test_lost_switch_acknowledgement_is_observed_without_second_switch(self):
        owner,w,auth,state,calls,tables,wrapper=self.fixture()
        import guarded_runtime_switch as switch
        real=switch.publish_once
        def lost(path,raw):
            if Path(path).name=='runtime-switch-receipt.json':raise TimeoutError('CI_LOST_SWITCH_ACK')
            return real(path,raw)
        with w.peer_window():
            self.prepare(owner)
            with patch.object(switch,'publish_once',side_effect=lost),self.assertRaises(switch.TransactionDenied):owner.switch_once()
            self.assertEqual(owner.observe_switch()[0],'APPLIED')
            current=wrapper.stat().st_ino
            with self.assertRaises((ValueError,RuntimeError,switch.TransactionDenied)):owner.switch_once()
            self.assertEqual(wrapper.stat().st_ino,current)
        self.assertFalse(any(p.endswith('/start') for _,p,_ in calls))
    def test_nonempty_native_guard_prevents_wrapper_or_start_claim(self):
        owner,w,auth,state,calls,tables,wrapper=self.fixture();prior=wrapper.read_bytes()
        with w.peer_window():
            self.prepare(owner)
            for value in tables.values():value['nftables'][0]['set']['elem']=[{'elem':{'val':'8.8.8.8','expires':1000}}]
            with self.assertRaises(TransactionDenied):owner.switch_once()
            self.assertFalse((owner.root/'runtime-switch-claim.json').exists())
            self.assertEqual(wrapper.read_bytes(),prior)
        self.assertFalse((owner.root/'provider-start-claim.json').exists())
    def test_unknown_start_preserves_consumed_dispatch_and_never_replays(self):
        owner,w,auth,state,calls,*_=self.fixture();real=owner.creation.engine.request
        def unknown(method,path,body=None):
            if method=='POST' and path.endswith('/start'):calls.append((method,path,None));raise TimeoutError('CI_START_UNKNOWN')
            return real(method,path,body)
        owner.creation.engine.request=unknown
        with self.assertRaises(TimeoutError):
            with w.peer_window():self.prepare(owner);owner.switch_once();owner.start_once()
        self.assertEqual(owner.observe_started()[0],'UNKNOWN')
        with self.assertRaises(ValueError):owner.start_once()
        self.assertTrue((owner.root/'provider-start-dispatch.json').exists())
        self.assertEqual(sum(method=='POST' and path.endswith('/start') for method,path,_ in calls),1)
    def test_same_lock_bytes_replaced_inode_are_not_accepted(self):
        owner,w,auth,state,calls,tables,wrapper=self.fixture();lock=Path(owner.issuer.scope['preparerTemplate']['lockFile'])
        with w.peer_window():
            self.prepare(owner);replacement=lock.with_name('replacement');auth.write(replacement,b'');replacement.replace(lock)
            with self.assertRaises(TransactionDenied):owner.switch_once()
        self.assertFalse((owner.root/'runtime-switch-claim.json').exists())

if __name__=='__main__':unittest.main()
