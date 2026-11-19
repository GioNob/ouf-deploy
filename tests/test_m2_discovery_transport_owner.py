"""Signed transport phase and real private journals; node/kernel observations synthetic."""
import copy,contextlib,sys,types,unittest
from pathlib import Path
from unittest import mock
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tests'),str(ROOT/'tools/semantic_application_cutover'),
    str(ROOT/'tools/semantic_frame_compiler'),str(ROOT/'tools/semantic_cohort_admission/cohort-draft')]
import test_cutover_authority_native as signed
import test_m2_discovery_node_owner as node_fixture
from tools.m2_discovery_installation_profile import transport_owner as m

class Transport(unittest.TestCase):
    def setUp(self):pass
    native=signed.SignedCutover.native
    write=signed.SignedCutover.write
    binding=signed.SignedCutover.binding
    sign=signed.SignedCutover.sign
    gate=signed.SignedCutover.gate

    def fixture(self):
        signed.SignedCutover.setUp(self);args,_=node_fixture.NodeOwner.prepared(self)
        request=args[2];store=args[4];node_recipe=args[11]
        commands={k:{'path':'/fixture/'+k,'sha256':'1'*64} for k in ('ip','nsenter','nft')}
        node_recipe['observationConfiguration']={'commands':{k:commands[k] for k in ('ip','nsenter')}}
        node_intent={**args[3],'nodeRecipeHash':m.digest(node_recipe)}
        c=object.__new__(m.Coordinator)
        c.binding={'transactionId':'a'*64,'configurationHash':'b'*64,'leaseStructureHash':'c'*64}
        c.configuration={'tableName':'fixture_lease','guardedInterfaces':['fixturebr'],'existingInterfaces':[],
            'providerFlows':[{'source':'10.77.0.2'}],'staticFlows':[]}
        c.owner=types.SimpleNamespace(configuration=copy.deepcopy(c.configuration),backend=types.SimpleNamespace(expected='c'*64))
        c.hold_lock=contextlib.nullcontext
        c.journal=lambda:{'state':'QUIESCED','leaseAuthorized':False};c.sets=lambda:[[],[]]
        recipe={'schema':'ouf.semantic-discovery-transport-recipe.v1','sourceClosureHash':self.expected['sourceClosureHash'],
            'nodeRecipeHash':m.digest(node_recipe),'coordinatorBindingHash':m.digest(c.binding),
            'leaseConfigurationHash':m.digest(c.configuration),'leaseStructureHash':'c'*64,
            'commands':commands,'nativeBudgetSeconds':5,'isolationSeconds':10}
        intent={'creationRequestHash':m.digest(request),'nodeRecipeHash':m.digest(node_recipe),
            'transportRecipeHash':m.digest(recipe),'priorEvidencePhase':'ATTEST_NEW_OCI_PEER'}
        auth=signed.decode(self.authority) if hasattr(signed,'decode') else __import__('json').loads(self.authority)
        auth['phaseIntentHashes'][m.PHASE]=m.digest(intent)
        auth['phaseIntentHashes']['ATTEST_NEW_OCI_PEER']=m.digest(node_intent)
        self.authority=signed.encoded(auth);self.approval['executionAuthorityHash']=signed.sha(self.authority)
        self.write(self.mandate,signed.encoded(self.approval));self.approved=signed.sha(self.mandate.read_bytes())
        for role in self.grant['roles']:self.sign(role)
        authority=self.gate()
        row={'state':'IN_FLIGHT','creationRequestHash':m.digest(request),
            'effects':[{'phase':'ATTEST_NEW_OCI_PEER','state':'APPLIED','intentHash':m.digest(node_intent)},
                {'phase':m.PHASE,'state':'IN_FLIGHT','intentHash':m.digest(intent)}]}
        transition=types.SimpleNamespace(context='d'*64,execution_profile=None,phases=tuple(auth['phaseIntentHashes']),
            read=lambda:copy.deepcopy(row))
        from transition_journal import PHASES
        transition.phases=PHASES
        node=m.DiscoveryNodeOwner(args[0],transition,request,node_intent,store,args[5],args[6],authority,self.authority,
            args[9],args[10],node_recipe,args[12])
        root=self.root/'transport';root.mkdir(mode=0o700)
        owner=m.TransportInstallationAdapter(transition=transition,store=store,authority=authority,
            authority_raw=self.authority,node_owner=node,coordinator=c,recipe=recipe,directory=root,intent=intent)
        profile={'schema':'ouf.semantic-preexec-profile.v2','namespaceOrigin':'OCI_CREATED','transactionId':'a'*64,
            'containerId':'b'*64,'bundlePath':'/fixture/bundle','bundleHash':'c'*64,'namespacePath':'/fixture/ns',
            'namespaceInode':24,'namespaceLinks':[{'interface':'eth0','ifindex':2,'hostIfindex':10004}],
            'policy':{'schema':'ouf.semantic-shared-faces.v2','tableName':'fixture_shared',
                'attachments':[{'workloadRef':'synthetic','interface':'ciport','ifindex':10004,'bridge':'fixturebr',
                    'mac':'02:00:00:00:00:02','ipv4':'10.77.0.2','bindingRef':'synthetic-port'}],
                'flows':[],'globalLeaseGuard':{'configurationHash':m.digest(c.configuration),'tableName':'fixture_lease','bridges':['fixturebr']}},
            'expectedFootprint':'0'*64,'applicationStartAuthorized':False,'infrastructureAuthorityComplete':False}
        generation={'pid':1234,'startTicks':23,'namespaceInode':24}
        kernel={'tables':None,'writes':0,'crash':False}
        class Backend:
            def tables(self):return copy.deepcopy(kernel['tables'])
            def footprint(self,value):return value['footprint']
            def structure_hash(self,value):return value['structure']
            def bindings(self,*a):return None
            def create(self,raw):
                kernel['writes']+=1;kernel['tables']={'footprint':'e'*64,'structure':'f'*64}
                if kernel['crash']:raise RuntimeError('synthetic-crash-after-kernel-write')
        owner.backend=lambda _:Backend()
        def base(intent):
            owner.current(intent)
            return copy.deepcopy(profile),copy.deepcopy(generation),{'syntheticNodeProof':True}
        owner.native_base=base
        patch=mock.patch.object(m.NativeBackend,'generation',lambda *a:copy.deepcopy(generation));patch.start();self.addCleanup(patch.stop)
        patch=mock.patch.object(m,'isolated_footprint',side_effect=lambda p,*a,**kw:{
            'schema':'ouf.semantic-shared-native-template.v1','profileHash':m.digest(p),'footprint':'e'*64,
            'rulesHash':'9'*64,'isolated':True,'hostRulesChanged':False,'startAuthorized':False})
        patch.start();self.addCleanup(patch.stop)
        return owner,intent,kernel,row,profile

    def test_exact_owned_apply_and_observation_write_kernel_once_without_start_authority(self):
        owner,intent,kernel,*_=self.fixture();owner.apply(intent)
        result,evidence=owner.observe(intent)
        self.assertEqual(result,'APPLIED');self.assertEqual(kernel['writes'],1)
        self.assertFalse(evidence['applicationStartAuthorized']);self.assertFalse(evidence['runtimeAuthorityIssued'])
        owner.observe(intent);self.assertEqual(kernel['writes'],1)
        with self.assertRaisesRegex(ValueError,'ALREADY_ATTEMPTED'):owner.apply(intent)
        self.assertEqual(kernel['writes'],1)

    def test_crash_after_atomic_kernel_write_reconciles_only_the_existing_journal(self):
        owner,intent,kernel,*_=self.fixture();kernel['crash']=True
        with self.assertRaisesRegex(RuntimeError,'synthetic-crash'):owner.apply(intent)
        journal=m.PrivateJournal(owner.root/'preexec-journal.json')
        self.assertEqual(journal.read()['state'],'INSTALLING')
        kernel['crash']=False
        outcome,_=owner.observe(intent)
        self.assertEqual(outcome,'APPLIED');self.assertEqual(journal.read()['state'],'PROTECTED')
        self.assertEqual(kernel['writes'],1)

    def test_missing_kernel_after_interruption_is_not_recreated(self):
        owner,intent,kernel,*_=self.fixture();kernel['crash']=True
        with self.assertRaises(RuntimeError):owner.apply(intent)
        kernel['tables']=None
        outcome,evidence=owner.observe(intent)
        self.assertEqual(outcome,'UNKNOWN');self.assertEqual(kernel['writes'],1)
        self.assertFalse(evidence['applyReplayAllowed'])

    def test_wrong_current_rules_are_never_adopted_or_replaced(self):
        owner,intent,kernel,*_=self.fixture();owner.apply(intent)
        kernel['tables']['footprint']='0'*64
        with self.assertRaisesRegex(ValueError,'TEMPLATE_OR_JOURNAL_DRIFT'):owner.observe(intent)
        self.assertEqual(kernel['writes'],1)

    def test_scope_or_signature_drift_stops_before_kernel_write(self):
        owner,intent,kernel,*_=self.fixture()
        (self.signatures/(signed.sha(self.authority)+'.FINAL_DEPLOYMENT_APPROVAL.json')).unlink()
        with self.assertRaises((signed.PreexecDenied,FileNotFoundError)):owner.apply(intent)
        self.assertEqual(kernel['writes'],0);self.assertEqual(list(owner.root.iterdir()),[])

    def test_partial_preparation_remains_unknown_without_repair(self):
        owner,intent,kernel,*_=self.fixture()
        self.write(owner.root/'claim.json',b'{}')
        outcome,_=owner.observe(intent)
        self.assertEqual(outcome,'UNKNOWN');self.assertEqual(kernel['writes'],0)
        self.assertEqual([p.name for p in owner.root.iterdir()],['claim.json'])

if __name__=='__main__':unittest.main()
