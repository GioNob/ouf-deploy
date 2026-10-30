"""Real parent/child signatures and journals; Engine/process effects synthetic."""
import copy,sys,types,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tests'),str(ROOT/'tools/semantic_application_cutover'),
    str(ROOT/'tools/semantic_lease_recovery'),str(ROOT/'tools/semantic_cohort_admission/cohort-draft')]
import test_m2_discovery_parent_authority as signed
from test_m2_discovery_native_profile import fixture
from tools.m2_discovery_installation_profile.native_profile import DiscoveryProfile
from tools.m2_discovery_installation_profile import gate_peer_window as m


class Window(unittest.TestCase):
    def fixture(self,kind='GATE_WAITING',unpause_status=204,pause_status=204,definition=None):
        auth=signed.Parent();auth.setUp();self.addCleanup(auth.doCleanups)
        request,selection,*_=(fixture() if definition is None else definition);profile=DiscoveryProfile(request,**selection)
        child,raw=auth.child(creation_request_hash=m.digest(request))
        root=auth.root/'window';root.mkdir(mode=0o700);evidence=auth.root/'evidence';evidence.mkdir(mode=0o700)
        store=m.NativeEvidenceStore(evidence);binding={'containerId':'f'*64,'pid':1234,'imageId':request['Image']}
        actual={'State':{'Running':True,'Paused':True},'RestartCount':0,'binding':binding}
        store.publish('STAGE_PAUSED_REPLACEMENT',actual)
        hashes=m.decode(raw)['phaseIntentHashes'];authority_hash=m.hashlib.sha256(raw).hexdigest()
        row={'state':'READY','nextPhase':6,'creationRequestHash':m.digest(request),
            'transitionAuthorityEvidenceHash':authority_hash,
            'effects':[{'phase':phase,'state':'APPLIED','intentHash':hashes[phase],
                'authorityEvidenceHash':authority_hash,
                'nativeEvidenceHash':m.digest(actual) if i==5 else 'a'*64} for i,phase in enumerate(m.PHASES[:6])]}
        transition=object.__new__(m.Transition);transition.execution_profile=None;transition.profile_hash=None
        transition.context='b'*64;transition.read=lambda:copy.deepcopy(row)
        engine=object.__new__(m.Engine);engine.inspect=lambda t:copy.deepcopy(actual)
        engine.matching_configuration=lambda t,r,v:v;engine.runtime_binding=lambda v:copy.deepcopy(v['binding'])
        calls=[]
        def dispatch(method,path):
            calls.append((method,path))
            if path.endswith('/unpause'):actual['State']['Paused']=False;return unpause_status,{}
            if path.endswith('/pause'):actual['State']['Paused']=True;return pause_status,{}
            raise AssertionError('UNREVIEWED_ENGINE_OPERATION')
        engine.request=dispatch
        scope=m.window_scope(m.digest(request),profile.sha256,child.expected['sourceClosureHash'],root,120)
        auth.review['components']['registryGatePeerWindow']=scope;parent=auth.fixture()
        window=m.GatePeerWindow(parent=parent,child=child,child_raw=raw,engine=engine,transition=transition,
            request=request,profile=profile,store=store,directory=root)
        observed={'generation':{'pid':1234,'startTicks':5678,'namespaceInode':99},'processKind':kind,
            'nonRootIdentityVerified':True,'capabilitiesEmpty':True,'noNewPrivileges':True}
        window.process.observe=lambda pid:copy.deepcopy(observed)
        return window,auth,calls,actual,observed,row

    def test_one_unpause_and_pause_are_separate_from_attribution_or_application_start(self):
        w,auth,calls,actual,process,row=self.fixture()
        with w.peer_window():
            proof=w.observe_open();self.assertFalse(actual['State']['Paused'])
            self.assertFalse(proof['ociAdmissionGranted']);self.assertFalse(proof['applicationSignalAuthorized'])
            self.assertTrue(proof['providerAdmissionIsSeparate'])
        self.assertTrue(actual['State']['Paused']);self.assertEqual(w.observe_closed()['state'],'CLOSED')
        self.assertEqual([path.rsplit('/',1)[1] for _,path in calls],['unpause','pause'])
        self.assertEqual(row['nextPhase'],6)

    def test_provider_failure_still_pauses_the_same_gate(self):
        w,auth,calls,actual,*_=self.fixture()
        with self.assertRaisesRegex(RuntimeError,'SYNTHETIC_PROVIDER_FAILURE'):
            with w.peer_window():raise RuntimeError('SYNTHETIC_PROVIDER_FAILURE')
        self.assertTrue(actual['State']['Paused']);self.assertEqual(w.retained()['state'],'CLOSED')
        self.assertEqual(len(calls),2)

    def test_ambiguous_unpause_is_contained_without_retransmission(self):
        w,auth,calls,actual,*_=self.fixture(unpause_status=500)
        with self.assertRaisesRegex(ValueError,'UNPAUSE_OUTCOME_REQUIRES_RECONCILIATION'):
            with w.peer_window():self.fail('unproven open entered provider action')
        self.assertTrue(actual['State']['Paused']);self.assertEqual(len(calls),2)
        with self.assertRaises(FileExistsError):w.open_once()
        self.assertEqual(len(calls),2)

    def test_ambiguous_pause_can_only_be_observed_not_resent(self):
        w,auth,calls,actual,*_=self.fixture(pause_status=500)
        with self.assertRaisesRegex(ValueError,'PAUSE_OUTCOME_REQUIRES_RECONCILIATION'):
            with w.peer_window():pass
        self.assertEqual(w.retained()['state'],'CLOSING');self.assertTrue(actual['State']['Paused'])
        self.assertEqual(w.observe_closed()['state'],'CLOSED');self.assertEqual(len(calls),2)

    def test_expired_human_window_does_not_prevent_narrowing_owned_gate(self):
        w,auth,calls,actual,*_=self.fixture()
        with w.peer_window():auth.now+=121
        self.assertTrue(actual['State']['Paused']);self.assertEqual(w.observe_closed()['state'],'CLOSED')
        with self.assertRaises(ValueError):w.open_once()
        self.assertEqual(len(calls),2)

    def test_already_running_application_is_not_used_as_wait_gate(self):
        w,auth,calls,actual,*_=self.fixture(kind='APPLICATION_RUNNING')
        with self.assertRaisesRegex(ValueError,'EXACT_PAUSED_WAIT_GATE'):
            with w.peer_window():self.fail('Java accepted as waiting gate')
        self.assertEqual(calls,[])

    def test_unexpected_exec_is_paused_and_requires_reconciliation(self):
        w,auth,calls,actual,process,row=self.fixture()
        with self.assertRaises(ValueError):
            with w.peer_window():process['processKind']='APPLICATION_RUNNING'
        self.assertTrue(actual['State']['Paused']);self.assertEqual(w.retained()['state'],'CLOSED_RECONCILE')
        self.assertEqual(len(calls),2)

    def test_wrong_predecessor_intent_cannot_open_window(self):
        w,auth,calls,actual,process,row=self.fixture();row['effects'][0]['intentHash']='e'*64
        with self.assertRaisesRegex(ValueError,'EXACT_GATE_WINDOW_AFTER_STAGE'):
            with w.peer_window():self.fail('foreign stage chain accepted')
        self.assertEqual(calls,[])

if __name__=='__main__':unittest.main()
