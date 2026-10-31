"""Real signed parent/child and journals; Engine create/gate observations modeled."""
import copy,sys,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tests'),str(ROOT/'tools/semantic_application_cutover'),
    str(ROOT/'tools/semantic_lease_recovery'),str(ROOT/'tools/semantic_cohort_admission/cohort-draft')]
import test_m2_discovery_gate_peer_window as gate
from test_m2_provider_installation_template import inputs
from tools.m2_discovery_installation_profile import provider_creation as m

class Creation(unittest.TestCase):
    def fixture(self,*,runtime_binding=None,definition=None,provider_inputs=None,gate_seconds=120):
        fixture=gate.Window();w,auth,gate_calls,registry,process,boundary=fixture.fixture(definition=definition,
            maximum_seconds=gate_seconds);self.addCleanup(fixture.doCleanups)
        root=auth.root/'provider-create';root.mkdir(mode=0o700);options=inputs() if provider_inputs is None else copy.deepcopy(provider_inputs)
        if runtime_binding is not None:options['runtime_binding']=runtime_binding
        template=m.templates.template(**options)
        scope=m.creation_scope(template,w.scope,root);auth.review['components']['providerInstallation']=scope
        w.parent=auth.fixture();w.parent_hash=w.parent.sha
        owner=m.ProviderCreation(parent=w.parent,window=w,template=template,journal_directory=root)
        state={'native':None};calls=[];registry_matching=w.engine.matching_configuration;old_request=w.engine.request
        def matching(transition,request,actual):
            if transition is w.transition:return registry_matching(transition,request,actual)
            return m.Engine.matching_configuration(w.engine,transition,request,actual)
        w.engine.matching_configuration=matching
        def request(method,path,body=None):
            if path.endswith(('/pause','/unpause')):return old_request(method,path)
            calls.append((method,path,copy.deepcopy(body)))
            if method=='GET':return (200,copy.deepcopy(state['native'])) if state['native'] is not None else (404,None)
            if method=='POST' and path=='/v1.44/containers/create?name='+owner.name:
                state['native']={'Id':'9'*64,'Name':'/'+owner.name,'Image':template['expectedImageId'],
                    'Config':{k:copy.deepcopy(v) for k,v in body.items() if k not in {'HostConfig','NetworkingConfig'}},
                    'HostConfig':copy.deepcopy(body['HostConfig']),
                    'State':{'Status':'created','Running':False,'Paused':False,'Restarting':False,'Pid':0}}
                return 201,{'Id':'9'*64}
            raise AssertionError('UNREVIEWED_ENGINE_OPERATION')
        w.engine.request=request
        return owner,w,auth,state,calls,gate_calls,registry,process,boundary
    def test_one_create_in_open_gate_owns_new_id_without_start_or_admission(self):
        owner,w,auth,state,calls,*_=self.fixture()
        with w.peer_window():
            row=owner.create_once();self.assertEqual(row['containerId'],'9'*64)
            self.assertEqual(owner.observe()[0],'APPLIED')
            with self.assertRaises(ValueError):owner.create_once()
        self.assertEqual(owner.owned_id(),'9'*64);self.assertEqual(owner.observe()[0],'APPLIED')
        mutations=[(method,path) for method,path,_ in calls if method!='GET']
        self.assertEqual(mutations,[('POST','/v1.44/containers/create?name='+owner.name)])
        self.assertEqual(state['native']['State']['Pid'],0)
    def test_lost_response_reconciles_after_gate_closure_without_second_post(self):
        owner,w,auth,state,calls,*_=self.fixture();original=owner.engine.request
        def lost(method,path,body=None):
            result=original(method,path,body)
            if method=='POST' and '/create?' in path:raise TimeoutError('CI_LOST_CREATE_REPLY')
            return result
        with patch.object(owner.engine,'request',side_effect=lost),self.assertRaises(TimeoutError):
            with w.peer_window():owner.create_once()
        self.assertTrue(w.observe_closed()['state']=='CLOSED')
        self.assertEqual(owner.observe()[0],'APPLIED');self.assertEqual(owner.owned_id(),'9'*64)
        self.assertEqual(sum(method=='POST' for method,_,_ in calls),1)
    def test_absence_after_attempt_is_unknown_not_permission_to_recreate(self):
        owner,w,auth,state,calls,*_=self.fixture()
        with w.peer_window():
            owner.create_once();state['native']=None
            outcome,evidence=owner.observe();self.assertEqual(outcome,'UNKNOWN')
            self.assertTrue(evidence['nativeNameAbsentIsNotNoEffect'])
            with self.assertRaises(FileExistsError):owner.create_once()
        self.assertEqual(sum(method=='POST' for method,_,_ in calls),1)
    def test_preexisting_name_is_preserved_without_claim_or_post(self):
        owner,w,auth,state,calls,*_=self.fixture();state['native']={'Id':'e'*64}
        with w.peer_window():
            with self.assertRaisesRegex(ValueError,'EXISTING_PROVIDER_NAME'):owner.create_once()
        self.assertEqual(list(owner.root.iterdir()),[]);self.assertFalse(any(method=='POST' for method,_,_ in calls))
    def test_partial_claim_without_dispatch_cannot_adopt_matching_native(self):
        owner,w,auth,state,calls,*_=self.fixture()
        with w.peer_window():
            with patch.object(m,'new_file',side_effect=OSError('CI_PARTIAL_BEFORE_DISPATCH')):
                with self.assertRaises(OSError):owner.create_once()
            self.assertEqual(owner.observe()[0],'UNKNOWN')
            with self.assertRaises(FileExistsError):owner.create_once()
        self.assertFalse(any(method=='POST' for method,_,_ in calls))
    def test_drifted_request_or_scope_cannot_reach_engine_create(self):
        owner,w,auth,state,calls,*_=self.fixture();owner.template['creationRequest']['Env'].append('DRIFT=true')
        with self.assertRaisesRegex(ValueError,'SCOPE_OR_OWNER_DRIFT'):owner.create_once()
        self.assertEqual(calls,[])
    def test_wrong_human_signature_or_expired_parent_stops_before_create(self):
        for invalid in ('signature','expires'):
            owner,w,auth,state,calls,*_=self.fixture()
            if invalid=='signature':(auth.signatures/(owner.parent.sha+'.FINAL_DEPLOYMENT_APPROVAL.json')).unlink()
            else:auth.now+=121
            with self.assertRaises((ValueError,FileNotFoundError)):owner.create_once()
            self.assertEqual(calls,[])
    def test_closed_gate_cannot_authorize_an_unattempted_create(self):
        owner,w,auth,state,calls,*_=self.fixture()
        with w.peer_window():pass
        with self.assertRaises(ValueError):owner.create_once()
        self.assertFalse(any(method=='POST' for method,_,_ in calls))
    def test_foreign_configuration_or_running_process_cannot_be_creation_proof(self):
        for drift in ('config','running','id'):
            owner,w,auth,state,calls,*_=self.fixture()
            with w.peer_window():
                owner.create_once()
                if drift=='config':state['native']['Config']['Env'].append('UNREVIEWED=true')
                elif drift=='running':state['native']['State'].update(Running=True,Status='running',Pid=42)
                else:state['native']['Id']='e'*64
                with self.assertRaises((ValueError,RuntimeError)):owner.observe()
    def test_registry_boundary_changes_are_not_accepted_as_provider_progress(self):
        owner,w,auth,state,calls,gate_calls,registry,process,boundary=self.fixture()
        with self.assertRaises(ValueError):
            with w.peer_window():boundary['nextPhase']=7;owner.create_once()
        self.assertFalse(any(method=='POST' for method,_,_ in calls))
    def test_composed_parent_scope_must_explicitly_include_same_creation(self):
        owner,w,auth,state,calls,*_=self.fixture()
        wrong={'schema':'ouf.discovery-composed-provider-installation-scope.v1','creation':{**owner.scope,'maximumCreateAttempts':2},
            'installation':{'scope':'fixture'},'admission':{'scope':'fixture'}}
        with self.assertRaisesRegex(ValueError,'EXACT_EXPLICIT_PROVIDER_CREATION'):m.ProviderCreation(parent=w.parent,window=w,
            template=owner.template,journal_directory=owner.root,installation_component=wrong)

if __name__=='__main__':unittest.main()
