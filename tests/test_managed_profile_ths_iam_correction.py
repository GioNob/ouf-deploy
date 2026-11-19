"""Additive IAM plan, current-state gate, partial outcomes and no replay."""
import ast,base64,copy,importlib.util,json,os,sys,time,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('ths_correction',ROOT/'scripts/correct-managed-profile-ths-iam-bindings-20261028.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
fixture_spec=importlib.util.spec_from_file_location('old_binding_fixture',ROOT/'tests/test_managed_profile_ths_iam_bindings.py');f=importlib.util.module_from_spec(fixture_spec);fixture_spec.loader.exec_module(f)

def baseline(name='tenant-ths'):
    definitions=[{'id':'known-'+str(i),'name':name,'protocol':'openid-connect','attributes':{'include.in.token.scope':'true'}}for i,name in enumerate(m.REQUIRED[:2])]
    definitions +=[{'id':'old-default','name':'prior.default','protocol':'openid-connect','attributes':{}},{'id':'old-optional','name':'prior.optional','protocol':'openid-connect','attributes':{}}]
    defaults=[copy.deepcopy(definitions[2])];optionals=[copy.deepcopy(definitions[3])]
    client=f.client(name);report=m.binding_report(client,defaults,optionals,definitions,{n:{}for n in m.REQUIRED[:2]},expected_client=name)
    return client,definitions,defaults,optionals,report
def plan_for(report,installation='one'):
    return m.compile_correction(report,copy.deepcopy(report),installation_ref=installation,parent_result_hash='a'*64,realm=installation)

class PlannerTests(unittest.TestCase):
    def setUp(self):self.client,self.defs,self.defaults,self.optionals,self.report=baseline();self.plan=plan_for(self.report)
    def test_one_fixed_uuid_definition_and_three_optional_links_only(self):
        self.assertEqual(len(self.plan['assignmentsToAdd']),3);self.assertTrue(all(r['type']=='OPTIONAL'for r in self.plan['assignmentsToAdd']))
        self.assertEqual(self.plan['definitionToCreate']['name'],m.REQUIRED[2]);self.assertEqual(self.plan['definitionToCreate']['protocolMappers'],[])
        self.assertFalse(self.plan['realmDefaultMutationAuthorized']);self.assertFalse(self.plan['clientSettingsMutationAuthorized']);self.assertFalse(self.plan['humanProfilingBudgetAuthorized'])
    def test_two_installations_get_separate_identity_bound_ids_with_reproducible_intent(self):
        one=plan_for(self.report,'one');two=plan_for(baseline('second-ths')[4],'two')
        self.assertEqual(one,plan_for(self.report,'one'));self.assertNotEqual(one['definitionToCreate']['id'],two['definitionToCreate']['id'])
        self.assertEqual(two['clientId'],'second-ths');self.assertNotEqual(one['operationRef'],two['operationRef'])
    def test_baseline_or_existing_definition_restriction_cannot_be_adopted(self):
        for kind in ('hash','id','role','defined'):
            observation=copy.deepcopy(self.report)
            if kind=='hash':observation['bindingSnapshotHash']='b'*64
            if kind=='id':observation['requiredScopes'][0]['id']='foreign'
            if kind=='role':observation['requiredScopes'][0]['unrestrictedByScopeRoleMappings']=False
            if kind=='defined':observation['requiredScopes'][2]['defined']=True
            with self.subTest(kind=kind),self.assertRaises(m.Stop):m.compile_correction(observation,self.report,installation_ref='one',parent_result_hash='a'*64,realm='one')
    def test_missing_or_modified_operation_marker_cannot_reconcile_foreign_scope(self):
        for change in ('marker','id','mappers','attributes'):
            detail=copy.deepcopy(self.plan['definitionToCreate'])
            if change=='marker':detail['attributes'][m.MARKER]='foreign'
            if change=='id':detail['id']='foreign'
            if change=='mappers':detail['protocolMappers']=[{'id':'foreign'}]
            if change=='attributes':detail['otherAttributeCount']=1
            with self.subTest(change=change),self.assertRaises(m.Stop):m.validate_created_scope(detail,self.plan)
    def test_only_fixed_provider_location_is_accepted_and_never_followed(self):
        endpoint={'storedServerUrl':'http://localhost:8080','connectHost':'127.0.0.1','connectPort':8080};path='/admin/realms/one/client-scopes/'+self.plan['definitionToCreate']['id']
        m.validate_location('https://idp.test'+path,self.plan,endpoint,'https://idp.test/realms/one')
        for location in ('https://foreign.test'+path,'https://idp.test'+path+'?secret=bad',path.replace('/one/','/foreign/')):
            with self.subTest(location=location),self.assertRaises(m.Stop):m.validate_location(location,self.plan,endpoint,'https://idp.test/realms/one')
    def test_duplicate_binding_ids_are_not_silently_deduplicated(self):
        with self.assertRaises(m.Stop):m.link_map(self.defaults+self.defaults)
    def test_sealed_functions_equal_reusable_production_modules(self):
        target={n.name:ast.dump(n,include_attributes=False)for n in ast.parse((ROOT/'scripts/correct-managed-profile-ths-iam-bindings-20261028.py').read_text()).body if isinstance(n,(ast.FunctionDef,ast.ClassDef))}
        for path in ('iam_correction.py','iam_correction_transport.py','iam_correction_controller.py'):
            for n in ast.parse((ROOT/'tools/managed_profile_ths_scopes'/path).read_text()).body:
                if isinstance(n,(ast.FunctionDef,ast.ClassDef)):self.assertEqual(ast.dump(n,include_attributes=False),target[n.name])
    def test_reusable_modules_import_without_authentication_or_network(self):
        sys.path.insert(0,str(ROOT))
        try:
            from tools.managed_profile_ths_scopes.iam_correction import compile_correction
            self.assertEqual(compile_correction(self.report,self.report,installation_ref='one',parent_result_hash='a'*64,realm='one')['definitionToCreate']['id'],self.plan['definitionToCreate']['id'])
        finally:sys.path.pop(0)

class WriteLedgerTests(unittest.TestCase):
    def setUp(self):
        self.cap=f.Capture();self.ledger=m.CorrectionLedger(self.cap,clock=lambda:100);self.ledger.deadline=200
        self.ledger.approvedReviewHash='c'*64;self.ledger.authenticated=self.ledger.identityVerified=True
        self.payload={'operation':'CREATE_SCOPE','scopeUuid':'new-scope','scopeName':m.REQUIRED[2],'clientUuid':'client'}
    def test_lost_write_response_is_reserved_once_and_cannot_be_replayed_under_other_stage(self):
        calls=[];send=lambda p:(calls.append(p)or{'status':0,'body':None,'retryAfter':'','bytes':0,'location':''})
        self.ledger.write('create','CREATE_SCOPE',self.payload,send,lambda:None,expiry=180)
        with self.assertRaisesRegex(m.Stop,'ALREADY_CLAIMED_NO_REPLAY'):self.ledger.write('different-stage','CREATE_SCOPE',self.payload,send,lambda:None,expiry=180)
        self.assertEqual(len(calls),1);self.assertEqual(self.cap.counts['iamWritesReserved'],1)
        with self.assertRaises(m.Stop):m.CorrectionLedger(self.cap)
    def test_http_receipt_is_persisted_before_process_guard_failure(self):
        guards=[0]
        def guard():
            guards[0]+=1
            if guards[0]>1:raise m.Stop('GENERATION_DRIFT_AFTER_RESPONSE')
        with self.assertRaises(m.Stop):self.ledger.write('create','CREATE_SCOPE',self.payload,lambda p:{'status':201,'body':None,'retryAfter':'','bytes':0,'location':'/fixed/location'},guard,expiry=180)
        self.assertTrue(any(v.get('status')==201 and v.get('responseReceived')for v in self.cap.values.values()))
    def test_denial_is_not_reconciled_as_authorized_success(self):
        with self.assertRaisesRegex(m.Stop,'DENIED_OR_UNKNOWN'):self.ledger.write('create','CREATE_SCOPE',self.payload,lambda p:{'status':403,'body':None,'retryAfter':'','bytes':0,'location':''},lambda:None,expiry=180)
        self.assertEqual(self.cap.counts['iamWritesReserved'],1);self.assertEqual(self.cap.counts['iamWritesObserved'],0)
    def test_each_observed_effect_requires_one_claim_and_one_proof(self):
        self.ledger.write('create','CREATE_SCOPE',self.payload,lambda p:{'status':201,'body':None,'retryAfter':'','bytes':0,'location':'/fixed'},lambda:None,expiry=180)
        self.ledger.observed('create',ambiguous=False)
        with self.assertRaises(m.Stop):self.ledger.observed('create',ambiguous=False)
        with self.assertRaises(m.Stop):self.ledger.observed('foreign',ambiguous=True)

class FakeProvider:
    def __init__(self,case,plan,*,drop_create=False,drop_assign=False,foreign=False,absent=False,denied=False,drift=False,post_drift=False,wrong_identity=False):
        self.case,self.plan=case,plan;self.client,self.definitions,self.defaults,self.optionals,_=baseline(case['clientId'])
        self.calls=[];self.writes=[];self.drop_create=drop_create;self.drop_assign=drop_assign;self.foreign=foreign;self.absent=absent;self.denied=denied
        self.post_drift=post_drift;self.wrong_identity=wrong_identity
        if drift:self.optionals=[]
    def __call__(self,program,namespace,p):
        op=p['operation'];self.calls.append(op);status=200;location='';value=None
        if op=='PASSWORD_GRANT':value=f.token(self.case['adminEndpoint'],self.case['issuer'])
        elif op=='IDENTITY':value={'id':'admin-subject','username':'foreign'if self.wrong_identity else self.case['adminEndpoint']['expectedAdminUser'],'enabled':True}
        elif op=='CLIENT_LIST':value=[self.client]
        elif op=='CLIENT':value=self.client
        elif op=='DEFAULTS':value=self.defaults
        elif op=='OPTIONALS':value=self.optionals
        elif op=='DEFINITIONS':value=self.definitions
        elif op=='SCOPE_ROLES':value={}
        elif op=='CLIENT_INTEGRITY':value={'id':self.client['id'],'clientId':self.client['clientId'],'nonCredentialNonBindingMetadataHash':'changed'if self.post_drift and len(self.writes)==4 else'preserved'}
        elif op=='DEFINITIONS_INTEGRITY':value={d['id']:{'name':d['name'],'metadataHash':m.digest(d)}for d in self.definitions}
        elif op=='REALM_DEFAULTS':value=self.defaults
        elif op=='REALM_OPTIONALS':value=[]
        elif op=='CREATE_SCOPE':
            self.writes.append((op,p['scopeUuid']))
            if self.denied:status=403
            else:
                if not self.absent:
                    definition=copy.deepcopy(self.plan['definitionToCreate'])
                    if self.foreign:definition['attributes'][m.MARKER]='foreign'
                    self.definitions.append(definition)
                status=0 if self.drop_create else 201;location='https://idp.one.test/admin/realms/one/client-scopes/'+p['scopeUuid']if status==201 else''
        elif op=='SCOPE_DETAIL':
            value=next((d for d in self.definitions if d['id']==p['scopeUuid']),None)
            if value is None:status=404
        elif op=='ASSIGN_OPTIONAL':
            self.writes.append((op,p['scopeUuid']));row=next(d for d in self.definitions if d['id']==p['scopeUuid']);self.optionals.append(copy.deepcopy(row))
            status=0 if self.drop_assign else 204
        else:raise AssertionError(op)
        return {'status':status,'body':copy.deepcopy(value),'retryAfter':'','bytes':1,'location':location}

class ControllerTests(unittest.TestCase):
    def invoke(self,*,decline=False,**kwargs):
        case=copy.deepcopy(m.CASE);case.update(clientId='tenant-ths',issuer='https://idp.one.test/realms/one',realm='one',installationRef='one')
        _,_,_,_,report=baseline(case['clientId']);plan=plan_for(report);parent={'bindingObservation':report,'counts':{'oauthRequestsReserved':1}}
        inputs={'currentObservations':{'onboarding':f.actual()},'clientMetadata':f.identity()};self.cap=f.Capture();self.provider=FakeProvider(case,plan,**kwargs)
        prepared=(inputs,parent,plan,{'plan':plan},os.open('/dev/null',os.O_RDONLY),{},lambda:None,lambda:None)
        def prompt(summary,phrase=None):
            return True if phrase else'PRIVATE_IAM_PASSWORD_CANARY'
        def approve(*_):
            if decline:raise m.Stop('OPERATOR_DECLINED')
        with patch('builtins.print'):return m.execute_correction(self.cap,prepared,case,approve=approve,prompt=prompt,sender=self.provider)
    def test_complete_additive_correction_prepares_profile_and_preserves_prior_links(self):
        out=self.invoke();self.assertTrue(out['complete']);self.assertEqual(out['iamMutations'],4);self.assertEqual(out['newOptionalClientBindings'],3)
        self.assertEqual(out['preservedDefaultBindings'],1);self.assertEqual(out['preservedOptionalBindings'],1);self.assertTrue(out['realmDefaultsPreserved'])
        self.assertEqual(out['counts']['oauthRequestsReserved'],1);self.assertEqual(out['counts']['adminGetsReserved'],29);self.assertEqual(out['cumulativeAdministrativeAuthenticationReservationsInThisLineage'],2)
        self.assertFalse(out['scopePatchApplied']);self.assertFalse(out['runtimeAuthorityIssued']);self.assertEqual(out['humanBudgetsGranted'],0)
        self.assertNotIn('PRIVATE_IAM',json.dumps(self.cap.values));self.assertNotIn('fixture.',json.dumps(self.cap.values))
    def test_lost_creation_and_assignment_responses_reconcile_same_ids_without_repeating_writes(self):
        out=self.invoke(drop_create=True,drop_assign=True);self.assertTrue(out['complete']);self.assertEqual(len(self.provider.writes),4)
        self.assertEqual(len(set(self.provider.writes)),4);self.assertEqual(out['counts']['iamWritesObserved'],4)
        self.assertEqual(sum(bool(v.get('httpOutcomeAmbiguous'))for v in self.cap.values.values()),4)
    def test_declined_review_does_not_authenticate(self):
        with self.assertRaisesRegex(m.Stop,'DECLINED'):self.invoke(decline=True)
        self.assertEqual(self.provider.calls,[]);self.assertEqual(self.cap.counts['oauthRequestsReserved'],0)
    def test_wrong_identity_stops_before_client_read_or_write(self):
        with self.assertRaisesRegex(m.Stop,'PROTECTED_IAM_ADMIN_IDENTITY'):self.invoke(wrong_identity=True)
        self.assertEqual(self.provider.calls,['PASSWORD_GRANT','IDENTITY']);self.assertEqual(self.provider.writes,[])
    def test_changed_baseline_stops_without_iam_mutation(self):
        with self.assertRaisesRegex(m.Stop,'BASELINE_DRIFT'):self.invoke(drift=True)
        self.assertEqual(self.provider.writes,[])
    def test_foreign_created_definition_is_not_adopted(self):
        with self.assertRaisesRegex(m.Stop,'EXACT_CREATED_DEFINITION'):self.invoke(drop_create=True,foreign=True)
        self.assertEqual(len(self.provider.writes),1);self.assertNotIn('configuration-profile.json',self.cap.values)
    def test_ambiguous_creation_without_observed_resource_stops_after_one_post(self):
        with self.assertRaises(m.Stop):self.invoke(drop_create=True,absent=True)
        self.assertEqual(len(self.provider.writes),1)
    def test_explicit_permission_denial_stops_before_following_mutations(self):
        with self.assertRaisesRegex(m.Stop,'DENIED_OR_UNKNOWN'):self.invoke(denied=True)
        self.assertEqual(len(self.provider.writes),1);self.assertNotIn('SCOPE_DETAIL',self.provider.calls)
    def test_postcondition_drift_keeps_all_proofs_and_blocks_configuration_profile(self):
        with self.assertRaisesRegex(m.Stop,'CLIENT_CONFIGURATION_CHANGED'):self.invoke(post_drift=True)
        self.assertEqual(self.cap.counts['iamWritesObserved'],4);self.assertNotIn('configuration-profile.json',self.cap.values)
    def test_non_tty_stops_before_private_capture_or_authentication(self):
        flags=type('Flags',(),{'isolated':1,'no_site':1})()
        with patch.object(m.sys,'argv',['entry']),patch.object(m.sys,'flags',flags),patch.object(m.sys,'dont_write_bytecode',True),patch.object(m.os,'geteuid',return_value=0),patch.object(m.os,'getegid',return_value=0),patch.object(m.pwd,'getpwnam',return_value=type('User',(),{'pw_uid':1001})()),patch.dict(m.os.environ,{'SUDO_UID':'1001'}),patch.object(m.sys.stdin,'isatty',return_value=False),patch.object(m,'CorrectionCapture')as cap,patch('builtins.print')as output:
            self.assertEqual(m.main(),2)
        cap.assert_not_called();self.assertIn('INTERACTIVE_OPERATOR_TERMINAL_REQUIRED',str(output.call_args))

if __name__=='__main__':unittest.main()
