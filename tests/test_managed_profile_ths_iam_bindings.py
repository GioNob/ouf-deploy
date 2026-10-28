"""Real pure compiler/ledger/identity functions, with no real credentials or network."""
import ast,base64,copy,importlib.util,json,os,sys,time,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('ths_iam_reader',ROOT/'scripts/read-managed-profile-ths-iam-bindings-20261028.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

def rows():return [{'id':'scope-'+str(i),'name':name,'protocol':'openid-connect','attributes':{'include.in.token.scope':'true'}}for i,name in enumerate(m.REQUIRED)]+[{'id':'baseline-scope','name':'prior.scope','protocol':'openid-connect','attributes':{}}]
def client(name='tenant-ths'):return {'id':'client-uuid','clientId':name,'enabled':True,'protocol':'openid-connect','standardFlowEnabled':True,'publicClient':False}
def report(name='tenant-ths',**kwargs):
    all_rows=rows();return m.binding_report(client(name),all_rows[-1:],all_rows[:-1],all_rows,{n:{}for n in m.REQUIRED},expected_client=name,**kwargs)
def actual(client_id='tenant-ths',issuer='https://idp.one.test/realms/one'):
    obj={m.SCOPE_PROPERTY:['openid','resolution.issue.read','resolution.match.approve'],'unrelated.scalar':'RETAINED_ENVIRONMENT_PRIVATE_CANARY',m.CLIENT_PROPERTY:client_id}
    return {'Id':'1'*64,'Image':'sha256:'+'2'*64,'Config':{'Env':['UNCHANGED=one','SPRING_APPLICATION_JSON='+json.dumps(obj)],'Cmd':['-jar','app.jar'],'Entrypoint':['java'],'Labels':{'retain':'yes'}},'HostConfig':{'Memory':999},'Mounts':[{'Source':'/profile/one','Destination':'/run/one','RW':False}]}
def identity(name='tenant-ths',issuer='https://idp.one.test/realms/one'):return {'clientId':name,'issuer':issuer,'registrationId':'ouf-ths','fileSelectionAndPrecedenceVerified':True}
class Capture:
    def __init__(self):self.counts={'bytes':0,'engineGets':0,'privateMetadataReads':0};self.values={};self.root=Path('/fixture/current-iam-operation')
    def put(self,name,value):
        if name in self.values:raise AssertionError('append-only journal overwritten')
        self.values[name]=copy.deepcopy(value)
def token(endpoint,issuer,*,remaining=60,subject='admin-subject'):
    now=int(time.time());base={'iss':issuer.rsplit('/realms/',1)[0]+'/realms/'+endpoint['adminRealm'],'azp':endpoint['adminClientId'],'iat':now,'exp':now+remaining}
    def jwt(value):return'fixture.'+base64.urlsafe_b64encode(m.encoded(value)).decode().rstrip('=')+'.fixture'
    return {'access_token':jwt(base),'id_token':jwt({**base,'aud':endpoint['adminClientId'],'sub':subject}),'token_type':'Bearer','expires_in':remaining}

class BindingCompilerTests(unittest.TestCase):
    def test_default_and_optional_assignments_both_eligible_without_grant_or_token_claim(self):
        value=report();self.assertTrue(value['bindingAndUnrestrictedEligibilityProven']);self.assertEqual(value['defaultScopeCount'],1);self.assertEqual(value['optionalScopeCount'],3)
        self.assertFalse(value['effectiveBrowserTokenScopesProven']);self.assertEqual(value['iamMutations'],0)
    def test_missing_definition_binding_include_flag_or_role_scope_blocks_profile(self):
        for kind in ('definition','binding','include','role','dynamic'):
            all_rows=rows();optional=copy.deepcopy(all_rows[:-1]);mapping={n:{}for n in m.REQUIRED}
            if kind=='definition':all_rows=all_rows[1:];optional=optional[1:]
            if kind=='binding':optional=optional[1:]
            if kind=='include':all_rows[0]['attributes']['include.in.token.scope']='false';optional[0]['attributes']['include.in.token.scope']='false'
            if kind=='role':mapping[m.REQUIRED[0]]={'realmMappings':[{'id':'restricted-role','name':'restricted'}]}
            if kind=='dynamic':all_rows[0]['attributes']['is.dynamic.scope']='true';optional[0]['attributes']['is.dynamic.scope']='true'
            with self.subTest(kind=kind):
                value=m.binding_report(client(),all_rows[-1:],optional,all_rows,mapping,expected_client='tenant-ths')
                self.assertFalse(value['bindingAndUnrestrictedEligibilityProven'])
                with self.assertRaises(m.Stop):m.configuration_profile(actual(),value,identity(),installation_ref='one')
    def test_absent_include_flag_matches_keycloak_default_true(self):
        all_rows=rows()
        for row in all_rows:row['attributes']={}
        value=m.binding_report(client(),[],all_rows,all_rows,{n:{}for n in m.REQUIRED},expected_client='tenant-ths')
        self.assertTrue(value['bindingAndUnrestrictedEligibilityProven']);self.assertIsNone(value['requiredScopes'][0]['includeInTokenScopeAttribute'])
    def test_duplicate_id_double_binding_or_different_definition_cannot_be_accepted(self):
        all_rows=rows()
        for kind in ('duplicate','double','drift'):
            d=[];o=copy.deepcopy(all_rows);definitions=copy.deepcopy(all_rows)
            if kind=='duplicate':definitions.append(copy.deepcopy(definitions[0]))
            if kind=='double':d=[copy.deepcopy(o[0])]
            if kind=='drift':o[0]['id']='different-id'
            with self.subTest(kind=kind),self.assertRaises(m.Stop):m.binding_report(client(),d,o,definitions,{},expected_client='tenant-ths')
    def test_wrong_disabled_or_non_browser_client_is_denied(self):
        for key,value in [('clientId','foreign'),('enabled',False),('standardFlowEnabled',False),('protocol','saml')]:
            row=client();row[key]=value
            with self.subTest(key=key),self.assertRaises(m.Stop):m.binding_report(row,[],[],[],{},expected_client='tenant-ths')
    def test_compiler_runs_on_two_independent_installation_profiles_and_preserves_every_other_property(self):
        for number in (1,2):
            name='tenant-'+str(number)+'-browser';issuer='https://idp'+str(number)+'.fixture.test/realms/realm'+str(number)
            before=actual(name,issuer);before['Id']=str(number)*64;before['Image']='sha256:'+str(number+3)*64;before['Mounts'][0]['Source']='/tenant'+str(number)+'/config'
            saved=copy.deepcopy(before);profile=m.configuration_profile(before,report(name),identity(name,issuer),installation_ref='installation-'+str(number))
            self.assertEqual(before,saved);self.assertEqual(profile['ownerImageId'],before['Image']);self.assertEqual(profile['clientId'],name);self.assertEqual(profile['issuer'],issuer)
            self.assertEqual(profile['replacementEnvironment'][0],before['Config']['Env'][0]);after=json.loads(profile['replacementEnvironment'][1].split('=',1)[1]);old=json.loads(before['Config']['Env'][1].split('=',1)[1])
            self.assertEqual(after[m.SCOPE_PROPERTY],old[m.SCOPE_PROPERTY]+list(m.REQUIRED));del after[m.SCOPE_PROPERTY];del old[m.SCOPE_PROPERTY];self.assertEqual(after,old)
            self.assertFalse(profile['targetApplyAuthorized']);self.assertTrue(profile['newHumanExecutionReviewRequired'])
    def test_already_complete_request_does_not_create_noop_deployment(self):
        value=actual();config=json.loads(value['Config']['Env'][1].split('=',1)[1]);config[m.SCOPE_PROPERTY]+=list(m.REQUIRED);value['Config']['Env'][1]='SPRING_APPLICATION_JSON='+json.dumps(config)
        with self.assertRaisesRegex(m.Stop,'ALREADY_COMPLETE_REQUEST'):m.configuration_profile(value,report(),identity(),installation_ref='one')
    def test_forged_summary_cannot_hide_blocked_row(self):
        value=report();value['requiredScopes'][0]['eligibleForExplicitRequest']=False
        with self.assertRaises(m.Stop):m.configuration_profile(actual(),value,identity(),installation_ref='one')
    def test_sealed_reader_contains_actual_reusable_function_bodies(self):
        target={n.name:ast.dump(n,include_attributes=False)for n in ast.parse((ROOT/'scripts/read-managed-profile-ths-iam-bindings-20261028.py').read_text()).body if isinstance(n,(ast.FunctionDef,ast.ClassDef))}
        for file in ('bindings.py','iam_read.py'):
            for node in ast.parse((ROOT/'tools/managed_profile_ths_scopes'/file).read_text()).body:
                if isinstance(node,(ast.FunctionDef,ast.ClassDef)):self.assertEqual(ast.dump(node,include_attributes=False),target[node.name])
    def test_reusable_module_import_has_no_network_or_login_effect(self):
        sys.path.insert(0,str(ROOT))
        try:
            from tools.managed_profile_ths_scopes.bindings import configuration_profile
            self.assertEqual(configuration_profile(actual(),report(),identity(),installation_ref='one')['addedRequestScopes'],list(m.REQUIRED))
        finally:sys.path.pop(0)

class LedgerTests(unittest.TestCase):
    def setUp(self):
        self.cap=Capture();self.now=[100.0];self.ledger=m.ReadLedger(self.cap,clock=lambda:self.now[0],sleep=lambda delay:self.now.__setitem__(0,self.now[0]+delay));self.ledger.deadline=220
    def test_ambiguous_authentication_consumes_one_reservation_and_never_retries(self):
        calls=[]
        def send(payload):calls.append(payload);return {'status':0,'body':None,'retryAfter':'','bytes':0}
        with self.assertRaisesRegex(m.Stop,'AUTHENTICATION_OUTCOME_STOP'):self.ledger.request('auth','PASSWORD_GRANT',{'operation':'PASSWORD_GRANT'},send,lambda:None)
        self.assertEqual(len(calls),1);self.assertEqual(self.cap.counts['oauthRequestsReserved'],1)
        with self.assertRaises(m.Stop):self.ledger.request('auth','PASSWORD_GRANT',{'operation':'PASSWORD_GRANT'},send,lambda:None)
        with self.assertRaisesRegex(m.Stop,'NO_COUNTER_RESET'):m.ReadLedger(self.cap)
        self.assertEqual(len(calls),1)
    def test_effective_identity_is_required_before_any_client_read(self):
        self.ledger.authenticated=True
        with self.assertRaisesRegex(m.Stop,'PROTECTED_EFFECTIVE_IAM_IDENTITY'):self.ledger.request('client','CLIENT',{'operation':'CLIENT'},lambda _:self.fail('request dispatched'),lambda:None,expiry=200)
    def test_transient_get_waits_in_same_ledger_and_never_extends_deadline_or_token(self):
        self.ledger.authenticated=self.ledger.identityVerified=True;values=iter([{'status':503,'body':None,'retryAfter':'7','bytes':1},{'status':200,'body':{'ok':True},'retryAfter':'','bytes':1}]);before=self.ledger.deadline
        value=self.ledger.request('defaults','DEFAULTS',{'operation':'DEFAULTS'},lambda _:next(values),lambda:None,expiry=200)
        self.assertEqual(value,{'ok':True});self.assertEqual(self.cap.counts['adminGetsReserved'],2);self.assertEqual(self.cap.counts['adminGetRetryReservations'],1);self.assertEqual(self.ledger.deadline,before);self.assertGreaterEqual(self.now[0],107)
        self.assertTrue(any(v.get('nextAttemptAt')for v in self.cap.values.values()))
    def test_permanent_denial_or_wait_beyond_original_expiry_stops_without_retry(self):
        self.ledger.authenticated=self.ledger.identityVerified=True
        for status,header in ((403,''),(429,'120')):
            cap=Capture();ledger=m.ReadLedger(cap,clock=lambda:100);ledger.deadline=200;ledger.authenticated=ledger.identityVerified=True;calls=[]
            with self.subTest(status=status),self.assertRaises(m.Stop):ledger.request('read','DEFAULTS',{'operation':'DEFAULTS'},lambda p:(calls.append(p)or{'status':status,'body':None,'retryAfter':header,'bytes':0}),lambda:None,expiry=150)
            self.assertEqual(len(calls),1)
    def test_counted_operation_cannot_dispatch_an_authentication_under_get_budget(self):
        with self.assertRaisesRegex(m.Stop,'EXACT_COUNTED_IAM_OPERATION'):self.ledger.request('read','DEFAULTS',{'operation':'PASSWORD_GRANT'},lambda _:self.fail('dispatched'),lambda:None,expiry=200)

class ObserveTests(unittest.TestCase):
    def invoke(self,*,wrong_identity=False,missing=False,short=False,drift=False):
        case=copy.deepcopy(m.CASE);case.update(clientId='tenant-ths',issuer='https://idp.one.test/realms/one',realm='one',installationRef='one')
        self.cap=Capture();self.calls=[];data={'currentObservations':{'onboarding':actual()},'clientMetadata':identity()};self.cap.counts.update(privateMetadataReads=2,engineGets=5)
        fd=os.open('/dev/null',os.O_RDONLY);prepared=(data,{'fixture':True},fd,{},lambda:None,lambda:None);snapshot=[0];all_rows=rows()
        if missing:all_rows=all_rows[1:]
        def send(program,namespace,payload):
            op=payload['operation'];self.calls.append(op)
            if op=='PASSWORD_GRANT':value=token(case['adminEndpoint'],case['issuer'],remaining=30 if short else 60)
            elif op=='IDENTITY':value={'id':'admin-subject','username':'wrong'if wrong_identity else case['adminEndpoint']['expectedAdminUser'],'enabled':True}
            elif op=='CLIENT_LIST':value=[client()]
            elif op=='CLIENT':snapshot[0]+=1;value=client()
            elif op=='DEFAULTS':value=all_rows[-1:]
            elif op=='OPTIONALS':value=all_rows[:-1]if not(drift and snapshot[0]>1)else[]
            elif op=='DEFINITIONS':value=all_rows
            elif op=='SCOPE_ROLES':value={}
            else:self.fail('unexpected operation')
            return {'status':200,'body':copy.deepcopy(value),'retryAfter':'','bytes':1}
        with patch('builtins.print'):return m.observe(self.cap,prepared,case,prompt=lambda summary,phrase=None:True if phrase else'PRIVATE_IAM_PASSWORD_CANARY',sender=send)
    def test_full_read_prepares_conditional_profile_without_iam_mutation_or_token_claim(self):
        out=self.invoke();self.assertTrue(out['configurationProfilePrepared']);self.assertEqual(out['counts']['oauthRequestsReserved'],1);self.assertEqual(out['counts']['adminGetsReserved'],16)
        self.assertEqual(self.calls[:3],['PASSWORD_GRANT','IDENTITY','CLIENT_LIST']);self.assertFalse(out['targetApplyAuthorized']);self.assertFalse(out['effectiveBrowserTokenScopesProven'])
        self.assertNotIn('PRIVATE_IAM',json.dumps(self.cap.values));self.assertNotIn('fixture.',json.dumps(self.cap.values));self.assertEqual(out['newGrantsGranted'],0)
    def test_missing_binding_is_observed_but_configuration_profile_is_not_produced(self):
        out=self.invoke(missing=True);self.assertFalse(out['configurationProfilePrepared']);self.assertIn(m.REQUIRED[0],out['bindingObservation']['blockedScopes']);self.assertNotIn('configuration-profile.json',self.cap.values)
    def test_wrong_identity_stops_before_client_reads(self):
        with self.assertRaisesRegex(m.Stop,'PROTECTED_EFFECTIVE_ADMIN_IDENTITY'):self.invoke(wrong_identity=True)
        self.assertEqual(self.calls,['PASSWORD_GRANT','IDENTITY'])
    def test_short_token_cannot_trigger_refresh_or_any_admin_read(self):
        with self.assertRaises(m.Stop):self.invoke(short=True)
        self.assertEqual(self.calls,['PASSWORD_GRANT'])
    def test_binding_drift_keeps_profile_unprepared(self):
        with self.assertRaisesRegex(m.Stop,'SNAPSHOT_DRIFT'):self.invoke(drift=True)
        self.assertNotIn('configuration-profile.json',self.cap.values)
    def test_no_tty_stops_before_metadata_or_authentication(self):
        flags=type('Flags',(),{'isolated':1,'no_site':1})()
        with patch.object(m.sys,'argv',['reader']),patch.object(m.sys,'flags',flags),patch.object(m.sys,'dont_write_bytecode',True),patch.object(m.os,'geteuid',return_value=0),patch.object(m.os,'getegid',return_value=0),patch.object(m.pwd,'getpwnam',return_value=type('User',(),{'pw_uid':1001})()),patch.dict(m.os.environ,{'SUDO_UID':'1001'}),patch.object(m.sys.stdin,'isatty',return_value=False),patch.object(m,'Capture')as cap,patch('builtins.print')as output:
            self.assertEqual(m.main(),2)
        cap.assert_not_called();self.assertIn('INTERACTIVE_OPERATOR_TERMINAL_REQUIRED',str(output.call_args))

if __name__=='__main__':unittest.main()
