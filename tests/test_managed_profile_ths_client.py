"""Client selection preserves the secret boundary and literal map-key semantics."""
import ast,copy,hashlib,importlib.util,json,os,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('ths_client',ROOT/'scripts/read-managed-profile-ths-client-20261028.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
base_spec=importlib.util.spec_from_file_location('prior_scope_fixture',ROOT/'tests/test_managed_profile_ths_scopes.py');f=importlib.util.module_from_spec(base_spec);base_spec.loader.exec_module(f)

def fixture(path='/fixture/onboarding-ths.yaml'):
    prior,review,oldresult,journal,cohort,observations,generations=f.fixture()
    actual=observations[cohort['onboarding']['containerId']]
    high=json.loads(actual['Config']['Env'][1].split('=',1)[1]);del high[m.CLIENT_PROPERTY]
    actual['Config']['Env'][1]='SPRING_APPLICATION_JSON='+json.dumps(high)
    actual['Config']['Env'].append('SPRING_CONFIG_ADDITIONAL_LOCATION=optional:file:/etc/owner.yaml')
    actual['Mounts']=[{'Type':'bind','RW':False,'Source':path,'Destination':'/etc/owner.yaml'}]
    observations[cohort['peer-0']['containerId']]['Name']='/ouf-keycloak'
    overlay={'spring':{'security':{'oauth2':{'client':{'registration':{'ouf-ths':{'client-id':'human-ui-fixture','client-secret':'NEVER_PUBLIC_PRIVATE_CANARY','provider':'tenant-oidc','authorization-grant-type':'authorization_code'}},'provider':{'tenant-oidc':{'issuer-uri':'https://idp.fixture.test/realms/fixture'}}}}}}}
    raw=json.dumps(overlay).encode();binding={'path':path,'sha256':hashlib.sha256(raw).hexdigest(),'metadata':[]}
    retained={'binding':binding,'target':'/etc/owner.yaml','metadata':{'format':'STRICT_JSON'}}
    review['nativePlan']['proposal']['nativeFlywayConfiguration']={'ownerOverlays':[retained]}
    review['frozenPlanHash']=m.digest(review['nativePlan']['proposal'])
    summary,environment=m.scope_patch(actual)
    engine_binding=review['nativePlan']['proposal']['engineBinding']
    inputs={'schema':'ouf.managed-profile-ths-scope-current-inputs.v1','bootId':'fixture-boot','engineBinding':engine_binding,
            'currentObservations':{r:observations[b['containerId']]for r,b in cohort.items()},'currentProcessPins':generations,
            'currentRootProcessPins':{'pid1':{'pid':1},'engine':{'pid':77}},'retainedReviewHash':m.digest(review),
            'scopeInspection':summary,'conditionalOnboardingEnvironment':environment,
            **{k:False for k in ('historicalAuthorityReused','executionEntryQualified','targetApplyAuthorized','runtimeAuthorityIssued','automaticReplayAllowed','budgetReset')}}
    case={**m.CASE,'inputsHash':m.digest(inputs),'reviewHash':m.digest(review),'frozenPlanHash':review['frozenPlanHash'],
          'installedRoot':review['executionRoot'],'ownerOverlayPath':path,'onboardingBindingHash':m.digest(m.stable_binding(actual))}
    receipt={'schema':'ouf.managed-profile-ths-scope-capture-result.v1','status':'MANAGED_PROFILE_THS_SCOPE_REQUEST_OBSERVED_NOT_AUTHORIZED',
             'complete':True,'inputsHash':case['inputsHash'],'contextPath':case['priorRoot'],'counts':{'bytes':743005,'engineGets':27,'privateMetadataReads':3},'scopeInspection':summary}
    return case,review,inputs,receipt,raw,retained

class ClientContractTests(unittest.TestCase):
    def setUp(self):
        self.case,self.review,self.inputs,self.receipt,self.raw,self.retained=fixture()
        self.actual=self.inputs['currentObservations']['onboarding']
    def test_observed_client_is_distinct_from_registration_and_secret_never_returned(self):
        metadata=m.client_metadata(self.actual,self.raw,self.retained)
        self.assertEqual(metadata['clientId'],'human-ui-fixture');self.assertEqual(metadata['registrationId'],'ouf-ths')
        self.assertFalse(metadata['iamBindingObserved']);self.assertFalse(metadata['browserTokenInspected']);self.assertFalse(metadata['rawOverlayPersisted'])
        self.assertNotIn('CANARY',json.dumps(metadata));self.assertEqual(metadata['realm'],'fixture')
    def test_higher_priority_client_override_is_resolved_without_replacing_other_properties(self):
        actual=copy.deepcopy(self.actual);high=json.loads(actual['Config']['Env'][1].split('=',1)[1]);high[m.CLIENT_PROPERTY]='actual-high-priority-client';actual['Config']['Env'][1]='SPRING_APPLICATION_JSON='+json.dumps(high)
        self.assertEqual(m.client_metadata(actual,self.raw,self.retained)['clientId'],'actual-high-priority-client')
    def test_registration_keys_are_literal_not_relaxed_names(self):
        raw=self.raw.replace(b'"ouf-ths"',b'"oufths"')
        with self.assertRaisesRegex(m.Stop,'EXACT_THS_OAUTH_MAP_KEY_REQUIRED'):m.client_metadata(self.actual,raw,self.retained)
    def test_duplicate_flat_nested_properties_rejected(self):
        value=json.loads(self.raw);value[m.CLIENT_PROPERTY]='other'
        with self.assertRaises(m.Stop):m.client_metadata(self.actual,json.dumps(value).encode(),self.retained)
    def test_unknown_namespace_or_placeholder_is_not_interpreted(self):
        for raw in (self.raw.replace(b'human-ui-fixture',b'${CLIENT_ID}'),b'{"spring.config.import":"file:/secret"}'):
            with self.subTest(raw=raw[:20]),self.assertRaises(m.Stop):m.client_metadata(self.actual,raw,self.retained)
    def test_missing_client_is_not_invented(self):
        value=json.loads(self.raw);del value['spring']['security']['oauth2']['client']['registration']['ouf-ths']['client-id']
        with self.assertRaisesRegex(m.Stop,'LITERAL_EFFECTIVE_THS_CLIENT_ID_REQUIRED'):m.client_metadata(self.actual,json.dumps(value).encode(),self.retained)
    def test_issuer_credentials_queries_non_tls_or_alternate_endpoint_rejected(self):
        for issuer in ('http://idp.fixture.test/realms/fixture','https://user:pass@idp.fixture.test/realms/fixture','https://idp.fixture.test/realms/fixture?token=secret'):
            with self.subTest(issuer=issuer),self.assertRaises(m.Stop):m.client_metadata(self.actual,self.raw.replace(b'https://idp.fixture.test/realms/fixture',issuer.encode()),self.retained)
        value=json.loads(self.raw);value['spring']['security']['oauth2']['client']['provider']['tenant-oidc']['token-uri']='https://other.test/token'
        with self.assertRaises(m.Stop):m.client_metadata(self.actual,json.dumps(value).encode(),self.retained)
    def test_wrong_mount_path_writable_mount_or_additional_loader_denied(self):
        for kind in ('writable','path','loader','java'):
            actual=copy.deepcopy(self.actual)
            if kind=='writable':actual['Mounts'][0]['RW']=True
            elif kind=='path':actual['Mounts'][0]['Source']='/other.yaml'
            elif kind=='loader':actual['Config']['Env'].append('SPRING_CONFIG_IMPORT=file:/other.yaml')
            else:actual['Config']['Env'].append('_JAVA_OPTIONS=-Dclient=other')
            with self.subTest(kind=kind),self.assertRaises(m.Stop):m.selected_overlay(actual,self.retained)
    def test_source_contract_and_custody_functions_are_exact_in_sealed_reader(self):
        reader={n.name:ast.dump(n,include_attributes=False)for n in ast.parse((ROOT/'scripts/read-managed-profile-ths-client-20261028.py').read_text()).body if isinstance(n,(ast.FunctionDef,ast.ClassDef))}
        for path,names in [('tools/managed_profile_ths_scopes/client.py',None),('tools/managed_profile_ths_scopes/overlay.py',None),('tools/acquisition_read_native/plan_helper.py',{'private_config','selected_directory_custody','selected_file_custody'})]:
            for node in ast.parse((ROOT/path).read_text()).body:
                if isinstance(node,ast.FunctionDef)and(names is None or node.name in names):self.assertEqual(ast.dump(node,include_attributes=False),reader[node.name])
        original={n.name:ast.dump(n,include_attributes=False)for n in ast.parse((ROOT/'tools/source_revision_update/configuration.py').read_text()).body if isinstance(n,ast.FunctionDef)}
        for name in ('owner_json_overlay','additional_location'):self.assertEqual(original[name],reader[name])
    def test_no_tty_before_capture_configuration_or_network(self):
        flags=type('Flags',(),{'isolated':1,'no_site':1})()
        with patch.object(m.sys,'argv',['reader']),patch.object(m.sys,'flags',flags),patch.object(m.sys,'dont_write_bytecode',True),patch.object(m.os,'geteuid',return_value=0),patch.object(m.os,'getegid',return_value=0),patch.object(m.pwd,'getpwnam',return_value=type('User',(),{'pw_uid':1001})()),patch.dict(m.os.environ,{'SUDO_UID':'1001'}),patch.object(m.sys.stdin,'isatty',return_value=False),patch.object(m,'Capture')as capture,patch('builtins.print')as output:
            self.assertEqual(m.main(),2)
        capture.assert_not_called();self.assertIn('INTERACTIVE_OPERATOR_TERMINAL_REQUIRED',str(output.call_args))
    def test_reusable_helper_imports_without_deployment_controller_side_effects(self):
        sys.path.insert(0,str(ROOT))
        try:
            from tools.managed_profile_ths_scopes.client import client_metadata
            self.assertEqual(client_metadata(self.actual,self.raw,self.retained)['clientId'],'human-ui-fixture')
        finally:sys.path.pop(0)
    def test_preparation_reads_only_expected_metadata_and_two_generations_twice(self):
        with tempfile.TemporaryDirectory()as directory:
            file=Path(directory)/'overlay.json';file.write_bytes(self.raw)
            self.retained['binding']['path']=str(file);self.retained['binding']['metadata']=list(m.frame(file.stat()))
            self.actual['Mounts'][0]['Source']=str(file);self.case['ownerOverlayPath']=str(file)
            self.review['frozenPlanHash']=self.case['frozenPlanHash']=m.digest(self.review['nativePlan']['proposal'])
            self.inputs['retainedReviewHash']=self.case['reviewHash']=m.digest(self.review)
            self.inputs['scopeInspection'],self.inputs['conditionalOnboardingEnvironment']=m.scope_patch(self.actual)
            self.case['onboardingBindingHash']=m.digest(m.stable_binding(self.actual));self.case['inputsHash']=self.receipt['inputsHash']=m.digest(self.inputs)
            self.receipt['scopeInspection']=self.inputs['scopeInspection'];writes={};reads=[];outer=self
            class Capture:
                root=Path('/fixture/new-client-scope');counts={'engineGets':0,'privateMetadataReads':0,'bytes':0};seals={}
                def private(s,path,expected=None):
                    s.counts['privateMetadataReads']+=1;return {'inputs.json':outer.inputs,'result.json':outer.receipt,'review.json':outer.review}[path.name]
                def put(s,name,value):writes[name]=copy.deepcopy(value)
            observations={v['Id']:v for v in self.inputs['currentObservations'].values()}
            class Engine:
                def __init__(s,c,binding,ids):s.c=c;outer.assertEqual(len(ids),2)
                def get(s,path):
                    reads.append(path);s.c.counts['engineGets']+=1
                    return {'ServerVersion':'29.8.1'}if path=='/v1.44/info'else copy.deepcopy(observations[path.split('/')[-2]])
            pins={v['pid']:v for v in self.inputs['currentProcessPins'].values()};pins[1]={'pid':1};pins[77]={'pid':77}
            boot=type('Boot',(),{'read_text':lambda s:'fixture-boot'})()
            out=m.inspect_client(Capture(),self.case,engine_factory=Engine,pin=lambda pid:pins[pid],boot_path=boot,read_overlay=lambda p,b:(file.read_bytes(),b),mounted_stat=lambda _:file.stat())
            self.assertEqual(len(reads),5);self.assertEqual(out['counts']['privateMetadataReads'],3);self.assertEqual(out['counts']['configurationFileContentReads'],1)
            self.assertNotIn('NEVER_PUBLIC',json.dumps(out));self.assertNotIn('NEVER_PUBLIC',json.dumps(writes));self.assertFalse(out['scopePatchApplied']);self.assertEqual(out['iamRequests'],0)
            self.assertFalse(out['runtimeAuthorityIssued']);self.assertFalse(out['targetApplyAuthorized'])

if __name__=='__main__':unittest.main()
