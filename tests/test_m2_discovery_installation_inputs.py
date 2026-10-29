import copy,importlib.util,json,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]


def module(name,path):
    spec=importlib.util.spec_from_file_location(name,ROOT/path)
    m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m


m=module('installation_inputs','scripts/read-m2-discovery-installation-inputs-20261029.py')
parent=module('parent_fixture','tests/test_m2_discovery_bindings.py')
builder=module('installation_inputs_builder','tools/build_m2_discovery_installation_inputs.py')


def fixture():
    old_case,_,_,_,observations,pins=parent.fixture()
    for actual in observations.values():
        actual['Mounts']=[{'Destination':'/run/fixture','Source':'/var/lib/fixture-private','Type':'bind','RW':False}]
        actual['Config']['Env']+=['MCP_OIDC_TOKEN_ENDPOINT=https://issuer.test/realms/fixture/protocol/openid-connect/token',
            'MCP_OIDC_CLIENT_ID=fixture-client','MCP_OIDC_CLIENT_SECRET_FILE=/run/fixture/credential',
            'MCP_WORKLOAD_TOKEN=never-publish-bearer','MCP_DATABASE_URL=postgresql://secret:never-publish-db@private/db',
            'OUF_SCHEMA_GOV_TOKEN_ENDPOINT=https://user:never-publish-uri@issuer.test/token',
            'SPRING_APPLICATION_JSON={"secret":"never-publish-json"}']
    previous={'schema':'ouf.m2-discovery-current-private-bindings.v1','bootId':'fixture-boot',
        'observations':{role:observations[('%064x'%(1000 if role=='onboarding' else int(role.split('-')[1])+1))] for role in pins},
        'processPins':pins,'rootProcessPins':{'pid1':{'pid':1},'engine':{'pid':77}},
        'engineBinding':{'peerCredentials':[77,0,0]},'historicalAuthorityReused':False,
        'runtimeAuthorityIssued':False,'automaticReplayAllowed':False,'budgetReset':False}
    receipt={'schema':'ouf.m2-discovery-current-bindings-result.v1',
        'status':'M2_DISCOVERY_CURRENT_BINDINGS_CAPTURED_NOT_AUTHORIZED','complete':True,
        'contextPath':'/synthetic/consumed-bindings','cohortSize':13,
        'runtimeAuthorityIssued':False,'targetApplyAuthorized':False,'automaticReplayAllowed':False,'budgetReset':False,
        'bindings':[parent.m.public_binding(actual,pins[role]) for role,actual in previous['observations'].items()]}
    case=copy.deepcopy(m.CASE);case.update(sourceRoot=receipt['contextPath'],outputRoot='/synthetic/new-installation-inputs',targets={})
    for target,old_role in zip(('mcp','semantic','gateway-owner','apisix'),('peer-1','peer-2','peer-3','peer-4')):
        actual=previous['observations'][old_role]
        case['targets'][target]={'containerId':actual['Id'],'imageId':actual['Image'],'nativeBindingHash':m.digest(m.stable_binding(actual))}
    case['sourceInputsHash']=receipt['inputsHash']=m.digest(previous)
    case['sourceResultHash']=m.digest(receipt)
    return case,previous,receipt,observations,pins


class InventoryTests(unittest.TestCase):
    def run_inventory(self,mutate=None,drift=False,root_drift=False,stopped=False):
        case,previous,receipt,observations,pins=fixture()
        if mutate:mutate(case,previous,receipt,observations,pins)
        class Capture:
            root=Path(case['outputRoot']);seals={}
            def __init__(self):self.counts={'privateMetadataReads':0,'engineGets':0,'bytes':0};self.output={}
            def private(self,path,expected=None):
                self.counts['privateMetadataReads']+=1
                return {'inputs.json':previous,'result.json':receipt}[path.name]
            def put(self,name,value):self.output[name]=value
        class Engine:
            def __init__(self,c,binding,ids):self.c=c;self.allowed=set(ids);self.reads={}
            def get(self,path):
                self.c.counts['engineGets']+=1
                if path=='/v1.44/info':return {'ServerVersion':'29.8.1'}
                cid=path.split('/')[-2];assert cid in self.allowed
                self.reads[cid]=self.reads.get(cid,0)+1;row=copy.deepcopy(observations[cid])
                if drift and self.reads[cid]==2:row['Config']['Env'].append('DRIFT=1')
                if stopped:row['State']['Running']=False
                return row
        class Boot:
            def read_text(self):return 'fixture-boot'
        def pin(pid):
            if pid in (1,77):return {'pid':pid,'drift':True} if root_drift else {'pid':pid}
            return next(v for v in pins.values() if v['pid']==pid)
        cap=Capture();self.last_capture=cap
        return m.installation_inputs(cap,case,engine_factory=Engine,pin=pin,boot_path=Boot()),cap

    def test_reproducible_standalone_source(self):
        self.assertEqual((ROOT/'scripts/read-m2-discovery-installation-inputs-20261029.py').read_text(),builder.build())

    def test_only_selected_four_targets_are_read_twice(self):
        out,c=self.run_inventory();self.assertEqual(c.counts,{'privateMetadataReads':2,'engineGets':9,'bytes':0})
        self.assertEqual(set(out['inventories']),{'mcp','semantic','gateway-owner','apisix'})
        self.assertFalse(out['otherNinePeersReobserved'])

    def test_safe_references_are_distinct_from_effective_configuration(self):
        out,c=self.run_inventory();value=out['inventories']['mcp']
        self.assertEqual(value['references']['MCP_OIDC_CLIENT_ID']['value'],'fixture-client')
        self.assertEqual(value['references']['MCP_OIDC_CLIENT_SECRET_FILE']['value'],'/run/fixture/credential')
        self.assertFalse(value['effectiveConfigurationProven']);self.assertFalse(value['credentialCustodyProven'])
        self.assertEqual(value['references']['OUF_SCHEMA_GOV_TOKEN_ENDPOINT']['state'],'UNRESOLVED_NOT_DISCLOSED')

    def test_secret_values_and_raw_mount_sources_never_reach_public_result(self):
        out,c=self.run_inventory();public=json.dumps(out);private=json.dumps(c.output['inputs.json'])
        for secret in ('never-publish-bearer','never-publish-db','never-publish-uri','never-publish-json','fixture-private-credential','/var/lib/fixture-private'):
            self.assertNotIn(secret,public);self.assertIn(secret,private)

    def test_snapshot_drift_stops_before_engine_or_publication(self):
        for selected in ('inputs','receipt'):
            def mutate(case,previous,receipt,obs,pins):
                (previous if selected=='inputs' else receipt)['unexpected']='private'
            with self.subTest(selected=selected),self.assertRaises(m.Stop):self.run_inventory(mutate)
            self.assertEqual(self.last_capture.counts['engineGets'],0);self.assertNotIn('inputs.json',self.last_capture.output)

    def test_target_binding_or_image_mismatch_stops_before_engine(self):
        for field in ('nativeBindingHash','imageId','containerId'):
            def mutate(case,*_):case['targets']['mcp'][field]='0'*64
            with self.subTest(field=field),self.assertRaises(m.Stop):self.run_inventory(mutate)
            self.assertEqual(self.last_capture.counts['engineGets'],0)

    def test_one_container_cannot_fill_two_roles(self):
        def mutate(case,*_):case['targets']['semantic']=case['targets']['mcp']
        with self.assertRaises(m.Stop):self.run_inventory(mutate)
        self.assertEqual(self.last_capture.counts['engineGets'],0)

    def test_changed_root_pin_stops_before_engine(self):
        with self.assertRaises(m.Stop):self.run_inventory(root_drift=True)
        self.assertEqual(self.last_capture.counts['engineGets'],0)

    def test_stopped_target_and_second_read_drift_do_not_publish_inputs(self):
        for opts in ({'stopped':True},{'drift':True}):
            with self.subTest(opts=opts),self.assertRaises(m.Stop):self.run_inventory(**opts)
            self.assertNotIn('inputs.json',self.last_capture.output)

    def test_duplicate_env_is_never_resolved_by_last_value(self):
        row=copy.deepcopy(next(iter(fixture()[3].values())))
        row['Config']['Env']+=['MCP_OIDC_CLIENT_ID=second-value']
        with self.assertRaises(m.Stop):m.reference_inventory(row)

    def test_unknown_states_and_override_bodies_are_not_disclosed(self):
        row=copy.deepcopy(next(iter(fixture()[3].values())))
        row['Config']['Env']=[x for x in row['Config']['Env'] if not x.startswith('OUF_SCHEMA_GOV_ENABLED=')]
        row['Config']['Env']+=['OUF_SCHEMA_GOV_ENABLED=private-flag']
        out=m.reference_inventory(row)
        self.assertEqual(out['declaredStates']['OUF_SCHEMA_GOV_ENABLED'],'UNRECOGNIZED')
        self.assertTrue(out['overrideSurfacePresent']['SPRING_APPLICATION_JSON'])
        self.assertNotIn('private-flag',json.dumps(out));self.assertNotIn('never-publish-json',json.dumps(out))

    def test_absent_config_and_null_env_are_reported_without_inference(self):
        row=copy.deepcopy(next(iter(fixture()[3].values())));row['Config']['Env']=None
        out=m.reference_inventory(row)
        self.assertEqual(out['references']['MCP_OIDC_CLIENT_ID'],{'state':'ABSENT'})
        self.assertFalse(out['effectiveConfigurationProven'])

    def test_wrong_env_type_is_not_treated_as_absent(self):
        row=copy.deepcopy(next(iter(fixture()[3].values())))
        for invalid in ({},'',False):
            row['Config']['Env']=invalid
            with self.subTest(invalid=invalid),self.assertRaises(m.Stop):m.reference_inventory(row)

    def test_reference_validation_never_discloses_inline_credentials_or_queries(self):
        for value in ('https://user:secret@issuer.test/token','https://issuer.test/token?secret=value',
                      'https://issuer.test/token#secret','https://issuer.test/%73ecret',
                      'https://issuer.test/../token','file:///credential','https://issuer.test/token\nsecret'):
            with self.subTest(value=value):self.assertIsNone(m.safe_reference(value,'URI'))
        for value in ('/run/../credential','/run//credential','../credential','/run/credential\nsecret'):
            self.assertIsNone(m.safe_reference(value,'PATH'))

    def test_metadata_inventory_never_promotes_runtime_or_e2e_authority(self):
        out,_=self.run_inventory()
        for key in ('runtimeAuthorityIssued','historicalAuthorityReused','targetApplyAuthorized','automaticReplayAllowed',
                    'budgetReset','stableCapabilitiesOperationalProven','applicationE2EProven','releaseAcceptance',
                    'effectiveProviderConfigurationProven','databaseAdmissionProven','credentialCustodyProven'):
            self.assertIs(out[key],False,key)
        for key in ('engineWrites','sqlSessions','oauthRequests','iamRequests','imageImports','containerLifecycleOperations',
                    'configurationFileContentReads','credentialFileReads','signingKeyReads','uploads','newJobs','resumes','newGrantsGranted','humanBudgetsGranted'):
            self.assertEqual(out[key],0,key)


if __name__=='__main__':unittest.main()
