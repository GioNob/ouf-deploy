import copy,importlib.util,json,os,shutil,unittest
from pathlib import Path
BASE=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('original_fixture',BASE/'tests/test_acquisition_native_plan.py');fixture=importlib.util.module_from_spec(spec);spec.loader.exec_module(fixture)
spec=importlib.util.spec_from_file_location('mac_plan',BASE/'scripts/continue-acquisition-read-native-plan-mac-20261025.py');p=importlib.util.module_from_spec(spec);spec.loader.exec_module(p);fixture.p=p
class MacPlanTest(fixture.NativePlanTest):
    def setUp(self):
        super().setUp()
        for i,role in enumerate(('ingestion','udp','mcp'),1):
            mac='02:42:ac:11:00:%02x'%i;self.actual[role]['Config']['MacAddress']=mac;self.actual[role]['NetworkSettings']['Networks']['ouf-backend']['MacAddress']=mac
        self.refresh()
    def test_read_replicas_request_distinct_dynamic_macs_and_mcp_preserves_endpoint(self):
        old=copy.deepcopy(self.actual);self.prepare();plan=json.loads((self.root/'execution-plan.json').read_text())
        self.assertEqual(old,self.actual)
        for role in('ingestion','udp'):
            proposal=plan['readComponents'][role];request=proposal['request'];self.assertNotIn('MacAddress',request);self.assertNotIn('MacAddress',request['NetworkingConfig']['EndpointsConfig']['ouf-backend']);self.assertTrue(proposal['macDistinctnessMustBeVerifiedBeforeReadiness'])
        request=plan['mcpReplacement']['request'];self.assertNotIn('MacAddress',request);self.assertEqual(request['NetworkingConfig']['EndpointsConfig']['ouf-backend']['MacAddress'],self.actual['mcp']['Config']['MacAddress']);self.assertTrue(plan['mcpReplacement']['oldMustBeStoppedAndDetachedBeforeNewStarts'])
    def test_mismatching_mac_stops_before_any_admin_read(self):
        self.actual['ingestion']['NetworkSettings']['Networks']['ouf-backend']['MacAddress']='02:42:ff:00:00:01';self.refresh()
        with self.assertRaisesRegex(p.Stop,'CONFIG_ENDPOINT_MAC_MISMATCH'):self.prepare()
        self.assertEqual(p.COUNTS['gatewayAdminGetAttempts'],0)
    def test_missing_endpoint_mac_stops_before_any_admin_read(self):
        del self.actual['mcp']['NetworkSettings']['Networks']['ouf-backend']['MacAddress'];self.refresh()
        with self.assertRaisesRegex(p.Stop,'ENDPOINT_MAC_REQUIRED'):self.prepare()
        self.assertEqual(p.COUNTS['gatewayAdminGetAttempts'],0)
    def test_invalid_declared_mac_stops_before_any_admin_read(self):
        self.actual['udp']['Config']['MacAddress']='private-unexpected-value';self.refresh()
        with self.assertRaisesRegex(p.Stop,'TYPED_RETAINED_CONFIG_MAC_REQUIRED'):self.prepare()
        self.assertEqual(p.COUNTS['gatewayAdminGetAttempts'],0)
    def test_new_entrypoint_negative_path_is_closed(self):
        import subprocess,sys
        result=subprocess.run([sys.executable,str(BASE/'scripts/continue-acquisition-read-native-plan-mac-20261025.py')],capture_output=True,text=True)
        self.assertEqual(result.returncode,2);self.assertEqual(json.loads(result.stdout)['reasonCode'],'ONE_ISOLATED_ROOT_PLAN_PREPARATION_REQUIRED');self.assertNotIn('Traceback',result.stderr)
    def context_fixture(self):
        parent=self.base/'retained-parent';parent.mkdir(mode=0o700);p.put(parent/'claim.json',{'schema':'ouf.acquisition-native-plan-claim.v1','caseHash':p.CASE_HASH,'maximumEngineGets':0,'maximumAdminGets':1})
        result=json.loads((BASE/'evidence/acquisition-retained-config-difference-target-20261025.json').read_text())['operatorResult'];path=self.base/'diagnostic.json';p.put(path,result);return parent,path
    def test_exact_retained_context_preserves_parent_and_counts(self):
        parent,path=self.context_fixture();before=(parent/'claim.json').read_bytes();lineage=p.continuation_context(parent,path)
        self.assertEqual(lineage['oldPreparationCountsRetained']['privateMetadataReads'],11);self.assertEqual(lineage['retainedDiagnosticPrivateReads'],6);self.assertEqual(lineage['cumulativeInfrastructureGetMaximum'],1);self.assertFalse(lineage['budgetReset']);self.assertEqual(before,(parent/'claim.json').read_bytes());self.assertEqual(len(list(parent.iterdir())),1)
    def test_parent_claimed_get_cannot_be_reopened(self):
        parent,path=self.context_fixture();p.put(parent/'gateway-get-claim.json',{'attempt':True})
        with self.assertRaisesRegex(p.Stop,'PARENT_GET_OR_PLAN_ALREADY_CLAIMED'):p.continuation_context(parent,path)
    def test_diagnostic_hash_cannot_be_rebound(self):
        parent,path=self.context_fixture()
        with self.assertRaisesRegex(p.Stop,'EXACT_PRIVATE_METADATA_HASH_REQUIRED'):p.continuation_context(parent,path,'0'*64)
if __name__=='__main__':unittest.main()
