import copy,importlib.util,json,unittest
from pathlib import Path
BASE=Path(__file__).resolve().parents[1]
def module(name,path):
    spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
m=module('image_plan',BASE/'scripts/prepare-mcp-denial-image-plan-20261026.py')
p=module('pure_plan',BASE/'tools/acquisition_read_native/plan_helper.py')
mac=module('pure_mac',BASE/'tools/acquisition_read_native/retained_mac.py')
def fixture():
    roles=('gateway','postgres','ingestion','udp','ingestion-read','udp-read','mcp');actual={};pins={}
    for i,role in enumerate(roles):
        cid=('%064x'%(i+1));pid=100+i
        actual[role]={'Id':cid,'Image':'sha256:'+'b'*64,'Name':'/synthetic-'+role,'State':{'Pid':pid,'StartedAt':'synthetic-generation','Running':True,'Paused':False,'Restarting':False},
          'Config':{'Hostname':'synthetic-'+role,'User':'10005:10005','Cmd':['server'],'Entrypoint':['/old-mcp'],'MacAddress':'02:42:ac:44:01:07','Env':['PATH=/bin','MCP_OIDC_TOKEN_ENDPOINT=https://not-contacted.invalid/token','MCP_OIDC_CLIENT_ID=synthetic-client','MCP_OIDC_CLIENT_SECRET_FILE=/not-read/secret'],'Labels':{'synthetic':'true'}},
          'HostConfig':{'AutoRemove':False,'NetworkMode':'synthetic-net','RestartPolicy':{'Name':'unless-stopped','MaximumRetryCount':0}},'Mounts':[],
          'NetworkSettings':{'Networks':{'synthetic-net':{'NetworkID':'c'*64,'MacAddress':'02:42:ac:44:01:07','Aliases':['synthetic-'+role]}}}}
        pins[role]={'pid':pid,'startTicks':123,'namespaces':{'net':[1,pid],'mnt':[2,pid]}}
    inputs={'schema':'ouf.mcp-denial-update-inputs.v1','candidate':{'sourceCommit':m.SOURCE,'imageId':m.IMAGE},'counts':{'bytes':65041,'engineGets':9,'privateMetadataReads':5},
      'installedCounts':{'adminGets':9,'adminPuts':2,'engineGets':306,'engineWrites':22,'imageLoadAttempts':3,'ownerConfigurationReads':83,'quarantineStops':2,'readinessGets':8,'serviceCredentialFileReads':3},
      'currentObservations':actual,'currentProcessPins':pins,'bootId':'synthetic-boot','engineBinding':{'synthetic':True},'engineInfo':{'ServerVersion':'29.8.1','Driver':'overlay2','DriverStatus':[]}}
    image={'Id':m.IMAGE,'Config':{'User':'10005:10005','Entrypoint':['/usr/local/bin/ouf-mcp'],'Cmd':['server'],'Env':['PATH=/bin'],'Labels':None}}
    return inputs,{'syntheticStaging':True},image
class Compiler(unittest.TestCase):
    def setUp(self):self.inputs,self.receipt,self.image=fixture()
    def compile(self):return m.compile_plan(self.inputs,self.receipt,self.image,p,mac)
    def test_no_authority_or_effect_and_preserved_full_cohort(self):
        original=copy.deepcopy(self.inputs);r=self.compile();self.assertEqual(original,self.inputs)
        self.assertEqual(r['retainedInstallationCounts'],original['installedCounts']);self.assertEqual(len(r['existingApplications']),7)
        self.assertFalse(r['targetUpdateAuthorized']);self.assertFalse(r['runtimeAuthorityIssued']);self.assertFalse(r['acquisitionCallsAuthorized']);self.assertFalse(r['automaticRollbackAllowed'])
        self.assertIn('CAPABILITIES',r['additionalExistingToolSchemaChange']);self.assertEqual(r['mcpReplacement']['request']['Env'],original['currentObservations']['mcp']['Config']['Env'])
    def test_one_replacement_preserves_network_mac_and_all_old_labels(self):
        r=self.compile()['mcpReplacement'];self.assertEqual(r['request']['NetworkingConfig']['EndpointsConfig']['synthetic-net']['MacAddress'],'02:42:ac:44:01:07')
        self.assertNotIn('MacAddress',r['request']);self.assertTrue(r['oldRetainedStopped']);self.assertEqual(r['normalOAuthManagerCountAfterReplacement'],1)
    def test_distinguishes_actual_store_identity(self):
        self.assertEqual(self.compile()['nativeIdentityProfile'],'CONFIG_DIGEST')
        self.inputs['engineInfo'].update(Driver='overlayfs',DriverStatus=[['driver-type','io.containerd.snapshotter.v1']]);self.assertEqual(self.compile()['nativeIdentityProfile'],'CONFIG_AND_NATIVE_MANIFEST')
    def test_no_unqualified_engine(self):
        for field,value in(('ServerVersion','29.9.0'),('Driver','unsupported')):
            before=copy.deepcopy(self.inputs);self.inputs['engineInfo'][field]=value
            with self.assertRaises(m.Stop):self.compile()
            self.inputs=before
    def test_no_legacy_mac_global_exclusion(self):
        for value in(None,'','00:00:00:00:00:00','01:42:ac:44:01:07','02:42:ac:44:01:08'):
            self.inputs['currentObservations']['mcp']['Config']['MacAddress']=value
            with self.assertRaises((m.Stop,p.Stop,mac.MacTransitionDenied)):self.compile()
    def test_no_inline_workload_credential(self):
        self.inputs['currentObservations']['mcp']['Config']['Env'].append('MCP_WORKLOAD_TOKEN=canary-not-output')
        with self.assertRaises(p.Stop):self.compile()
    def test_history_counts_cannot_be_reset(self):
        self.inputs['installedCounts']['engineWrites']=0
        with self.assertRaisesRegex(m.Stop,'HISTORY'):self.compile()
    def test_unreviewed_environment_or_label_defaults_denied(self):
        self.image['Config']['Env'].append('NEW_ENV=not-authorized')
        with self.assertRaisesRegex(m.Stop,'ENV_DEFAULT'):self.compile()
        self.image['Config']['Env'].pop();self.image['Config']['Labels']={'new-unreviewed':'true'}
        with self.assertRaisesRegex(m.Stop,'LABEL'):self.compile()
if __name__=='__main__':unittest.main()
