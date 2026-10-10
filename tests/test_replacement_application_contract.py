import copy,importlib.util,unittest,os,tempfile,shutil
from pathlib import Path
spec=importlib.util.spec_from_file_location('contract',Path(__file__).parent.parent/'scripts/compile-replacement-application-contract.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class Contract(unittest.TestCase):
    def setUp(self):
        route={'issuer':'https://auth.example.test/realms/ouf','audience':'ouf-api-gateway','workload':'ouf-semantic','scope':'gateway.southbound.invoke','searchPath':'/internal/providers/schema-gov/search','fetchPath':'/internal/providers/schema-gov/fetch'}
        settings={'OUF_IAM_ISSUER':route['issuer'],'OUF_IAM_AUDIENCE':route['audience'],'OUF_SCHEMA_GOV_TOKEN_ENDPOINT':route['issuer']+'/protocol/openid-connect/token','OUF_SCHEMA_GOV_GATEWAY_BASE_URL':'https://ouf-semantic-southbound-v2:10443','OUF_SEMANTIC_DISCOVERY_DELEGATION_WORKLOAD':'ouf-mcp-server','OUF_SCHEMA_GOV_CLIENT_SECRET_FILE':'/run/secrets/schema-gov-client-secret','OUF_SEMANTIC_DISCOVERY_DELEGATION_KEY_FILE':'/run/secrets/semantic-discovery-owner.key'}
        settings.update({k:route[v] for k,v in {'OUF_SCHEMA_GOV_SEARCH_PATH':'searchPath','OUF_SCHEMA_GOV_FETCH_PATH':'fetchPath','OUF_SCHEMA_GOV_CLIENT_ID':'workload','OUF_SCHEMA_GOV_WORKLOAD_SCOPE':'scope'}.items()})
        mounts=[{'source':'/root/'+n,'target':t,'uid':10001,'gid':10001,'mode':0o400,'readOnly':True} for n,t in [('schema-gov-client-secret',settings['OUF_SCHEMA_GOV_CLIENT_SECRET_FILE']),('semantic-discovery-owner.key',settings['OUF_SEMANTIC_DISCOVERY_DELEGATION_KEY_FILE']),('java-truststore.p12','/run/ouf-discovery-trust/java-truststore.p12')]]
        self.v={'productionApplyReady':False,'replacementConfigurationDraft':{'applyAuthorized':False,'candidateConfig':{'Env':[k+'='+v for k,v in settings.items()]},'newReadOnlyMounts':mounts,'retainedAuthMounts':[]},'originalProviderBinding':{'routes':route,'adapter':{'admission':{k:route[k] for k in ('issuer','audience','workload','scope')},'searchPath':route['searchPath'],'fetchPath':route['fetchPath']},'tlsIdentities':{'southboundHostname':'ouf-semantic-southbound-v2'}},'runtimeInputManifest':{'mountsInstalled':False,'consumerIdentities':{'semantic':{'uid':10001,'gid':10001},'gateway':{'uid':636,'gid':636}},'existingWorkloadCredentialHash':'a'*64,'discoveryMacKeyHash':'b'*64},'javaTrustReceipt':{'truststoreHash':'c'*64}}
    def test_provider_workload_and_caller_are_distinct_bound_roles(self):
        plan,public=m.compile_contract(self.v);self.assertEqual(public['providerWorkload'],'ouf-semantic');self.assertEqual(public['discoveryCallerWorkload'],'ouf-mcp-server');self.assertEqual(plan['roleOwnedReadOnlyMounts'][0]['sha256'],'a'*64);self.assertFalse(plan['productionApplyReady']);self.assertFalse(public['secretBytesFreshlyVerified'])
    def test_path_or_admission_drift_denied(self):
        for group,key in [('routes','searchPath'),('admission','audience')]:
            v=copy.deepcopy(self.v)
            if group=='routes':v['originalProviderBinding']['routes'][key]='/unbound'
            else:v['originalProviderBinding']['adapter']['admission'][key]='wrong'
            with self.assertRaises(ValueError):m.compile_contract(v)
    def test_uid_writable_and_target_drift_denied(self):
        for key,val in [('uid',636),('readOnly',False),('target','/unbound')]:
            v=copy.deepcopy(self.v);v['replacementConfigurationDraft']['newReadOnlyMounts'][0][key]=val
            with self.assertRaises(ValueError):m.compile_contract(v)
    def test_public_receipt_does_not_disclose_secret_hashes(self):
        _,public=m.compile_contract(self.v)
        for digest in ('a'*64,'b'*64,'c'*64):self.assertNotIn(digest,str(public))
@unittest.skipUnless(os.environ.get('OUF_NATIVE_ROLE_METADATA_TEST')=='1','native root fixture only')
class RoleMetadata(unittest.TestCase):
    def setUp(self):
        self.root=Path(tempfile.mkdtemp(prefix='ouf-contract-fixture-',dir='/var/lib'));self.root.chmod(0o700)
        self.file=self.root/'fixture-secret';self.file.write_bytes(b'fixture-only');os.chown(self.file,10001,10001);self.file.chmod(0o400)
        self.mount={'source':str(self.file),'uid':10001,'gid':10001,'mode':0o400}
    def tearDown(self):shutil.rmtree(self.root)
    def test_real_uid_gid_mode_and_stable_inode(self):
        self.assertEqual(m.role_metadata(self.mount),m.role_metadata(self.mount))
    def test_wrong_owner_writable_and_symlink_sources_denied(self):
        self.file.chmod(0o600)
        with self.assertRaises(ValueError):m.role_metadata(self.mount)
        self.file.chmod(0o400);os.chown(self.file,0,0)
        with self.assertRaises(ValueError):m.role_metadata(self.mount)
        self.file.unlink();self.file.symlink_to('/etc/passwd')
        with self.assertRaises(ValueError):m.role_metadata(self.mount)
    def test_writable_ancestor_denied(self):
        self.root.chmod(0o777)
        with self.assertRaises(ValueError):m.role_metadata(self.mount)
if __name__=='__main__':unittest.main()
