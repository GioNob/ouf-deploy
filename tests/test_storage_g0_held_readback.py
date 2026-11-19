import importlib.util,json,os,tempfile,unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('held_readback',ROOT/'scripts/readback-storage-g0-held-20261106.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

def put(path,value):
    raw=value if isinstance(value,bytes) else m.encode(value)
    path.write_bytes(raw);path.chmod(0o600)
    return m.sha(raw)

class HeldReadbackTests(unittest.TestCase):
    def setUp(self):
        self.mask=os.umask(0o077)
        anchor='/var/lib' if os.environ.get('GITHUB_ACTIONS')=='true' else str(Path.cwd())
        self.tmp=tempfile.TemporaryDirectory(dir=anchor);self.root=Path(self.tmp.name)
        self.stage=self.root/'stage';self.parent=self.stage/'inputs/capacity-directory-preparation-20261106'
        self.parent.mkdir(parents=True,mode=0o700)
        self.scope=self.stage/'evidence'/m.OPERATION;self.scope.mkdir(parents=True,mode=0o700)
        self.meta=self.root/'docker-containers';self.meta.mkdir(mode=0o700)
        self.bound={};self.config={'operationId':m.OPERATION,'installationRef':'fixture',
            'collectionDecisionRef':None,'outputParent':str(self.stage/'evidence'),
            'roles':{str(i):{'containerId':format(i,'064x')} for i in range(1,14)},
            'connectionFiles':{},'operatorEvidenceFiles':{},'priorReceiptFiles':[]}
        for i in range(1,71):(self.meta/format(i,'064x')).mkdir(mode=0o700)
        for key in ['s3','onboarding','udp','ingestion']:
            path=self.parent/(key+'.json');raw=m.encode({'fixture':key})
            self.bound['connection:'+key]=put(path,raw);self.config['connectionFiles'][key]=str(path)
            put(self.scope/('input-'+key+'.private.json'),raw)
        path=self.parent/'network.json';raw=m.encode({'network':'fixture'})
        self.bound['network']=put(path,raw);self.config['networkBindingFile']=str(path)
        put(self.scope/'network-binding.private.json',raw)
        for key in ['runtime','capacity']:
            path=self.parent/(key+'.json');self.bound['operator:'+key]=put(path,{'fixture':key})
            self.config['operatorEvidenceFiles'][key]=str(path)
        for key in ['access','custody','window','writers']:self.config['operatorEvidenceFiles'][key]=None
        for i in range(1,18):
            path=self.parent/('history'+str(i)+'.json');digest=put(path,{'fixture':i})
            self.bound['history:'+str(i)]=digest
            self.config['priorReceiptFiles'].append({'control':i,'path':str(path),'sha256':digest})
        self.input_sha=put(self.parent/'package-input.review.json',self.config)
        execution_sha=put(self.parent/'package-input.collection.json',self.config|{'collectionDecisionRef':m.DECISION})
        claim={'collectionDecisionRef':m.DECISION,'operationId':m.OPERATION,'installationRef':'fixture',
            'inputSha256':execution_sha,'packageManifestSha256':m.MANIFEST_SHA,
            'boundInputSha256':self.bound,'limits':m.EXPECTED_LIMITS}
        put(self.scope/'claim.private.json',claim)
        decision={'decisionRef':m.DECISION,'baseInputSha256':self.input_sha,
            'executionInputSha256':execution_sha,'boundInputSha256':self.bound,
            'limits':claim['limits'],'scope':str(self.scope),'runtimeAuthorityIssued':False,
            'authenticatedHumanApproval':False}
        put(self.parent/'collection-decision.private.json',decision)
        put(self.scope/'result.json',m.EXPECTED_RESULT)
        put(self.scope/'phase-HOST_BEFORE.json',{'phase':'HOST_BEFORE','reserved':True})
        put(self.scope/'engine-request-1.json',{'sequence':1,'method':'GET',
            'pathSha256':m.sha(b'/containers/json?all=1')})
    def tearDown(self):self.tmp.cleanup();os.umask(self.mask)
    def inspect(self):return m.inspect(self.stage,self.meta,input_sha=self.input_sha)
    def test_receipts_and_seventy_local_directories_without_live_count_claim(self):
        before={str(p):m.sha(p.read_bytes()) for p in self.root.rglob('*') if p.is_file()}
        r=self.inspect();self.assertEqual(r['cumulativeEngineGets'],53)
        self.assertEqual(r['metadataObservation']['directoryNamesMatchingContainerIds'],70)
        self.assertEqual(r['metadataObservation']['boundRoleDirectoryNamesPresent'],13)
        self.assertFalse(r['metadataObservation']['liveEngineContainerCountProven'])
        self.assertEqual(r['providerRequests'],0);self.assertEqual(r['credentialFilesRead'],0)
        self.assertEqual(before,{str(p):m.sha(p.read_bytes()) for p in self.root.rglob('*') if p.is_file()})
    def test_changed_result_denied(self):
        put(self.scope/'result.json',m.EXPECTED_RESULT|{'engineGets':2});self.assertRaises(m.Held,self.inspect)
    def test_unexpected_child_scope_denied(self):
        (self.scope/'unexpected').mkdir();self.assertRaises(m.Held,self.inspect)
    def test_history_drift_denied(self):
        put(Path(self.config['priorReceiptFiles'][0]['path']),{'altered':True});self.assertRaises(m.Held,self.inspect)
    def test_frozen_connection_drift_denied(self):
        put(self.scope/'input-s3.private.json',{'altered':True});self.assertRaises(m.Held,self.inspect)
    def test_absent_metadata_is_not_assumed_zero(self):
        self.meta=self.root/'absent';r=self.inspect()
        self.assertEqual(r['metadataObservation']['status'],'ABSENT_NOT_PROOF_OF_DOCKER_ROOT')
        self.assertNotIn('directoryNamesMatchingContainerIds',r['metadataObservation'])
    def test_coordinated_limit_tampering_denied(self):
        for path in [self.scope/'claim.private.json',self.parent/'collection-decision.private.json']:
            v=json.loads(path.read_bytes());v['limits']['engineGets']=131;put(path,v)
        self.assertRaises(m.Held,self.inspect)
    def test_metadata_symlink_not_followed(self):
        (self.meta/'link').symlink_to(self.parent,target_is_directory=True)
        r=self.inspect();self.assertEqual(r['metadataObservation']['symlinkEntries'],1)
        self.assertEqual(r['metadataObservation']['directoryNamesMatchingContainerIds'],70)

if __name__=='__main__':unittest.main()
