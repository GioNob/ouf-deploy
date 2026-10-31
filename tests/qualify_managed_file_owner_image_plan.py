"""CI-only exact original V38 archive and protected synthetic runtime metadata."""
import importlib.util,json,os,shutil,stat
from pathlib import Path
from unittest.mock import patch
BASE=Path(__file__).resolve().parents[1]
def load(name,path):
    s=importlib.util.spec_from_file_location(name,BASE/path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
f=load('owner_image_fixture','tests/test_managed_file_owner_image_plan.py');m=f.m
stage=load('v38_stage','scripts/stage_managed_file_owner_image.py');custody=load('retained_custody','tools/acquisition_read_native/image_custody.py')
assert os.geteuid()==os.getegid()==0
root=Path('/var/lib/ouf-owner-image-plan-ci');root.mkdir(mode=0o700);root.chmod(0o700)
source=Path(os.environ['OUF_EXACT_OWNER_ZIP']);zip_path=root/'onboarding.zip';shutil.copyfile(source,zip_path);zip_path.chmod(0o400)
receipt=json.loads((BASE/'releases/managed-file-owner-v38-image-custody-20261028.json').read_text())
# Reperform full JAR, all38 SQL CRC/SHA, image layer and native-manifest custody on the exact CI ZIP.
case={k:v for k,v in receipt.items()if k not in('schema','sourceManifest','imageArchiveSha256','imageArchiveBytes','expandedArchiveSha256','expandedArchiveBytes','nativeImageId','derivedArchiveSha256','nativeArchiveBytes','imageAudit','application','parts','imageRebuilt','imageImported','imageRelabelled','runtimeAuthorityIssued','humanBudgetGranted','applicationE2EProven','releaseAcceptance')}
with patch('socket.socket',side_effect=AssertionError('network/runtime ports forbidden')),patch('subprocess.Popen',side_effect=AssertionError('runtime processes forbidden')):
    audited=stage.prepare(zip_path,root/'independent-custody',BASE,case)
assert audited==receipt
inputs,result,info,_,archive,fixture_case=f.fixture(root)
capture=root/'capture';capture.mkdir(mode=0o700)
paths=[capture/'inputs.json',capture/'result.json',capture/'engine-get-1-response.json']
for path,value in zip(paths,(inputs,result,info)):path.write_bytes(m.encoded(value));path.chmod(0o400)
before={p:p.read_bytes()for p in paths};scope=m.Scope(root/'plan')
with patch('socket.socket',side_effect=AssertionError('network/runtime ports forbidden')),patch('subprocess.Popen',side_effect=AssertionError('runtime processes forbidden')):
    out=m.prepare(scope,fixture_case,receipt,zip_path,f.p,f.mac,custody,stage.unpack)
assert out['complete']is True and out['counts']=={'privateMetadataReads':3,'privateMetadataBytes':sum(len(v)for v in before.values()),'ciZipReads':1,'nativeArchivesPrepared':1,'engineGets':0,'containerWrites':0,'imageImports':0}
assert out['unchangedPeers']==12 and out['databaseMigration']=={'from':36,'to':38,'newMigrations':2}
assert not out['runtimeAuthorityIssued']and not out['targetUpdateAuthorized']and out['humanOwnershipReceiptsCreated']==out['humanBudgetsGranted']==out['resumes']==0
assert all(p.read_bytes()==raw for p,raw in before.items())and all(stat.S_IMODE(p.stat().st_mode)==0o400 for p in scope.root.iterdir()if p.is_file())
assert 'secret-fixture'not in json.dumps(out)
with(scope.root/'onboarding-native.tar').open('rb')as stream:h,size=custody.hashed(stream,1073741824)
assert h==receipt['derivedArchiveSha256']and size==receipt['nativeArchiveBytes']
saved=(scope.root/'result.json').read_bytes()
try:m.Scope(scope.root);raise AssertionError('scope replayed')
except m.Stop:pass
assert(scope.root/'result.json').read_bytes()==saved
print(json.dumps({'status':'OWNER_V38_EXACT_ARCHIVE_AND_CONDITIONAL_PLAN_PASS','actualOriginalCiZips':1,'metadataReads':3,'nativeArchivesPrepared':1,'all36MigrationBytesAndYamlRoleRetained':True,'exactNewMigrationVersions':[37,38],'candidateNativeImageId':receipt['nativeImageId'],'privatePlan400':True,'oldFilesUnchanged':True,'runtimePortsAndProcessesDenied':True,'sameScopeReplayDenied':True,'syntheticRuntimeMetadata':True,'databaseAdmissionProven':False,'runtimeAuthorityIssued':False,'targetExecuted':False,'applicationE2EProven':False},sort_keys=True))
