"""CI-only disposable root custody; exact original CI image, no live service."""
import importlib.util,json,os,pathlib,socket,stat,subprocess
from unittest.mock import patch
ROOT=pathlib.Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('fixture',ROOT/'tests/test_onboarding_profile_recovery_image_plan.py');unit=importlib.util.module_from_spec(spec);spec.loader.exec_module(unit);m=unit.m
assert os.geteuid()==os.getegid()==0
scope=pathlib.Path('/root/ouf-profile-image-plan-ci');scope.mkdir(mode=0o700)
sealed=scope/'code';sealed.mkdir(mode=0o700)
for name in ('image_custody.py','plan_helper.py','retained_mac.py'):
    m.put(sealed/name,(ROOT/'tools/acquisition_read_native'/name).read_bytes())
m.put(sealed/'case.json',(ROOT/'releases/onboarding-profile-recovery-image-custody-20261027.json').read_bytes())
inputs,receipt,frozen,_=unit.fixtures();source=scope/'captured';source.mkdir(mode=0o700)
m.INPUT_HASH=m.digest(inputs);receipt['inputsHash']=m.INPUT_HASH;m.DATABASE_PLAN_HASH=m.digest(frozen)
for name,value in [('inputs.json',inputs),('result.json',receipt),('frozen-plan.json',frozen)]:m.put(source/name,value)
before={str(path):m.sha(path.read_bytes())for path in source.iterdir()}
target=scope/'prepared'
with patch.object(socket,'socket',side_effect=AssertionError('Network/Engine forbidden')),patch.object(subprocess,'run',side_effect=AssertionError('Subprocess forbidden')):
    result=m.prepare(ROOT/'candidate.zip',sealed,root=target,input_root=source,database_plan=source/'frozen-plan.json')
assert result['complete'] and result['counts']=={'privateMetadataReads':3,'ciZipReads':1,'nativeArchivesPrepared':1,'engineGets':0,'containerWrites':0,'imageImports':0}
private=json.loads((target/'execution-inputs.json').read_text());plan=json.loads((target/'execution-plan.json').read_text())
assert private['currentOnboarding']==inputs['onboardingObservation'] and plan['engineBinding']['peerCredentials']==[1,0,0]
assert result['conditionalNativePlanHash']==m.digest(plan) and private['conditionalNativePlanHash']==m.digest(plan)
assert result['nativeImageId']==unit.CASE['nativeImageId'] and result['databaseAdmissionProven']is False
assert 'PRIVATE_CANARY' not in str(result) and result['runtimeAuthorityIssued']is False and result['executionEntryQualified']is False
assert before=={str(path):m.sha(path.read_bytes())for path in source.iterdir()}
assert all(stat.S_IMODE(path.stat().st_mode)==0o400 for path in target.iterdir())
try:m.prepare(ROOT/'candidate.zip',sealed,root=target,input_root=source,database_plan=source/'frozen-plan.json');raise AssertionError('scope replay allowed')
except m.Stop as error:assert str(error)=='IMAGE_INPUT_SCOPE_CONSUMED_NO_REPLAY'
security=scope/'security-claims';security.mkdir(mode=0o700)
symlink=source/'symlink.json';symlink.symlink_to(source/'inputs.json');m.COUNTS['privateMetadataReads']=0
try:m.private(security,symlink);raise AssertionError('symlink read allowed')
except OSError:pass
hardlink=source/'hardlink.json';os.link(source/'frozen-plan.json',hardlink)
try:m.private(security,hardlink);raise AssertionError('hardlink read allowed')
except m.Stop as error:assert str(error)=='PROTECTED_CAPTURE_METADATA_REQUIRED'
print(json.dumps({'status':'EXACT_V36_ARCHIVE_AND_CONDITIONAL_PLAN_QUALIFIED','nativeImageId':result['nativeImageId'],'metadataReads':3,
    'engineRequests':0,'sqlSessions':0,'oldFilesWritten':0,'privateValuesPrinted':False,'scopeReplayRejected':True,'fixtureNotTargetProof':True,'applicationE2EProven':False},sort_keys=True))
