"""Compile observed ENV names with exact published image config, disposable values.
No private VPS values or current runtime authority are supplied by this fixture.
"""
import hashlib,json,sys,tarfile
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
from test_file_only_preparation import Preparation,prep,FileOnlyProfile

package=Path(sys.argv[1]);record=json.loads((package/'package-record.json').read_text())
assert record['sourceCommit']=='eccef11a97367f20e278db40b9ed6f45dd980c37'
assert record['imageId']=='sha256:29e32c1487b5ba29d6d29ec04f7daa3baeb1e30f392a46c838eef01493d60489'
with tarfile.open(package/'image.docker.tar','r:') as archive:
    manifest=json.load(archive.extractfile('manifest.json'))
    raw=archive.extractfile(manifest[0]['Config']).read(2097153)
assert len(raw)<=2097152 and 'sha256:'+hashlib.sha256(raw).hexdigest()==record['imageId']
config=json.loads(raw)['config']
request,old,audit,tree,token,key,proposal=Preparation().retained_candidate(config)
request['Image']=audit['imageId']=record['imageId']
result=prep.creation(request,{'retainedNativeCreationFrame':old},old,audit,tree,token,key,proposal,
    {'issuer':'gateway','audience':'semantic','workload':'ouf-semantic'})
FileOnlyProfile(result,tree)
env=prep.environment(result['Env'])
assert len(request['Env'])==31 and len(old['Config']['Env'])==19
assert 'JAVA_TOOL_OPTIONS' not in env and 'OUF_SEM_DB_PASSWORD' not in env
assert env['OUF_IAM_ENABLED']=='true' and all(env[k]=='false' for k in prep.FLAGS)
(package/'compiled-registry-environment.json').write_text(json.dumps(env,sort_keys=True))
print('OUF_EXACT_IMAGE_RETAINED_ENV_COMPILATION='+json.dumps({'status':'PASS',
    'imageId':record['imageId'],'historicalCreationNames':31,'historicalNativeNames':19,
    'values':'DISPOSABLE_AND_PUBLIC_SOURCE_DERIVED_NOT_TARGET_VALUES',
    'fourMountProfileCompiled':True,'unreviewedJvmOptionsAccepted':False,
    'targetPreparationProven':False,'chatbotEndToEndProven':False,'notReleaseAcceptance':True},sort_keys=True))
