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
if len(sys.argv)==3:
    from image_custody import runtime_image_id
    audit=json.loads(Path(sys.argv[2]).read_text())
    assert audit['imageId']==record['imageId'] and audit['imageConfig']==config
    expected_native=runtime_image_id(audit)
else:expected_native=record['imageId']
result=prep.creation(request,{'retainedNativeCreationFrame':old},old,audit,tree,token,key,proposal,
    {'issuer':'gateway','audience':'semantic','workload':'ouf-semantic'})
FileOnlyProfile(result,tree)
assert result['Image']==expected_native
# Exercise the same composed sequence as prepare_file_only_installation, not
# only the standalone execution profile. Validation identities are discarded;
# they do not become runtime observations or signing authority.
token={k:v for k,v in token.items() if k not in ('directoryDevice','directoryInode')}
token['directoryCustodyScopeHash']='7'*64
baseline=(Path(__file__).resolve().parents[1]/
    'tools/semantic_frame_compiler/containerd-overlayfs-southbound.json').read_bytes()
template,launch=prep.compile_inputs(baseline,result,tree,token,key,proposal,prep.FRAME_ENGINE)
context={'schema':'ouf.semantic-docker-frame-context.v1','containerId':'a'*64,
    'bundleParent':prep.BUNDLE_PARENTS[1],'metadataParent':'/var/lib/docker/containers',
    'networkNamespaceParent':'/var/run/docker/netns','networkNamespaceName':'b'*12,
    'cgroupDriver':'systemd','storageParent':'/var/lib/docker','rootfsPath':'/var/lib/docker/validation-only-rootfs'}
policy=prep.compile_policy(template,launch,context,execution_profile=FileOnlyProfile(result,tree),
    renewable_token=token,delegation_key_metadata_hash='d'*64,proposal_receipt_key=proposal)
assert policy['startup']['args']==policy['expectedOci']['process']['args']==result['Entrypoint']+result['Cmd']
assert policy['schema']=='ouf.semantic-configured-file-only-four-mount-frame-policy.v2-proposal'
env=prep.environment(result['Env'])
assert len(request['Env'])==31 and len(old['Config']['Env'])==19
assert 'JAVA_TOOL_OPTIONS' not in env and 'OUF_SEM_DB_PASSWORD' not in env
assert env['OUF_IAM_ENABLED']=='true' and all(env[k]=='false' for k in prep.FLAGS)
(package/'compiled-registry-environment.json').write_text(json.dumps(env,sort_keys=True))
print('OUF_EXACT_IMAGE_RETAINED_ENV_COMPILATION='+json.dumps({'status':'PASS',
    'imageId':record['imageId'],'nativeImageId':expected_native,'historicalCreationNames':31,'historicalNativeNames':19,
    'values':'DISPOSABLE_AND_PUBLIC_SOURCE_DERIVED_NOT_TARGET_VALUES',
    'fourMountProfileCompiled':True,'fourMountFramePolicyCompiled':True,'exactRuntimeGatePreserved':True,
    'contextIdentities':'VALIDATION_ONLY_DISCARDED_NOT_TARGET_OBSERVATIONS','unreviewedJvmOptionsAccepted':False,
    'targetPreparationProven':False,'chatbotEndToEndProven':False,'notReleaseAcceptance':True},sort_keys=True))
