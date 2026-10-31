"""Exact two CI ZIPs, real root custody and Docker29 stores; synthetic VPS metadata."""
import copy,importlib.util,json,os,shutil,stat,subprocess,sys,uuid
from pathlib import Path
BASE=Path(__file__).resolve().parents[1]
def module(name,path):
    spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
f=module('redaction_plan_fixture',BASE/'tests/test_acquisition_redaction_image_plan.py');m=f.m
assert len(sys.argv)==3 and os.geteuid()==0
downloads=Path(sys.argv[1]);backend=sys.argv[2];assert backend in('classic','containerd')
root=Path('/var/lib/ouf-redaction-image-plan-ci');assert not root.exists();root.mkdir(mode=0o700)
folder=root/'code';folder.mkdir(mode=0o700)
for name,path in [('prepare.py',BASE/'scripts/prepare-acquisition-redaction-image-plan-20261026.py'),('case.json',BASE/'releases/acquisition-redaction-artifact-case-20261026.json'),*[(n+'.py',BASE/'tools/acquisition_read_native'/(n+'.py'))for n in('plan_helper','retained_mac','image_custody')]]:
    (folder/name).write_bytes(path.read_bytes());(folder/name).chmod(0o400)
images={}
import zipfile
for role in('ingestion','udp'):
    with zipfile.ZipFile(downloads/(role+'.zip'))as z:images[role]=json.loads(z.read('acquisition-image-config.json'))[0]
inputs,_,_=f.fixture(images)
if backend=='containerd':inputs['engineInfo'].update(Driver='overlayfs',DriverStatus=[['driver-type','io.containerd.snapshotter.v1']])
m.INPUT_HASH=m.digest(inputs)
captured=root/'captured';captured.mkdir(mode=0o700)
result={'status':'ACQUISITION_REDACTION_UPDATE_INPUTS_CAPTURED_NOT_AUTHORIZED','complete':True,'inputsHash':m.INPUT_HASH,
        'counts':inputs['counts'],'containerWrites':0,'runtimeAuthorityIssued':False}
for name,value in [('inputs.json',inputs),('result.json',result)]:
    (captured/name).write_bytes(m.encoded(value));(captured/name).chmod(0o600)
before={name:(captured/name).read_bytes()for name in('inputs.json','result.json')}
out=m.prepare(downloads,folder,root=root/'prepared',input_root=captured)
assert out['complete']is True and out['counts']=={'privateMetadataReads':2,'ciZipReads':2,'nativeArchivesPrepared':2,'engineGets':0,'containerWrites':0,'imageImports':0}
assert before=={name:(captured/name).read_bytes()for name in before}
native=json.loads((root/'prepared/native-plan.json').read_text())
def docker(*args):return subprocess.check_output(['docker',*args],stderr=subprocess.PIPE,text=True,timeout=120).strip()
info=json.loads(docker('info','--format','{{json .}}'))
assert info['ServerVersion']=='29.8.1'
assert (['driver-type','io.containerd.snapshotter.v1']in(info.get('DriverStatus')or[]))==(backend=='containerd')
custody=module('redaction_custody',folder/'image_custody.py')
for role,row in native['nativeImages'].items():
    for path in(root/'prepared'/role).iterdir():
        assert path.stat().st_uid==0 and stat.S_IMODE(path.stat().st_mode)==0o400
    image_id=row['identity']['nativeImageId'];docker('image','load','--input',row['archive']['path'])
    observed=json.loads(docker('image','inspect',image_id))[0];custody.loaded(row['audit'],observed)
    assert not observed.get('RepoTags')
    cid=None
    try:
        cid=docker('create','--network','none','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges:true',
                   '--name','ouf-redaction-native-'+role+'-'+uuid.uuid4().hex[:8],image_id)
        actual=json.loads(docker('inspect',cid))[0]
        assert actual['Image']==image_id and actual['State']['Running']is False and actual['State']['Pid']==0
        assert actual['HostConfig']['ReadonlyRootfs']is True
        for field in('User','Entrypoint','Cmd'):assert actual['Config'].get(field)==row['audit']['imageConfig'].get(field)
    finally:
        if cid:docker('rm',cid)
try:m.prepare(downloads,folder,root=root/'prepared',input_root=captured)
except m.Stop as e:assert str(e)=='IMAGE_PLAN_SCOPE_CONSUMED_NO_REPLAY'
else:raise AssertionError('Consumed preparation was reopened')
m.COUNTS.update(privateMetadataReads=0,ciZipReads=0,nativeArchivesPrepared=0)
qualification={'schema':'ouf.acquisition-redaction-native-qualification.v1','caseHash':m.CASE_HASH,'profiles':{backend:out['nativeImages']}}
second=m.prepare(downloads,folder,root=root/'independently-checked',input_root=captured,qualified=qualification)
assert second['nativeImages']==out['nativeImages'] and second['runtimeAuthorityIssued']is False
print(json.dumps({'schema':'ouf.acquisition-redaction-image-plan-native-ci.v1','complete':True,'backend':backend,
    'nativeImages':out['nativeImages'],'realExactCiZipBytes':True,'rootPrivateCodeAndPlan':True,'actualDocker29ImportAndUnstartedConfig':True,
    'inputBytesUnchanged':True,'consumedScopeReplayDenied':True,'independentlyCheckedNativeBytes':True,
    'fullReplacementLifecycleQualified':False,'candidateStarted':False,'productionRuntimeAccess':False,
    'runtimeAuthorityIssued':False,'applicationE2EProven':False},sort_keys=True),flush=True)
