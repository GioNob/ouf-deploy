"""Exact root copier + public CI ZIPs and entrypoint; retained runtime metadata synthetic."""
import contextlib,importlib.util,io,json,os,stat,subprocess,sys
from pathlib import Path
BASE=Path(__file__).resolve().parents[1]
def module(name,path):
    spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
assert len(sys.argv)==2 and os.geteuid()==0
downloads=Path(sys.argv[1]);root=Path('/var/lib/ouf-redaction-plan-delivery-ci');assert not root.exists();root.mkdir(mode=0o700)
folder=root/'downloaded-code';folder.mkdir(mode=0o700);owner=BASE.stat().st_uid;assert owner>0
files={'prepare.py':'scripts/prepare-acquisition-redaction-image-plan-20261026.py',
       'case.json':'releases/acquisition-redaction-artifact-case-20261026.json',
       'qualification.json':'releases/acquisition-redaction-native-qualification-20261026.json',
       **{n+'.py':'tools/acquisition_read_native/'+n+'.py'for n in('plan_helper','retained_mac','image_custody')}}
for name,path in files.items():
    (folder/name).write_bytes((BASE/path).read_bytes());(folder/name).chmod(0o600);os.chown(folder/name,owner,owner)
wrapper=(BASE/'releases/prepare-acquisition-redaction-image-plan-20261026.sh').read_text()
copier=wrapper.split("<<'PY' 2>&1 | tee -a \"$delivery_log\"\n",1)[1].split('\nPY\n',1)[0]
copied=subprocess.run([sys.executable,'-I','-S','-B','-',str(folder),str(owner)],input=copier,text=True,capture_output=True,timeout=20)
assert copied.returncode==0,(copied.stdout,copied.stderr)
path_line=[line for line in copied.stdout.splitlines()if line.startswith('ProtectedCode=')];assert len(path_line)==1
sealed=Path(path_line[0].split('=',1)[1]).parent
assert stat.S_IMODE(sealed.stat().st_mode)==0o700
for path in sealed.iterdir():
    assert path.stat().st_uid==path.stat().st_gid==0 and stat.S_IMODE(path.stat().st_mode)==0o400
    denied=subprocess.run(['setpriv','--reuid=65534','--regid=65534','--clear-groups','cat',str(path)],capture_output=True)
    assert denied.returncode!=0 and not denied.stdout
fixture=module('delivery_plan_fixture',BASE/'tests/test_acquisition_redaction_image_plan.py')
import zipfile
images={}
for role in('ingestion','udp'):
    with zipfile.ZipFile(downloads/(role+'.zip'))as z:images[role]=json.loads(z.read('acquisition-image-config.json'))[0]
inputs,_,_=fixture.fixture(images)
inputs['engineInfo'].update(Driver='overlayfs',DriverStatus=[['driver-type','io.containerd.snapshotter.v1']])
m=module('sealed_actual_entry',sealed/'prepare.py')
captured=root/'captured';captured.mkdir(mode=0o700)
m.INPUT_HASH=m.digest(inputs);m.INPUT_ROOT=captured;m.ROOT=root/'prepared'
# Function keyword defaults bind at definition time; redirect both globals and
# defaults to the same isolated synthetic custody roots. Production bytes stay sealed.
m.prepare.__kwdefaults__.update(root=m.ROOT,input_root=m.INPUT_ROOT)
result={'status':'ACQUISITION_REDACTION_UPDATE_INPUTS_CAPTURED_NOT_AUTHORIZED','complete':True,'inputsHash':m.INPUT_HASH,
        'counts':inputs['counts'],'containerWrites':0,'runtimeAuthorityIssued':False}
for name,value in [('inputs.json',inputs),('result.json',result)]:
    (captured/name).write_bytes(m.encoded(value));(captured/name).chmod(0o600)
before={p.name:p.read_bytes()for p in captured.iterdir()};sys.argv=[str(sealed/'prepare.py'),str(downloads)]
printed=io.StringIO()
with contextlib.redirect_stdout(printed):code=m.main()
assert code==0,printed.getvalue()
output=json.loads(printed.getvalue());assert output['complete']is True and output['executionEntryQualified']is False
assert output['counts']=={'privateMetadataReads':2,'ciZipReads':2,'nativeArchivesPrepared':2,'engineGets':0,'containerWrites':0,'imageImports':0}
assert before=={p.name:p.read_bytes()for p in captured.iterdir()}
state={str(p.relative_to(m.ROOT)):list(m.frame(p.lstat()))for p in m.ROOT.rglob('*')}
printed=io.StringIO()
with contextlib.redirect_stdout(printed):code=m.main()
assert code==2 and json.loads(printed.getvalue())['reasonCode']=='IMAGE_PLAN_SCOPE_CONSUMED_NO_REPLAY'
assert state=={str(p.relative_to(m.ROOT)):list(m.frame(p.lstat()))for p in m.ROOT.rglob('*')}
partial=root/'prior-claimed';partial.mkdir(mode=0o700);(partial/'claim.json').write_text('{}');m.ROOT=partial;m.prepare.__kwdefaults__['root']=partial
printed=io.StringIO()
with contextlib.redirect_stdout(printed):code=m.main()
assert code==2 and {p.name for p in partial.iterdir()}=={'claim.json'}
print(json.dumps({'schema':'ouf.acquisition-redaction-plan-delivery-custody-ci.v1','complete':True,
    'exactWrapperRootCopierExecuted':True,'sixRootCodeFiles0400':True,'nonrootReadDenied':True,
    'actualEntryPointPositiveWithSyntheticCapture':True,'twoExactPublicPushArtifacts':True,
    'nativeIdentityComparedToIndependentQualification':True,'consumedAndPartialScopesUnchanged':True,
    'oldInputBytesUnchanged':True,'engineGets':0,'imageImports':0,'containerWrites':0,
    'productionRuntimeAccess':False,'runtimeAuthorityIssued':False,'applicationE2EProven':False},sort_keys=True),flush=True)
