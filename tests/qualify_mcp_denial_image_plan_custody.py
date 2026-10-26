"""Real retained artifact/root custody; all captured runtime metadata synthetic."""
import copy,importlib.util,json,os,shutil,subprocess,sys
from pathlib import Path
BASE=Path(__file__).resolve().parents[1]
def module(name,path):
    s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
fixture=module('plan_fixture',BASE/'tests/test_mcp_denial_image_plan.py')
assert os.geteuid()==0 and len(sys.argv)==3
backend=sys.argv[2];assert backend in('classic','containerd')
root=Path('/var/lib/ouf-mcp-plan-custody-ci');assert not root.exists();root.mkdir(mode=0o700)
downloads=root/'downloaded-code';downloads.mkdir(mode=0o700)
for name,path in [('prepare.py',BASE/'scripts/prepare-mcp-denial-image-plan-20261026.py'),*[(n+'.py',BASE/'tools/acquisition_read_native'/(n+'.py'))for n in('plan_helper','retained_mac','image_custody')]]:
    target=downloads/name;target.write_bytes(path.read_bytes());target.chmod(0o600);os.chown(target,1001,1001)
wrapper=(BASE/'releases/prepare-mcp-denial-image-plan-20261026.sh').read_text()
copier=wrapper.split("<<'PY' 2>&1 | tee -a \"$delivery_log\"\n",1)[1].split('\nPY\n',1)[0]
copied=subprocess.run([sys.executable,'-I','-S','-B','-',str(downloads),'1001'],input=copier,text=True,capture_output=True,timeout=20)
assert copied.returncode==0,(copied.stdout,copied.stderr)
sealed=Path('/usr/local/lib/ouf-mcp-denial-image-plan-96cb2f55d3000d54')
assert sealed.stat().st_mode&0o777==0o700
for target in sealed.iterdir():
    assert target.stat().st_uid==target.stat().st_gid==0 and target.stat().st_mode&0o777==0o400
    result=subprocess.run(['setpriv','--reuid=65534','--regid=65534','--clear-groups','cat',str(target)],capture_output=True)
    assert result.returncode!=0 and not result.stdout
m=module('protected_image_plan',sealed/'prepare.py');inputs,_,_=fixture.fixture()
if backend=='containerd':inputs['engineInfo'].update(Driver='overlayfs',DriverStatus=[['driver-type','io.containerd.snapshotter.v1']])
# These are actual byte hashes of these synthetic metadata records, not a
# production hash or consent. The production entrypoint's constants unchanged.
m.INPUT_HASH=m.digest(inputs)
incoming=root/'captured';incoming.mkdir(mode=0o700)
(incoming/'inputs.json').write_bytes(m.encoded(inputs));(incoming/'inputs.json').chmod(0o600)
result={'status':'MCP_DIAGNOSTIC_UPDATE_INPUTS_CAPTURED_NOT_AUTHORIZED','complete':True,'inputsHash':m.INPUT_HASH,'counts':inputs['counts'],'containerWrites':0,'runtimeAuthorityIssued':False}
(incoming/'result.json').write_bytes(m.encoded(result));(incoming/'result.json').chmod(0o600)
original={p.name:p.read_bytes()for p in incoming.iterdir()}
prepared=m.prepare(Path(sys.argv[1]),sealed,root=root/'prepared',input_root=incoming)
assert prepared['complete'] is True and prepared['counts']=={'privateMetadataReads':2,'ciZipReads':1,'nativeArchivesPrepared':1,'engineGets':0,'containerWrites':0,'imageImports':0}
assert prepared['runtimeAuthorityIssued'] is False and prepared['executionEntryQualified'] is False
assert {p.name:p.read_bytes()for p in incoming.iterdir()}==original
for p in(root/'prepared').iterdir():
    assert p.is_file() and p.stat().st_uid==p.stat().st_gid==0 and p.stat().st_mode&0o777==0o400
try:m.prepare(Path(sys.argv[1]),sealed,root=root/'prepared',input_root=incoming)
except m.Stop as error:assert str(error)=='IMAGE_PLAN_SCOPE_CONSUMED_NO_REPLAY'
else:raise AssertionError('CONSUMED_SCOPE_WAS_REOPENED')
assert {p.name:p.read_bytes()for p in incoming.iterdir()}==original
# Failure before a source ZIP is read must preserve its claim and consume scope.
m.COUNTS.update(privateMetadataReads=0,ciZipReads=0,nativeArchivesPrepared=0)
m.INPUT_HASH='0'*64
try:m.prepare(Path(sys.argv[1]),sealed,root=root/'negative',input_root=incoming)
except m.Stop as error:assert str(error)=='EXACT_CAPTURE_BYTES_REQUIRED'
else:raise AssertionError('WRONG_CAPTURE_ACCEPTED')
assert (root/'negative/claim.json').is_file()and(root/'negative/private-read-1-claim.json').is_file()
assert not(root/'negative/staged-receipt.json').exists()
assert {p.name:p.read_bytes()for p in incoming.iterdir()}==original
print(json.dumps({'schema':'ouf.mcp-denial-plan-root-custody-ci.v1','complete':True,'backend':backend,'realRetainedCiArtifact':True,'privateCaptureMetadataSynthetic':True,'exactWrapperRootCopierExecuted':True,'rootCode0400':True,'nonrootReadDenied':True,'inputBytesUnchanged':True,'positiveStageAndNativePlan':True,'scopeReplayDenied':True,'wrongCaptureRejectedBeforeZipRead':True,'containerWrites':0,'engineGets':0,'imageImports':0,'productionRuntimeAccess':False,'targetUpdateAuthorized':False}),flush=True)
