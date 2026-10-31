"""Actual wrapper/sudo/HTTP chain with gh absent; isolated CI only.

Real source and exact public artifact. Deliberately invalid synthetic capture:
root preparation must STOP before ZIP staging. Positive stage tested separately.
No production configuration, approval, image import or runtime access.
"""
import json,os,pwd,shutil,subprocess
from pathlib import Path
BASE=Path(__file__).resolve().parents[1]
assert os.geteuid()==0
owner=int(os.environ['SUDO_UID']);assert owner>0
account=pwd.getpwuid(owner);group=account.pw_gid
root=Path('/var/lib/ouf-mcp-curl-delivery-ci');assert not root.exists();root.mkdir(mode=0o755)
minimal=root/'bin';minimal.mkdir(mode=0o755)
for name in('bash','curl','id','mktemp','chmod','tee','sudo','sha256sum'):
    source=shutil.which(name);assert source;os.symlink(source,minimal/name)
assert shutil.which('gh',path=str(minimal))is None
assert shutil.which('timeout',path=str(minimal))is None
def home(name):
    value=root/name;value.mkdir(mode=0o700);os.chown(value,owner,group);return value
def run(wrapper,directory):
    return subprocess.run(['/usr/bin/sudo','-n','-u',account.pw_name,'/usr/bin/env','PATH='+str(minimal),'HOME='+str(directory),'/usr/bin/bash',str(wrapper)],capture_output=True,text=True,timeout=240)
scope=Path('/etc/ouf/deploy-snapshots/mcp-denial-image-plan-fb4b7c9ae832e779-v1')
code=Path('/usr/local/lib/ouf-mcp-denial-image-plan-96cb2f55d3000d54')
assert not scope.exists()and not code.exists()
old=run(BASE/'releases/prepare-mcp-denial-image-plan-20261026.sh',home('legacy-home'))
assert old.returncode==127 and 'STOP: comando richiesto assente: gh'in old.stdout
assert 'DeliveryExit=127'in old.stdout and not scope.exists()and not code.exists()
assert 'ProtectedCode='not in old.stdout
capture=Path('/etc/ouf/deploy-snapshots/mcp-denial-update-inputs-9a374dd07745f059-v1')
capture.mkdir(parents=True,mode=0o700)
for p in(capture,capture.parent,capture.parent.parent):p.chmod(0o700)
synthetic=b'{"syntheticWrongHash":true}'
(capture/'inputs.json').write_bytes(synthetic);(capture/'inputs.json').chmod(0o600)
new_home=home('curl-home')
new=run(BASE/'releases/prepare-mcp-denial-image-plan-curl-20261026.sh',new_home)
assert new.returncode==2,(new.returncode,new.stdout,new.stderr)
assert 'CodeClosure=OK (4 file root0400; checksum eseguiti root)'in new.stdout
assert 'Exit=2'in new.stdout and 'DeliveryExit=2'in new.stdout
assert 'comando richiesto assente'not in new.stdout
rows=[json.loads(line)for line in new.stdout.splitlines()if line.startswith('{')]
assert len(rows)==1 and rows[0]['reasonCode']=='EXACT_CAPTURE_BYTES_REQUIRED'
assert rows[0]['status']=='STOP_RECONCILE'and rows[0]['counts']['privateMetadataReads']==1
assert rows[0]['counts']['ciZipReads']==rows[0]['counts']['engineGets']==rows[0]['counts']['containerWrites']==rows[0]['counts']['imageImports']==0
assert (capture/'inputs.json').read_bytes()==synthetic
assert (scope/'claim.json').is_file()and(scope/'private-read-1-claim.json').is_file()
assert not(scope/'staged-receipt.json').exists()
deliveries=list(new_home.glob('ouf-mcp-image-plan-delivery.*'));assert len(deliveries)==1
artifact=deliveries[0]/'candidate.zip'
import hashlib
assert artifact.stat().st_size==9617218 and hashlib.sha256(artifact.read_bytes()).hexdigest()=='6c31a1b5698942ddbb47b96ec1b49860c690c44aac8106beb1ca4b1ed7bba56a'
assert (deliveries[0]/'bootstrap.log').is_file()
print(json.dumps({'schema':'ouf.mcp-image-plan-curl-delivery-ci.v1','complete':True,'ghAbsentFromPath':True,'timeoutAbsentFromPath':True,'oldPrerequisiteStopReproduced':True,'oldStopBeforeSudoOrScope':True,'newWrapperExecutedAsNonroot':True,'realPublicHttpSourcesAndArtifactDownloaded':True,'exactArtifactSha256Verified':True,'sudoRootFourFileCopierSucceeded':True,'realProtectedRuntimeEntryInvoked':True,'syntheticCaptureWrongHashRejected':True,'positivePreparationClaimed':False,'privateInputPreserved':True,'logsRetained':True,'containerWrites':0,'imageImports':0,'productionRuntimeAccess':False,'targetUpdateAuthorized':False}),flush=True)
