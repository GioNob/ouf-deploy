"""Actual public download/nonroot/sudo/root400/main negative; zero production IAM."""
import hashlib,json,os,pwd,shutil,subprocess
from pathlib import Path

BASE=Path(__file__).resolve().parents[1]
assert os.geteuid()==os.getegid()==0
owner=int(os.environ['SUDO_UID']);assert owner>0
account=pwd.getpwuid(owner)
root=Path('/var/lib/ouf-farmacie-service-policy-delivery-ci');assert not root.exists();root.mkdir(mode=0o755)
home=root/'home';home.mkdir(mode=0o700);os.chown(home,owner,account.pw_gid)
minimal=root/'bin';minimal.mkdir(mode=0o755)
for name in('bash','curl','id','mktemp','chmod','tee','sudo','sha256sum'):
    path=shutil.which(name);assert path;os.symlink(path,minimal/name)
assert shutil.which('gh',path=str(minimal))is None
scope=Path('/etc/ouf/deploy-snapshots/farmacie-service-policy-read-20261027-v1')
assert not os.path.lexists(scope)
def operator():
    os.setgroups([account.pw_gid]);os.setgid(account.pw_gid);os.setuid(owner)
result=subprocess.run(['/usr/bin/bash','--noprofile','--norc',str(BASE/'releases/read-farmacie-service-policy-20261027.sh')],
    stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,preexec_fn=operator,
    env={'PATH':str(minimal),'HOME':str(home),'LC_ALL':'C'},timeout=120)
text=result.stdout.decode();assert result.returncode==2,text
assert 'INTERACTIVE_OPERATOR_TERMINAL_REQUIRED'in text and 'Apri nel browser:'not in text
assert 'SourceChecksum=OK (root0400; verifica eseguita root)'in text
deliveries=list(home.glob('ouf-farmacie-service-policy-delivery.*'));assert len(deliveries)==1
log=(deliveries[0]/'bootstrap.log').read_text();assert 'Exit=2'in log and 'DeliveryExit=2'in log
code=Path('/usr/local/lib/ouf-farmacie-service-policy-read-ad582e403e4a8016')
path=code/'read.py';s=path.stat()
assert s.st_uid==s.st_gid==0 and s.st_nlink==1 and s.st_mode&0o777==0o400
assert code.stat().st_mode&0o777==0o700
assert hashlib.sha256(path.read_bytes()).hexdigest()=='ad582e403e4a80165797352469c842667c5ed2b7aae906756eccc33545abda98'
denied=subprocess.run(['setpriv','--reuid=65534','--regid=65534','--clear-groups','cat',str(path)],capture_output=True)
assert denied.returncode!=0 and not denied.stdout
assert not os.path.lexists(scope) and not(code/'operator.log').exists()
print(json.dumps({'schema':'ouf.farmacie-service-policy-sealed-delivery-ci.v1','complete':True,
    'publicPinnedSourceDownloaded':True,'realNonrootWrapperAndSudoRootCopier':True,
    'checksumExecutedByRoot':True,'root400CodeInRoot700Directory':True,'nonrootCodeReadDenied':True,
    'actualProtectedMainRefusedNonTtyBeforeScopeOrLogin':True,'bootstrapLogPreserved':True,
    'iamRequests':0,'ownerRequests':0,'credentialReads':0,'policyWrites':0,'engineRequests':0,
    'applicationCalls':0,'productionAuthorityIssued':False,'targetExecuted':False}),flush=True)
