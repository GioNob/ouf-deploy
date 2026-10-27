"""Actual nonroot curl/sudo/root0400 reader delivery on isolated CI paths.

The exact protected reader refuses a deliberately wrong private-input hash.
No original controller, Engine, SQL, signing key or HUMAN authority is executed.
"""
import hashlib,importlib.util,json,os,pwd,shutil,subprocess,time
from pathlib import Path
BASE=Path(__file__).resolve().parents[1]
assert os.geteuid()==0
uid=int(os.environ['SUDO_UID']);assert uid>0;account=pwd.getpwuid(uid)
root=Path('/var/lib/ouf-transport-stop-delivery-ci');assert not root.exists();root.mkdir(mode=0o755)
home=root/'home';home.mkdir(mode=0o700);os.chown(home,uid,account.pw_gid)
bin_dir=root/'bin';bin_dir.mkdir(mode=0o755)
for name in('bash','id','mktemp','chmod','curl','sha256sum','tee','sudo'):
 path=shutil.which(name);assert path;os.symlink(path,bin_dir/name)
assert shutil.which('gh',path=str(bin_dir))is None and shutil.which('timeout',path=str(bin_dir))is None
def module(name,path):
 s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
m=module('retained_ci_reader',BASE/'scripts/read-onboarding-diagnostic-transport-stop-20261027.py')
b=module('retained_ci_bundle',BASE/'tools/onboarding_diagnostic_update/bundle.py')
old_code=Path(m.TARGET['oldCode']);old_code.parent.mkdir(parents=True,exist_ok=True);b.stage(BASE,old_code)
assert hashlib.sha256((old_code/'sources.json').read_bytes()).hexdigest()==m.TARGET['oldManifestHash']
old=Path(m.TARGET['oldScope']);old.mkdir(parents=True,mode=0o700);old.chmod(0o700)
def put(path,value,mode=0o400):
 raw=value if isinstance(value,bytes)else m.encoded(value);path.write_bytes(raw);path.chmod(mode)
put(old/'preparation-claim.json',{'schema':'ouf.onboarding-diagnostic-update-preflight-claim.v1','executionInputsHash':m.TARGET['executionInputsHash'],'maximums':m.LIMITS,'runtimeEffectsDispatched':0,'automaticReplayAllowed':False,'budgetReset':False})
for i in range(1,4):put(old/('preflight-attempt-1234-%05d.json'%i),{'kind':'ownerConfigurationReads','attempt':i,'attemptNotCompletion':True})
put(old_code/'operator.log',m.EXPECTED_STOP,0o600)
prepared=Path(m.TARGET['executionInputsPath']);prepared.parent.mkdir(parents=True,mode=0o700)
put(prepared,b'{"CI_ONLY_WRONG_PRIVATE_SEAL":true}')
before={p:p.read_bytes()for folder in(old_code,old)for p in folder.iterdir()if p.is_file()};before[prepared]=prepared.read_bytes()
def demote():os.setgroups([account.pw_gid]);os.setgid(account.pw_gid);os.setuid(uid)
proc=subprocess.run(['/usr/bin/bash','--noprofile','--norc',str(BASE/'releases/read-onboarding-diagnostic-transport-stop-20261027.sh')],
 stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,preexec_fn=demote,
 env={'HOME':str(home),'PATH':str(bin_dir),'LC_ALL':'C'},timeout=180)
output=proc.stdout.decode();assert proc.returncode==2,(proc.returncode,output)
rows=[json.loads(line)for line in output.splitlines()if line.startswith('{')]
assert len(rows)==1 and rows[0]['status']=='STOP_RECONCILE'and rows[0]['reasonCode']=='EXACT_RETAINED_FILE_HASH_REQUIRED',output
code=Path('/usr/local/lib/ouf-onboarding-transport-stop-read-cd89338de4dcdbb5/read.py');s=code.stat()
assert s.st_uid==s.st_gid==0 and s.st_mode&0o777==0o400 and hashlib.sha256(code.read_bytes()).hexdigest()=='cd89338de4dcdbb55930981f05a446c3b5184648945b9f5e6f8060ca215e932a'
denied=subprocess.run(['setpriv','--reuid=65534','--regid=65534','--clear-groups','cat',str(code)],capture_output=True);assert denied.returncode!=0 and not denied.stdout
assert all(p.read_bytes()==raw for p,raw in before.items())
delivery=list(home.glob('ouf-onboarding-transport-stop-read-delivery.*'));assert len(delivery)==1
log=delivery[0]/'bootstrap.log';assert log.stat().st_mode&0o777==0o600
assert 'Exit=2'in log.read_text()and'DeliveryExit=2'in log.read_text()
scope=Path(m.TARGET['root']);assert(scope/'claim.json').exists()and not(scope/'result.json').exists()and not(scope/'authority').exists()
assert len(list(old.iterdir()))==4 and not(old/'authority').exists()and not(old/'recovery.json').exists()
print(json.dumps({'schema':'ouf.onboarding-transport-read-delivery-ci.v1','complete':True,'publicPinnedReaderDownloaded':True,
 'curlOnlyWithGhAndTimeoutAbsent':True,'realSudoRootCopy':True,'root0400ChecksumVerified':True,'nonrootCodeReadDenied':True,
 'actualProtectedMainWrongPrivateSealRefused':True,'oldFilesPreserved':True,'bootstrapLog0600':True,
 'newEngineRequests':0,'sqlSessions':0,'oauthRequests':0,'configurationContentReads':0,'credentialOrSigningKeyReads':0,
 'humanApprovalRequested':False,'runtimeAuthorityIssued':False,'targetRuntimeAccess':False}),flush=True)
