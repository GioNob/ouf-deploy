"""Real HTTPS/nonroot/sudo/root0400/foregroundTTY, wrong private seal must stop before authority."""
import fcntl,hashlib,json,os,pwd,select,shutil,signal,subprocess,termios,time
from pathlib import Path
BASE=Path(__file__).resolve().parents[1]
assert os.geteuid()==0
owner=int(os.environ['SUDO_UID']);assert owner>0;account=pwd.getpwuid(owner)
root=Path('/var/lib/ouf-profile-v36-delivery-ci');root.mkdir(mode=0o755)
home=root/'home';home.mkdir(mode=0o700);os.chown(home,owner,account.pw_gid)
minimal=root/'bin';minimal.mkdir(mode=0o755)
for name in('bash','curl','id','mktemp','chmod','tee','sudo','sha256sum'):
    target=shutil.which(name);assert target;os.symlink(target,minimal/name)
assert shutil.which('gh',path=str(minimal))is None and shutil.which('timeout',path=str(minimal))is None
prepared=Path('/etc/ouf/deploy-snapshots/onboarding-profile-recovery-image-plan-1ce0ce1cd2719556-v1');prepared.mkdir(parents=True,mode=0o700)
for parent in(prepared,prepared.parent,prepared.parent.parent):parent.chmod(0o700)
fake=b'{"CI_ONLY_WRONG_NEW_INPUT_HASH":true}';input_path=prepared/'execution-inputs.json';input_path.write_bytes(fake);input_path.chmod(0o400)
scope=Path('/etc/ouf/deploy-snapshots/onboarding-profile-recovery-v36-apply-564038c5d487f0a4-v1');assert not scope.exists()
def demote():os.setgroups([account.pw_gid]);os.setgid(account.pw_gid);os.setuid(owner)
env={'PATH':str(minimal),'HOME':str(home),'TERM':'xterm','LC_ALL':'C'}
wrapper=home/'run.sh'
download=subprocess.run(['/usr/bin/curl','--fail','--silent','--show-error','--location','--proto','=https','--proto-redir','=https','--max-redirs','3','--connect-timeout','15','--max-time','60',
    'https://raw.githubusercontent.com/GioNob/ouf-deploy/2f04dff7438b0f59c94e341d9c946f9098ba67ef/releases/apply-onboarding-profile-recovery-update-20261027.sh','-o',str(wrapper)],preexec_fn=demote,env=env,capture_output=True,timeout=65)
assert download.returncode==0 and wrapper.read_bytes()==(BASE/'releases/apply-onboarding-profile-recovery-update-20261027.sh').read_bytes();wrapper.chmod(0o400)
def invoke():
    master,slave=os.openpty()
    def session():os.setsid();fcntl.ioctl(0,termios.TIOCSCTTY,0);demote()
    proc=subprocess.Popen(['/usr/bin/bash','--noprofile','--norc',str(wrapper)],stdin=slave,stdout=slave,stderr=slave,preexec_fn=session,env=env)
    os.close(slave);output=bytearray();deadline=time.monotonic()+420
    try:
        while proc.poll()is None and time.monotonic()<deadline:
            if select.select([master],[],[],.1)[0]:
                try:raw=os.read(master,65536)
                except OSError:break
                output.extend(raw)
        proc.wait(timeout=5);return proc.returncode,output.decode(errors='replace')
    finally:
        if proc.poll()is None:os.killpg(proc.pid,signal.SIGKILL)
        proc.wait(timeout=5);os.close(master)
status,output=invoke();assert status==2,(status,output)
deliveries=list(home.glob('ouf-onboarding-profile-v36-apply-delivery.*'));assert len(deliveries)==1
bootstrap=(deliveries[0]/'bootstrap.log').read_text();assert 'Exit=2'in bootstrap and 'DeliveryExit=2'in bootstrap
code=Path('/usr/local/lib/ouf-onboarding-profile-recovery-update-a46b19156c35cb91');raw=(code/'sources.json').read_bytes()
assert hashlib.sha256(raw).hexdigest()=='a46b19156c35cb915b0842e52a72a97bac691c0cd64676aaaa704eb285793cc2'
mapping=json.loads(raw);assert len(mapping)==23
for name,digest in mapping.items():
    path=code/name;info=path.stat();assert info.st_uid==info.st_gid==0 and info.st_mode&0o777==0o400 and hashlib.sha256(path.read_bytes()).hexdigest()==digest
    denied=subprocess.run(['setpriv','--reuid=65534','--regid=65534','--clear-groups','cat',str(path)],capture_output=True);assert denied.returncode!=0 and not denied.stdout
log=code/'operator.log';assert log.stat().st_mode&0o777==0o600
rows=[json.loads(line)for line in log.read_text().splitlines()if line.startswith('{')];assert len(rows)==1
assert rows[0]['reasonCode']=='EXACT_PRIVATE_METADATA_HASH_REQUIRED'and rows[0]['complete']is False,rows
assert (scope/'preparation-claim.json').is_file() and not(scope/'authority').exists()and not(scope/'recovery.json').exists()
assert not list(scope.glob('raw-engine-response-*')) and input_path.read_bytes()==fake
attempts=list(scope.glob('preflight-attempt-*.json'));assert len(attempts)==1 and json.loads(attempts[0].read_bytes())['attempt']==1
before={path:path.read_bytes()for path in scope.iterdir()if path.is_file()};old_log=log.read_bytes()
replay_status,replay_output=invoke();assert replay_status!=0 and 'ONBOARDING_UPDATE_SCOPE_CONSUMED_NO_REPLAY'in replay_output
assert all(path.read_bytes()==raw for path,raw in before.items())and log.read_bytes()==old_log and input_path.read_bytes()==fake
assert 'APPROVO 'not in log.read_text()
print(json.dumps({'status':'PROFILE_V36_SEALED_CURL_SUDO_DELIVERY_QUALIFIED','sources':23,'rootCode400AndChecksum':True,
    'nonrootReadDenied':True,'ghAndTimeoutAbsent':True,'actualForegroundTtyMain':True,'wrongPrivateSealRejectedBeforeAuthority':True,
    'consumedScopeRefused':True,'logsRetained':True,'oldFilesWritten':0,'engineRequests':0,'sqlSessions':0,'credentialOrSigningKeyReads':0,
    'humanApprovalRequested':False,'targetApplyExecuted':False,'applicationE2EProven':False},sort_keys=True))
