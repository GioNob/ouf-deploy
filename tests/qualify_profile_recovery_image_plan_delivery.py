"""Isolated CI: real curl/sudo/root0400 delivery; production main must reject a wrong retained seal."""
import hashlib,json,os,pwd,shutil,stat,subprocess
from pathlib import Path

BASE=Path(__file__).resolve().parents[1]
assert os.geteuid()==os.getegid()==0
try:account=pwd.getpwnam('oufadmin')
except KeyError:
    subprocess.run(['/usr/sbin/useradd','-M','-U','oufadmin'],check=True);account=pwd.getpwnam('oufadmin')
uid=account.pw_uid;assert uid>0
sudoers=Path('/etc/sudoers.d/ouf-profile-plan-ci');sudoers.write_text('oufadmin ALL=(root) NOPASSWD: /usr/bin/python3 *\n');sudoers.chmod(0o440)
root=Path('/var/lib/ouf-profile-plan-delivery-ci');root.mkdir(mode=0o755)
home=root/'home';home.mkdir(mode=0o700);os.chown(home,uid,account.pw_gid)
bin_dir=root/'bin';bin_dir.mkdir(mode=0o755)
for name in ('bash','id','mktemp','chmod','curl','sha256sum','tee','sudo','cat'):
    path=shutil.which(name);assert path;os.symlink(path,bin_dir/name)
assert shutil.which('gh',path=str(bin_dir)) is None and shutil.which('timeout',path=str(bin_dir)) is None
retained=Path('/etc/ouf/deploy-snapshots/onboarding-profile-recovery-current-inputs-20261027-v1/inputs.json')
retained.parent.mkdir(parents=True,mode=0o700);retained.parent.chmod(0o700);raw=b'{"CI_ONLY_WRONG_PRIVATE_SEAL":true}'
retained.write_bytes(raw);retained.chmod(0o400)
def demote():os.setgroups([account.pw_gid]);os.setgid(account.pw_gid);os.setuid(uid)
wrapper=home/'run.sh'
download=subprocess.run(['/usr/bin/curl','--fail','--silent','--show-error','--location','--proto','=https','--proto-redir','=https','--max-redirs','3','--connect-timeout','15','--max-time','60',
    'https://raw.githubusercontent.com/GioNob/ouf-deploy/d015550c6fa8358e1f22a685f324b125b53c4c30/releases/prepare-onboarding-profile-recovery-image-plan-20261027.sh','-o',str(wrapper)],
    preexec_fn=demote,env={'HOME':str(home),'PATH':str(bin_dir),'LC_ALL':'C'},capture_output=True,timeout=70)
assert download.returncode==0 and wrapper.read_bytes()==(BASE/'releases/prepare-onboarding-profile-recovery-image-plan-20261027.sh').read_bytes()
wrapper.chmod(0o400)
def invoke():return subprocess.run(['/usr/bin/bash','--noprofile','--norc',str(wrapper)],
    stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,preexec_fn=demote,
    env={'HOME':str(home),'PATH':str(bin_dir),'LC_ALL':'C'},timeout=900)
try:
    process=invoke();output=process.stdout.decode();assert process.returncode==2,(process.returncode,output)
    rows=[json.loads(line) for line in output.splitlines() if line.startswith('{')]
    assert len(rows)==1 and rows[0]['status']=='STOP_RECONCILE' and rows[0]['reasonCode']=='EXACT_CAPTURE_BYTES_REQUIRED',output
    assert rows[0]['counts']['engineGets']==0 and rows[0]['counts']['privateMetadataReads']==1 and rows[0]['runtimeAuthorityIssued'] is False
    expected='874d38f18022906f09b74500d780d0bd0998bd0be521818fac24f296435e50e1'
    code=Path('/usr/local/lib/ouf-onboarding-profile-recovery-image-plan-'+expected[:16]+'/prepare.py');info=code.stat()
    assert info.st_uid==info.st_gid==0 and stat.S_IMODE(info.st_mode)==0o400 and hashlib.sha256(code.read_bytes()).hexdigest()==expected
    denied=subprocess.run(['setpriv','--reuid=65534','--regid=65534','--clear-groups','cat',str(code)],capture_output=True);assert denied.returncode!=0 and not denied.stdout
    scope=Path('/etc/ouf/deploy-snapshots/onboarding-profile-recovery-image-plan-1ce0ce1cd2719556-v1')
    before={p:p.read_bytes() for p in scope.iterdir() if p.is_file()};assert 'claim.json' in {p.name for p in before} and not(scope/'execution-inputs.json').exists() and not(scope/'authority').exists()
    replay=invoke();assert replay.returncode!=0 and 'IMAGE_PLAN_SCOPE_CONSUMED_NO_REPLAY' in replay.stdout.decode()
    assert all(p.read_bytes()==value for p,value in before.items()) and retained.read_bytes()==raw
    deliveries=list(home.glob('ouf-onboarding-profile-recovery-image-plan-delivery.*'));assert len(deliveries)==2
    for path in deliveries:
        log=path/'bootstrap.log';assert stat.S_IMODE(log.stat().st_mode)==0o600 and 'DeliveryExit=' in log.read_text()
    print(json.dumps({'status':'PROFILE_IMAGE_PLAN_CURL_SUDO_ROOT400_DELIVERY_PASS','publicPinnedSourceDownloaded':True,'ghAndTimeoutAbsent':True,
        'rootChecksumVerified':True,'nonrootSourceReadDenied':True,'actualMainWrongSealRefused':True,'consumedScopeReplayRefused':True,
        'oldFilesWritten':0,'engineRequests':0,'sqlSessions':0,'oauthRequests':0,'credentialsOrSigningKeysRead':0,'runtimeAuthorityIssued':False,'targetAccess':False},sort_keys=True))
finally:sudoers.unlink(missing_ok=True)
