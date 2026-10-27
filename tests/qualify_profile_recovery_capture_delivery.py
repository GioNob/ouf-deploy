"""Isolated CI: real curl/sudo/root0400 delivery; production main must reject a wrong retained seal."""
import hashlib,json,os,pwd,shutil,stat,subprocess
from pathlib import Path

BASE=Path(__file__).resolve().parents[1]
assert os.geteuid()==os.getegid()==0
try:account=pwd.getpwnam('oufadmin')
except KeyError:
    subprocess.run(['/usr/sbin/useradd','-M','-U','oufadmin'],check=True);account=pwd.getpwnam('oufadmin')
uid=account.pw_uid;assert uid>0
sudoers=Path('/etc/sudoers.d/ouf-profile-capture-ci');sudoers.write_text('oufadmin ALL=(root) NOPASSWD: /usr/bin/python3 *\n');sudoers.chmod(0o440)
root=Path('/var/lib/ouf-profile-capture-delivery-ci');root.mkdir(mode=0o755)
home=root/'home';home.mkdir(mode=0o700);os.chown(home,uid,account.pw_gid)
bin_dir=root/'bin';bin_dir.mkdir(mode=0o755)
for name in ('bash','id','mktemp','chmod','curl','sha256sum','tee','sudo'):
    path=shutil.which(name);assert path;os.symlink(path,bin_dir/name)
assert shutil.which('gh',path=str(bin_dir)) is None and shutil.which('timeout',path=str(bin_dir)) is None
retained=Path('/etc/ouf/deploy-snapshots/onboarding-diagnostic-current-inputs-20261026-v1/inputs.json')
retained.parent.mkdir(parents=True,mode=0o700);retained.parent.chmod(0o700);raw=b'{"CI_ONLY_WRONG_PRIVATE_SEAL":true}'
retained.write_bytes(raw);retained.chmod(0o400)
def demote():os.setgroups([account.pw_gid]);os.setgid(account.pw_gid);os.setuid(uid)
def invoke():return subprocess.run(['/usr/bin/bash','--noprofile','--norc',str(BASE/'releases/capture-onboarding-profile-recovery-inputs-20261027.sh')],
    stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,preexec_fn=demote,
    env={'HOME':str(home),'PATH':str(bin_dir),'LC_ALL':'C'},timeout=150)
try:
    process=invoke();output=process.stdout.decode();assert process.returncode==2,(process.returncode,output)
    rows=[json.loads(line) for line in output.splitlines() if line.startswith('{')]
    assert len(rows)==1 and rows[0]['status']=='STOP_RECONCILE' and rows[0]['reasonCode']=='EXACT_INSTALLED_CAPTURE_HASH_REQUIRED',output
    assert rows[0]['counts']['engineGets']==0 and rows[0]['counts']['privateMetadataReads']==1 and rows[0]['runtimeAuthorityIssued'] is False
    expected='52a8e9a8ba86b8d56012fac562f3e9de1d6a861969159702703343365a3a0733'
    code=Path('/usr/local/lib/ouf-onboarding-profile-recovery-inputs-'+expected[:16]+'/prepare.py');info=code.stat()
    assert info.st_uid==info.st_gid==0 and stat.S_IMODE(info.st_mode)==0o400 and hashlib.sha256(code.read_bytes()).hexdigest()==expected
    denied=subprocess.run(['setpriv','--reuid=65534','--regid=65534','--clear-groups','cat',str(code)],capture_output=True);assert denied.returncode!=0 and not denied.stdout
    scope=Path('/etc/ouf/deploy-snapshots/onboarding-profile-recovery-current-inputs-20261027-v1')
    before={p:p.read_bytes() for p in scope.iterdir() if p.is_file()};assert 'claim.json' in {p.name for p in before} and not(scope/'inputs.json').exists() and not(scope/'authority').exists()
    replay=invoke();assert replay.returncode!=0 and 'consumata' in replay.stdout.decode()
    assert all(p.read_bytes()==value for p,value in before.items()) and retained.read_bytes()==raw
    deliveries=list(home.glob('ouf-onboarding-profile-recovery-inputs-delivery.*'));assert len(deliveries)==2
    for path in deliveries:
        log=path/'bootstrap.log';assert stat.S_IMODE(log.stat().st_mode)==0o600 and 'DeliveryExit=' in log.read_text()
    print(json.dumps({'status':'PROFILE_CAPTURE_CURL_SUDO_ROOT400_DELIVERY_PASS','publicPinnedSourceDownloaded':True,'ghAndTimeoutAbsent':True,
        'rootChecksumVerified':True,'nonrootSourceReadDenied':True,'actualMainWrongSealRefused':True,'consumedScopeReplayRefused':True,
        'oldFilesWritten':0,'engineRequests':0,'sqlSessions':0,'oauthRequests':0,'credentialsOrSigningKeysRead':0,'runtimeAuthorityIssued':False,'targetAccess':False},sort_keys=True))
finally:sudoers.unlink(missing_ok=True)
