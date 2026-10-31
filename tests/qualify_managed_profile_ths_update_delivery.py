"""CI only: actual pinned HTTPS/sudo/direct TTY/root400 production main; no consent or runtime."""
import fcntl,hashlib,json,os,pwd,select,shutil,signal,stat,subprocess,termios,time
from pathlib import Path
BASE=Path(__file__).resolve().parents[1]
WRAPPER_COMMIT='79710e413ef0692f65c04836372150a701af126f'
assert os.geteuid()==os.getegid()==0
pins=json.loads((BASE/'releases/managed-profile-ths-request-update-delivery-pins-20261028.json').read_bytes())
try:account=pwd.getpwnam('oufadmin')
except KeyError:
    subprocess.run(['/usr/sbin/useradd','-M','-U','oufadmin'],check=True);account=pwd.getpwnam('oufadmin')
uid=account.pw_uid
sudoers=Path('/etc/sudoers.d/ouf-ths-request-update-delivery-ci');sudoers.write_text('oufadmin ALL=(root) NOPASSWD: /usr/bin/python3 *\n');sudoers.chmod(0o440)
root=Path('/var/lib/ouf-ths-request-update-delivery-ci');root.mkdir(mode=0o755)
home=root/'home';home.mkdir(mode=0o700);os.chown(home,uid,account.pw_gid)
bin_dir=root/'bin';bin_dir.mkdir(mode=0o755)
for name in('bash','id','mktemp','chmod','curl','sha256sum','tee','sudo'):os.symlink(shutil.which(name),bin_dir/name)
assert shutil.which('gh',path=str(bin_dir))is None and shutil.which('timeout',path=str(bin_dir))is None
prepared=Path('/etc/ouf/deploy-snapshots/managed-profile-ths-native-plan-d0dbbd61-20261028-v1')
prepared.mkdir(parents=True,mode=0o700);prepared.parent.chmod(0o700)
raw=b'{"CI_ONLY_WRONG_PREPARED_HASH":true}';retained=prepared/'execution-inputs.json';retained.write_bytes(raw);retained.chmod(0o400)
def demote():os.setgroups([account.pw_gid]);os.setgid(account.pw_gid);os.setuid(uid)
wrapper=home/'run.sh'
process=subprocess.run(['/usr/bin/curl','--fail','--silent','--show-error','--location','--proto','=https','--proto-redir','=https','--max-redirs','3','--connect-timeout','15','--max-time','60',
    'https://raw.githubusercontent.com/GioNob/ouf-deploy/'+WRAPPER_COMMIT+'/releases/apply-managed-profile-ths-request-20261028.sh','-o',str(wrapper)],
    preexec_fn=demote,env={'HOME':str(home),'PATH':str(bin_dir),'LC_ALL':'C'},capture_output=True,timeout=70)
assert process.returncode==0,process.stderr
assert wrapper.read_bytes()==(BASE/'releases/apply-managed-profile-ths-request-20261028.sh').read_bytes()
assert hashlib.sha256(wrapper.read_bytes()).hexdigest()==pins['wrapperSha256'];wrapper.chmod(0o400)
def invoke():
    master,slave=os.openpty();os.fchown(slave,uid,account.pw_gid);os.fchmod(slave,0o600)
    def session():os.setsid();fcntl.ioctl(0,termios.TIOCSCTTY,0);demote()
    proc=subprocess.Popen(['/usr/bin/bash','--noprofile','--norc',str(wrapper)],stdin=slave,stdout=slave,stderr=slave,preexec_fn=session,
                          env={'HOME':str(home),'PATH':str(bin_dir),'LC_ALL':'C'});os.close(slave)
    output=bytearray();deadline=time.monotonic()+240
    try:
        while True:
            if select.select([master],[],[],.1)[0]:
                try:block=os.read(master,65536)
                except OSError:break
                if not block:break
                output.extend(block)
            assert time.monotonic()<deadline,'FINITE_DELIVERY_CI_WINDOW'
            if proc.poll()is not None:
                while select.select([master],[],[],0)[0]:
                    try:block=os.read(master,65536)
                    except OSError:break
                    if not block:break
                    output.extend(block)
                break
        return proc.wait(timeout=5),output.decode(errors='replace')
    finally:
        if proc.poll()is None:os.killpg(proc.pid,signal.SIGKILL)
        proc.wait(timeout=5);os.close(master)
try:
    status,output=invoke();assert status==2,(status,output)
    rows=[json.loads(line.strip())for line in output.splitlines()if line.strip().startswith('{')]
    assert len(rows)==1,output
    result=rows[0]
    assert result['status']=='STOP_RECONCILE'and result['reasonCode']=='EXACT_PRIVATE_METADATA_HASH_REQUIRED',output
    assert result['runtimeEffectsMayBePartial']is False and result['automaticReplayAllowed']is False,output
    assert 'APPROVO '+('0'*64)not in output and 'Inserisci ESCLUSIVAMENTE'not in output
    code=Path(pins['codeRoot']);protected=[]
    for source in pins['files']:
        path=code/source['name'];info=path.stat();assert info.st_uid==info.st_gid==0 and info.st_nlink==1 and stat.S_IMODE(info.st_mode)==0o400
        assert hashlib.sha256(path.read_bytes()).hexdigest()==source['sha256'];protected.append(path)
    manifest=code/'sources.json';assert hashlib.sha256(manifest.read_bytes()).hexdigest()==pins['sourceClosureHash'];assert stat.S_IMODE(manifest.stat().st_mode)==0o400
    assert manifest.stat().st_uid==manifest.stat().st_gid==0
    denied=subprocess.run(['/usr/bin/setpriv','--reuid=65534','--regid=65534','--clear-groups','/usr/bin/cat',str(code/'entry.py')],capture_output=True)
    assert denied.returncode!=0 and not denied.stdout
    scope=Path(pins['executionRoot']);before={path:path.read_bytes()for path in [*scope.iterdir(),*code.iterdir()]if path.is_file()}
    assert(scope/'preparation-claim.json').is_file()and not(scope/'authority').exists()and not(scope/'review.json').exists()
    non_tty=subprocess.run(['/usr/bin/python3','-I','-S','-B',str(code/'entry.py')],stdin=subprocess.DEVNULL,capture_output=True,env={'SUDO_UID':str(uid),'PATH':'/usr/bin:/bin'})
    assert non_tty.returncode==2 and b'DIRECT_INTERACTIVE_SUDO_NO_PIPE_REQUIRED'in non_tty.stdout
    replay_status,replay=invoke();assert replay_status!=0 and 'consumata'in replay
    assert all(path.read_bytes()==value for path,value in before.items())and retained.read_bytes()==raw
    deliveries=list(home.glob('ouf-managed-profile-ths-request-update-delivery.*'));assert len(deliveries)==2
    assert all(stat.S_IMODE((path/'bootstrap.log').stat().st_mode)==0o600 for path in deliveries)
    assert stat.S_IMODE((code/'operator.log').stat().st_mode)==0o600
    print(json.dumps({'status':'THS_REQUEST_UPDATE_ACTUAL_PROTECTED_DELIVERY_PASS','actualPinnedHttpsSudoDirectTTY':True,'sourceFilesRoot400':32,
        'ghAndTimeoutAbsent':True,'wrongPrivateSealRefusedBeforeRuntimeOrReview':True,'consumedScopeRefused':True,'nonTTYEntryRefused':True,
        'oldFilesWritten':0,'engineRequests':0,'sqlSessions':0,'oauthRequests':0,'credentialsOrSigningKeysRead':0,'humanApprovalSimulated':False,
        'runtimeAuthorityIssued':False,'targetAccess':False,'applicationE2EProven':False},sort_keys=True))
finally:sudoers.unlink(missing_ok=True)
