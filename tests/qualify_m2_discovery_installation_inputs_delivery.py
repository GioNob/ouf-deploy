"""Real pinned HTTPS/nonroot/sudo/root400, negative main and retained failed scope. No real IAM."""
import hashlib,importlib.util,json,os,pwd,shutil,stat,subprocess,sys
from pathlib import Path
from unittest.mock import patch
BASE=Path(__file__).resolve().parents[1]
assert os.geteuid()==os.getegid()==0
try:account=pwd.getpwnam('oufadmin')
except KeyError:
 subprocess.run(['/usr/sbin/useradd','-M','-U','oufadmin'],check=True);account=pwd.getpwnam('oufadmin')
owner=account.pw_uid;assert owner>0
sudoers=Path('/etc/sudoers.d/ouf-m2-installation-inputs-ci');sudoers.write_text('oufadmin ALL=(root) NOPASSWD: /usr/bin/python3 *\n');sudoers.chmod(0o440)
root=Path('/var/lib/ouf-m2-installation-inputs-delivery-ci');root.mkdir(mode=0o755)
home=root/'home';home.mkdir(mode=0o700);os.chown(home,owner,account.pw_gid)
minimal=root/'bin';minimal.mkdir(mode=0o755)
for name in('bash','curl','id','mktemp','chmod','tee','sudo','sha256sum'):os.symlink(shutil.which(name),minimal/name)
assert shutil.which('gh',path=str(minimal))is None and shutil.which('timeout',path=str(minimal))is None
scope=Path('/etc/ouf/deploy-snapshots/m2-discovery-installation-inputs-14e42ac9-20261029-v1')
scope.parent.mkdir(parents=True,exist_ok=True,mode=0o700);scope.parent.chmod(0o700)
def operator():os.setgroups([account.pw_gid]);os.setgid(account.pw_gid);os.setuid(owner)
wrapper=home/'read.sh'
result=subprocess.run(['/usr/bin/curl','--fail','--silent','--show-error','--location','--proto','=https','--proto-redir','=https','--max-redirs','3','--connect-timeout','15','--max-time','60',
 'https://raw.githubusercontent.com/GioNob/ouf-deploy/c2035ca457e95f95d772b8e3660c241bfdec6e7b/releases/read-m2-discovery-installation-inputs-20261029.sh','-o',str(wrapper)],
 preexec_fn=operator,env={'HOME':str(home),'PATH':str(minimal),'LC_ALL':'C'},capture_output=True,timeout=70)
assert result.returncode==0,result.stderr
assert wrapper.read_bytes()==(BASE/'releases/read-m2-discovery-installation-inputs-20261029.sh').read_bytes()
assert hashlib.sha256(wrapper.read_bytes()).hexdigest()=='ec7775e982a705feb7a8ceaaa789397241d990eed36c7efefb26fde675dcb969'
def invoke():return subprocess.run(['/usr/bin/bash','--noprofile','--norc',str(wrapper)],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,preexec_fn=operator,env={'HOME':str(home),'PATH':str(minimal),'LC_ALL':'C'},timeout=120)
try:
 process=invoke();output=process.stdout.decode();assert process.returncode==2,output
 assert 'INTERACTIVE_OPERATOR_TERMINAL_REQUIRED'in output and 'Apri nel browser:'not in output
 assert 'SourceChecksum=OK (root0400; verifica eseguita root)'in output
 code=Path('/usr/local/lib/ouf-m2-discovery-installation-inputs-f9574bc696b34077');entry=code/'read.py';info=entry.stat()
 assert info.st_uid==info.st_gid==0 and info.st_nlink==1 and stat.S_IMODE(info.st_mode)==0o400
 assert hashlib.sha256(entry.read_bytes()).hexdigest()=='f9574bc696b34077e146f74810918625880a48d2108fc8038834eb23e45779ed'
 denied=subprocess.run(['/usr/bin/setpriv','--reuid=65534','--regid=65534','--clear-groups','cat',str(entry)],capture_output=True)
 assert denied.returncode!=0 and not denied.stdout
 assert not scope.exists()and not(code/'operator.log').exists()
 spec=importlib.util.spec_from_file_location('sealed_reader_fixture',entry);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
 original=sys.stdout
 try:
  # Synthetic input/denial only. Real root ancestry, source bytes, modes, exclusive scope and fsync are exercised.
  with patch.object(m.sys,'argv',[str(entry)]),patch.object(m.sys.stdin,'isatty',return_value=True),patch.object(m.sys.stdout,'isatty',return_value=True),patch.dict(m.os.environ,{'SUDO_UID':str(owner)}),patch.object(m,'installation_inputs',side_effect=m.Stop('CI_ONLY_M2_CAPTURE_DENIED_NO_ENGINE'))as login,patch('urllib.request.OpenerDirector.open',side_effect=AssertionError('CI_NETWORK_FORBIDDEN')):
   assert m.main()==2
   assert login.call_count==1
 finally:
  logger=sys.stdout;sys.stdout=original
  if isinstance(logger,m.Logger):logger.file.close()
 state=scope/'result.json';saved=state.read_bytes();record=json.loads(saved)
 assert record['status']=='STOP_RECONCILE'and record['counts']=={'engineGets':0,'privateMetadataReads':0,'bytes':0}
 assert stat.S_IMODE((scope/'claim.json').stat().st_mode)==0o600 and stat.S_IMODE(state.stat().st_mode)==0o600 and stat.S_IMODE((code/'operator.log').stat().st_mode)==0o600
 replay=invoke();assert replay.returncode!=0 and 'NO_REPLAY'in replay.stdout.decode()
 assert state.read_bytes()==saved
 deliveries=list(home.glob('ouf-m2-discovery-installation-inputs-delivery.*'));assert len(deliveries)==2
 assert all(stat.S_IMODE((d/'bootstrap.log').stat().st_mode)==0o600 for d in deliveries)
 print(json.dumps({'status':'M2_DISCOVERY_INSTALLATION_INPUTS_ACTUAL_DELIVERY_PASS','actualPinnedHttpsNonrootSudo':True,'root400SourceAndChecksum':True,'nonTTYBeforeScopeOrIAM':True,'failedScopePreservedNoReplay':True,'realPrivateStateAndLog600':True,'nonrootCodeReadDenied':True,'ghAndTimeoutAbsent':True,'iamRequests':0,'ownerRequests':0,'policyWrites':0,'engineRequests':0,'sqlSessions':0,'credentialOrKeyFileReads':0,'humanApprovalSimulated':False,'targetExecuted':False,'applicationE2EProven':False},sort_keys=True))
finally:sudoers.unlink(missing_ok=True)
