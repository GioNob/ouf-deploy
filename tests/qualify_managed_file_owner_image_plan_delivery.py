"""CI-only actual public delivery, exact ZIP transfer and negative production entry."""
import hashlib,json,os,pwd,shutil,stat,subprocess
from pathlib import Path

BASE=Path(__file__).resolve().parents[1]
assert os.geteuid()==os.getegid()==0
try:account=pwd.getpwnam('oufadmin')
except KeyError:
    subprocess.run(['/usr/sbin/useradd','-M','-U','oufadmin'],check=True);account=pwd.getpwnam('oufadmin')
uid=account.pw_uid
sudoers=Path('/etc/sudoers.d/ouf-owner-v38-image-plan-ci');sudoers.write_text('oufadmin ALL=(root) NOPASSWD: /usr/bin/python3 *\n');sudoers.chmod(0o440)
root=Path('/var/lib/ouf-owner-v38-image-plan-delivery-ci');root.mkdir(mode=0o755)
home=root/'home';home.mkdir(mode=0o700);os.chown(home,uid,account.pw_gid)
bin_dir=root/'bin';bin_dir.mkdir(mode=0o755)
for name in ('bash','id','mktemp','chmod','curl','sha256sum','tee','sudo'):
    os.symlink(shutil.which(name),bin_dir/name)
assert shutil.which('gh',path=str(bin_dir)) is None and shutil.which('timeout',path=str(bin_dir)) is None
retained=Path('/etc/ouf/deploy-snapshots/managed-file-owner-recovery-inputs-1c0cff56-20261028-v1')/'inputs.json';retained.parent.mkdir(parents=True,mode=0o700);retained.parent.chmod(0o700)
raw=b'{"CI_ONLY_WRONG_CAPTURE_SEAL":true}';retained.write_bytes(raw);retained.chmod(0o400)
def demote():os.setgroups([account.pw_gid]);os.setgid(account.pw_gid);os.setuid(uid)
wrapper=home/'run.sh'
download=subprocess.run(['/usr/bin/curl','--fail','--silent','--show-error','--location','--proto','=https','--proto-redir','=https','--max-redirs','3','--connect-timeout','15','--max-time','60',
    'https://raw.githubusercontent.com/GioNob/ouf-deploy/63d7370f50814adda04f8cdcaf40cd4d7f619e54/releases/prepare-managed-file-owner-image-plan-20261028.sh','-o',str(wrapper)],
    preexec_fn=demote,env={'HOME':str(home),'PATH':str(bin_dir),'LC_ALL':'C'},capture_output=True,timeout=70)
assert hashlib.sha256(wrapper.read_bytes()).hexdigest()=='f185922cea4d0b9980d46408fbc6778569adeffef830125b2bd9cc86e0a23919'
assert download.returncode==0 and wrapper.read_bytes()==(BASE/'releases/prepare-managed-file-owner-image-plan-20261028.sh').read_bytes()
wrapper.chmod(0o400)
def invoke():return subprocess.run(['/usr/bin/bash','--noprofile','--norc',str(wrapper)],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,
    preexec_fn=demote,env={'HOME':str(home),'PATH':str(bin_dir),'LC_ALL':'C'},timeout=1500)
try:
    process=invoke();output=process.stdout.decode();assert process.returncode==2,(process.returncode,output)
    rows=[json.loads(line)for line in output.splitlines()if line.startswith('{')]
    downloads=[row for row in rows if row.get('status')=='EXACT_EXISTING_CI_ZIP_DOWNLOADED'];assert len(downloads)==1,output
    final=[row for row in rows if row.get('schema')=='ouf.managed-file-owner-recovery-image-plan-result.v1'];assert len(final)==1,output
    result=final[0]
    assert result['status']=='STOP_RECONCILE'and result['reasonCode']=='EXACT_CAPTURE_METADATA_HASH_REQUIRED',output
    assert result['counts']['privateMetadataReads']==1 and result['counts']['privateMetadataBytes']==len(raw)
    assert result['counts']['engineGets']==result['counts']['containerWrites']==result['counts']['ciZipReads']==result['counts']['nativeArchivesPrepared']==0
    code=Path('/usr/local/lib/ouf-managed-file-owner-image-plan-83465836310ad2bd');sources=[{"name":"entry.py","path":"scripts/prepare-managed-file-owner-image-plan.py","sha256":"eba155574b113974b3699cd16b5a0dc0c49a8d8832f1285830583d240747f343"},{"name":"image_plan.py","path":"tools/managed_file_owner_recovery/image_plan.py","sha256":"1f5a4de5df532503c5ee10e5d635f1350ca1d691d8b0dee320b6e8515c3441d1"},{"name":"common_image_plan.py","path":"tools/managed_csv_recovery/image_plan.py","sha256":"d95720bd315b2f7e08378ecc60250088b4173601705297ca65a904f9316a3375"},{"name":"download.py","path":"scripts/download-managed-file-owner-image.py","sha256":"a17c0c4c76302e2182f2c2701fa20bfe3a3f1462b36c710133fc038276a5f2eb"},{"name":"image_custody.py","path":"tools/acquisition_read_native/image_custody.py","sha256":"5d0fc0edb1ebd9386326eadbbee08f2cf0a9fd1e122940c0661b5ac5e3655ed8"},{"name":"plan_helper.py","path":"tools/acquisition_read_native/plan_helper.py","sha256":"09b892a89f7cd7fa31fbc891822445ed09554e9362e397bb9b12b98316e1d8dd"},{"name":"retained_mac.py","path":"tools/acquisition_read_native/retained_mac.py","sha256":"cb5dbbee4a80ce71860dfe5d32362a662d98898c58fd82009e69c5eb6ac1f7ce"},{"name":"stage_image.py","path":"scripts/stage_managed_file_owner_image.py","sha256":"9c036afc5256c6f845d545439ee8c677e720b0b2036dc3ed0b5b0fac78109955"},{"name":"case.json","path":"releases/managed-file-owner-v38-image-plan-case-20261028.json","sha256":"6afc3ee56a4c81a7bf45ffcaa9c64af28bd36e22ba6c156cd3b05fbbce98ce2f"},{"name":"onboarding-custody.json","path":"releases/managed-file-owner-v38-image-custody-20261028.json","sha256":"e86a73dd52682e40c040ce3db4634afd2f6802694198c77433ca33e3a49eb9ba"}]
    for source in sources:
        path=code/source['name'];info=path.stat()
        assert info.st_uid==info.st_gid==0 and stat.S_IMODE(info.st_mode)==0o400 and hashlib.sha256(path.read_bytes()).hexdigest()==source['sha256']
    for role in ('onboarding',):
        path=code/(role+'.zip');info=path.stat();assert info.st_uid==0 and stat.S_IMODE(info.st_mode)==0o400
    denied=subprocess.run(['setpriv','--reuid=65534','--regid=65534','--clear-groups','cat',str(code/'entry.py')],capture_output=True)
    assert denied.returncode!=0 and not denied.stdout
    scope=Path('/etc/ouf/deploy-snapshots/managed-file-owner-v38-image-plan-8a4c8475-20261028-v1')
    before={path:path.read_bytes()for path in scope.iterdir()if path.is_file()}
    assert 'claim.json'in{path.name for path in before}and not(scope/'inputs.json').exists()and not(scope/'execution-inputs.json').exists()
    replay=invoke();assert replay.returncode!=0 and 'consumata'in replay.stdout.decode()
    assert all(path.read_bytes()==value for path,value in before.items())and retained.read_bytes()==raw
    deliveries=list(home.glob('ouf-managed-file-owner-image-plan-delivery.*'));assert len(deliveries)==2
    assert all(stat.S_IMODE((path/'bootstrap.log').stat().st_mode)==0o600 for path in deliveries)
    print(json.dumps({'status':'OWNER_V38_IMAGE_PLAN_ACTUAL_DELIVERY_PASS','actualPinnedCurlSudo':True,'sourceFilesRoot400':10,
        'originalCiZipsRoot400':1,'ghAndTimeoutAbsent':True,'wrongPrivateSealRefusedBeforeArchiveProcessing':True,'consumedScopeRefused':True,
        'oldFilesWritten':0,'engineRequests':0,'sqlSessions':0,'oauthRequests':0,'credentialsOrSigningKeysRead':0,'runtimeAuthorityIssued':False,'targetAccess':False},sort_keys=True))
finally:sudoers.unlink(missing_ok=True)
