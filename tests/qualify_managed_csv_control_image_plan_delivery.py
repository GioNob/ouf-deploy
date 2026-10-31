"""CI-only actual public delivery, exact ZIP transfer and negative production entry."""
import hashlib,json,os,pwd,shutil,stat,subprocess
from pathlib import Path

BASE=Path(__file__).resolve().parents[1]
assert os.geteuid()==os.getegid()==0
try:account=pwd.getpwnam('oufadmin')
except KeyError:
    subprocess.run(['/usr/sbin/useradd','-M','-U','oufadmin'],check=True);account=pwd.getpwnam('oufadmin')
uid=account.pw_uid
sudoers=Path('/etc/sudoers.d/ouf-control-image-plan-ci');sudoers.write_text('oufadmin ALL=(root) NOPASSWD: /usr/bin/python3 *\n');sudoers.chmod(0o440)
root=Path('/var/lib/ouf-control-image-plan-delivery-ci');root.mkdir(mode=0o755)
home=root/'home';home.mkdir(mode=0o700);os.chown(home,uid,account.pw_gid)
bin_dir=root/'bin';bin_dir.mkdir(mode=0o755)
for name in ('bash','id','mktemp','chmod','curl','sha256sum','tee','sudo'):
    os.symlink(shutil.which(name),bin_dir/name)
assert shutil.which('gh',path=str(bin_dir)) is None and shutil.which('timeout',path=str(bin_dir)) is None
retained=Path('/etc/ouf/deploy-snapshots/managed-csv-recovery-control-inputs-20261027-v1/reconcile-retained-peer-binding-v1')/'inputs.json';retained.parent.mkdir(parents=True,mode=0o700);retained.parent.chmod(0o700)
raw=b'{"CI_ONLY_WRONG_CAPTURE_SEAL":true}';retained.write_bytes(raw);retained.chmod(0o400)
def demote():os.setgroups([account.pw_gid]);os.setgid(account.pw_gid);os.setuid(uid)
wrapper=home/'run.sh'
download=subprocess.run(['/usr/bin/curl','--fail','--silent','--show-error','--location','--proto','=https','--proto-redir','=https','--max-redirs','3','--connect-timeout','15','--max-time','60',
    'https://raw.githubusercontent.com/GioNob/ouf-deploy/d872420c44bf6ca2bdc0055201c8c332ae0f09da/releases/prepare-managed-csv-control-image-plan-20261027.sh','-o',str(wrapper)],
    preexec_fn=demote,env={'HOME':str(home),'PATH':str(bin_dir),'LC_ALL':'C'},capture_output=True,timeout=70)
assert download.returncode==0 and wrapper.read_bytes()==(BASE/'releases/prepare-managed-csv-control-image-plan-20261027.sh').read_bytes()
wrapper.chmod(0o400)
def invoke():return subprocess.run(['/usr/bin/bash','--noprofile','--norc',str(wrapper)],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,
    preexec_fn=demote,env={'HOME':str(home),'PATH':str(bin_dir),'LC_ALL':'C'},timeout=1500)
try:
    process=invoke();output=process.stdout.decode();assert process.returncode==2,(process.returncode,output)
    rows=[json.loads(line)for line in output.splitlines()if line.startswith('{')]
    downloads=[row for row in rows if row.get('status')=='EXACT_EXISTING_CI_ZIP_DOWNLOADED'];assert len(downloads)==2,output
    final=[row for row in rows if row.get('schema')=='ouf.managed-csv-control-image-plan-result.v1'];assert len(final)==1,output
    result=final[0]
    assert result['status']=='STOP_RECONCILE'and result['reasonCode']=='EXACT_CAPTURE_METADATA_HASH_REQUIRED',output
    assert result['counts']['privateMetadataReads']==1 and result['counts']['privateMetadataBytes']==len(raw)
    assert result['counts']['engineGets']==result['counts']['containerWrites']==result['counts']['ciZipReads']==result['counts']['nativeArchivesPrepared']==0
    code=Path('/usr/local/lib/ouf-managed-csv-control-image-plan-2d42559b5e4418b7');sources=[{"name":"entry.py","path":"scripts/prepare-managed-csv-control-image-plan.py","sha256":"cfae87208111dcbc19497d01cb6667c3c838f52375487b8719aa690f4705d70e"},{"name":"image_plan.py","path":"tools/managed_csv_recovery/image_plan.py","sha256":"d95720bd315b2f7e08378ecc60250088b4173601705297ca65a904f9316a3375"},{"name":"download.py","path":"scripts/download-managed-csv-control-images.py","sha256":"05788878890b894f9e5037ee04ddc373b2b2dbd24eb91081855d3f88cab56be1"},{"name":"image_custody.py","path":"tools/acquisition_read_native/image_custody.py","sha256":"5d0fc0edb1ebd9386326eadbbee08f2cf0a9fd1e122940c0661b5ac5e3655ed8"},{"name":"plan_helper.py","path":"tools/acquisition_read_native/plan_helper.py","sha256":"09b892a89f7cd7fa31fbc891822445ed09554e9362e397bb9b12b98316e1d8dd"},{"name":"retained_mac.py","path":"tools/acquisition_read_native/retained_mac.py","sha256":"cb5dbbee4a80ce71860dfe5d32362a662d98898c58fd82009e69c5eb6ac1f7ce"},{"name":"stage_image.py","path":"scripts/stage_managed_profile_control_image.py","sha256":"63badba653890bb82cde89aabd9277017b52f10f644a6a8cf6918d997fe1d36f"},{"name":"case.json","path":"releases/managed-csv-control-image-plan-case-20261027.json","sha256":"e76d548e58ea3654c48760a7cdefb8cf371bd5a6ddbeeb94916d2c03a36598f6"},{"name":"onboarding-custody.json","path":"releases/managed-profile-control-onboarding-image-custody-20261027.json","sha256":"ef8f32bceb053718761401a3b775c49e76dc9eef1d46f9df80872d52c88f62e6"},{"name":"mcp-custody.json","path":"releases/managed-profile-control-mcp-image-custody-20261027.json","sha256":"c977f4aa3701992c9570d1faa26e65c953313ae91f685a1094a46f89b4ed7a69"}]
    for source in sources:
        path=code/source['name'];info=path.stat()
        assert info.st_uid==info.st_gid==0 and stat.S_IMODE(info.st_mode)==0o400 and hashlib.sha256(path.read_bytes()).hexdigest()==source['sha256']
    for role in ('onboarding','mcp'):
        path=code/(role+'.zip');info=path.stat();assert info.st_uid==0 and stat.S_IMODE(info.st_mode)==0o400
    denied=subprocess.run(['setpriv','--reuid=65534','--regid=65534','--clear-groups','cat',str(code/'entry.py')],capture_output=True)
    assert denied.returncode!=0 and not denied.stdout
    scope=Path('/etc/ouf/deploy-snapshots/managed-csv-control-image-plan-14a96f782827c894-v1')
    before={path:path.read_bytes()for path in scope.iterdir()if path.is_file()}
    assert 'claim.json'in{path.name for path in before}and not(scope/'inputs.json').exists()and not(scope/'execution-inputs.json').exists()
    replay=invoke();assert replay.returncode!=0 and 'consumata'in replay.stdout.decode()
    assert all(path.read_bytes()==value for path,value in before.items())and retained.read_bytes()==raw
    deliveries=list(home.glob('ouf-managed-csv-control-image-plan-delivery.*'));assert len(deliveries)==2
    assert all(stat.S_IMODE((path/'bootstrap.log').stat().st_mode)==0o600 for path in deliveries)
    print(json.dumps({'status':'MANAGED_CSV_IMAGE_PLAN_ACTUAL_DELIVERY_PASS','actualPinnedCurlSudo':True,'sourceFilesRoot400':10,
        'originalCiZipsRoot400':2,'ghAndTimeoutAbsent':True,'wrongPrivateSealRefusedBeforeArchiveProcessing':True,'consumedScopeRefused':True,
        'oldFilesWritten':0,'engineRequests':0,'sqlSessions':0,'oauthRequests':0,'credentialsOrSigningKeysRead':0,'runtimeAuthorityIssued':False,'targetAccess':False},sort_keys=True))
finally:sudoers.unlink(missing_ok=True)
