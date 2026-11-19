"""Offline delivery qualification: real nonroot/bash/sudo/root400, fixture download.

No HTTPS or IAM is contacted. Only the temporary test launcher receives synthetic
commit/SHA pins; the tracked launcher retains its explicit release placeholders.
The curl substitute asserts the pinned HTTPS URL/options, then copies local bytes.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import stat
import subprocess
import sys
from unittest.mock import patch

BASE = Path(__file__).resolve().parents[1]
assert os.geteuid() == os.getegid() == 0
try:account = pwd.getpwnam('oufadmin')
except KeyError:
    subprocess.run(['/usr/sbin/useradd','-M','-U','oufadmin'],check=True)
    account = pwd.getpwnam('oufadmin')
owner = account.pw_uid
assert owner > 0
sudoers = Path('/etc/sudoers.d/ouf-admin-operational-grants-publication-ci')
sudoers.write_text('oufadmin ALL=(root) NOPASSWD: /usr/bin/python3 *\n')
sudoers.chmod(0o440)
root = Path('/var/lib/ouf-admin-operational-grants-delivery-ci')
root.mkdir(mode=0o755)
home = root/'home'
home.mkdir(mode=0o700)
os.chown(home,owner,account.pw_gid)
minimal = root/'bin'
minimal.mkdir(mode=0o755)
for name in ('bash','id','mktemp','chmod','tee','sudo','sha256sum'):
    os.symlink(shutil.which(name),minimal/name)
assert shutil.which('gh',path=str(minimal)) is None
assert shutil.which('timeout',path=str(minimal)) is None
source = (BASE/'scripts/publish-ouf-admin-operational-grants-20261111.py').read_bytes()
sha = hashlib.sha256(source).hexdigest()
commit = '1'*40  # CI fixture, not a release/source claim.
download = root/'fixture.py'
download.write_bytes(source)
download.chmod(0o644)
curl = minimal/'curl'
curl.write_text('''#!/usr/bin/python3
import os,sys
from pathlib import Path
a=sys.argv[1:]
expected=['--fail','--silent','--show-error','--location','--proto','=https',
 '--proto-redir','=https','--max-redirs','3','--connect-timeout','15',
 '--max-time','60','--max-filesize','65536',
 'https://raw.githubusercontent.com/GioNob/ouf-deploy/'''+commit+'''/scripts/publish-ouf-admin-operational-grants-20261111.py','-o']
assert a[:-1]==expected,a
assert Path(a[-1]).name=='publish.py'
Path(a[-1]).write_bytes(Path('''+repr(str(download))+''').read_bytes())
''')
curl.chmod(0o755)
scope = Path('/etc/ouf/deploy-snapshots/ouf-admin-operational-grants-policy69-20261111-v1')
scope.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
scope.parent.chmod(0o700)
tracked = (BASE/'releases/publish-ouf-admin-operational-grants-20261111.sh').read_text()
commit_pin = re.search(r'^code_commit=(__PIN_COMMIT__|[a-f0-9]{40})$',tracked,re.M).group(1)
sha_pin = re.search(r'^code_sha=(__PIN_SHA256__|[a-f0-9]{64})$',tracked,re.M).group(1)
assert (commit_pin=='__PIN_COMMIT__') == (sha_pin=='__PIN_SHA256__')
if sha_pin == '__PIN_SHA256__':
    assert tracked.count('__PIN_SHA256_PREFIX16__') == 2
    template = tracked
else:
    # The same offline suite remains valid after Claude pins the delivery.
    assert sha_pin == sha and tracked.count(sha_pin)==2
    assert tracked.count('ouf-admin-operational-grants-publish-'+sha[:16])==2
    template = tracked.replace(commit_pin,'__PIN_COMMIT__').replace(sha_pin,'__PIN_SHA256__').replace(sha[:16],'__PIN_SHA256_PREFIX16__')
wrapper = home/'publish.sh'
def install(text):
    wrapper.write_text(text)
    wrapper.chmod(0o600)
    os.chown(wrapper,owner,account.pw_gid)
def operator():
    os.setgroups([account.pw_gid]);os.setgid(account.pw_gid);os.setuid(owner)
def invoke():
    return subprocess.run(['/usr/bin/bash','--noprofile','--norc',str(wrapper)],
        stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,
        preexec_fn=operator,env={'HOME':str(home),'PATH':str(minimal),'LC_ALL':'C'},timeout=120)
try:
    install(template)
    unpinned = invoke()
    assert unpinned.returncode == 2 and b'PUBLICATION_DELIVERY_PINS_REQUIRED' in unpinned.stdout
    assert not scope.exists()
    pinned = template.replace('__PIN_COMMIT__',commit).replace('__PIN_SHA256__',sha).replace('__PIN_SHA256_PREFIX16__',sha[:16])
    install(pinned)
    download.write_bytes(source+b'\n# CI corrupted download\n')
    corrupt = invoke()
    assert corrupt.returncode != 0 and b'SourceChecksum=OK' not in corrupt.stdout
    assert not scope.exists()
    download.write_bytes(source)
    process = invoke()
    output = process.stdout.decode()
    assert process.returncode == 2,output
    assert 'INTERACTIVE_OPERATOR_TERMINAL_REQUIRED' in output and 'Apri nel browser:' not in output
    assert 'SourceChecksum=OK (root0400; verifica eseguita root)' in output
    code = Path('/usr/local/lib/ouf-admin-operational-grants-publish-'+sha[:16])
    entry = code/'publish.py'
    info = entry.stat()
    assert info.st_uid == info.st_gid == 0 and info.st_nlink == 1 and stat.S_IMODE(info.st_mode)==0o400
    assert hashlib.sha256(entry.read_bytes()).hexdigest()==sha
    denied = subprocess.run(['/usr/bin/setpriv','--reuid=65534','--regid=65534','--clear-groups','cat',str(entry)],capture_output=True)
    assert denied.returncode != 0 and not denied.stdout
    assert not scope.exists() and not (code/'operator.log').exists()
    spec = importlib.util.spec_from_file_location('sealed_operational_grants',entry)
    m = importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
    original = sys.stdout
    try:
        # Only TTY and denied login are synthetic. Custody/fsync/journal are real.
        with patch.object(m.sys,'argv',[str(entry)]), patch.object(m.sys.stdin,'isatty',return_value=True), patch.object(m.sys.stdout,'isatty',return_value=True), patch.object(m,'login',side_effect=m.Stop('CI_ONLY_LOGIN_DENIED_NO_NETWORK')) as login, patch('urllib.request.OpenerDirector.open',side_effect=AssertionError('CI_NETWORK_FORBIDDEN')):
            try:m.main();raise AssertionError('denial ignored')
            except m.Stop as error:assert str(error)=='CI_ONLY_LOGIN_DENIED_NO_NETWORK'
            assert login.call_count==1
    finally:
        logger=sys.stdout;sys.stdout=original
        if isinstance(logger,m.Logger):logger.file.close()
    state = scope/'state.json'
    saved = state.read_bytes()
    record = json.loads(saved)
    assert record['state']=='STOP_RECONCILE' and record['counts']=={} and record['effects']=={}
    assert not record.get('humanReviewApproved')
    assert stat.S_IMODE(state.stat().st_mode)==0o600
    assert stat.S_IMODE((code/'operator.log').stat().st_mode)==0o600
    replay = invoke()
    assert replay.returncode != 0 and b'NO_REPLAY' in replay.stdout
    assert state.read_bytes()==saved
    deliveries = list(home.glob('ouf-admin-operational-grants-publish-delivery.*'))
    assert len(deliveries)==4
    assert all(stat.S_IMODE((d/'bootstrap.log').stat().st_mode)==0o600 for d in deliveries)
    print(json.dumps({'status':'OUF_ADMIN_OPERATIONAL_GRANTS_OFFLINE_DELIVERY_PASS',
        'realNonrootSudoRoot400':True,'fixtureDownloadOnly':True,'liveHttpsProven':False,
        'unpinnedLauncherStops':True,'corruptedDownloadStops':True,
        'failedScopePreservedNoReplay':True,'nonTTYBeforeScopeOrIAM':True,
        'externalRequests':0,'iamRequests':0,'ownerRequests':0,'policyWrites':0,
        'humanApprovalSimulated':False,'targetExecuted':False},sort_keys=True))
finally:
    sudoers.unlink(missing_ok=True)
