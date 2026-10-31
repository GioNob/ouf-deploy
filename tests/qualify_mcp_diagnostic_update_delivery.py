"""Actual public HTTP -> nonroot wrapper -> sudo root400 -> protected main/TTY.

Isolated CI deliberately supplies a wrong synthetic native-plan hash. The real
protected main must refuse BEFORE approval/keys/Engine. Positive lifecycle and
actual HUMAN input are independently covered by the native and PTY suites.
"""
import fcntl,hashlib,json,os,pwd,select,shutil,signal,subprocess,termios,time
from pathlib import Path
BASE=Path(__file__).resolve().parents[1]
assert os.geteuid()==0
owner=int(os.environ['SUDO_UID']);assert owner>0;account=pwd.getpwuid(owner)
root=Path('/var/lib/ouf-mcp-update-delivery-ci');assert not root.exists();root.mkdir(mode=0o755)
home=root/'home';home.mkdir(mode=0o700);os.chown(home,owner,account.pw_gid)
minimal=root/'bin';minimal.mkdir(mode=0o755)
for name in('bash','curl','id','mktemp','chmod','tee','sudo','sha256sum'):
    target=shutil.which(name);assert target;os.symlink(target,minimal/name)
assert shutil.which('gh',path=str(minimal))is None
assert shutil.which('timeout',path=str(minimal))is None
prepared=Path('/etc/ouf/deploy-snapshots/mcp-denial-image-plan-fb4b7c9ae832e779-v1');prepared.mkdir(parents=True,mode=0o700)
for parent in(prepared,prepared.parent,prepared.parent.parent):parent.chmod(0o700)
fake=b'{"syntheticWrongNativeHash":true}'
(prepared/'native-plan.json').write_bytes(fake);(prepared/'native-plan.json').chmod(0o400)
prior=Path('/etc/ouf/deploy-snapshots/mcp-diagnostic-update-ff06ec1afc5da65d-v1');prior.mkdir(mode=0o700)
def put(path,value):
    path.write_bytes(json.dumps(value,sort_keys=True,separators=(',',':')).encode());path.chmod(0o400)
limits={'engineGets':256,'engineWrites':10,'imageLoadAttempts':1,'readinessGets':96,'adminGets':0,'adminPuts':0,'ownerConfigurationReads':64,'serviceCredentialFileReads':0,'quarantineStops':1}
put(prior/'preparation-claim.json',{'schema':'ouf.mcp-diagnostic-update-preflight-claim.v1','nativePlanHash':'ff06ec1afc5da65dc6b6c64edb9ab9ec87926f4a9de7aec355b69b96c4cd8653','maximums':limits,'runtimeEffectsDispatched':0,'automaticReplayAllowed':False,'budgetReset':False})
for i in(1,2):put(prior/('preflight-attempt-1234-%05d.json'%i),{'kind':'ownerConfigurationReads','attempt':i,'attemptNotCompletion':True})
prior_bytes={p:p.read_bytes()for p in prior.iterdir()}
reconciled=prior.parent/'mcp-host-policy-stop-read-ff06ec1a-v1';reconciled.mkdir(mode=0o700)
put(reconciled/'result.json',json.loads((BASE/'tests/fixtures/mcp-zero-memory-reconciliation.json').read_bytes()))
scope=prior/'retained-host-policy-continuation-v1';assert not scope.exists()
master,slave=os.openpty()
def session():
    os.setsid();fcntl.ioctl(0,termios.TIOCSCTTY,0);os.setgroups([account.pw_gid]);os.setgid(account.pw_gid);os.setuid(owner)
proc=subprocess.Popen(['/usr/bin/bash','--noprofile','--norc',str(BASE/'releases/apply-mcp-diagnostic-host-policy-continuation-20261026.sh')],stdin=slave,stdout=slave,stderr=slave,preexec_fn=session,env={'PATH':str(minimal),'HOME':str(home),'TERM':'xterm','LC_ALL':'C'})
os.close(slave);output=bytearray();deadline=time.monotonic()+240
try:
    while proc.poll()is None and time.monotonic()<deadline:
        if select.select([master],[],[],.1)[0]:
            try:raw=os.read(master,65536)
            except OSError:break
            output.extend(raw)
    proc.wait(timeout=5);assert proc.returncode==2,(proc.returncode,output.decode(errors='replace'))
    deliveries=list(home.glob('ouf-mcp-host-policy-apply-delivery.*'));assert len(deliveries)==1
    bootstrap=(deliveries[0]/'bootstrap.log').read_text();assert 'Exit=2'in bootstrap and 'DeliveryExit=2'in bootstrap
    code=Path('/usr/local/lib/ouf-mcp-diagnostic-update-b8bae202a3222f01');manifest=(code/'sources.json').read_bytes()
    assert hashlib.sha256(manifest).hexdigest()=='b8bae202a3222f014eab096e6e06c4f7339a655dabe351f3aea677f9acb30a50'
    mapping=json.loads(manifest);assert len(mapping)==18
    for name,digest in mapping.items():
        path=code/name;s=path.stat();assert s.st_uid==s.st_gid==0 and s.st_mode&0o777==0o400 and hashlib.sha256(path.read_bytes()).hexdigest()==digest
        denied=subprocess.run(['setpriv','--reuid=65534','--regid=65534','--clear-groups','cat',str(path)],capture_output=True);assert denied.returncode!=0 and not denied.stdout
    log=code/'operator.log';assert log.stat().st_mode&0o777==0o600
    rows=[json.loads(line)for line in log.read_text().splitlines()if line.startswith('{')];assert len(rows)==1
    assert rows[0]['reasonCode']=='EXACT_PRIVATE_METADATA_HASH_REQUIRED'and rows[0]['complete']is False,rows
    assert (scope/'preparation-claim.json').is_file()
    assert not(scope/'authority').exists()and not(scope/'recovery.json').exists()
    assert not list(scope.glob('raw-engine-response-*'))
    assert (prepared/'native-plan.json').read_bytes()==fake
    assert all(p.read_bytes()==raw for p,raw in prior_bytes.items())
    assert len(list(prior.iterdir()))==4
    assert not any('APPROVO '+c in log.read_text()for c in json.loads(manifest).values())
    print(json.dumps({'schema':'ouf.mcp-update-actual-sealed-delivery-ci.v1','complete':True,'realPublicHttpsSourcesDownloaded':18,'nonrootWrapperWithGhAndTimeoutAbsent':True,'realSudoRootCopier':True,'rootCode0400':True,'nonrootReadDenied':True,'actualMainWithControllingForegroundTty':True,'operatorLog0600':True,'preflightClaimBeforeWrongNativeHashRejection':True,'exactPriorUnissuedPreflightAndNineReadReconciliationVerified':True,'oldMetadataCountsPreserved':2,'syntheticNativeInputUnchanged':True,'humanApprovalRequested':False,'runtimeAuthorityIssued':False,'engineRequests':0,'privateSigningKeysRead':False,'productionRuntimeAccess':False,'targetApplyExecuted':False}),flush=True)
finally:
    if proc.poll()is None:os.killpg(proc.pid,signal.SIGKILL)
    proc.wait(timeout=5);os.close(master)
