"""Actual pinned HTTPS/nonroot/sudo/root0400 delivery on a disposable CI VM.

Production capture source is byte-exact. Missing target metadata intentionally
stops it before credential reads; positive custody collection has separate real
POSIX fixture tests. This is not target evidence or IAM admission.
"""
import hashlib,json,os,pwd,shutil,subprocess,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
SOURCE_SHA='834dd9b0b7e9f7b02fc07c7080f6d3e51cc7b7fd541691f26942e136a08c00cf'
SCOPE=Path('/etc/ouf/deploy-snapshots/m2-discovery-custody-f759d397-20261029-v1')
CODE=Path('/usr/local/lib/ouf-m2-discovery-custody-'+SOURCE_SHA[:16])

def run(args,**kwargs):return subprocess.run(args,stdin=subprocess.DEVNULL,capture_output=True,text=True,timeout=100,**kwargs)
def main():
    assert os.geteuid()==0 and os.environ.get('GITHUB_ACTIONS')=='true'
    assert not SCOPE.exists() and not CODE.exists()
    try:pwd.getpwnam('oufadmin')
    except KeyError:pass
    else:raise AssertionError('disposable account must not preexist')
    subprocess.run(['useradd','--create-home','--shell','/bin/bash','oufadmin'],check=True)
    home=Path('/home/oufadmin');account=pwd.getpwnam('oufadmin')
    sudo=Path('/etc/sudoers.d/ouf-custody-ci');sudo.write_text('oufadmin ALL=(root) NOPASSWD: /usr/bin/bash\n');sudo.chmod(0o440)
    subprocess.run(['visudo','-cf',str(sudo)],check=True,stdout=subprocess.DEVNULL)
    source=ROOT/'tools/m2_discovery_installation_profile/custody_capture.py'
    assert hashlib.sha256(source.read_bytes()).hexdigest()==SOURCE_SHA
    script=home/'custody-wrapper.sh';shutil.copyfile(ROOT/'releases/read-m2-discovery-custody-20261029.sh',script)
    os.chown(script,account.pw_uid,account.pw_gid);script.chmod(0o400)
    notty=run(['runuser','-u','oufadmin','--','/usr/bin/bash',str(script)])
    assert notty.returncode==1 and 'INTERACTIVE_SSH_TTY_REQUIRED_BEFORE_DOWNLOAD_OR_SCOPE' in notty.stderr
    assert not SCOPE.exists() and not list(home.glob('ouf-m2-discovery-custody-delivery.*'))
    Path('/etc/ouf/deploy-snapshots').mkdir(parents=True,exist_ok=True)
    command='runuser -u oufadmin -- /usr/bin/bash '+str(script)
    first=run(['script','-q','-e','-c',command,'/dev/null'])
    assert first.returncode==1,first.stdout[-1000:]
    assert 'ProtectedCode=' in first.stdout and 'STOP_RECONCILE' in first.stdout and 'DeliveryExit=1' in first.stdout,first.stdout[-2000:]
    code=CODE/'capture.py';assert hashlib.sha256(code.read_bytes()).hexdigest()==SOURCE_SHA
    assert code.stat().st_uid==code.stat().st_gid==0 and code.stat().st_mode&0o777==0o400
    assert CODE.stat().st_mode&0o777==0o700
    denied=run(['runuser','-u','oufadmin','--','/usr/bin/test','-r',str(code)]);assert denied.returncode==1
    result=json.loads((SCOPE/'result.json').read_text());assert result['status']=='STOP_RECONCILE' and result['scopeConsumed'] is True
    assert result['counts']['credentialFileReads']==result['counts']['applicationMacKeyReads']==0
    sealed={p:(p.read_bytes(),p.stat().st_mtime_ns) for p in [code,CODE/'operator.log',SCOPE/'capture.claim.json',SCOPE/'result.json']}
    second=run(['script','-q','-e','-c',command,'/dev/null'])
    assert second.returncode==1 and 'CUSTODY_CAPTURE_SCOPE_CONSUMED_NO_REPLAY' in second.stdout
    for p,(raw,mtime) in sealed.items():assert p.read_bytes()==raw and p.stat().st_mtime_ns==mtime
    print(json.dumps({'schema':'ouf.m2-discovery-custody-delivery-ci.v1','pinnedHttpsDelivery':True,
        'actualNonrootSudoRoot400Checksum':True,'nonTtyRejectedBeforeScopeOrDownload':True,
        'nonrootProtectedSourceReadDenied':True,'failureScopePreserved':True,'replayRefusedBeforeProtectedExecution':True,
        'positiveCaptureQualifiedSeparately':True,'targetMetadataAbsentInThisFixture':True,
        'credentialFileReads':0,'applicationMacKeyReads':0,'runtimeAuthorityIssued':False,'targetApplyAuthorized':False}))

if __name__=='__main__':main()
