"""Actual pinned HTTPS/nonroot/sudo/root0400 delivery on a disposable CI VM.

Production capsule is byte-exact. Missing target metadata intentionally
stops it before credential reads; positive material preparation has separate real
POSIX fixture tests. This is not target evidence or IAM admission.
"""
import hashlib,json,os,pwd,shutil,subprocess,sys,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
SOURCE_SHA='8facf88b7fe725d3a6f75ce494a3133d49d79e81972dfa8c318967a0919076ff'
SCOPE=Path('/etc/ouf/deploy-snapshots/m2-provider-reconciliation-960507a9-20261029-v1')
CODE=Path('/usr/local/lib/ouf-m2-provider-reconciliation-'+SOURCE_SHA[:16])

def run(args,**kwargs):return subprocess.run(args,stdin=subprocess.DEVNULL,capture_output=True,text=True,timeout=100,**kwargs)
def main():
    assert os.geteuid()==0 and os.environ.get('GITHUB_ACTIONS')=='true'
    assert sys.argv[1:] in ([],['--prior-log'])
    assert not SCOPE.exists() and not CODE.exists()
    try:pwd.getpwnam('oufadmin')
    except KeyError:pass
    else:raise AssertionError('disposable account must not preexist')
    subprocess.run(['useradd','--create-home','--shell','/bin/bash','oufadmin'],check=True)
    home=Path('/home/oufadmin');account=pwd.getpwnam('oufadmin')
    sudo=Path('/etc/sudoers.d/ouf-provider-reconciliation-ci');sudo.write_text('oufadmin ALL=(root) NOPASSWD: /usr/bin/bash\n');sudo.chmod(0o440)
    subprocess.run(['visudo','-cf',str(sudo)],check=True,stdout=subprocess.DEVNULL)
    source=ROOT/'releases/m2-provider-reconciliation-20261029.py'
    assert hashlib.sha256(source.read_bytes()).hexdigest()==SOURCE_SHA
    script=home/'material-wrapper.sh';shutil.copyfile(ROOT/'releases/prepare-m2-provider-reconciliation-20261029.sh',script)
    os.chown(script,account.pw_uid,account.pw_gid);script.chmod(0o400)
    notty=run(['runuser','-u','oufadmin','--','/usr/bin/bash',str(script)])
    assert notty.returncode==1 and 'INTERACTIVE_SSH_TTY_REQUIRED_BEFORE_DOWNLOAD_OR_SCOPE' in notty.stderr
    assert not SCOPE.exists() and not list(home.glob('ouf-m2-provider-reconciliation-delivery.*'))
    Path('/etc/ouf/deploy-snapshots').mkdir(parents=True,exist_ok=True)
    command='runuser -u oufadmin -- /usr/bin/bash '+str(script)
    if sys.argv[1:]==['--prior-log']:
        # Separate disposable VM case. No consumed scope or prior log is erased.
        CODE.mkdir(mode=0o700);protected=CODE/'prepare.py'
        protected.write_bytes(source.read_bytes());protected.chmod(0o400)
        log=CODE/'operator.log';log.write_bytes(b'SYNTHETIC_PRIOR_ATTEMPT_KEEP_UNCHANGED\n');log.chmod(0o600)
        before={p:(p.read_bytes(),p.stat().st_mtime_ns) for p in (protected,log)}
        reply=run(['script','-q','-e','-c',command,'/dev/null'])
        assert reply.returncode==1 and 'PROTECTED_PROVIDER_RECONCILIATION_INVOCATION_ALREADY_ATTEMPTED_NO_REPLAY' in reply.stdout
        assert not SCOPE.exists()
        assert all(p.read_bytes()==raw and p.stat().st_mtime_ns==mtime for p,(raw,mtime) in before.items())
        print(json.dumps({'schema':'ouf.m2-provider-reconciliation-preparation-prior-log-ci.v1',
            'pinnedHttpsDelivery':True,'existingProtectedLogRefusedBeforeScopeOrExecution':True,
            'priorLogAndCodePreserved':True,'targetExecuted':False,'runtimeAuthorityIssued':False,'targetApplyAuthorized':False}))
        return
    first=run(['script','-q','-e','-c',command,'/dev/null'])
    assert first.returncode==1,first.stdout[-1000:]
    assert 'ProtectedCode=' in first.stdout and 'STOP_RECONCILE' in first.stdout and 'DeliveryExit=1' in first.stdout,first.stdout[-2000:]
    code=CODE/'prepare.py';assert hashlib.sha256(code.read_bytes()).hexdigest()==SOURCE_SHA
    assert code.stat().st_uid==code.stat().st_gid==0 and code.stat().st_mode&0o777==0o400
    assert CODE.stat().st_mode&0o777==0o700
    denied=run(['runuser','-u','oufadmin','--','/usr/bin/test','-r',str(code)]);assert denied.returncode==1
    result=json.loads((SCOPE/'result.json').read_text());assert result['status']=='STOP_RECONCILE' and result['scopeConsumed'] is True
    assert result['counts']['credentialFileReads']==result['counts']['applicationMacKeyReads']==result['counts']['privateCopiesPrepared']==0
    sealed={p:(p.read_bytes(),p.stat().st_mtime_ns) for p in [code,CODE/'operator.log',SCOPE/'capture.claim.json',SCOPE/'result.json']}
    second=run(['script','-q','-e','-c',command,'/dev/null'])
    assert second.returncode==1 and 'PROVIDER_RECONCILIATION_SCOPE_CONSUMED_NO_REPLAY' in second.stdout
    for p,(raw,mtime) in sealed.items():assert p.read_bytes()==raw and p.stat().st_mtime_ns==mtime
    print(json.dumps({'schema':'ouf.m2-provider-reconciliation-preparation-delivery-ci.v1','pinnedHttpsDelivery':True,
        'actualNonrootSudoRoot400Checksum':True,'nonTtyRejectedBeforeScopeOrDownload':True,
        'nonrootProtectedSourceReadDenied':True,'failureScopePreserved':True,'replayRefusedBeforeProtectedExecution':True,
        'positivePreparationQualifiedSeparatelyWithActualDockerPeers':True,'targetMetadataAbsentInThisFixture':True,
        'credentialFileReads':0,'applicationMacKeyReads':0,'runtimeAuthorityIssued':False,'targetApplyAuthorized':False}))

if __name__=='__main__':main()
