"""Fresh root-private R9/peer read only; no keys, locks, DNS, grants or replay.
The sealed original cutover reader is executed only from verified memory bytes.
"""
import hashlib, json, math, os, re, subprocess, sys, types
from pathlib import Path

READER_HASH='b9ea8aa1a8cf31d28dfa1df0960dcf6930880d11244fe1f84e710bfe0b9ec4cf'
ROOT=Path('/etc/ouf/deploy-snapshots/semantic-dns-recovery-r9-hkv5exgo')
CLAIM=Path('/etc/ouf/provider-dns-window-recovery-r9.claim')
UNIT='ouf-semantic-provider-lease-dns-r9.service'
APPROVAL='OUF_DNS_WINDOW_RECOVERY_R9_APPROVED_20261010T075611_CEST'
PROGRAMS={'activate.py':'6183733f02d3a5e633deac8c07924276df8b6a5cbaa57494be289808c3aaf244',
 'activation_core.py':'3ea3c575da5a61b153294a10abf810811d846f04b64bd12d9a2b8dd5380879aa',
 'reader.py':READER_HASH,'materialize_southbound_lease_refresh.py':'c3160940cf79678cb8e44c036cb0d947016f885ab09acfe6cce571833db5b079',
 'dns.py':'f1491cca148c488bbee8089dabcada0361781962d7b2858ad2fc4549cea3696f'}
PROPERTIES=('LoadState','ActiveState','SubState','MainPID','InvocationID','ExecMainCode','ExecMainStatus','NRestarts','Restart','Transient','Result','ExecMainStartTimestamp','ExecMainExitTimestamp','ExecStart')

def require(ok,reason):
    if not ok:raise ValueError(reason)
def sha(raw):return hashlib.sha256(raw).hexdigest()

def load_reader(raw):
    require(type(raw) is bytes and len(raw)<=131072 and sha(raw)==READER_HASH,'PINNED_READ_ONLY_SOURCE_REQUIRED')
    module=types.ModuleType('ouf_transition_read_only_source');module.__file__='sealed-original-cutover-reader.py'
    exec(compile(raw,module.__file__,'exec'),module.__dict__)
    return module

def project_worker(status,unit,lease):
    require(type(status) is dict and status.get('schema')=='ouf.provider-lease-worker-status.v1','EXACT_R9_WORKER_RECORD_REQUIRED')
    safe={key:unit.get(key,'') for key in PROPERTIES if key!='ExecStart'}
    matches=str(ROOT/'activate.py') in unit.get('ExecStart','')
    pid=unit.get('MainPID','')
    same_pid=type(pid) is str and pid.isdecimal() and int(pid)>1 and int(pid)==status.get('workerPid')
    live=unit.get('ActiveState')=='active' and unit.get('SubState')=='running' and matches and same_pid
    membership=lease.get('journalAndMembershipConsistent') is True and lease.get('leaseAuthorized') is True and lease.get('journalState')=='LEASE_READY' and lease.get('providerSetsEmpty') is False
    safe_status={key:status[key] for key in ('schema','status','phase','refreshCount','workerPid','flowAddressCounts','leaseAuthorized','setsRevoked','doNotRerunApply') if key in status}
    errors=[]
    for row in status.get('exceptionChain',[])[:6]:
        reason=row.get('reason','')
        kind=row.get('errorType','')
        item={'errorType':kind if type(kind) is str and re.fullmatch('[A-Za-z][A-Za-z0-9_]{0,63}',kind) else 'UnprovenError',
              'reason':reason if type(reason) is str and re.fullmatch('[A-Z][A-Z0-9_]{0,120}',reason) else 'REDACTED_UNBOUNDED_REASON'}
        window=row.get('dnsObservationWindow')
        if type(window) is dict and set(window)=={'minimumObservedTtlSeconds','elapsedSeconds','ttlNoncacheable','freshObservationAttempts'}:
            ttl,elapsed,noncacheable,attempts=(window[k] for k in ('minimumObservedTtlSeconds','elapsedSeconds','ttlNoncacheable','freshObservationAttempts'))
            if type(ttl) is int and 0<=ttl<2**31 and type(elapsed) in (int,float) and math.isfinite(elapsed) and 0<=elapsed<=30 and type(noncacheable) is bool and noncacheable==(ttl==0) and type(attempts) is int and 1<=attempts<=3:
                item['dnsObservationWindow']=window
        errors.append(item)
    return {'worker':safe_status,'exceptionChain':errors,'service':safe,'execStartMatchesR9Snapshot':matches,'sameLiveWorkerPid':same_pid,
            'r9WorkerAndLeaseActiveAtStableObservation':live and membership and status.get('status')=='LEASE_ACTIVE',
            'notContinuousLivenessProof':True,'applicationHealthProven':False,'executionWindowIsStartupGate':True,'consumedR9ReplayAllowed':False}

def service(reader,binding):
    raw=reader.private(binding['path'],binding['sha256'],executable=True)
    argv=[binding['path'],'show',UNIT,'--no-pager','--property='+','.join(PROPERTIES)]
    result=subprocess.run(argv,capture_output=True,timeout=5,env={'PATH':'/usr/bin:/bin','LANG':'C','LC_ALL':'C'})
    require(result.returncode in (0,1,4) and len(result.stdout)<=65536 and len(result.stderr)<=65536,'BOUNDED_SYSTEMD_METADATA_READ_REQUIRED')
    require(reader.private(binding['path'],binding['sha256'],executable=True)==raw,'SYSTEMCTL_COMMAND_BYTES_CHANGED')
    values=dict(line.split('=',1) for line in result.stdout.decode().splitlines() if '=' in line)
    require(set(values)<=set(PROPERTIES) and values.get('LoadState') in ('loaded','not-found'),'EXACT_SYSTEMD_UNIT_METADATA_REQUIRED')
    return values

def collect(reader):
    cutover=reader.collect_cutover()
    cfg=reader.parse(reader.SAVED[str(reader.CONTEXT/'execution-configuration.json')])
    claim_raw=reader.private(CLAIM);claim=reader.parse(claim_raw)
    require(claim.get('schema')=='ouf.provider-dns-recovery-activation-claim.v1' and claim.get('approvalRef')==APPROVAL and claim.get('directory')==str(ROOT) and claim.get('startAuthorized') is False,'EXACT_CONSUMED_R9_CLAIM_REQUIRED')
    authorization_raw=reader.private(ROOT/'authorization.json');authorization=reader.parse(authorization_raw)
    require(authorization.get('schema')=='ouf.provider-dns-recovery-authorization.v1' and authorization.get('approvalRef')==APPROVAL
        and authorization.get('ownerConfigurationHash')==reader.OWNER_HASH and authorization.get('serviceUnit')==UNIT
        and authorization.get('programHashes')==PROGRAMS and authorization.get('automaticRestart') is False
        and authorization.get('enableAtBoot') is False and authorization.get('containerLifecycleAuthorized') is False,'SEALED_R9_AUTHORIZATION_SCOPE_DRIFT')
    programs={name:reader.private(ROOT/name,expected) for name,expected in PROGRAMS.items()}
    receipt_raw=reader.private(ROOT/'activation-receipt.json');receipt=reader.parse(receipt_raw)
    require(receipt.get('status')=='TWO_FLOW_LEASE_ACTIVE_AND_RENEWED' and receipt.get('serviceUnit')==UNIT and receipt.get('doNotRerunApply') is True,'RETAINED_ACTIVATION_RECEIPT_REQUIRED')
    status_raw=reader.private(ROOT/'worker-status.json');status=reader.parse(status_raw)
    before=service(reader,cfg['commandBindings']['systemctl'])
    result=project_worker(status,before,cutover['lease'])
    after=service(reader,cfg['commandBindings']['systemctl'])
    require(before==after and reader.private(ROOT/'worker-status.json')==status_raw,'WORKER_OR_SERVICE_CHANGED_DURING_READ_RETRY_SAFE')
    require(reader.private(CLAIM)==claim_raw and reader.private(ROOT/'authorization.json')==authorization_raw and reader.private(ROOT/'activation-receipt.json')==receipt_raw,'R9_IMMUTABLE_CUSTODY_CHANGED')
    for name,expected in PROGRAMS.items():require(reader.private(ROOT/name,expected)==programs[name],'R9_PROGRAM_BYTES_CHANGED')
    return {'cutover':cutover,'r9':result,'authorizationHash':sha(authorization_raw),'claimHash':sha(claim_raw),'activationReceiptHash':sha(receipt_raw),'workerStatusHash':sha(status_raw),'programClosureVerified':True}

def main():
    base={'schema':'ouf.discovery.current-r9-transition-read.v1','applyAuthorized':False,'existingConfigurationWrites':0,'firewallWrites':0,'databaseWrites':0,'containerLifecycleOperations':0,
          'privateKeysRead':0,'privateValuesPrinted':False,'signaturesIssued':0,'providerCalls':0,'dnsQueries':0,'commonLockAcquired':False,'readOnlyRetrySafe':True,'notReleaseAcceptance':True,
          'readConsistencyMode':'STABLE_REREADS_NOT_ATOMIC_TRANSITION_AUTHORITY'}
    try:
        require(os.geteuid()==0 and sys.flags.isolated and sys.dont_write_bytecode and len(sys.argv)==1,'ISOLATED_ROOT_READ_ONLY_REQUIRED')
        result={**base,**collect(load_reader(globals().get('__reader_source_bytes__'))),'status':'CURRENT_R9_TRANSITION_BINDINGS_CAPTURED'}
        code=0
    except Exception as error:
        result={**base,'status':'READ_BLOCKED','errorType':type(error).__name__,'reason':str(error) if re.fullmatch('[A-Z][A-Z0-9_]{0,120}',str(error)) else 'CURRENT_TRANSITION_INPUT_UNPROVEN'};code=1
    print('OUF_CURRENT_R9_TRANSITION_READ='+json.dumps(result,sort_keys=True));return code

if __name__=='__main__':raise SystemExit(main())
