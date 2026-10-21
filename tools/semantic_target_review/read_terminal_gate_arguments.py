"""Read exact retained shim options and evaluate pure gate predicates. No delete."""
import hashlib,json,os,stat,subprocess,sys,time,traceback
from pathlib import Path
EVIDENCE=Path('/etc/ouf/deploy-snapshots/semantic-terminal-task-cleanup-uoq_m_o7')
PACKAGE=EVIDENCE.parent/'semantic-provider-v2-transaction-source-ff13uh3n'
CONTEXT=EVIDENCE.parent/'semantic-provider-v2-approved-context-155oj3tc'
WRAPPER=Path('/usr/local/sbin/ouf-semantic-admitted-v2')
WRAPPER_SHA='4bd86d0c27039a238ac4894cf0c151745c92814c94af7b5a2f2ed173b70d685a'
GATE_SHA='b30fb108a72f6aaa008789a6af8b9801ca23dce3dd5f6bd62eb799496cf07027'
APPROVAL='OUF_TERMINAL_TASK_CLEANUP_HUMAN_APPROVAL_20261009_152018'
A='f3d59af93fc90162681cee3a7562bdff3bf2af8c05cbdb7e270d1508fff18f67'
S='1fc5ae6a0db4600e0124bb1f9d2998780d533fd2b4de7cb086d8675b6afb5916'
SHIMS={S:(1687756,187652001,'f2a0198b8e06603b3daa6530a927e41e11184fbdae125a1018d81fe9dab3eebf'),A:(1722469,188620013,'762364382f44d3e488899586852dac34e4e1c0118d91239a4d178ff9e75825b1')}
class Denied(RuntimeError):pass
def require(ok,reason):
    if not ok:raise Denied(reason)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def option(value,names):
    found=[value[name] for name in names if name in value]
    require(len(found)==1,'EXPLICIT_SINGLE_RUNC_OPTION_REQUIRED')
    return found[0]
def reconstruct(options,bundle,cid):
    require(type(options) is dict and len(options)<=32,'BOUNDED_RUNC_OPTIONS_REQUIRED')
    root=option(options,('root','Root'));binary=option(options,('binary_name','BinaryName','binaryName'))
    require(type(root) is str and Path(root).is_absolute() and '..' not in Path(root).parts,'EXPLICIT_RETAINED_RUNC_ROOT_REQUIRED')
    require(type(binary) is str and len(binary)<=4096,'EXPLICIT_RETAINED_RUNTIME_BINARY_REQUIRED')
    systemd=[options[k] for k in ('systemd_cgroup','SystemdCgroup','systemdCgroup') if k in options]
    require(len(systemd)<=1 and all(type(v) is bool for v in systemd),'BOUNDED_SYSTEMD_CGROUP_OPTION_REQUIRED')
    # containerd v2.3.5 process.NewRunc: filepath.Join(options.Root, namespace).
    supplied=str(Path(root)/'moby')
    args=['--root',supplied,'--log',str(bundle/'log.json'),'--log-format','json']
    if systemd and systemd[0]:args.append('--systemd-cgroup')
    return binary,supplied,args+['delete',cid]
def root_projection(supplied,expected):
    canonical=str(Path(supplied).resolve(strict=True))
    return {'suppliedRootHash':sha(supplied.encode()),'retainedRootHash':sha(expected.encode()),
        'canonicalSuppliedRootHash':sha(canonical.encode()),'lexicallyEqual':supplied==expected,'canonicallyEqual':canonical==expected}
def main():
    report={'schema':'ouf.semantic-terminal-gate-arguments-read-only.v1','status':'BLOCKED','privateKeysRead':0,'signaturesIssued':0,
        'containerLifecycleOperations':0,'existingConfigurationWrites':0,'providerCalls':0,'privateValuesPrinted':False,
        'startAuthorized':False,'cleanupAuthorized':False,'doNotRerunApply':True,'notReleaseAcceptance':True,
        'argumentSource':'RETAINED_OPTIONS_AND_CONTAINERD_V2_3_5_NEW_RUNC_SOURCE','historicalArgvCaptured':False,'gateAcknowledgementInvoked':False}
    phase='VERIFY_EXACT_CONSUMED_DENIAL_AND_GATE'
    try:
        require(os.geteuid()==0 and sys.flags.isolated and sys.dont_write_bytecode,'ISOLATED_ROOT_READER_REQUIRED')
        p=PACKAGE/'provider_transaction_intake.py';fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        try:raw=os.read(fd,131073)
        finally:os.close(fd)
        require(sha(raw)=='edc3c97d54a9d241c93ea9791f4dffce9984565763c2236ad1644e8b90c4c4b5','SEALED_ENTRY_HASH_DRIFT')
        entry={'__name__':'terminal_argument_reader','__file__':str(p)};exec(compile(raw,str(p),'exec'),entry);read=entry['read']
        claim=json.loads(read(CONTEXT/'terminal-task-cleanup-claim.json'));result=json.loads(read(EVIDENCE/'maintenance-result.json'))
        require(claim['approvalRef']==APPROVAL and claim['evidenceDirectory']==str(EVIDENCE) and claim['approvedAt']==1791552018,'EXACT_CONSUMED_CLAIM_REQUIRED')
        require(result['reason']=='TERMINAL_TASK_DELETE_UNPROVEN' and result['taskDeleteRequests']==1 and result['doNotRerunApply'] is True,'EXACT_CONSUMED_DENIAL_REQUIRED')
        wrapper=read(WRAPPER,True);require(sha(wrapper)==WRAPPER_SHA,'RESTORED_WRAPPER_REQUIRED')
        raw=read(EVIDENCE/'gate.py');require(sha(raw)==GATE_SHA,'EXACT_RETAINED_GATE_REQUIRED')
        gate={'__name__':'gate_pure_predicate_reader','__file__':str(EVIDENCE/'gate.py')};exec(compile(raw,gate['__file__'],'exec'),gate)
        window_raw=read(EVIDENCE/'window.json');window=json.loads(window_raw)
        require(sha(window_raw)==claim['windowHash'] and window['tasks']==claim['tasks'] and window['approvalRef']==APPROVAL,'EXACT_RETAINED_WINDOW_REQUIRED')
        report['retainedWindow']={'issuedAt':window['issuedAt'],'expiresAt':window['expiresAt'],'durationSeconds':window['expiresAt']-window['issuedAt'],
            'expiredNow':time.time()>=window['expiresAt'],'clockChanged':False,'expirationNotAttributedToOriginalAttempt':True}
        phase='READ_PERSISTED_SHIM_OPTIONS_AND_GENERATION'
        report['roles']={};frozen={}
        for cid,(pid,ticks,argv_hash) in SHIMS.items():
            bundle=Path('/run/containerd/io.containerd.runtime.v2.task/moby')/cid
            proc=Path('/proc')/str(pid);stat_raw=(proc/'stat').read_bytes();tail=stat_raw[stat_raw.rfind(b')')+2:].split()
            require(int(tail[19])==ticks and sha((proc/'cmdline').read_bytes())==argv_hash
                and os.readlink(proc/'cwd')==str(bundle),'EXACT_RETAINED_SHIM_GENERATION_REQUIRED')
            raw=read(bundle/'options.json');frozen[str(bundle/'options.json')]=raw
            options=json.loads(raw);binary,supplied,argv=reconstruct(options,bundle,cid)
            runtime_raw=read(bundle/'runtime');frozen[str(bundle/'runtime')]=runtime_raw
            require(runtime_raw.decode()==binary,'PERSISTED_RUNTIME_AND_OPTIONS_MISMATCH')
            summary={'shimGenerationMatches':True,'optionsHash':sha(raw),'runtimeBinaryHash':sha(binary.encode()),
                'runtimeBinaryIsReviewedWrapper':binary==str(WRAPPER),'rootComparison':root_projection(supplied,window['runtimeRoot']),
                'rootArgumentHash':sha(supplied.encode()),'argvHash':sha(json.dumps(argv,separators=(',',':')).encode()),'argvPrinted':False}
            try:
                gate['parse_delete'](argv,window['tasks'],window['runtimeRoot']);summary['pureArgvGate']={'status':'PASS'}
            except gate['Denied'] as error:summary['pureArgvGate']={'status':'BLOCKED','reason':str(error)}
            report['roles'][cid]=summary
        phase='READ_RUNC_LIST_AND_PURE_ABSENCE_PREDICATE'
        runtime=window['runcBinding'];binary=gate['private'](runtime['path'],True)
        require(sha(binary)==runtime['sha256'],'EXACT_RETAINED_RUNC_BINARY_REQUIRED')
        rows=subprocess.run([runtime['path'],'--root',window['runtimeRoot'],'list','--format','json'],stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=10,env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'})
        require(rows.returncode==0 and len(rows.stdout)<=131072,'BOUNDED_RUNC_LIST_REQUIRED')
        try:
            gate['absent'](window,json.loads(rows.stdout));report['pureAbsenceGate']={'status':'PASS'}
        except gate['Denied'] as error:report['pureAbsenceGate']={'status':'BLOCKED','reason':str(error)}
        require(read(WRAPPER,True)==wrapper and read(EVIDENCE/'window.json')==window_raw
            and all(read(path)==raw for path,raw in frozen.items()),'READ_ONLY_CUSTODY_DRIFT')
        report['status']='TERMINAL_GATE_ARGUMENTS_CAPTURED'
    except Exception as error:report.update(reason=str(error) if isinstance(error,Denied) else 'ARGUMENT_READ_UNPROVEN',errorType=type(error).__name__,exceptionPoints=[{'file':Path(t.filename).name,'function':t.name,'line':t.lineno} for t in traceback.extract_tb(error.__traceback__)[-4:]])
    report['phase']=phase
    print('OUF_TERMINAL_GATE_ARGUMENTS_READ_ONLY='+json.dumps(report,sort_keys=True))
    return 0 if report['status']=='TERMINAL_GATE_ARGUMENTS_CAPTURED' else 1
if __name__=='__main__':sys.exit(main())
