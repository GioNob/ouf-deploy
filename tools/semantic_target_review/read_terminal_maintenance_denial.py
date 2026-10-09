"""Exact consumed maintenance diagnosis. No writes, keys or lifecycle calls."""
import contextlib,fcntl,hashlib,io,json,os,re,stat,subprocess,sys,traceback
from pathlib import Path
EVIDENCE=Path('/etc/ouf/deploy-snapshots/semantic-terminal-task-cleanup-uoq_m_o7')
PACKAGE=EVIDENCE.parent/'semantic-provider-v2-transaction-source-ff13uh3n'
CONTEXT=EVIDENCE.parent/'semantic-provider-v2-approved-context-155oj3tc'
ROOT=EVIDENCE.parent/'semantic-provider-v2-transaction-155oj3tc'
WRAPPER=Path('/usr/local/sbin/ouf-semantic-admitted-v2')
WRAPPER_SHA='4bd86d0c27039a238ac4894cf0c151745c92814c94af7b5a2f2ed173b70d685a'
GATE_SHA='b30fb108a72f6aaa008789a6af8b9801ca23dce3dd5f6bd62eb799496cf07027'
APPROVAL='OUF_TERMINAL_TASK_CLEANUP_HUMAN_APPROVAL_20261009_152018'
A='f3d59af93fc90162681cee3a7562bdff3bf2af8c05cbdb7e270d1508fff18f67'
S='1fc5ae6a0db4600e0124bb1f9d2998780d533fd2b4de7cb086d8675b6afb5916'
CIDS=(S,A)
class Denied(RuntimeError):pass
def require(ok,reason):
    if not ok:raise Denied(reason)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def safe_failure(error):
    return str(error) if isinstance(error,Denied) else 'READ_ONLY_DIAGNOSIS_UNPROVEN'
PUBLIC_WORDS=frozenset('failed failure error unable cannot could did terminate successfully create start stop stopped delete deletion container containerd shim task runtime OCI runc process executable exit status code signal killed kill permission denied operation permitted invalid argument resource temporarily unavailable directory file exists found open read write log console mount network busy timeout deadline exceeded timed out context closed connection refused unexpected EOF JSON input unknown command option flag usage required root gate window maintenance force Python Traceback FileNotFoundError PermissionError OSError TypeError ValueError 1 2 126 127'.split())
GATE_REASONS=frozenset('ABSOLUTE_GATE_PATH_REQUIRED ROOT_GATE_ANCESTOR_REQUIRED ROOT_GATE_FILE_REQUIRED GATE_FILE_UNBOUNDED GATE_FILE_CHANGED BOUNDED_DELETE_ARGV_REQUIRED DUPLICATE_RUNTIME_OPTION EXACT_RUNTIME_OPTION_REQUIRED DELETE_ONLY_NO_FORCE_REQUIRED EXACT_TERMINAL_CID_REQUIRED EXACT_RETAINED_RUNTIME_ROOT_REQUIRED RUNC_JSON_LOG_FORMAT_REQUIRED BOUNDED_RUNC_INVENTORY_REQUIRED TERMINAL_RUNC_ABSENCE_REQUIRED EXACT_RECORDED_TASK_PID_REQUIRED TERMINAL_TASK_PID_ABSENCE_REQUIRED TERMINAL_RUNC_DIRECTORY_ABSENCE_REQUIRED ISOLATED_ROOT_GATE_REQUIRED EXACT_TWO_TASK_WINDOW_REQUIRED LIVE_TERMINAL_MAINTENANCE_WINDOW_REQUIRED EXPLICIT_MAINTENANCE_APPROVAL_REFERENCE_REQUIRED MAINTENANCE_RUNC_EXECUTABLE_DRIFT TERMINAL_RUNC_READ_FAILED MAINTENANCE_GATE_CUSTODY_DRIFT MAINTENANCE_WINDOW_EXPIRED EXACT_MAINTENANCE_GATE_CLI_REQUIRED TERMINAL_DELETE_UNPROVEN'.split())
def safe_text(raw):
    require(type(raw) is str and len(raw)<=65536,'BOUNDED_LOG_MESSAGE_REQUIRED')
    words=[]
    for token in raw.split():
        clean=token.strip('\"\'():,;[].')
        word=clean if '/' not in token and '\\' not in token and '=' not in token and clean in PUBLIC_WORDS else '<redacted>'
        if word!='<redacted>' or not words or words[-1]!=word:words.append(word)
    return {'sha256':sha(raw.encode()),'bytes':len(raw.encode()),'publicStructure':' '.join(words[:250]),
        'gateReasons':sorted(reason for reason in GATE_REASONS if re.search(r'(?<![A-Z0-9_])'+re.escape(reason)+r'(?![A-Z0-9_])',raw)),
        'rawLogPrinted':False}
def task_inventory(raw):
    rows={cid:{'present':False,'pid':None,'status':None} for cid in CIDS}
    for line in raw.decode().splitlines()[1:]:
        fields=line.split();require(len(fields)==3 and fields[1].isdigit(),'TASK_LIST_FORMAT_UNPROVEN')
        if fields[0] in rows:
            require(not rows[fields[0]]['present'],'DUPLICATE_TASK_ID_UNPROVEN')
            require(fields[2] in ('RUNNING','CREATED','STOPPED','PAUSED','PAUSING','UNKNOWN'),'TASK_STATUS_UNPROVEN')
            rows[fields[0]]={'present':True,'pid':int(fields[1]),'status':fields[2]}
    return rows
def retained_summary(result,claim):
    require(result['schema']=='ouf.semantic-terminal-task-cleanup.v1' and result['status']=='BLOCKED'
        and result['reason']=='TERMINAL_TASK_DELETE_UNPROVEN' and result['taskDeleteRequests']==1
        and result['doNotRerunApply'] is True and result['wrapperRestored'] is True,'EXACT_RETAINED_MAINTENANCE_DENIAL_REQUIRED')
    require(result['evidenceDirectory']==str(EVIDENCE) and result['dockerStartRequests']==0 and result['startAuthorized'] is False,'EXACT_RETAINED_MAINTENANCE_SCOPE_REQUIRED')
    require(claim['approvalRef']==APPROVAL and claim['approvedAt']==1791552018 and claim['evidenceDirectory']==str(EVIDENCE)
        and set(claim['tasks'])==set(CIDS),'EXACT_CONSUMED_MAINTENANCE_CLAIM_REQUIRED')
    return {k:result[k] for k in ('status','reason','phase','taskDeleteRequests','wrapperRestored','priorJournalsPreserved','containerLifecycleOperations','doNotRerunApply')}
def main():
    report={'schema':'ouf.semantic-terminal-maintenance-denial-read-only.v1','status':'BLOCKED','privateKeysRead':0,
        'signaturesIssued':0,'containerLifecycleOperations':0,'existingConfigurationWrites':0,'providerCalls':0,
        'privateValuesPrinted':False,'startAuthorized':False,'cleanupAuthorized':False,'doNotRerunApply':True,'notReleaseAcceptance':True}
    phase='VERIFY_EXACT_RETAINED_MAINTENANCE'
    try:
        require(os.geteuid()==0 and sys.flags.isolated and sys.dont_write_bytecode,'ISOLATED_ROOT_READER_REQUIRED')
        p=PACKAGE/'provider_transaction_intake.py';fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        try:raw=os.read(fd,131073)
        finally:os.close(fd)
        require(sha(raw)=='edc3c97d54a9d241c93ea9791f4dffce9984565763c2236ad1644e8b90c4c4b5','SEALED_ENTRY_HASH_DRIFT')
        entry={'__name__':'terminal_denial_entry','__file__':str(p)}
        with contextlib.redirect_stdout(io.StringIO()):exec(compile(raw,str(p),'exec'),entry);entry['load'](PACKAGE)
        read=entry['read'];parse=entry['parse']
        claim=parse(read(CONTEXT/'terminal-task-cleanup-claim.json'))
        result=parse(read(EVIDENCE/'maintenance-result.json'));report['retainedResult']=retained_summary(result,claim)
        previous=read(EVIDENCE/'prior-wrapper.sh');current=read(WRAPPER,True)
        require(sha(previous)==WRAPPER_SHA and current==previous,'RESTORED_WRAPPER_READBACK_REQUIRED')
        report['installedWrapperHash']=sha(current)
        deletion=parse(read(EVIDENCE/('task-delete-'+S+'.json')))
        require(deletion['containerId']==S and type(deletion['exitCode']) is int and deletion['exitCode']!=0
            and deletion['forceUsed'] is False,'EXACT_FIRST_DELETE_RESULT_REQUIRED')
        report['retainedDeleteResult']={k:deletion[k] for k in ('containerId','exitCode','stdoutHash','stderrHash','forceUsed','rawOutputPrinted')}
        report['secondDeleteResultPresent']=os.path.lexists(EVIDENCE/('task-delete-'+A+'.json'))
        window_raw=read(EVIDENCE/'window.json');window=parse(window_raw)
        require(sha(window_raw)==claim['windowHash'] and window['tasks']==claim['tasks']
            and window['approvalRef']==APPROVAL and window['expiresAt']-window['issuedAt']<=120,'EXACT_CONSUMED_WINDOW_REQUIRED')
        frozen=parse(read(EVIDENCE/'retained-file-hashes.json'));require(type(frozen) is dict and len(frozen)<=100,'BOUNDED_RETAINED_FILE_SET_REQUIRED')
        differences=[];unreadable=0
        for name,digest in frozen.items():
            p=Path(name);require(p.is_relative_to(ROOT) and '..' not in p.parts,'RETAINED_PATH_ESCAPE')
            try:
                if sha(read(p))!=digest:differences.append(sha(name.encode()))
            except (OSError,RuntimeError):unreadable+=1
        report['retainedFiles']={'count':len(frozen),'changedPathHashes':differences,'unreadableCount':unreadable,'allPreserved':not differences and unreadable==0}
        gate_raw=read(EVIDENCE/'gate.py');require(sha(gate_raw)==GATE_SHA,'EXACT_GATE_SOURCE_REQUIRED')
        gate={'__name__':'terminal_gate_custody_reader','__file__':str(EVIDENCE/'gate.py')};exec(compile(gate_raw,str(EVIDENCE/'gate.py'),'exec'),gate)
        phase='READ_GATE_CUSTODY_WITHOUT_ACKNOWLEDGING_DELETE'
        report['gateCustodyChecks']={}
        for name,path,executable in (('window',EVIDENCE/'window.json',False),('runc',window['runcBinding']['path'],True)):
            try:
                b=gate['private'](path,executable)
                report['gateCustodyChecks'][name]={'status':'PASS','sha256':sha(b)}
            except Exception as error:
                reason=str(error) if isinstance(error,gate['Denied']) and str(error) in GATE_REASONS else 'GATE_CUSTODY_READ_UNPROVEN'
                report['gateCustodyChecks'][name]={'status':'BLOCKED','reason':reason,'errorType':type(error).__name__}
        approval=parse(read(CONTEXT/'human-approval-binding.json'))
        cfg=parse(entry['bound']({'path':str(CONTEXT/'execution-configuration.json'),'sha256':approval['configurationHash']}))
        require(cfg['outputRoot']==str(ROOT),'EXACT_R5_CONTEXT_REQUIRED')
        from transaction_guard_observation import executable_binding,observe_locked
        from authenticate_provider_transaction import TARGETS
        ctr={'path':'/usr/bin/ctr','sha256':'8bb9bc5014e0f7623603d6a0dc1f7fedfe5b5a9ea5e265cc00dfbbae23ee984e'}
        executable_binding(ctr)
        def command(binary,args):
            return subprocess.run([binary,*args],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=10,
                env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'})
        phase='READ_CURRENT_TASKS_METADATA_AND_RUNC_ONLY'
        prefix=['--address','/run/containerd/containerd.sock','--namespace','moby']
        rows=command(ctr['path'],prefix+['tasks','list']);require(rows.returncode==0 and len(rows.stdout)<=131072,'TASK_READ_UNPROVEN')
        report['currentTasks']=task_inventory(rows.stdout)
        review=parse(read(EVIDENCE/'reviewed-terminal-facts.json'))
        report['containerMetadataPreserved']={}
        for cid in CIDS:
            info=command(ctr['path'],prefix+['containers','info',cid]);require(info.returncode==0 and len(info.stdout)<=131072,'CONTAINER_METADATA_READ_UNPROVEN')
            report['containerMetadataPreserved'][cid]=sha(info.stdout)==review['containerdRequestedTasks'][cid]['containerMetadataHash']
        runtime=window['runcBinding'];executable_binding(runtime)
        inventory=command(runtime['path'],['--root',window['runtimeRoot'],'list','--format','json'])
        require(inventory.returncode==0 and len(inventory.stdout)<=131072,'RUNC_LIST_READ_UNPROVEN')
        native=parse(inventory.stdout) or [];require(type(native) is list and len(native)<=1024,'BOUNDED_RUNC_INVENTORY_REQUIRED')
        report['runcEntryPresent']={cid:any(row.get('id')==cid for row in native) for cid in CIDS}
        report['recordedPidPresent']={cid:os.path.lexists('/proc/'+str(window['tasks'][cid]['pid'])) for cid in CIDS}
        executable_binding(ctr);executable_binding(runtime)
        phase='READ_BOUNDED_RETAINED_GATE_ERRORS'
        report['bundleLogs']={}
        for cid in CIDS:
            path=Path('/run/containerd/io.containerd.runtime.v2.task/moby')/cid/'log.json'
            try:
                b=read(path);require(len(b)<=131072,'BOUNDED_BUNDLE_LOG_REQUIRED')
                report['bundleLogs'][cid]={'status':'READ','summary':safe_text(b.decode(errors='replace')[:65536])}
            except FileNotFoundError:report['bundleLogs'][cid]={'status':'ABSENT'}
            except Exception as error:report['bundleLogs'][cid]={'status':'UNAVAILABLE','errorType':type(error).__name__}
        report['daemonJournal']={'status':'UNAVAILABLE','notEvidenceOfNoError':True}
        journal=Path('/usr/bin/journalctl')
        try:
            binary=read(journal,True);info=journal.stat();require(info.st_uid==0 and info.st_mode&0o111 and not info.st_mode&0o022,'ROOT_JOURNAL_READER_REQUIRED')
            logs=command(str(journal),['--since=@1791552018','--until=@1791552318','--no-pager','--output=json','--output-fields=MESSAGE,_COMM','--lines=500','_COMM=containerd','_COMM=dockerd','_COMM=containerd-shim'])
            require(logs.returncode==0 and len(logs.stdout)<=2097152,'BOUNDED_DAEMON_JOURNAL_UNPROVEN')
            selected=[];count=0
            for line in logs.stdout.splitlines():
                row=json.loads(line);count+=1;message=row.get('MESSAGE');comm=row.get('_COMM')
                if type(message) is not str or len(message)>65536:continue
                if not any(cid in message for cid in CIDS):continue
                require(comm in ('containerd','dockerd','containerd-shim'),'EXACT_DAEMON_LOG_OWNER_REQUIRED')
                selected.append({'daemon':comm,'containerIds':[cid for cid in CIDS if cid in message],'message':safe_text(message)})
            require(read(journal,True)==binary,'JOURNAL_EXECUTABLE_DRIFT')
            report['daemonJournal']={'status':'READ','scannedEntryCount':count,'limitReached':count==500,'matched':selected[:40],'matchedCount':len(selected),'rawLogPrinted':False}
        except Exception as error:report['daemonJournal']['errorType']=type(error).__name__
        phase='READ_CURRENT_NATIVE_EMPTY_GUARD'
        pointer=parse(entry['bound'](cfg['guardPointerBinding']));binding={'path':pointer['receiptFile'],'sha256':pointer['receiptHash']}
        owner_hash='656c23f18e3f3eb4c1ce630f5056be87f7883eab7b048065092dafbd018284a8'
        owner=parse(entry['bound']({'path':str(Path(binding['path']).parent/'coordinated-configuration.json'),'sha256':owner_hash}))
        fd=os.open(owner['commonLockFile'],os.O_RDWR|os.O_NOFOLLOW)
        try:
            fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            candidates={t['containerId']:{'imageManifestDigest':t['imageManifestDigest'],'runtimeName':'ouf-semantic-admitted-v2'} for t in TARGETS.values()}
            report['currentEmptyGuard']=observe_locked(fd,binding,owner_hash,candidates,cfg['commandBindings'])
        finally:os.close(fd)
        require(read(WRAPPER,True)==current and read(EVIDENCE/'window.json')==window_raw,'READ_ONLY_CUSTODY_DRIFT')
        report['status']='TERMINAL_MAINTENANCE_DENIAL_READBACK_CAPTURED'
    except Exception as error:
        report.update(errorType=type(error).__name__,reason=safe_failure(error),exceptionPoints=[{'file':Path(t.filename).name,'function':t.name,'line':t.lineno} for t in traceback.extract_tb(error.__traceback__)[-4:]])
    report['phase']=phase
    print('OUF_TERMINAL_MAINTENANCE_DENIAL_READ_ONLY='+json.dumps(report,sort_keys=True))
    return 0 if report['status']=='TERMINAL_MAINTENANCE_DENIAL_READBACK_CAPTURED' else 1
if __name__=='__main__':sys.exit(main())
