"""Exact consumed maintenance diagnosis. No writes, keys or lifecycle calls."""
import hashlib,json,os,re,shlex,stat,subprocess,sys,traceback
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
PUBLIC_WORDS=frozenset('a an the for from to of in on at with without and or not no is was are be been after before running reading retrieve retrieving such does exist failed failure error unable cannot could did terminate successfully create start stop stopped delete deletion container containerd shim task runtime OCI runc process executable exit status code signal killed kill permission denied operation permitted invalid argument resource temporarily unavailable directory file exists found open read write log console mount network busy timeout deadline exceeded timed out context closed connection refused unexpected EOF JSON input unknown command option flag usage required root gate window maintenance force Python Traceback FileNotFoundError PermissionError OSError TypeError ValueError 1 2 126 127'.split())
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

PHRASES=('unable to retrieve OCI runtime error','does not exist','no such file or directory','permission denied','operation not permitted','failed to delete task','failed rootfs umount','device or resource busy','exit status 1','exit status 2','unknown command','flag provided but not defined','failed to read','failed to open','cannot delete a running task','failed precondition','context deadline exceeded')
def error_fields(message):
    result={'wholeMessage':safe_text(message),'recognizedPhrases':[p for p in PHRASES if p.lower() in message.lower()]}
    try:tokens=shlex.split(message)
    except ValueError:tokens=[]
    for token in tokens:
        key,sep,value=token.partition('=')
        if sep and key in ('error','errorMessage','msg','desc') and len(value)<=65536:
            result[key]=safe_text(value)
    return result

def attributes(info):return tuple(getattr(info,k) for k in ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
def validate_log_info(info):
    require(stat.S_ISREG(info.st_mode) and info.st_uid==info.st_gid==0 and info.st_nlink==1
        and stat.S_IMODE(info.st_mode) in (0o600,0o640,0o644) and info.st_size<=131072,'BOUNDED_ROOT_LOG_FILE_REQUIRED')
def log_read(path):
    require(path in tuple(Path('/run/containerd/io.containerd.runtime.v2.task/moby')/cid/'log.json' for cid in CIDS),'EXACT_BUNDLE_LOG_PATH_REQUIRED')
    for parent in path.parents:
        info=parent.lstat();require(stat.S_ISDIR(info.st_mode) and info.st_uid==0 and not info.st_mode&0o022,'ROOT_LOG_ANCESTOR_REQUIRED')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        info=os.fstat(fd)
        validate_log_info(info)
        raw=os.read(fd,131073)
        require(len(raw)==info.st_size and attributes(info)==attributes(os.fstat(fd))==attributes(path.lstat()),'LOG_CHANGED_DURING_READ')
        return raw,{'mode':oct(stat.S_IMODE(info.st_mode)),'sha256':sha(raw),'bytes':len(raw)}
    finally:os.close(fd)
def json_log(raw):
    summaries=[];invalid=0
    for line in raw.splitlines():
        try:record=json.loads(line)
        except (ValueError,UnicodeError):invalid+=1;continue
        if type(record) is not dict:invalid+=1;continue
        msg=record.get('msg');level=record.get('level')
        if type(msg) is str and len(msg)<=65536 and level in ('error','fatal','panic'):
            item={'level':level,'message':error_fields(msg)}
            stamp=record.get('time')
            if type(stamp) is str and re.fullmatch(r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.]+(?:Z|[+-][0-9]{2}:[0-9]{2})',stamp):item['time']=stamp
            summaries.append(item)
    return {'errorRecords':summaries[-8:],'errorCount':len(summaries),'invalidLineCount':invalid,'rawLogPrinted':False}
def main():
    report={'schema':'ouf.semantic-terminal-maintenance-error-detail-read-only.v1','status':'BLOCKED','containerLifecycleOperations':0,'existingConfigurationWrites':0,'privateKeysRead':0,'signaturesIssued':0,'providerCalls':0,'startAuthorized':False,'cleanupAuthorized':False,'doNotRerunApply':True,'privateValuesPrinted':False,'notReleaseAcceptance':True}
    phase='VERIFY_EXACT_CONSUMED_DENIAL'
    try:
        require(os.geteuid()==0 and sys.flags.isolated and sys.dont_write_bytecode,'ISOLATED_ROOT_READER_REQUIRED')
        p=PACKAGE/'provider_transaction_intake.py';fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        try:raw=os.read(fd,131073)
        finally:os.close(fd)
        require(sha(raw)=='edc3c97d54a9d241c93ea9791f4dffce9984565763c2236ad1644e8b90c4c4b5','SEALED_ENTRY_HASH_DRIFT')
        entry={'__name__':'exact_terminal_log_reader','__file__':str(p)};exec(compile(raw,str(p),'exec'),entry)
        read=entry['read']
        result=json.loads(read(EVIDENCE/'maintenance-result.json'));claim=json.loads(read(CONTEXT/'terminal-task-cleanup-claim.json'))
        require(result['status']=='BLOCKED' and result['reason']=='TERMINAL_TASK_DELETE_UNPROVEN' and result['taskDeleteRequests']==1 and result['doNotRerunApply'] is True,'EXACT_CONSUMED_DENIAL_REQUIRED')
        require(claim['approvalRef']==APPROVAL and claim['evidenceDirectory']==str(EVIDENCE),'EXACT_CONSUMED_CLAIM_REQUIRED')
        wrapper=read(WRAPPER,True);require(sha(wrapper)==WRAPPER_SHA,'RESTORED_WRAPPER_REQUIRED')
        phase='READ_EXACT_ROOT_OWNED_BUNDLE_LOGS'
        report['bundleLogs']={}
        for cid in CIDS:
            path=Path('/run/containerd/io.containerd.runtime.v2.task/moby')/cid/'log.json'
            try:
                raw,metadata=log_read(path);report['bundleLogs'][cid]={'status':'READ',**metadata,**json_log(raw)}
            except FileNotFoundError:report['bundleLogs'][cid]={'status':'ABSENT'}
            except Exception as error:report['bundleLogs'][cid]={'status':'UNAVAILABLE','reason':safe_failure(error),'errorType':type(error).__name__}
        phase='READ_EXACT_RETAINED_DAEMON_ERROR'
        journal=Path('/usr/bin/journalctl');binary=read(journal,True)
        logs=subprocess.run([str(journal),'--since=@1791552018','--until=@1791552318','--no-pager','--output=json','--output-fields=MESSAGE,_COMM','--lines=500','_COMM=containerd','_COMM=dockerd','_COMM=containerd-shim'],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=10,env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'})
        require(logs.returncode==0 and len(logs.stdout)<=2097152,'BOUNDED_JOURNAL_READ_REQUIRED')
        matches=[]
        for line in logs.stdout.splitlines():
            row=json.loads(line);message=row.get('MESSAGE');comm=row.get('_COMM')
            if type(message) is not str or len(message)>65536 or not any(cid in message for cid in CIDS):continue
            require(comm in ('containerd','dockerd','containerd-shim'),'EXACT_DAEMON_LOG_OWNER_REQUIRED')
            matches.append({'daemon':comm,'containerIds':[cid for cid in CIDS if cid in message],'retainedJournalFingerprintMatches':sha(message.encode())=='10d5670b1354676be5b93b0d5baa2fd4da6e6c5933fa544a1caa162946ca34f3','detail':error_fields(message)})
        report['daemonErrors']=matches[:40]
        require(read(journal,True)==binary and read(WRAPPER,True)==wrapper,'READ_ONLY_CUSTODY_DRIFT')
        report['status']='TERMINAL_MAINTENANCE_ERROR_DETAIL_CAPTURED'
    except Exception as error:report.update(reason=safe_failure(error),errorType=type(error).__name__,exceptionPoints=[{'file':Path(t.filename).name,'function':t.name,'line':t.lineno} for t in traceback.extract_tb(error.__traceback__)[-4:]])
    report['phase']=phase
    print('OUF_TERMINAL_MAINTENANCE_ERROR_DETAIL_READ_ONLY='+json.dumps(report,sort_keys=True))
    return 0 if report['status']=='TERMINAL_MAINTENANCE_ERROR_DETAIL_CAPTURED' else 1
if __name__=='__main__':sys.exit(main())
