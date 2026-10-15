#!/usr/bin/env python3
"""Read retained finite-action status after terminal loss. No mutation/replay."""
import datetime,json,os,re,stat,subprocess,time
from pathlib import Path

PARENT=Path('/etc/ouf/deploy-snapshots')
UNIT=re.compile(r'ouf-file-cohort-[0-9a-f]{32}\.service')
CODE=re.compile(r'[A-Z][A-Z0-9_]{0,159}')
PROPERTIES=('Id','LoadState','ActiveState','SubState','Result','MainPID',
    'ExecMainCode','ExecMainStatus','ExecMainStartTimestamp','ExecMainExitTimestamp',
    'ActiveEnterTimestamp','InactiveEnterTimestamp','RuntimeMaxUSec','Restart','StandardOutput','StandardError')

def emit(check,**value):
    print(json.dumps({'schema':'ouf.chatbot-finite-action-readback.v1','check':check,
        'readOnly':True,'automaticRetry':False,'budgetReset':False,**value},sort_keys=True),flush=True)

def read_json(path,limit):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        info=os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or not 0<info.st_size<=limit:
            raise ValueError('BOUNDED_REGULAR_JSON_REQUIRED')
        raw=os.read(fd,limit+1)
        if len(raw)!=info.st_size:raise ValueError('JSON_CHANGED_DURING_READ')
        return json.loads(raw),info.st_mtime
    finally:os.close(fd)

def command(argv):
    result=subprocess.run(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,timeout=20,check=False,
        env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C','LC_ALL':'C'})
    if len(result.stdout)>8388608:raise ValueError('DIAGNOSTIC_OUTPUT_TOO_LARGE')
    return result.returncode,result.stdout.decode('utf-8',errors='replace')

def public_record(message):
    try:value=json.loads(message)
    except (ValueError,TypeError):
        marker='OUF_POLICY_TOKEN_OWNER_STATUS='
        if message.startswith(marker):
            try:value=json.loads(message[len(marker):])
            except ValueError:return None
            keys={'state','reason','attempts','publications','live','applicationReady','runtimeAuthorityIssued'}
            return {k:value[k] for k in keys if k in value} if type(value)is dict else None
        match=re.fullmatch(r'[A-Za-z_][A-Za-z0-9_.]*: ([A-Z][A-Z0-9_]{0,159})',message.strip())
        return {'safeExceptionCode':match.group(1)} if match else None
    if type(value)is dict:
        if value.get('schema')=='ouf.chatbot-file-cohort-delivery-status.v1':return value
        if value.get('schema')=='ouf.chatbot-file-cohort-child-exit.v1':
            return {k:value[k] for k in ('schema','phase','exceptionType','privateDiagnosticPrinted') if k in value}
    return None

def observe(context):
    emit('CONTEXT',path=str(context))
    review,_=read_json(context/'review.json',262144)
    unit=review['scopes']['finiteActionProcess']['unit']
    if not UNIT.fullmatch(unit):raise ValueError('EXACT_FINITE_UNIT_REQUIRED')
    emit('REVIEW_BINDING',unit=unit,sourceCommit=review['sourceClosure']['declaration']['sourceCommit'])
    try:
        decision,_=read_json(context/'decision.json',8192)
        expires=decision.get('expiresAt')
        emit('DECISION_TIME',approvedAt=decision.get('approvedAt'),expiresAt=expires,
            expiredAtRead=(expires<=time.time()) if type(expires)is int else None)
    except FileNotFoundError:emit('DECISION_TIME',present=False)
    rc,output=command(['/usr/bin/systemctl','show',unit,'--property='+','.join(PROPERTIES)])
    properties=dict(line.split('=',1) for line in output.splitlines() if '=' in line)
    emit('SYSTEMD',exitCode=rc,properties={k:properties[k] for k in PROPERTIES if k in properties})
    try:
        status,mtime=read_json(context/'delivery-status.json',8192)
        if type(status)is not dict or status.get('schema')!='ouf.chatbot-file-cohort-delivery-status.v1':
            raise ValueError('KNOWN_PUBLIC_STATUS_REQUIRED')
        emit('RETAINED_DELIVERY_STATUS',modifiedAt=mtime,ageSeconds=max(0,int(time.time()-mtime)),status=status)
    except FileNotFoundError:emit('RETAINED_DELIVERY_STATUS',present=False)
    rc,output=command(['/usr/bin/journalctl','--unit='+unit,'--no-pager','--lines=1000',
        '--output=json','--output-fields=MESSAGE,__REALTIME_TIMESTAMP'])
    records=[]
    for line in output.splitlines():
        try:event=json.loads(line)
        except ValueError:continue
        message=event.get('MESSAGE')
        if type(message)is not str or len(message)>16384:continue
        record=public_record(message)
        if record is not None:records.append({'timestampMicroseconds':event.get('__REALTIME_TIMESTAMP'),'record':record})
    emit('PUBLIC_JOURNAL',exitCode=rc,scannedMaximum=1000,matchingRecords=len(records),lastRecords=records[-20:],rawJournalPrinted=False)

def main():
    if os.geteuid()!=0:raise SystemExit('ROOT_READ_ACCESS_REQUIRED')
    emit('BEGIN',observedAt=datetime.datetime.now(datetime.timezone.utc).isoformat(),serviceMutations=0,databaseMutations=0)
    candidates=[]
    for path in PARENT.glob('chatbot-file-cohort-signed-*'):
        if re.fullmatch(r'chatbot-file-cohort-signed-[0-9a-f]{64}',path.name) and not path.is_symlink() and path.is_dir():
            candidates.append(path)
    selected=sorted(candidates,key=lambda p:p.stat().st_mtime,reverse=True)[:3]
    emit('SELECTED_CONTEXTS',total=len(candidates),selected=len(selected))
    for context in selected:
        try:observe(context)
        except Exception as error:
            reason=str(error)
            emit('CONTEXT_READ_ERROR',path=str(context),reason=reason if CODE.fullmatch(reason) else type(error).__name__)
    emit('END',serviceMutations=0,databaseMutations=0,runtimeAuthorityIssuedByReader=False,
        renewedAuthority=False,chatbotEndToEndProvenByReader=False)

if __name__=='__main__':main()
