#!/usr/bin/env python3
"""One bounded historical stop-window read; no restart, credentials or authority.

Installation-specific diagnosis of the Registry/UDP stop on 18 October.
Only timestamps and closed classifications leave this process, never messages.
"""
import collections,datetime,hashlib,json,os,re,selectors,signal,stat,subprocess,sys,time
from pathlib import Path

SCHEMA='ouf.semantic-stop-journal-observation.v1'
REGISTRY='790c62742c92eabc095d4ab22f2070e0c40a41e4a219685a7d8120e4661e4e5d'
SINCE='2026-10-18 08:07:50 UTC'
UNTIL='2026-10-18 08:11:50 UTC'
MAX_BYTES=4194304
MAX_ROWS=2000
UNITS=('docker.service','containerd.service','systemd-journald.service','systemd-reboot.service','systemd-poweroff.service')

class Stop(Exception):pass
def require(ok,reason):
    if not ok:raise Stop(reason)

def executable():
    p=Path('/usr/bin/journalctl').resolve(strict=True)
    for directory in p.parents:
        s=directory.lstat()
        require(stat.S_ISDIR(s.st_mode) and s.st_uid==0 and not s.st_mode&0o022,'JOURNAL_PROGRAM_ANCESTRY_UNPROVEN')
    fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        s=os.fstat(fd)
        require(stat.S_ISREG(s.st_mode) and s.st_uid==0 and not s.st_mode&0o022 and s.st_mode&0o111
                and 0<s.st_size<=16777216,'ROOT_CONTROLLED_JOURNAL_PROGRAM_REQUIRED')
        digest=hashlib.sha256();total=0
        while block:=os.read(fd,65536):
            total+=len(block);require(total<=16777216,'JOURNAL_PROGRAM_SIZE_LIMIT');digest.update(block)
        pin=lambda i:(i.st_dev,i.st_ino,i.st_size,i.st_mtime_ns,i.st_ctime_ns)
        require(total==s.st_size and pin(s)==pin(os.fstat(fd))==pin(p.stat()),'JOURNAL_PROGRAM_CHANGED')
        return str(p),digest.hexdigest()
    finally:os.close(fd)

def journal():
    program,before=executable()
    args=[program,'--no-pager','--output=json','--all','--lines='+str(MAX_ROWS),'--since='+SINCE,'--until='+UNTIL]
    for unit in UNITS:args+=['--unit='+unit]
    child=subprocess.Popen(args,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,
                           env={'LC_ALL':'C'},close_fds=True,cwd='/')
    raw=bytearray();deadline=time.monotonic()+12
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(child.stdout,selectors.EVENT_READ)
            while selector.get_map():
                require(time.monotonic()<deadline,'JOURNAL_READ_DEADLINE')
                for key,_ in selector.select(min(.2,max(0,deadline-time.monotonic()))):
                    block=os.read(key.fd,65536)
                    if not block:selector.unregister(key.fileobj);continue
                    raw.extend(block);require(len(raw)<=MAX_BYTES,'JOURNAL_BYTE_LIMIT')
        require(child.wait(timeout=max(.01,deadline-time.monotonic()))==0,'JOURNAL_READ_FAILED')
        require(executable()==(program,before),'JOURNAL_PROGRAM_CHANGED')
        return bytes(raw)
    finally:
        if child.poll() is None:child.kill()
        child.wait(timeout=2);child.stdout.close()

def classify(raw):
    require(type(raw) is bytes and len(raw)<=MAX_BYTES,'JOURNAL_BYTE_LIMIT')
    lines=raw.splitlines();require(len(lines)<MAX_ROWS,'JOURNAL_SELECTION_LIMIT_REACHED')
    counts=collections.Counter();events=[];boots=set()
    for line in lines:
        require(len(line)<=262144,'JOURNAL_RECORD_LIMIT')
        row=json.loads(line);require(type(row) is dict,'JOURNAL_OBJECT_REQUIRED')
        message=row.get('MESSAGE');require(type(message) is str,'TEXT_JOURNAL_MESSAGE_REQUIRED')
        unit=row.get('UNIT',row.get('_SYSTEMD_UNIT',''))
        if type(unit) is not str:unit=''
        text=message.lower();categories=[]
        if 'processing signal' in text and ('terminated' in text or 'sigterm' in text):categories.append('DOCKER_TERMINATION_REQUEST')
        if 'daemon shutdown complete' in text:categories.append('DOCKER_SHUTDOWN_COMPLETE')
        if unit=='docker.service' and ('stopping docker' in text or 'docker.service: deactivating' in text):categories.append('DOCKER_UNIT_STOPPING')
        if unit=='docker.service' and ('stopped docker' in text or 'docker.service: deactivated successfully' in text):categories.append('DOCKER_UNIT_STOPPED')
        if unit=='containerd.service' and ('stopping' in text or 'stopped' in text):categories.append('CONTAINERD_STOP')
        if unit in ('systemd-reboot.service','systemd-poweroff.service'):categories.append('HOST_SHUTDOWN_SERVICE')
        if REGISTRY in message:categories.append('EXACT_REGISTRY_ID_MENTIONED')
        if not categories:continue
        timestamp=row.get('__REALTIME_TIMESTAMP','');require(type(timestamp) is str and re.fullmatch('[0-9]{1,20}',timestamp),
                                                           'JOURNAL_TIMESTAMP_REQUIRED')
        instant=datetime.datetime.fromtimestamp(int(timestamp)/1000000,datetime.timezone.utc)
        require(datetime.datetime(2026,10,18,8,7,50,tzinfo=datetime.timezone.utc)<=instant
                <=datetime.datetime(2026,10,18,8,11,50,tzinfo=datetime.timezone.utc),'JOURNAL_EVENT_OUTSIDE_SELECTED_WINDOW')
        boot=row.get('_BOOT_ID','')
        if type(boot) is str and re.fullmatch('[a-f0-9]{32}',boot):boots.add(boot)
        for category in categories:
            counts[category]+=1
            if len(events)<40:events.append({'timeUtc':instant.isoformat().replace('+00:00','Z'),'classification':category})
    corroborated=bool(counts['DOCKER_TERMINATION_REQUEST'] and counts['DOCKER_SHUTDOWN_COMPLETE'])
    return {'schema':SCHEMA,'status':'STOP_WINDOW_JOURNAL_OBSERVED','complete':True,
        'finding':'DOCKER_SHUTDOWN_CORROBORATED_IN_REGISTRY_STOP_WINDOW' if corroborated else 'STOP_CAUSE_NOT_ESTABLISHED_BY_SELECTED_JOURNAL',
        'sinceUtc':'2026-10-18T08:07:50Z','untilUtc':'2026-10-18T08:11:50Z',
        'journalRowsRead':len(lines),'journalBytesRead':len(raw),'classifications':dict(sorted(counts.items())),
        'selectedEvents':events,'selectedEventsMayBeTruncated':sum(counts.values())>40,'observedBootCount':len(boots),
        'exactRegistryIdMentionObserved':bool(counts['EXACT_REGISTRY_ID_MENTIONED']),
        'temporalCorrelationIsNotProofOfStoppingActor':True,'absenceOfMatchIsNotProofOfHealth':True,
        'readOnly':True,'engineGets':0,'oauthRequests':0,'databaseCalls':0,'credentialFilesOpened':0,
        'rawLinesPrinted':False,'addressesPrinted':False,'runtimeEffectsDispatched':0,
        'runtimeAuthorityIssued':False,'activationResubmitted':False,'automaticReplayAllowed':False,
        'budgetReset':False,'rootCauseEstablished':False,'releaseAcceptance':False}

if __name__=='__main__':
    try:
        require(os.geteuid()==0 and sys.flags.isolated and len(sys.argv)==1,'ROOT_ISOLATED_NO_ARGUMENT_READER_REQUIRED')
        signal.signal(signal.SIGALRM,lambda *_:(_ for _ in ()).throw(Stop('JOURNAL_DIAGNOSTIC_DEADLINE')));signal.alarm(25)
        print(json.dumps(classify(journal()),sort_keys=True),flush=True)
    except Exception as error:
        code=str(error) if type(error) is Stop else 'JOURNAL_UNCONFIRMED_'+type(error).__name__
        require(re.fullmatch('[A-Z][A-Z0-9_]{0,127}',code),'INVALID_DIAGNOSTIC_CODE')
        print(json.dumps({'schema':SCHEMA,'status':'STOP_RECONCILE','reasonCode':code,'readOnly':True,
            'runtimeEffectsDispatched':0,'runtimeAuthorityIssued':False,'activationResubmitted':False,
            'automaticReplayAllowed':False,'budgetReset':False},sort_keys=True),flush=True)
        sys.exit(1)
