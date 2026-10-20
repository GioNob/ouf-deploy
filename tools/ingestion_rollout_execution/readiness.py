"""Generation-bound Ingestion readiness over its selected local namespace.

Only a reviewed loopback endpoint and the fixed Spring readiness API are used.
Actual candidate frame/CID/first process is checked around each sealed child.
No auth, SQL, source activation or mutation is performed by this component.
"""
import base64
import copy
import ipaddress
import json
import os
import subprocess
import time
import iam_governance_intake as governance
from tools.ingestion_rollout_execution.contract import AUTHORITY_KEY,require,scope,digest,path,hashed
from tools.ingestion_rollout_execution.lifecycle import NativeLifecycle
from tools.ingestion_rollout_execution.namespace import identity
from tools.ingestion_rollout_execution.engine_channel import after_reads
from tools.chat_recovery_update.readiness import classify
MAX_GETS=128
CHILD_SOURCE=r'''import base64,http.client,ipaddress,json,os,re,signal,sys
signal.alarm(12)
try:
    v=json.loads(sys.stdin.buffer.read(4097))
    if type(v)is not dict or set(v)!={'host','port'}:raise ValueError()
    if type(v['host'])is not str or not ipaddress.ip_address(v['host']).is_loopback:raise ValueError()
    if type(v['port'])is not int or not 1<=v['port']<=65535:raise ValueError()
    if len(sys.argv)!=2 or not re.fullmatch('[0-9]{1,10}',sys.argv[1]):raise ValueError()
    fd=int(sys.argv[1]);os.setns(fd,0);os.close(fd)
    client=http.client.HTTPConnection(v['host'],v['port'],timeout=5)
    try:
        client.request('GET','/actuator/health/readiness',headers={'Accept':'application/json','Connection':'close'})
        reply=client.getresponse();body=reply.read(65537);status=reply.status;retry=reply.getheader('Retry-After')
        if len(body)>65536 or(retry is not None and(len(retry)>128 or any(ord(c)<32 or ord(c)>126 for c in retry))):raise ValueError()
    except (OSError,http.client.HTTPException):
        status,body,retry=503,b'',None
    finally:client.close()
    output=json.dumps({'status':status,'bodyBase64':base64.b64encode(body).decode('ascii'),'retryAfter':retry},
        sort_keys=True,separators=(',',':'),allow_nan=False).encode()
    if len(output)>90000:raise ValueError()
    sys.stdout.buffer.write(output);sys.stdout.buffer.flush()
except BaseException:
    os._exit(1)
os._exit(0)
'''

def validate_profile(p):
    require(type(p)is dict and set(p)=={'schema','endpoint','pythonExecutable'}
            and p['schema']=='ouf.ingestion-rollout-ingestion-readiness-local-ns.v1',
            'EXACT_INGESTION_READINESS_PROFILE_REQUIRED')
    endpoint=p['endpoint']
    require(type(endpoint)is dict and set(endpoint)=={'host','port'}and type(endpoint['host'])is str
            and type(endpoint['port'])is int and 1<=endpoint['port']<=65535,'EXPLICIT_INGESTION_READINESS_ENDPOINT_REQUIRED')
    try:loopback=ipaddress.ip_address(endpoint['host']).is_loopback
    except ValueError:loopback=False
    require(loopback,'INGESTION_NAMESPACE_LOOPBACK_ONLY')
    program=p['pythonExecutable']
    require(type(program)is dict and set(program)=={'path','sha256'}and path(program['path'])and hashed(program['sha256']),
            'EXACT_READINESS_NAMESPACE_PROGRAM_REQUIRED')
    return p

class NativeIngestionReadiness:
    def __init__(self,lifecycle):
        require(type(lifecycle)is NativeLifecycle,'CONCRETE_SIGNED_LIFECYCLE_REQUIRED_FOR_READINESS')
        self.lifecycle=lifecycle;self.review=copy.deepcopy(lifecycle.review);self.scope=scope(self.review)
        self.profile=copy.deepcopy(self.review.get('ingestionReadinessProfile'));validate_profile(self.profile)
        require(self.review.get('maximumIngestionReadinessGets')==MAX_GETS,'FINITE_SIGNED_INGESTION_READINESS_BUDGET_REQUIRED')
    def guard(self):
        native=self.lifecycle
        require(scope(self.review)==self.scope and self.profile==native.review['ingestionReadinessProfile'],
                'READINESS_REVIEW_DRIFT')
        native.action.guard(AUTHORITY_KEY,self.scope)
        require(native.human.current()==self.scope['humanBinding'],'SAME_CURRENT_AUTHENTICATED_HUMAN_REQUIRED')
        row=native.journal.read();count=row.get('nativeIngestionReadinessGets',0)
        require(row.get('scopeHash')==digest(self.scope)and row.get('authorityHash')==native.action.authority_hash
                and row.get('budgetReset')is False and type(count)is int and 0<=count<=MAX_GETS,
                'PERSISTENT_INGESTION_READINESS_BUDGET_REQUIRED')
        start=native.process('ingestion');require(start is not None,'DURABLE_FIRST_INGESTION_PROCESS_REQUIRED')
        restored=any(e['stage']=='ingestion.RESTORE_RESTART'and e['state']=='APPLIED'for e in row['effects'])
        actual,_=native.replacement('ingestion',phase='RUNNING',process=start,restored=restored)
        program=self.profile['pythonExecutable']
        require(program==governance.executable(program['path']),'READINESS_PROGRAM_CHANGED')
        return after_reads(native.journal,row),actual
    def observe(self):
        row,actual=self.guard();count=row.get('nativeIngestionReadinessGets',0)
        require(count<MAX_GETS,'CUMULATIVE_INGESTION_READINESS_BUDGET_EXHAUSTED')
        require(min(row['expiresAt']-time.time(),row['expiresMonotonic']-time.monotonic())>16,
                'CURRENT_INGESTION_READINESS_STAGE_WINDOW_REQUIRED')
        native=self.lifecycle
        native.journal.compare_and_save(row,{**row,'nativeIngestionReadinessGets':count+1,'version':row['version']+1})
        self.guard();process=native.process('ingestion');selected='/proc/'+str(process['pid'])+'/ns/net'
        binding=identity(os.stat(selected));fd=os.open(selected,os.O_RDONLY|os.O_CLOEXEC);child=None
        try:
            require(identity(os.fstat(fd))==binding,'INGESTION_NAMESPACE_FD_CHANGED');self.guard()
            child=subprocess.Popen([self.profile['pythonExecutable']['path'],'-I','-B','-S','-c',CHILD_SOURCE,str(fd)],
                stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,pass_fds=(fd,),close_fds=True,cwd='/',env={'LC_ALL':'C'})
            try:output,_=child.communicate(json.dumps(self.profile['endpoint']).encode(),timeout=15)
            except subprocess.TimeoutExpired:require(False,'INGESTION_READINESS_CHILD_UNPROVEN')
            require(child.returncode==0 and 0<len(output)<=90000,'INGESTION_READINESS_CHILD_UNPROVEN')
            self.guard()
            require(identity(os.stat(selected))==binding==identity(os.fstat(fd)),'INGESTION_NAMESPACE_CHANGED_DURING_READ')
            result=json.loads(output)
            require(type(result)is dict and set(result)=={'status','bodyBase64','retryAfter'}
                    and type(result['bodyBase64'])is str,'TYPED_INGESTION_READINESS_RESULT_REQUIRED')
            body=base64.b64decode(result['bodyBase64'],validate=True)
            status,proof=classify('spring-readiness',result['status'],body,retry_after=result['retryAfter'],now=time.time())
            return status,{**proof,'candidateFirstProcessMatched':True,'readinessNamespaceBound':True}
        finally:
            if child is not None:
                if child.poll()is None:child.kill()
                child.wait(timeout=5)
                for pipe in(child.stdin,child.stdout):
                    if pipe is not None:pipe.close()
            os.close(fd)
