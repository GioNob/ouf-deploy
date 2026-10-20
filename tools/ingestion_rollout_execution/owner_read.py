"""Unchanged-owner namespace pin and GET-only bearer control component.

Local FD transport is explicit in a signed profile; no public Gateway fallback.
HUMAN.current and role signatures are required, without login/refresh/wait loops.
This is a component, not a complete rollout NativePorts or authority issuer.
"""
import copy
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import stat
import time
import iam_governance_intake as governance
from engine_creation import Engine
from tools.ingestion_rollout_execution.contract import AUTHORITY_KEY,require,scope,digest,encoded,path,hashed
from tools.ingestion_rollout_execution.replacement import EngineReader
from tools.ingestion_rollout_execution.namespace import identity
from tools.ingestion_rollout_execution import private_file,runtime_bindings
from tools.semantic_policy_token_owner.owner_installation import AggregateAction
from tools.semantic_lease_recovery.recovery_journal import Journal
from tools.chatbot_file_cohort.human_session import HumanSession

MAX_GETS=512
CHILD_SOURCE=r'''import http.client,ipaddress,json,os,re,signal,sys
signal.alarm(12)
try:
    raw=sys.stdin.buffer.read(32769)
    if not 0<len(raw)<=32768:raise ValueError()
    v=json.loads(raw)
    if type(v)is not dict or set(v)!={'host','port','path','bearer','correlation'}:raise ValueError()
    if type(v['host'])is not str or not ipaddress.ip_address(v['host']).is_loopback:raise ValueError()
    if type(v['port'])is not int or not 1<=v['port']<=65535:raise ValueError()
    if type(v['path'])is not str or not re.fullmatch(r'/api/trusted-human/v1/installations/[A-Za-z0-9._-]{1,128}/(?:active|revisions/[1-9][0-9]{0,18})',v['path']):raise ValueError()
    if type(v['bearer'])is not str or not re.fullmatch(r'[A-Za-z0-9_.-]{1,16384}',v['bearer']):raise ValueError()
    if type(v['correlation'])is not str or not re.fullmatch('[0-9a-f]{64}',v['correlation']):raise ValueError()
    if len(sys.argv)!=2 or not re.fullmatch('[0-9]{1,10}',sys.argv[1]):raise ValueError()
    fd=int(sys.argv[1]);os.setns(fd,0);os.close(fd)
    client=http.client.HTTPConnection(v['host'],v['port'],timeout=10)
    client.request('GET',v['path'],headers={'Authorization':'Bearer '+v['bearer'],'Accept':'application/json',
        'X-Correlation-ID':v['correlation'],'Connection':'close'})
    response=client.getresponse();raw=response.read(2097153)
    if not 0<len(raw)<=2097152:raise ValueError()
    tag=response.getheader('ETag','')
    if len(tag)>256 or any(ord(c)<32 or ord(c)>126 for c in tag):raise ValueError()
    # Only successful closed GETs are accepted; no redirects, proxy, retries,
    # projection export, authority refresh or owner mutation.
    if response.status!=200:raise ValueError()
    result=json.dumps({'status':response.status,'body':json.loads(raw),'etag':tag},
        sort_keys=True,separators=(',',':'),allow_nan=False).encode()
    if len(result)>2162688:raise ValueError()
    sys.stdout.buffer.write(result);sys.stdout.buffer.flush();client.close()
except BaseException:
    os._exit(1)
os._exit(0)
'''

def validate_profile(p):
    require(type(p)is dict and set(p)=={'schema','runtimeBinding','networkNamespace','endpoint','pythonExecutable',
            'installationId','expectedActive','expectedPayload','projection','restartCount','runtimeBindingProfile'},'EXACT_OWNER_CONTROL_PROFILE_REQUIRED')
    require(p['schema']=='ouf.ingestion-rollout-owner-local-namespace-http.v1','QUALIFIED_OWNER_LOCAL_TRANSPORT_REQUIRED')
    require(type(p['restartCount'])is int and p['restartCount']>=0,'EXPLICIT_RETAINED_OWNER_RESTART_COUNT_REQUIRED')
    require(p['runtimeBindingProfile']in runtime_bindings.PROFILES,'EXPLICIT_OWNER_RUNTIME_BINDING_PROFILE_REQUIRED')
    binding=p['runtimeBinding']
    require(type(binding)is dict and set(binding)=={'containerId','imageId','pid','startedAt','configHash',
            'hostConfigHash','mountsHash','networkSettingsHash'}and hashed(binding['containerId'])
            and re.fullmatch('sha256:[0-9a-f]{64}',binding['imageId'])
            and type(binding['pid'])is int and binding['pid']>0 and type(binding['startedAt'])is str
            and binding['startedAt'] and all(hashed(binding[k])for k in('configHash','hostConfigHash','mountsHash','networkSettingsHash')),
            'FULL_IMMUTABLE_OWNER_RUNTIME_BINDING_REQUIRED')
    require(type(p['networkNamespace'])is dict and set(p['networkNamespace'])=={'device','inode'}
            and all(type(v)is int and v>0 for v in p['networkNamespace'].values()),'EXPLICIT_OWNER_NAMESPACE_IDENTITY_REQUIRED')
    endpoint=p['endpoint'];require(type(endpoint)is dict and set(endpoint)=={'host','port'}
            and type(endpoint['host'])is str and type(endpoint['port'])is int and 1<=endpoint['port']<=65535,
            'EXPLICIT_OWNER_LOOPBACK_ENDPOINT_REQUIRED')
    try:loopback=ipaddress.ip_address(endpoint['host']).is_loopback
    except ValueError:loopback=False
    require(loopback,'OWNER_NAMESPACE_LOOPBACK_ONLY')
    program=p['pythonExecutable'];require(type(program)is dict and set(program)=={'path','sha256'}
            and path(program['path'])and hashed(program['sha256']),'EXACT_OWNER_NAMESPACE_PROGRAM_REQUIRED')
    require(type(p['installationId'])is str and re.fullmatch('[A-Za-z0-9._-]{1,128}',p['installationId']),
            'EXPLICIT_OWNER_INSTALLATION_ID_REQUIRED')
    active=p['expectedActive']
    require(type(active)is dict and set(active)=={'installationId','revision','checksum','generation','etag'}
            and active['installationId']==p['installationId']
            and type(active['revision'])is int and 1<=active['revision']<2**63
            and type(active['generation'])is int and 1<=active['generation']<2**63 and hashed(active['checksum'])
            and active['etag']=='"'+str(active['revision'])+':'+active['checksum']+':'+str(active['generation'])+'"',
            'EXACT_EXPECTED_OWNER_STRONG_ETAG_REQUIRED')
    require(type(p['expectedPayload'])is dict and p['expectedPayload'].get('installationId')==p['installationId']
            and 0<len(encoded(p['expectedPayload']))<=524288,'EXACT_RETAINED_IMMUTABLE_OWNER_PAYLOAD_REQUIRED')
    private_file.validate(p['projection']);return p

def validate_active_result(result):
    require(type(result)is dict and set(result)=={'status','body','etag'}and type(result['status'])is int
            and result['status']==200 and type(result['body'])is dict
            and set(result['body'])=={'installationId','revision','checksum','generation'}
            and type(result['body']['installationId'])is str and hashed(result['body']['checksum'])
            and type(result['body']['revision'])is int and 1<=result['body']['revision']<2**63
            and type(result['body']['generation'])is int and 1<=result['body']['generation']<2**63,
            'TYPED_OWNER_ACTIVE_RESPONSE_REQUIRED')

class OwnerNamespacePin:
    def __init__(self,reader,profile):
        require(type(reader)is EngineReader,'EXACT_NATIVE_OWNER_ENGINE_READER_REQUIRED')
        validate_profile(profile);self.reader=reader;self.profile=copy.deepcopy(profile);self.fd=None
        try:
            self.check();self.fd=os.open(self.path,os.O_RDONLY|os.O_CLOEXEC)
            require(identity(os.fstat(self.fd))==self.profile['networkNamespace'],'OWNER_NAMESPACE_FD_IDENTITY_CHANGED')
            self.check()
        except BaseException:self.close();raise
    @property
    def path(self):return '/proc/'+str(self.profile['runtimeBinding']['pid'])+'/ns/net'
    def check(self):
        actual=self.reader.container(self.profile['runtimeBinding']['containerId']);state=actual['State']
        require(runtime_bindings.observed(actual,self.profile['runtimeBindingProfile'])==self.profile['runtimeBinding']and state['Running']is True
                and state['Paused']is False and state['Restarting']is False and actual['RestartCount']==self.profile['restartCount'],
                'UNCHANGED_RUNNING_OWNER_GENERATION_REQUIRED')
        require(identity(os.stat(self.path))==self.profile['networkNamespace'],'OWNER_NAMESPACE_PROCESS_CHANGED')
        if self.fd is not None:require(identity(os.fstat(self.fd))==self.profile['networkNamespace'],'HELD_OWNER_NAMESPACE_CHANGED')
    def close(self):
        if self.fd is not None:os.close(self.fd);self.fd=None
    def __enter__(self):self.check();require(self.fd is not None,'OPEN_OWNER_NAMESPACE_FD_REQUIRED');return self
    def __exit__(self,*unused):self.close()

class NativeOwnerRead:
    def __init__(self,action,journal,review,human,pin):
        require(type(action)is AggregateAction and type(journal)is Journal and type(human)is HumanSession
                and type(pin)is OwnerNamespacePin and pin.fd is not None,'CONCRETE_CURRENT_OWNER_READ_COMPONENTS_REQUIRED')
        self.action,self.journal,self.human,self.pin=action,journal,human,pin
        self.review=copy.deepcopy(review);self.scope=scope(self.review)
        self.profile=copy.deepcopy(review.get('ownerControlProfile'));validate_profile(self.profile)
        require(self.profile==pin.profile and review.get('maximumOwnerGetAttempts')==MAX_GETS
                and str(journal.root)==review['executionContext'],'SAME_SIGNED_OWNER_PROFILE_AND_FINITE_READ_BUDGET_REQUIRED')
        self.check()
    def check(self):
        require(scope(self.review)==self.scope and self.profile==self.review['ownerControlProfile'],'OWNER_CONTROL_REVIEW_DRIFT')
        self.action.guard(AUTHORITY_KEY,self.scope)
        require(self.human.current()==self.scope['humanBinding'],'SAME_CURRENT_AUTHENTICATED_HUMAN_REQUIRED')
        row=self.journal.read();count=row.get('nativeOwnerGetAttempts',0)
        require(row.get('scopeHash')==digest(self.scope)and row.get('authorityHash')==self.action.authority_hash
                and row.get('budgetReset')is False and type(count)is int and 0<=count<=MAX_GETS,
                'SAME_PERSISTENT_OWNER_READ_BUDGET_REQUIRED')
        require(self.profile['pythonExecutable']==governance.executable(self.profile['pythonExecutable']['path']),
                'OWNER_NAMESPACE_PROGRAM_CHANGED')
        require(self.pin.profile==self.profile,'OWNER_PIN_PROFILE_DRIFT')
        self.pin.check();return row
    def reserve(self):
        row=self.check();count=row.get('nativeOwnerGetAttempts',0)
        require(count<MAX_GETS,'CUMULATIVE_OWNER_READ_BUDGET_EXHAUSTED')
        self.journal.compare_and_save(row,{**row,'nativeOwnerGetAttempts':count+1,'version':row['version']+1})
        self.check()
    def token(self):
        self.check();row=self.human._read();require(row['accessExpiresAt']>time.time()+15,'CURRENT_OWNER_BEARER_NO_REFRESH_REQUIRED')
        # current() has checked the private journal, binding, budget and claims.
        # The published token must still be the exact file consumed by owners.
        fd=os.open(self.human.token_path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        try:
            before=os.fstat(fd);require(stat.S_ISREG(before.st_mode)and before.st_uid==os.geteuid()and before.st_nlink==1
                and before.st_mode&0o777==0o600 and 0<before.st_size<=16384,'PRIVATE_PUBLISHED_HUMAN_BEARER_REQUIRED')
            raw=os.read(fd,16385);after=os.fstat(fd)
            require(private_file.metadata(before)==private_file.metadata(after)
                    ==private_file.metadata(os.stat(self.human.token_path,follow_symlinks=False))
                    and len(raw)==before.st_size,'PUBLISHED_HUMAN_BEARER_CHANGED')
            value=raw.decode('ascii').strip()
            require(value==row['publishedAccessToken'],'SAME_VERIFIED_PUBLISHED_HUMAN_BEARER_REQUIRED')
            self.human._claims(value);self.check();return value
        finally:os.close(fd)
    def get(self,suffix):
        require(suffix in('/active','/revisions/'+str(self.profile['expectedActive']['revision'])),
                'ONLY_EXPECTED_OWNER_ACTIVE_AND_IMMUTABLE_REVISION_GETS')
        self.check()
        row=self.journal.read()
        require(min(row['expiresAt']-time.time(),row['expiresMonotonic']-time.monotonic())>16,
                'CURRENT_OWNER_READ_STAGE_WINDOW_REQUIRED')
        request=encoded({**self.profile['endpoint'],'path':'/api/trusted-human/v1/installations/'
                +self.profile['installationId']+suffix,'bearer':self.token(),'correlation':self.scope['reviewHash']})
        self.reserve();child=None
        try:
            child=subprocess.Popen([self.profile['pythonExecutable']['path'],'-I','-B','-S','-c',CHILD_SOURCE,str(self.pin.fd)],
                stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,pass_fds=(self.pin.fd,),
                close_fds=True,cwd='/',env={'LC_ALL':'C'})
            try:output,_=child.communicate(request,timeout=15)
            except subprocess.TimeoutExpired:require(False,'OWNER_READ_UNPROVEN_RETAIN_BUDGET')
            require(child.returncode==0 and 0<len(output)<=2162688,'OWNER_READ_UNPROVEN_RETAIN_BUDGET')
            self.check();result=json.loads(output)
            require(type(result)is dict and set(result)=={'status','body','etag'}and result['status']==200
                    and type(result['body'])is dict and type(result['etag'])is str,'EXACT_OWNER_READ_RESPONSE_REQUIRED')
            return result
        finally:
            if child is not None:
                if child.poll()is None:child.kill()
                child.wait(timeout=5)
                for pipe in(child.stdin,child.stdout):
                    if pipe is not None:pipe.close()
    def verify(self):
        self.check();active=self.profile['expectedActive'];plain={k:active[k]for k in active if k!='etag'}
        first=self.get('/active');validate_active_result(first)
        require(first['body']==plain and first['etag']==active['etag'],'CURRENT_OWNER_ACTIVE_OR_STRONG_ETAG_CHANGED')
        revision=self.get('/revisions/'+str(active['revision']))['body']
        require(set(revision)=={'installationId','revision','checksum','validationState','validationFindings','payload'}
                and revision.get('installationId')==active['installationId']and type(revision.get('revision'))is int
                and revision['revision']==active['revision']and revision.get('checksum')==active['checksum']
                and encoded(revision.get('payload'))==encoded(self.profile['expectedPayload'])
                and revision.get('validationState')=='VALIDATED'and revision.get('validationFindings')==[],
                'CURRENT_OWNER_IMMUTABLE_PAYLOAD_CHANGED')
        private_file.read(self.profile['projection'])
        last=self.get('/active');validate_active_result(last);require(last==first,'OWNER_ACTIVE_CHANGED_DURING_READ')
        self.check()
        return {'ownerActiveAndStrongEtagMatched':True,'immutablePayloadMatched':True,
                'retainedProjectionBytesAndMetadataUnchanged':True,'ownerGetRequests':3,
                'ownerMutations':0,'projectionExports':0,'runtimeAuthorityIssued':False}
