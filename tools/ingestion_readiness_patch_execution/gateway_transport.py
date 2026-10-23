"""New-Gateway generation-bound route admin transport, never a rollout issuer.

Every local path, trusted file identity, endpoint and program is a signed review
input. Only a pinned FD for the created Gateway process is inherited by a sealed
stdlib child. Parent namespace is unchanged; credentials cross private stdin.
No retries, route discovery writes, deletion or fallback transport are allowed.
"""
import copy
import datetime
import email.utils
import time
import ipaddress
import json
import os
import re
import subprocess
import iam_governance_intake as governance
from tools.ingestion_readiness_patch_execution.contract import AUTHORITY_KEY,require,path,hashed,scope,encoded,digest
from tools.ingestion_readiness_patch_execution.namespace import GatewayNamespacePin
from tools.ingestion_readiness_patch_execution import private_file
from tools.chatbot_file_cohort.gateway import selected_admin_key,route_map
from tools.semantic_policy_token_owner.owner_installation import AggregateAction
from tools.semantic_lease_recovery.recovery_journal import Journal
from tools.chatbot_file_cohort.human_session import HumanSession

CHILD_SOURCE = r'''import hashlib,http.client,ipaddress,json,os,re,signal,sys
signal.alarm(12)
try:
    raw=sys.stdin.buffer.read(655361)
    if not 0<len(raw)<=655360:raise ValueError()
    v=json.loads(raw)
    if type(v)is not dict or set(v)!={'method','path','body','key','host','port'}:raise ValueError()
    method,path,body,key=(v[n] for n in ('method','path','body','key'))
    if method!='GET' or path!='/apisix/admin/routes' or body is not None:raise ValueError()
    if path!='/apisix/admin/routes' and not re.fullmatch(r'/apisix/admin/routes/[A-Za-z0-9._-]{1,128}',path):raise ValueError()
    
    
    if type(key)is not str or not 16<=len(key)<=4096 or not all(33<=ord(c)<=126 for c in key):raise ValueError()
    host,port=v['host'],v['port']
    if type(host)is not str or not ipaddress.ip_address(host).is_loopback:raise ValueError()
    if type(port)is not int or not 1<=port<=65535:raise ValueError()
    payload=None if body is None else json.dumps(body,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
    if payload is not None and len(payload)>262144:raise ValueError()
    if len(sys.argv)!=2 or not re.fullmatch(r'[0-9]{1,10}',sys.argv[1]):raise ValueError()
    fd=int(sys.argv[1]);os.setns(fd,0);os.close(fd)
    client=http.client.HTTPConnection(host,port,timeout=10)
    client.request(method,path,body=payload,headers={'X-API-KEY':key,'Content-Type':'application/json','Accept':'application/json','Connection':'close'})
    response=client.getresponse();payload=response.read(8388609)
    if len(payload)>8388608:raise ValueError()
    retry=response.getheader('Retry-After','')
    if len(retry)>128 or any(ord(c)<32 or ord(c)>126 for c in retry):raise ValueError()
    try:parsed=json.loads(payload) if payload else {}
    except ValueError:
        if method!='GET' or response.status not in (429,502,503,504):raise
        parsed={'unparsedBodySha256':hashlib.sha256(payload).hexdigest(),'bodyBytes':len(payload)}
    result=json.dumps({'status':response.status,'body':parsed,'retryAfter':retry},sort_keys=True,separators=(',',':'),allow_nan=False).encode()
    if len(result)>8454144:raise ValueError()
    sys.stdout.buffer.write(result);sys.stdout.buffer.flush();client.close()
except BaseException:
    os._exit(1)
os._exit(0)
'''
ROUTE=re.compile(r'/apisix/admin/routes/[A-Za-z0-9._-]{1,128}')

class GatewayTransient(RuntimeError):
    def __init__(self,retry_after_seconds):
        super().__init__('BOUNDED_GATEWAY_READ_TRANSIENT')
        self.retry_after_seconds=retry_after_seconds

def retry_after_seconds(value,now=None):
    require(type(value)is str and len(value)<=128,'BOUNDED_RETRY_AFTER_REQUIRED')
    if not value:return 0.
    if re.fullmatch('[0-9]{1,10}',value):return float(value)
    try:
        parsed=email.utils.parsedate_to_datetime(value)
        require(parsed.tzinfo is not None and parsed.utcoffset()==datetime.timedelta(0),
                'UTC_RETRY_AFTER_DATE_REQUIRED')
        return max(0.,parsed.timestamp()-(time.time()if now is None else now))
    except (TypeError,ValueError,OverflowError):
        require(False,'VALID_RETRY_AFTER_REQUIRED')

def validate_profile(profile):
    require(type(profile)is dict and set(profile)=={'schema','endpoint','pythonExecutable','config','adminKey'},
            'EXACT_GATEWAY_TRANSPORT_PROFILE_REQUIRED')
    require(profile['schema']=='ouf.ingestion-rollout-gateway-transport.v1',
            'QUALIFIED_GATEWAY_TRANSPORT_SCHEMA_REQUIRED')
    endpoint=profile['endpoint']
    require(type(endpoint)is dict and set(endpoint)=={'host','port'}
            and type(endpoint['host'])is str and type(endpoint['port'])is int
            and 1<=endpoint['port']<=65535,'EXPLICIT_GATEWAY_LOOPBACK_ENDPOINT_REQUIRED')
    try:loopback=ipaddress.ip_address(endpoint['host']).is_loopback
    except ValueError:loopback=False
    require(loopback,'GATEWAY_NAMESPACE_LOOPBACK_ONLY')
    program=profile['pythonExecutable']
    require(type(program)is dict and set(program)=={'path','sha256'}
            and path(program['path'])and hashed(program['sha256']),'EXACT_NAMESPACE_PROGRAM_BINDING_REQUIRED')
    private_file.validate(profile['config'])
    if profile['adminKey']is not None:private_file.validate(profile['adminKey'])
    return profile

class NativeGatewayTransport:
    def __init__(self,action,journal,review,packet,human,pin):
        require(type(action)is AggregateAction and type(journal)is Journal and type(human)is HumanSession
                and type(pin)is GatewayNamespacePin and pin.fd is not None,'CONCRETE_UNCHANGED_GATEWAY_COMPONENTS_REQUIRED')
        self.action,self.journal,self.human,self.pin=action,journal,human,pin
        self.review,self.packet=copy.deepcopy(review),copy.deepcopy(packet);self.scope=scope(review)
        self.profile=copy.deepcopy(review['gatewayTransportProfile']);validate_profile(self.profile)
        require(digest(packet)==review['packetBinding']['sha256'] and str(journal.root)==review['executionContext']
                and {k:self.profile['config'][k] for k in ('path','sha256','metadata')}==packet['retainedGatewayConfig']
                and pin.pin==review['runtimeGuardProfile']['unchangedApplications']['gateway'],
                'SAME_UNCHANGED_GATEWAY_REVIEW_AND_CONFIG_REQUIRED')
        self.retry_after='';self.check()
    def check(self):
        require(scope(self.review)==self.scope and self.profile==self.review['gatewayTransportProfile']
                and digest(self.packet)==self.review['packetBinding']['sha256'],'READ_ONLY_GATEWAY_REVIEW_DRIFT')
        self.action.guard(AUTHORITY_KEY,self.scope)
        require(self.human.current()==self.scope['humanBinding'],'SAME_CURRENT_HUMAN_REQUIRED')
        row=self.journal.read()
        require(row.get('scopeHash')==digest(self.scope) and row.get('authorityHash')==self.action.authority_hash
                and row.get('budgetReset')is False and self.review['maximumGatewayGetAttempts']==512,
                'SAME_READ_ONLY_GATEWAY_JOURNAL_REQUIRED')
        require(self.profile['pythonExecutable']==governance.executable(self.profile['pythonExecutable']['path']),
                'NAMESPACE_EXECUTABLE_CHANGED')
        self.pin.check()
    def reserve_get(self):
        self.check();row=self.journal.read();count=row.get('nativeGatewayGetAttempts',0)
        require(type(count)is int and 0<=count<512,'CUMULATIVE_GATEWAY_GET_BUDGET_EXHAUSTED')
        self.journal.compare_and_save(row,{**row,'nativeGatewayGetAttempts':count+1,'version':row['version']+1})
        self.check()

    def _request(self,method,resource,body=None):
        require(method=='GET'and resource=='/apisix/admin/routes'and body is None,'PATCH_GATEWAY_GET_ONLY')
        self.check();profile=self.profile
        config=private_file.read(profile['config'])
        external=None if profile['adminKey']is None else private_file.read(profile['adminKey']).decode('ascii').strip()
        request=encoded({'method':method,'path':resource,'body':body,'key':selected_admin_key(config,external),
                         **profile['endpoint']})
        require(len(request)<=655360 and(body is None or len(encoded(body))<=262144),'PRIVATE_GATEWAY_REQUEST_TOO_LARGE')
        child=None;self.retry_after=''
        try:
            self.check()
            if method=='GET':self.reserve_get()
            child=subprocess.Popen([profile['pythonExecutable']['path'],'-I','-B','-S','-c',CHILD_SOURCE,str(self.pin.fd)],
                stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,pass_fds=(self.pin.fd,),
                close_fds=True,cwd='/',env={'LC_ALL':'C'})
            try:output,_=child.communicate(request,timeout=15)
            except subprocess.TimeoutExpired:require(False,'GATEWAY_OUTCOME_UNKNOWN_RECONCILE_ONLY')
            require(child.returncode==0 and 0<len(output)<=8454144,'GATEWAY_OUTCOME_UNKNOWN_RECONCILE_ONLY')
            self.check()
            private_file.read(profile['config'])
            if profile['adminKey']is not None:private_file.read(profile['adminKey'])
            result=json.loads(output)
            require(type(result)is dict and set(result)=={'status','body','retryAfter'}
                    and type(result['status'])is int and 100<=result['status']<=599
                    and type(result['retryAfter'])is str and len(result['retryAfter'])<=128
                    and all(32<=ord(c)<=126 for c in result['retryAfter']),'BOUNDED_GATEWAY_RESPONSE_REQUIRED')
            self.retry_after=result['retryAfter'];return result['status'],result['body']
        finally:
            if child is not None:
                if child.poll()is None:child.kill()
                child.wait(timeout=5)
                for pipe in(child.stdin,child.stdout):
                    if pipe is not None:pipe.close()

    def routes(self):
        status,body=self._request('GET','/apisix/admin/routes')
        if status in(429,502,503,504):raise GatewayTransient(retry_after_seconds(self.retry_after))
        require(status==200 and type(body)is dict and type(body.get('list'))is list
                and type(body.get('total'))is int and body['total']==len(body['list'])==82,
                'COMPLETE_CURRENT_82_ROUTE_MAP_REQUIRED')
        return route_map(body['list'])

    def close(self):self.pin.close()
