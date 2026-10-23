"""Same configured Ingestion service identity and exact semantic references.

The request is GET-only through its configured Gateway, in the unchanged
caller's netns. No HUMAN bearer, owner override, login, refresh, compatibility
attestation POST, source activation, redirect or latest-reference fallback.
"""
import copy,hashlib,json,os,re,subprocess,uuid
from pathlib import PurePosixPath
from urllib.parse import urlsplit
from .core import require,digest,encoded,hashed
from .gateway import CurrentGateway
from .caller_configuration import verify as verify_configuration
from .read_budget import ReadBudget
from tools.ingestion_readiness_patch_execution import private_file,runtime_guard
from tools.semantic_live_route_diagnostic.reader import verify_program,process_ticks

CLIENT_SOURCE='GioNob/ouf-ingestion-runtime@4165b9e149be467d5d7c6bed35e4e1af4e249db1:src/main/java/it/comune/trieste/ouf/ingestion/PublicationGatewayClient.java'
OBSERVABLE_NON_SUCCESS = (403,429,502,503,504)

CHILD_SOURCE=r'''import hashlib,http.client,ipaddress,json,os,re,signal,ssl,sys,uuid
from urllib.parse import urlsplit,urlencode
signal.alarm(9)
try:
    raw=sys.stdin.buffer.read(262145)
    if not 0<len(raw)<=262144:raise ValueError()
    v=json.loads(raw)
    if set(v)!={'origin','token','reference','ca','peerCertificateSha256'}:raise ValueError()
    u=urlsplit(v['origin']);b=v['reference'];token=v['token']
    if u.scheme not in ('http','https') or not u.hostname or u.username or u.password or u.path not in ('','/') or u.query or u.fragment:raise ValueError()
    if set(b)!={'semanticId','semanticVersion','revisionId','publicationSetId'}:raise ValueError()
    if not all(type(x)is str and 0<len(x)<=2048 and not any(ord(c)<32 for c in x)for x in b.values()):raise ValueError()
    if any(str(uuid.UUID(b[k]))!=b[k]for k in ('revisionId','publicationSetId')):raise ValueError()
    if type(token)is not str or not 0<len(token)<=16384 or any(c.isspace()for c in token):raise ValueError()
    if len(sys.argv)!=2 or not sys.argv[1].isdigit():raise ValueError()
    fd=int(sys.argv[1]);os.setns(fd,0);os.close(fd)
    if u.scheme=='https':
        context=ssl.create_default_context(cadata=v['ca'])
        client=http.client.HTTPSConnection(u.hostname,u.port or 443,context=context,timeout=4)
    else:
        if not ipaddress.ip_address(u.hostname).is_private or v['ca']is not None or v['peerCertificateSha256']is not None:raise ValueError()
        client=http.client.HTTPConnection(u.hostname,u.port or 80,timeout=4)
    client.connect()
    if u.scheme=='https' and hashlib.sha256(client.sock.getpeercert(binary_form=True)).hexdigest()!=v['peerCertificateSha256']:raise ValueError()
    path='/api/semantic/v1/references:resolve?'+urlencode({k:b[k]for k in ('semanticId','revisionId','publicationSetId')})
    client.request('GET',path,headers={'Authorization':'Bearer '+token,'Accept':'application/json','X-Correlation-ID':str(uuid.uuid4()),'Connection':'close'})
    response=client.getresponse();body=response.read(2097153)
    if len(body)>2097152:raise ValueError()
    matched=False
    if response.status==200:
        def unique(pairs):
            result={}
            for k,val in pairs:
                if k in result:raise ValueError()
                result[k]=val
            return result
        result=json.loads(body,object_pairs_hook=unique)
        matched=(type(result)is dict and result.get('semantic_id')==b['semanticId']
            and result.get('semantic_version')==b['semanticVersion'] and result.get('revision_id')==b['revisionId']
            and result.get('publication_set_id')==b['publicationSetId'] and result.get('status')=='ACTIVE')
    output={'status':response.status,'exactActiveReferenceMatched':matched,'bodySha256':hashlib.sha256(body).hexdigest()}
    sys.stdout.buffer.write(json.dumps(output,sort_keys=True,separators=(',',':')).encode());sys.stdout.buffer.flush();client.close()
except BaseException:os._exit(1)
os._exit(0)
'''

def request_scope(gateway,profile):
    return {'schema':'ouf.semantic-registry-recovery-original-request-scope.v1',
        'planHash':digest(gateway.lifecycle.plan),'gatewayScopeHash':digest(gateway.scope),
        'requestProfileHash':digest(profile),'clientSource':CLIENT_SOURCE,'method':'GET',
        'path':'/api/semantic/v1/references:resolve','callerIdentity':'EXISTING_INGESTION_SERVICE',
        'boundedObservationStatuses':list(OBSERVABLE_NON_SUCCESS),'nonSuccessIsReadinessProof':False,
        'sourceActivationAllowed':False,'credentialAcquisitionAllowed':False,'latestFallbackAllowed':False}

class OriginalSemanticRequest:
    def __init__(self,gateway,profile):
        require(type(gateway) is CurrentGateway,'ACTUAL_CURRENT_GATEWAY_FOR_ORIGINAL_REQUEST_REQUIRED')
        self.gateway,self.lifecycle,self.budget=gateway,gateway.lifecycle,gateway.budget
        self.profile=copy.deepcopy(profile)
        fields={'caller','origin','tokenTarget','tokenSource','pythonExecutable','ca','peerCertificateSha256',
            'references','frozenConfigurationHash','onboardingVersionId','frozenConfiguration'}
        require(type(profile) is dict and set(profile) in (fields, fields | {'callerConfiguration'}),'EXACT_ORIGINAL_SERVICE_REQUEST_PROFILE_REQUIRED')
        refs=profile['references']
        require(type(refs) is list and 1<=len(refs)<=32,'EXACT_BOUNDED_ORIGINAL_REFERENCES_REQUIRED')
        seen=set()
        for ref in refs:
            require(type(ref) is dict and set(ref)=={'semanticId','semanticVersion','revisionId','publicationSetId'}
                and all(type(v) is str and 0<len(v)<=2048 and not any(ord(c)<32 for c in v) for v in ref.values()),
                'EXACT_VERSIONED_REFERENCE_FIELDS_REQUIRED')
            require(all(str(uuid.UUID(ref[k]))==ref[k] for k in ('revisionId','publicationSetId')),
                'CANONICAL_ORIGINAL_REFERENCE_UUIDS_REQUIRED')
            key=ref['semanticId']+'@'+ref['semanticVersion'];require(key not in seen,'DISTINCT_ORIGINAL_REFERENCES_REQUIRED');seen.add(key)
        require(type(profile['frozenConfigurationHash']) is str
            and profile['frozenConfigurationHash'].startswith('sha256:') and hashed(profile['frozenConfigurationHash'][7:])
            and str(uuid.UUID(profile['onboardingVersionId']))==profile['onboardingVersionId'],
            'ORIGINAL_FROZEN_CONFIGURATION_VERSION_REQUIRED')
        frozen=profile['frozenConfiguration']
        require(type(frozen) is dict and frozen.get('onboardingVersionId')==profile['onboardingVersionId']
            and frozen.get('configurationHash')==profile['frozenConfigurationHash']
            and frozen.get('state') in ('IN_REVIEW','APPROVED')
            and type(frozen.get('configuration')) is dict
            and frozen['configuration'].get('semanticReferenceBindings')==refs,
            'SAME_ORIGINAL_FROZEN_CONFIGURATION_REFERENCES_REQUIRED')
        configuration=frozen['configuration']
        mapped=configuration.get('semanticMapping',{}).get('semanticRefs')
        require(type(mapped) is list and 1<=len(mapped)<=32 and len(set(mapped))==len(mapped)
            and all(type(v) is str and re.fullmatch(r'[^@\s]+@[^@\s]+',v) for v in mapped),
            'ORIGINAL_EXACT_FROZEN_REFERENCE_SYNTAX_REQUIRED')
        calculated='sha256:'+hashlib.sha256(json.dumps(configuration,sort_keys=True,separators=(',',':'),
            ensure_ascii=False,allow_nan=False).encode()).hexdigest()
        require(calculated==profile['frozenConfigurationHash']
            and set(mapped)==seen,
            'ORIGINAL_FROZEN_CONFIGURATION_CHECKSUM_AND_REFERENCE_SET_REQUIRED')
        private_file.validate(profile['tokenSource'],maximum=16384)
        target=PurePosixPath(profile['tokenTarget'])
        require(target.is_absolute() and str(target)==profile['tokenTarget'] and '..' not in target.parts,
            'EXACT_ORIGINAL_MOUNTED_TOKEN_TARGET_REQUIRED')
        u=urlsplit(profile['origin'])
        require(u.scheme in ('http','https') and u.hostname and not u.username and not u.password
            and u.path in ('','/') and not u.query and not u.fragment,'ORIGINAL_CONFIGURED_GATEWAY_ORIGIN_REQUIRED')
        if u.scheme=='https':
            private_file.validate(profile['ca'])
            require(hashed(profile['peerCertificateSha256']),
                'INDEPENDENT_CURRENT_GATEWAY_TLS_PEER_REQUIRED')
        else:require(profile['ca'] is None and profile['peerCertificateSha256'] is None,'HTTP_REQUEST_CANNOT_ADOPT_TLS_PROFILE')
        self.scope=request_scope(gateway,profile);self.guard()

    def guard(self):
        row=self.lifecycle.journal();p=self.profile
        require(request_scope(self.gateway,p)==self.scope
            and json.loads(self.lifecycle.authority.raw).get('semanticRegistryRecoveryOriginalRequest')==self.scope,
            'CURRENT_SIGNED_ORIGINAL_SERVICE_REQUEST_SCOPE_REQUIRED')
        status,actual=self.lifecycle.engine.request('GET','/v1.44/containers/'+p['caller']['binding']['containerId']+'/json')
        require(status==200,'CURRENT_ORIGINAL_SERVICE_CALLER_REQUIRED');runtime_guard.unchanged(actual,p['caller'])
        verify_configuration(actual,p)
        gateway=self.gateway.guard();u=urlsplit(p['origin'])
        if u.scheme=='http':
            require(any(e.get('IPAddress')==u.hostname for e in gateway['NetworkSettings']['Networks'].values()),
                'HTTP_ORIGIN_MUST_BE_THE_REVIEWED_GATEWAY')
        verify_program(p['pythonExecutable'])
        require(self.lifecycle.journal()==row,'ORIGINAL_SERVICE_REQUEST_SCOPE_CHANGED')
        return actual

    def _get(self,ref):
        actual=self.guard();p=self.profile;pid=actual['State']['Pid'];fds=[];child=None
        with private_file.opened(p['tokenSource'],maximum=16384) as host:
            try:
                current=os.open('/proc/'+str(pid)+'/root',os.O_PATH|os.O_DIRECTORY);fds.append(current)
                parts=PurePosixPath(p['tokenTarget']).parts[1:]
                for part in parts[:-1]:
                    current=os.open(part,os.O_PATH|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=current);fds.append(current)
                mounted=os.open(parts[-1],os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=current);fds.append(mounted)
                require(private_file.metadata(os.fstat(mounted))==private_file.metadata(os.fstat(host))==p['tokenSource']['metadata'],
                    'SAME_ORIGINAL_MOUNTED_WORKLOAD_TOKEN_REQUIRED')
                raw=os.read(mounted,16385);require(0<len(raw)<=16384,'BOUNDED_ORIGINAL_WORKLOAD_TOKEN_REQUIRED')
                token=raw.decode('ascii').strip();require(token and not any(c.isspace() for c in token),
                    'ORIGINAL_WORKLOAD_TOKEN_ENCODING_REQUIRED')
                ca=None if p['ca'] is None else private_file.read(p['ca']).decode('ascii')
                ns='/proc/'+str(pid)+'/ns/net';ticks=process_ticks(pid)
                fd=os.open(ns,os.O_RDONLY|os.O_CLOEXEC);fds.append(fd)
                pin=lambda s:(s.st_dev,s.st_ino);identity=pin(os.fstat(fd))
                self.budget.reserve('semanticGets');self.guard()
                request=encoded({'origin':p['origin'],'token':token,'reference':ref,'ca':ca,
                    'peerCertificateSha256':p['peerCertificateSha256']})
                require(len(request)<=262144,'BOUNDED_ORIGINAL_SERVICE_PRIVATE_REQUEST_REQUIRED')
                child=subprocess.Popen([p['pythonExecutable']['path'],'-I','-B','-S','-c',CHILD_SOURCE,str(fd)],
                    stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,pass_fds=(fd,),
                    close_fds=True,cwd='/',env={'LC_ALL':'C'})
                output,_=child.communicate(request,timeout=12)
                require(child.returncode==0 and 0<len(output)<=4096,'ORIGINAL_SEMANTIC_REQUEST_UNCONFIRMED')
                require(process_ticks(pid)==ticks and pin(os.fstat(fd))==identity==pin(os.stat(ns))
                    and private_file.metadata(os.fstat(mounted))==p['tokenSource']['metadata']
                    and self.guard()['Id']==actual['Id'],'ORIGINAL_CALLER_OR_TOKEN_CHANGED_DURING_GET')
                if p['ca'] is not None:private_file.read(p['ca'])
                result=json.loads(output)
                require(set(result)=={'status','exactActiveReferenceMatched','bodySha256'}
                    and type(result['status']) is int and 100<=result['status']<=599
                    and type(result['exactActiveReferenceMatched']) is bool,
                    'BOUNDED_ORIGINAL_SERVICE_RESPONSE_REQUIRED')
                return result
            finally:
                if child is not None:
                    if child.poll() is None:child.kill()
                    child.wait(timeout=5)
                    for stream in (child.stdin,child.stdout):
                        if stream is not None:stream.close()
                for fd in reversed(fds):os.close(fd)

    def verify(self):
        row=self.lifecycle.journal();require(row['nextStage']==11,'FINAL_ORIGINAL_SEMANTIC_GET_ONLY')
        self.gateway.verify(endpoint_required=True);results=[]
        for ref in self.profile['references']:
            result=self._get(ref)
            # Registry intentionally exposes the same 403 for a missing policy
            # bundle and an actual capability denial. Neither is called healthy
            # or classified transient. A finite controller may observe again
            # with this exact SERVICE identity and the same durable read budget.
            if result['status'] in OBSERVABLE_NON_SUCCESS:
                return 'UNKNOWN',{'httpStatus':result['status'],'originalSemanticGetSucceeded':False,
                    'policyAdmissionUnproven':result['status']==403}
            require(result['status']==200 and result['exactActiveReferenceMatched'] is True,
                'ORIGINAL_EXACT_ACTIVE_SEMANTIC_REFERENCE_UNPROVEN')
            results.append(result)
        require(self.lifecycle.journal()==row,'RECOVERY_CHANGED_DURING_ORIGINAL_SEMANTIC_REQUEST')
        return 'APPLIED',{'schema':'ouf.semantic-registry-recovery-original-request-verified.v1',
            'newGeneration':copy.deepcopy(row['newGeneration']),'httpStatus':200,'originalSemanticGetSucceeded':True,
            'sameConfiguredServiceCaller':True,'exactActiveReferenceCount':len(results),
            'responseEvidenceHash':digest(results),'sourceActivationResubmitted':False,'releaseAcceptance':False}
