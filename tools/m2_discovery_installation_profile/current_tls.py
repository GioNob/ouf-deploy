"""Current IAM/provider TLS identity from the admitted Registry namespace.

The exact public CA inputs are parent-bound. Java's immutable public PKCS12 must
contain the same anchors and no key bag. Only two reviewed peers/four native
GETs and four bounded TLS handshakes occur. No credential/OAuth or HTTP request,
new key, file publication, lifecycle action or complete admission is provided.
"""
import copy,hashlib,ipaddress,os,re,stat,subprocess,sys
from pathlib import Path
from urllib.parse import urlsplit
from .custody_capture import decode,digest,encoded,require
from .current_cohort import CurrentCohortRuntime,CurrentCohortEngine,INPUT_SCHEMA_V2,validate_inputs
from .current_operational_worker import CurrentOperationalWorker
from .node_owner import ObservationBudget
from .native_profile import DiscoveryProfile
from .private_review import absolute,hashed
from .public_truststore import PEM
from tools.semantic_provider_deployment_authentication import attributes
from tools.semantic_target_review.prepare_application_runtime_inputs import file_bytes
from gated_process_observation import RunningWorkloadBinding
from engine_creation import Engine

SCHEMA='ouf.discovery-current-tls-inputs.v1'
CHILD=r'''
import hashlib,ipaddress,json,os,socket,ssl,sys
raw=sys.stdin.buffer.read(1048577)
assert 0<len(raw)<=1048576
p=json.loads(raw)
assert set(p)=={'ip','port','serverName','caPem','caFingerprints','timeout'}
a=ipaddress.ip_address(p['ip'])
assert a.version==4 and a.is_private and not a.is_loopback and not a.is_unspecified and not a.is_multicast
assert type(p['port']) is int and 1<=p['port']<=65535 and type(p['serverName']) is str
assert type(p['timeout']) in (int,float) and 0<p['timeout']<=5
if hasattr(os,'setns'):os.setns(int(sys.argv[1]),os.CLONE_NEWNET)
else:
    import ctypes
    libc=ctypes.CDLL(None,use_errno=True)
    if libc.setns(int(sys.argv[1]),0x40000000)!=0:raise OSError(ctypes.get_errno(),'SETNS_DENIED')
c=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT);c.minimum_version=ssl.TLSVersion.TLSv1_2
c.check_hostname=True;c.verify_mode=ssl.CERT_REQUIRED
assert c.get_ca_certs()==[]
c.load_verify_locations(cadata=p['caPem'])
assert {hashlib.sha256(v).hexdigest() for v in c.get_ca_certs(binary_form=True)}==set(p['caFingerprints'])
with socket.create_connection((p['ip'],p['port']),timeout=p['timeout']) as plain:
    with c.wrap_socket(plain,server_hostname=p['serverName']) as channel:
        certificate=channel.getpeercert(binary_form=True)
        assert 0<len(certificate)<=65536 and channel.version() in ('TLSv1.2','TLSv1.3')
        result={'schema':'ouf.discovery-native-tls-session.v1','tlsVersion':channel.version(),
            'peerCertificateHash':hashlib.sha256(certificate).hexdigest(),'hostnameAndChainVerified':True}
sys.stdout.buffer.write(json.dumps(result,sort_keys=True,separators=(',',':')).encode())
'''


def validate(inputs):
    fields={'schema','sourceClosureHash','installationInputsHash','desiredProfileHash','cohortManifestHash',
        'executionProfileHash','trustStoreBindingHash','caFiles','endpoints'}
    require(type(inputs) is dict and set(inputs)==fields and inputs['schema']==SCHEMA
        and all(hashed(inputs[k]) for k in fields-{'schema','caFiles','endpoints'})
        and len(encoded(inputs))<=16384,'EXACT_CURRENT_TLS_INPUTS_REQUIRED')
    require(type(inputs['caFiles']) is dict and type(inputs['endpoints']) is dict
        and set(inputs['caFiles'])==set(inputs['endpoints'])=={'iam','provider'},'EXACT_CURRENT_TLS_PEER_SET_REQUIRED')
    for role,ref in inputs['caFiles'].items():
        require(type(ref) is dict and set(ref)=={'path','sha256','maximumBytes'} and hashed(ref['sha256'])
            and type(ref['maximumBytes']) is int and 1<=ref['maximumBytes']<=1048576,'PINNED_CURRENT_PUBLIC_CA_REQUIRED')
        absolute(ref['path']);peer=inputs['endpoints'][role]
        require(type(peer) is dict and set(peer)=={'peerRole','network','port','serverName'}
            and peer['peerRole'] in ({'provider'} if role=='provider' else {'caddy','keycloak'})
            and type(peer['network']) is str and re.fullmatch('[A-Za-z0-9_.-]{1,128}',peer['network'])
            and type(peer['port']) is int and 1<=peer['port']<=65535
            and type(peer['serverName']) is str and re.fullmatch('[A-Za-z0-9][A-Za-z0-9.-]{0,252}',peer['serverName']),
            'EXACT_REVIEWED_CURRENT_TLS_ENDPOINT_REQUIRED')
    return digest(inputs)


def bind_tls_inputs(runtime_inputs,inputs):
    validate_inputs(runtime_inputs);sha=validate(inputs)
    require(all(runtime_inputs[k]==inputs[k] for k in ('sourceClosureHash','installationInputsHash','desiredProfileHash','cohortManifestHash')),
        'SAME_CURRENT_COHORT_AND_TLS_INPUTS_REQUIRED')
    result=copy.deepcopy(runtime_inputs);extra=result.setdefault('additionalInputsHashes',{})
    require('tlsIam' not in extra or extra['tlsIam']==sha,'CURRENT_TLS_INPUT_BINDING_CANNOT_BE_REPLACED')
    result['schema']=INPUT_SCHEMA_V2;extra['tlsIam']=sha;validate_inputs(result);return result


def certificates(raw,*,public_only):
    import ssl
    require(type(raw) is bytes and 0<len(raw)<=2097152,'BOUNDED_CURRENT_PUBLIC_CA_BYTES_REQUIRED')
    blocks=PEM.findall(raw)
    require(1<=len(blocks)<=16 and all(len(v)<=65536 for v in blocks)
        and (not public_only or not PEM.sub(b'',raw).strip()),'PUBLIC_CERTIFICATE_ONLY_CA_INPUT_REQUIRED')
    values={hashlib.sha256(ssl.PEM_cert_to_DER_cert(v.decode('ascii'))).hexdigest():v for v in blocks}
    return values


class CurrentTlsEngine(CurrentCohortEngine):
    TARGET_COUNT=2
    MAX_GETS=4


class CurrentTlsIdentities:
    def __init__(self,runtime,operational,inputs):
        require(type(runtime) is CurrentCohortRuntime and type(operational) is CurrentOperationalWorker
            and runtime.selected is operational.selected,'ACTUAL_SAME_CURRENT_COHORT_AND_OPERATIONAL_WORKER_REQUIRED')
        self.runtime,self.operational=runtime,operational;self.inputs=copy.deepcopy(inputs);self.input_hash=validate(inputs)
        self.ids=(id(runtime),id(operational));self.guard()

    def guard(self):
        r,o=self.runtime,self.operational;r.guard();o.guard();app=r.selected.installation.application;p=app.profile;i=self.inputs
        require(self.ids==(id(r),id(o)) and r.selected is o.selected and type(p) is DiscoveryProfile
            and p.verify(app.request)==i['executionProfileHash']
            and digest(p.selection['files']['tlsTrustStore'])==i['trustStoreBindingHash']
            and r.inputs['schema']==INPUT_SCHEMA_V2 and r.inputs['additionalInputsHashes'].get('tlsIam')==self.input_hash
            and validate(i)==self.input_hash and all(r.inputs[k]==i[k] for k in
                ('sourceClosureHash','installationInputsHash','desiredProfileHash','cohortManifestHash')),
            'EXACT_PARENT_BOUND_CURRENT_TLS_PROFILE_AND_INPUTS_REQUIRED')
        network=app.request['HostConfig']['NetworkMode']
        for role,key in (('iam','OUF_IAM_ISSUER'),('provider','OUF_SCHEMA_GOV_GATEWAY_BASE_URL')):
            endpoint=i['endpoints'][role];url=urlsplit(p.selection['references'][key])
            require(endpoint['serverName']==url.hostname and endpoint['network']==network,
                'CURRENT_TLS_IDENTITY_MUST_MATCH_SIGNED_APPLICATION_REFERENCE')
        return app

    def trust(self,budget,proposal):
        app=self.guard();f=app.profile.selection['files']['tlsTrustStore'];pins={};cas={}
        for role,ref in self.inputs['caFiles'].items():
            path=Path(ref['path']);pins[str(path)]=attributes(path.lstat());budget.check()
            raw=file_bytes(path,0,{0o400,0o440,0o600,0o644},limit=ref['maximumBytes'],expected=ref['sha256'])
            cas[role]=certificates(raw,public_only=True)
        path=Path(f['source']);info=path.lstat();pins[str(path)]=attributes(info)
        require(digest(pins[str(path)])==f['metadataHash']
            and (info.st_uid,info.st_gid,stat.S_IMODE(info.st_mode))==(f['uid'],f['gid'],f['mode']),
            'CURRENT_JAVA_PUBLIC_TRUSTSTORE_CUSTODY_CHANGED')
        file_bytes(path,0,{0o440},limit=f['maxBytes'],expected=f['sha256'])
        openssl=proposal['configuration']['verification']['openssl']
        file_bytes(openssl['path'],0,{0o755},limit=67108864,expected=openssl['sha256'])
        result=subprocess.run([openssl['path'],'pkcs12','-info','-nokeys','-in',str(path),'-passin','pass:changeit'],
            stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=budget.remaining(5),
            env={'PATH':'/usr/bin:/bin','LC_ALL':'C','OPENSSL_CONF':'/dev/null'})
        require(result.returncode==0 and len(result.stdout)<=2097152 and len(result.stderr)<=16384
            and not re.search(rb'(?im)^(?:shrouded keybag|key bag)\b',result.stderr)
            and b'PRIVATE KEY-----' not in result.stdout,
            'CURRENT_JAVA_TRUSTSTORE_MUST_CONTAIN_PUBLIC_CERTIFICATES_ONLY')
        actual=certificates(result.stdout,public_only=False);expected=set().union(*(set(v) for v in cas.values()))
        require(set(actual)==expected,'CURRENT_JAVA_TRUST_ANCHORS_DIFFER_FROM_REVIEWED_CA_SET')
        require(all(attributes(Path(path).lstat())==pin for path,pin in pins.items()),'CURRENT_TLS_TRUST_MATERIAL_CHANGED')
        budget.check();return cas,pins

    def session(self,namespace_fd,address,port,server_name,pem,budget):
        p=self.operational.worker.template['python']
        require(Path(sys.executable).resolve()==Path(p['path']).resolve(),'SAME_REVIEWED_NATIVE_TLS_PYTHON_REQUIRED')
        file_bytes(p['path'],0,{0o755},limit=p['maximumBytes'],expected=p['sha256'])
        params={'ip':address,'port':port,'serverName':server_name,'caPem':pem.decode('ascii'),
            'caFingerprints':sorted(certificates(pem,public_only=True)),'timeout':budget.remaining(5)}
        raw=encoded(params);require(len(raw)<=1048576,'BOUNDED_NATIVE_TLS_SESSION_INPUT_REQUIRED')
        result=subprocess.run([p['path'],'-I','-B','-S','-c',CHILD,str(namespace_fd)],input=raw,
            stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,pass_fds=(namespace_fd,),timeout=budget.remaining(6),
            env={'PATH':'/usr/bin:/bin','LC_ALL':'C'})
        require(result.returncode==0 and 0<len(result.stdout)<=4096,'CURRENT_NAMESPACE_TLS_IDENTITY_UNPROVEN')
        value=decode(result.stdout)
        require(type(value) is dict and set(value)=={'schema','tlsVersion','peerCertificateHash','hostnameAndChainVerified'}
            and value['schema']=='ouf.discovery-native-tls-session.v1' and value['tlsVersion'] in ('TLSv1.2','TLSv1.3')
            and hashed(value['peerCertificateHash']) and value['hostnameAndChainVerified'] is True,
            'EXACT_CURRENT_NATIVE_TLS_SESSION_REQUIRED')
        budget.check();return value

    def observe(self):
        budget=ObservationBudget(180);app=self.guard();held=self.runtime.selected.held();o=self.operational;w=o.worker
        material,proposal,snapshot,configuration,*_=o.base.material(budget);o.operational(material,proposal,configuration)
        w.verify_generation(material);cas,pins=self.trust(budget,proposal)
        running=RunningWorkloadBinding(w.node.engine,w.transition,w.node.request,w.store).observe()
        pid=running['runtimeBinding']['pid'];fd=os.open('/proc/'+str(pid)+'/ns/net',os.O_RDONLY|os.O_CLOEXEC)
        provider=snapshot['peers']['provider'];iam_role=self.inputs['endpoints']['iam']['peerRole']
        iam=self.runtime.inputs['peers'][iam_role]['runtimeBinding']
        reader=CurrentTlsEngine(w.node.engine,self.runtime.inputs['engineBinding'],[provider['containerId'],iam['containerId']],budget)
        def read_peers():
            values={}
            for role,binding in (('provider',provider),('iam',iam)):
                actual=reader.get(binding['containerId']);state=actual['State'];endpoint=self.inputs['endpoints'][role]
                require(state['Running'] is True and state['Paused'] is False and state['Restarting'] is False
                    and actual['RestartCount']==0,'CURRENT_TLS_PEER_RUNNING_GENERATION_REQUIRED')
                if role=='iam':require(Engine.runtime_binding(actual)==binding,'CURRENT_TLS_IAM_GENERATION_CHANGED')
                else:
                    from .native_generation_probe import DOCKER_FIELDS,ticks
                    require(digest({k:actual[k] for k in DOCKER_FIELDS})==binding['dockerBindingHash']
                        and state['Pid']==binding['pid'] and state['StartedAt']==binding['startedAt']
                        and ticks(binding['pid'])==binding['startTicks'],'CURRENT_TLS_PROVIDER_GENERATION_CHANGED')
                net=actual['NetworkSettings']['Networks'][endpoint['network']]
                expected_network=app.request['NetworkingConfig']['EndpointsConfig'][endpoint['network']]['NetworkID']
                address=ipaddress.ip_address(net['IPAddress']);url=urlsplit(app.profile.selection['references'][
                    'OUF_IAM_ISSUER' if role=='iam' else 'OUF_SCHEMA_GOV_GATEWAY_BASE_URL'])
                exposed=actual['NetworkSettings'].get('Ports') or {};mapped=exposed.get(str(endpoint['port'])+'/tcp') or []
                require(net['NetworkID']==expected_network and address.version==4 and address.is_private
                    and not address.is_loopback and not address.is_unspecified and not address.is_multicast
                    and (endpoint['port']==(url.port or 443) or any(v.get('HostPort')==str(url.port or 443) for v in mapped)),
                    'CURRENT_TLS_ENDPOINT_OUTSIDE_REVIEWED_PEER_NETWORK_OR_PORT')
                values[role]={'ip':str(address),'bindingHash':digest(Engine.runtime_binding(actual))}
            return values
        try:
            require(os.fstat(fd).st_ino==running['process']['generation']['namespaceInode'],'CURRENT_TLS_REGISTRY_NAMESPACE_CHANGED')
            peers=read_peers();sessions={}
            for _ in range(2):
                for role in ('iam','provider'):
                    endpoint=self.inputs['endpoints'][role]
                    value=self.session(fd,peers[role]['ip'],endpoint['port'],endpoint['serverName'],b'\n'.join(cas[role].values())+b'\n',budget)
                    require(role not in sessions or sessions[role]==value,'CURRENT_TLS_PEER_CERTIFICATE_CHANGED_DURING_READ')
                    sessions[role]=value
            current=o.observe()
            require(current['currentWorkerAndPositiveOwnedLeasesObserved'] is True and read_peers()==peers
                and self.trust(budget,proposal)==(cas,pins)
                and RunningWorkloadBinding(w.node.engine,w.transition,w.node.request,w.store).observe()==running
                and os.fstat(fd).st_ino==running['process']['generation']['namespaceInode'],
                'CURRENT_TLS_IDENTITIES_OR_ADMISSION_CHANGED_DURING_READ')
            self.guard();self.runtime.selected.held(held);budget.check()
        finally:os.close(fd)
        return {'schema':'ouf.discovery-current-tls-peer-identities.v1','inputHash':self.input_hash,
            'heldHistoryHash':digest(held),'tlsSessionsHash':digest(sessions),'operationalAdmissionHash':digest(current),
            'sameRegistryNamespaceUsed':True,'currentTlsIdentitiesObserved':True,'reviewedJavaTrustAnchorsObserved':True,
            'engineGets':4,'tlsHandshakes':4,'workloadCredentialAdmissionProvenHere':False,
            'httpApplicationReadinessProvenHere':False,'fullCohortProven':False,'newKeysGenerated':0,
            'runtimeAuthorityIssued':False,'targetApplyAuthorized':False,'releaseAcceptance':False}
