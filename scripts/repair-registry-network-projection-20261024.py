#!/usr/bin/env python3
"""One signed host IP projection repair; original service, IAM and ledger intact.

The kernel's exact live conntrack tuple must bind the configured TLS origin to
one current published container endpoint. A fresh reviewed mandate authorizes
one persistent IPAddressAllow update, without restarting the existing worker.
"""
import ast
import base64
import copy
import gzip
import hashlib
import http.client
import io
import ipaddress
import json
import os
from pathlib import Path
import re
import signal
import socket
import ssl
import stat
import struct
import subprocess
import sys
import termios
import time
import types
import urllib.parse

REVIEW='/etc/ouf/deploy-snapshots/semantic-registry-operational-review-e4e54229fd43165b0f11f9779d8428ac56a69201cff91c36fe1445cd305eed0f/review.json'
REVIEW_HASH='b67488693c49241d8b6bdf1691216847bd07d7057895a26aa35946442ee450fe'
CONFIG_HASH='0b72275fcc2c51be0929ca0ba454de932ae4863af1b2410dd67bef61bf81e91a'
INPUT_HASH='3bf787073c876f743ce7ec56963c8aea521545de2a8ed161df8e508f6d359550'
CAPTURE_HELPER='/etc/ouf/deploy-snapshots/semantic-network-policy-339637e5941e475b/capture.py'
CAPTURE_HELPER_HASH='339637e5941e475b24567ce6dc5c8ad72eef178e2da1c6f33231eef5c6db0020'
PROBE_HELPER='/etc/ouf/deploy-snapshots/semantic-network-probe-96f9f2da571e8b2f/probe.py'
PROBE_HELPER_HASH='96f9f2da571e8b2f56dbfd27f66fa7db40d60bb2a4e904a7e18d64895f8b6cc1'
CAPSULE='/etc/ouf/deploy-snapshots/semantic-checkpoint-review-launch.cgFB2WhS/capsule.py'
CAPSULE_HASH='f7d5c566dc3bab63873970ed781682d65f18f10aa69b01b74c037c9e1780cb57'
CLOSURE_HASH='e78fca8785b3424271e9edbb1900a78944f68d2bd512417f093360b772195200'
AUTHORITY_SCHEMA='ouf.registry-network-projection-authority.v1'
HUMAN_SCHEMA='ouf.registry-network-projection-human.v1'
DECISION='APPROVE_EXACT_EXISTING_IAM_NETWORK_PROJECTION'
COUNTS={'engineGetAttempts':0,'conntrackGetAttempts':0,'publicDiscoveryGetAttempts':0,
        'tlsConnectionAttempts':0,'managerMutationAttempts':0,'installationSigningOperations':0}


class Denied(RuntimeError):pass


def require(ok,code='NETWORK_PROJECTION_INPUT_UNPROVEN'):
    if not ok:raise Denied(code)


def encoded(value):return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def sha(raw):return hashlib.sha256(raw).hexdigest()
def digest(value):return sha(encoded(value))


def read(path,maximum,expected=None,mutable=False):
    path=Path(path);require(path.is_absolute() and '..'not in path.parts and len(path.parts)<=48)
    fds=[];pins=[]
    def identity(s):return (s.st_dev,s.st_ino,s.st_uid,s.st_gid,s.st_mode)
    def contents(s):return identity(s)+(s.st_size,s.st_mtime_ns)
    try:
        fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);fds.append(fd)
        for part in path.parts[1:-1]:
            s=os.fstat(fd);require(s.st_uid==0 and not s.st_mode&0o022)
            parent=fd;fd=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent);fds.append(fd)
            pins.append((parent,part,fd,identity(os.fstat(fd))))
        s=os.fstat(fd);require(s.st_uid==0 and not s.st_mode&0o022)
        leaf=os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=fd);fds.append(leaf);before=os.fstat(leaf)
        require(stat.S_ISREG(before.st_mode) and before.st_uid==0 and before.st_nlink==1
            and not before.st_mode&0o022 and 0<before.st_size<=maximum)
        raw=bytearray()
        while len(raw)<before.st_size:
            piece=os.read(leaf,min(65536,before.st_size-len(raw)));require(bool(piece));raw.extend(piece)
        require(contents(before)==contents(os.fstat(leaf)))
        if not mutable:require(contents(before)==contents(os.stat(path.name,dir_fd=fd,follow_symlinks=False)))
        for parent,part,child,pin in pins:require(pin==identity(os.fstat(child))==identity(os.stat(part,dir_fd=parent,follow_symlinks=False)))
        raw=bytes(raw);require(expected is None or sha(raw)==expected);return raw
    finally:
        for fd in reversed(fds):os.close(fd)


def json_at(path,expected=None,maximum=16777216,mutable=False):
    raw=read(path,maximum,expected,mutable);value=json.loads(raw)
    require(type(value)is dict and encoded(value)==raw);return value


def new_file(root,name,value):
    require(re.fullmatch('[A-Za-z0-9_.-]{1,160}',name) is not None)
    raw=value if type(value)is bytes else encoded(value);require(len(raw)<=16777216)
    directory=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        s=os.fstat(directory);require(s.st_uid==s.st_gid==0 and stat.S_IMODE(s.st_mode)==0o700)
        fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=directory)
        try:
            offset=0
            while offset<len(raw):
                count=os.write(fd,raw[offset:offset+65536]);require(count>0);offset+=count
            os.fsync(fd)
        finally:os.close(fd)
        os.fsync(directory)
    finally:os.close(directory)


def exclusive_root(parent,name):
    require(re.fullmatch('[A-Za-z0-9_.-]{1,160}',name)is not None)
    fd=os.open(parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        s=os.fstat(fd);require(s.st_uid==s.st_gid==0 and stat.S_IMODE(s.st_mode)==0o700)
        os.mkdir(name,0o700,dir_fd=fd);os.fsync(fd)
    finally:os.close(fd)
    return Path(parent)/name


def helper(path,expected,name):
    source=read(path,65536,expected);module=types.ModuleType(name)
    module.__file__=path;exec(compile(source,path,'exec'),module.__dict__);return module


def load_legacy():
    raw=read(CAPSULE,2097152,CAPSULE_HASH)
    values={node.targets[0].id:ast.literal_eval(node.value)for node in ast.parse(raw).body
        if isinstance(node,ast.Assign)and len(node.targets)==1 and isinstance(node.targets[0],ast.Name)}
    manifest=values['DELIVERY']['nativeDeclaration'];require(digest(manifest)==CLOSURE_HASH)
    with gzip.GzipFile(fileobj=io.BytesIO(base64.b64decode(values['PACKED'],validate=True)))as stream:
        payload=stream.read(16777217)
    require(0<len(payload)<=16777216);payload=json.loads(payload)
    loader=payload['loader'].encode();sources={key:value.encode()for key,value in payload['sources'].items()}
    require(len(sources)==142 and set(sources)==set(manifest['sourceHashes']) and sha(loader)==manifest['loaderHash']
        and all(sha(value)==manifest['sourceHashes'][key]for key,value in sources.items()))
    namespace={};exec(compile(loader,'<verified-network-projection-dependencies>','exec'),namespace)
    _,observed=namespace['load_entry'](manifest['sourceCommit'],sources,loader,digest(manifest),manifest['sourcePins'])
    require(observed==manifest)


def nla(kind,raw,nested=False):
    length=len(raw)+4;return struct.pack('=HH',length,kind|(0x8000 if nested else 0))+raw+b'\0'*((-length)%4)


def attrs(raw):
    result={};offset=0
    while offset<len(raw):
        require(offset+4<=len(raw),'KERNEL_FLOW_ATTRIBUTES_TRUNCATED')
        length,kind=struct.unpack_from('=HH',raw,offset);kind&=0x3fff
        require(length>=4 and offset+length<=len(raw) and kind not in result,'KERNEL_FLOW_ATTRIBUTES_UNPROVEN')
        result[kind]=raw[offset+4:offset+length];offset+=(length+3)&~3
    require(offset==len(raw),'KERNEL_FLOW_ATTRIBUTES_TRUNCATED');return result


def tuple_bytes(family,source,source_port,destination,destination_port):
    version=ipaddress.ip_address(source).version;require(version==ipaddress.ip_address(destination).version)
    require(family==(socket.AF_INET if version==4 else socket.AF_INET6))
    ip=nla(1 if version==4 else 3,socket.inet_pton(family,source))+nla(2 if version==4 else 4,socket.inet_pton(family,destination))
    proto=nla(1,b'\x06')+nla(2,struct.pack('!H',source_port))+nla(3,struct.pack('!H',destination_port))
    return nla(1,ip,True)+nla(2,proto,True)


def decode_tuple(family,raw):
    outer=attrs(raw);ip=attrs(outer[1]);proto=attrs(outer[2]);version=4 if family==socket.AF_INET else 6
    require(family in(socket.AF_INET,socket.AF_INET6) and proto[1]==b'\x06')
    source=socket.inet_ntop(family,ip[1 if version==4 else 3]);destination=socket.inet_ntop(family,ip[2 if version==4 else 4])
    require(len(proto[2])==len(proto[3])==2)
    return {'source':source,'sourcePort':struct.unpack('!H',proto[2])[0],
        'destination':destination,'destinationPort':struct.unpack('!H',proto[3])[0],'protocol':6}


def conntrack_flow(source,source_port,destination,destination_port):
    require(COUNTS['conntrackGetAttempts']<2,'KERNEL_FLOW_QUERY_BUDGET_EXHAUSTED')
    family=socket.AF_INET if ipaddress.ip_address(destination).version==4 else socket.AF_INET6
    original={'source':source,'sourcePort':source_port,'destination':destination,'destinationPort':destination_port,'protocol':6}
    COUNTS['conntrackGetAttempts']+=1
    with socket.socket(socket.AF_NETLINK,socket.SOCK_RAW,12)as control:
        control.bind((0,0));control.settimeout(3);sequence=int.from_bytes(os.urandom(4),'little')or 1
        body=struct.pack('!BBH',family,0,0)+nla(1,tuple_bytes(family,source,source_port,destination,destination_port),True)
        request=struct.pack('=IHHII',16+len(body),0x101,1,sequence,control.getsockname()[0])+body
        require(control.sendto(request,(0,0))==len(request))
        for _ in range(4):
            raw,sender=control.recvfrom(65536);require(sender[0]==0 and len(raw)>=16)
            offset=0
            while offset<len(raw):
                require(offset+16<=len(raw));length,kind,flags,seq,pid=struct.unpack_from('=IHHII',raw,offset)
                require(16<=length<=len(raw)-offset and seq==sequence)
                value=raw[offset+16:offset+length];offset+=(length+3)&~3
                if kind==2:
                    require(len(value)>=4 and struct.unpack_from('=i',value)[0]==0,'KERNEL_NAT_FLOW_UNPROVEN');continue
                require(kind>>8==1 and len(value)>=4 and value[0]==family,'KERNEL_NAT_FLOW_UNPROVEN')
                fields=attrs(value[4:]);observed=decode_tuple(family,fields[1]);reply=decode_tuple(family,fields[2])
                require(observed==original,'KERNEL_FLOW_IDENTITY_CHANGED')
                return {'original':observed,'reply':reply,'kernelOriginAuthenticated':True}
    raise Denied('KERNEL_NAT_FLOW_UNPROVEN')


def prove_origin(profile,ca,candidate):
    require(COUNTS['tlsConnectionAttempts']<2 and COUNTS['publicDiscoveryGetAttempts']<2,'ORIGIN_PROOF_BUDGET_EXHAUSTED')
    endpoint=urllib.parse.urlsplit(profile['issuer']);peer=profile['peer_addresses'][0];port=endpoint.port or 443
    require(endpoint.scheme=='https' and endpoint.hostname and not endpoint.username and not endpoint.query and not endpoint.fragment)
    family=socket.AF_INET if ipaddress.ip_address(peer).version==4 else socket.AF_INET6
    context=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT);context.load_verify_locations(cadata=ca.decode('ascii'))
    COUNTS['tlsConnectionAttempts']+=1;deadline=time.monotonic()+12
    def timeout(*_):raise TimeoutError()
    previous=signal.signal(signal.SIGALRM,timeout);signal.alarm(15)
    try:
        with socket.socket(family,socket.SOCK_STREAM)as raw:
            raw.settimeout(5);raw.connect((peer,port));raw.settimeout(max(0.01,deadline-time.monotonic()))
            with context.wrap_socket(raw,server_hostname=endpoint.hostname)as secured:
                require(str(ipaddress.ip_address(secured.getpeername()[0]))==peer,'CONFIGURED_TLS_PEER_CHANGED')
                local=secured.getsockname();flow=conntrack_flow(str(ipaddress.ip_address(local[0])),local[1],peer,port)
                require(flow['reply']['source']==candidate['address'] and flow['reply']['sourcePort']==candidate['port'],
                    'OBSERVED_KERNEL_NAT_TARGET_DIFFERS_FROM_CANDIDATE')
                require((peer,port)!=(candidate['address'],candidate['port']),'TRANSLATED_PROVIDER_PATH_REQUIRED')
                path=endpoint.path+'/.well-known/openid-configuration'
                require(all(33<=ord(char)<=126 for char in path+endpoint.netloc))
                request=('GET '+path+' HTTP/1.1\r\nHost: '+endpoint.netloc+'\r\nAccept: application/json\r\nConnection: close\r\n\r\n').encode('ascii')
                secured.settimeout(max(0.01,deadline-time.monotonic()));COUNTS['publicDiscoveryGetAttempts']+=1;secured.sendall(request)
                response=http.client.HTTPResponse(secured)
                try:
                    response.begin();body=response.read(65537)
                    require(response.status==200 and len(body)<=65536
                        and response.getheader('Content-Type','').split(';')[0].strip().lower()=='application/json',
                        'AUTHENTICATED_PUBLIC_DISCOVERY_REQUIRED')
                    def unique(pairs):
                        value={}
                        for key,item in pairs:require(key not in value);value[key]=item
                        return value
                    value=json.loads(body,object_pairs_hook=unique)
                    require(type(value)is dict and value.get('issuer')==profile['issuer']
                        and value.get('token_endpoint')==profile['token_endpoint'] and value.get('introspection_endpoint')==profile['introspection_endpoint'],
                        'ORIGINAL_IAM_DISCOVERY_IDENTITY_REQUIRED')
                finally:response.close()
                return {'schema':'ouf.registry-original-iam-nat-flow-proof.v1','flow':flow,
                    'certificateChainAndHostnameVerified':True,'originalConfiguredPeerUsed':True,'publicDiscoveryMatched':True,
                    'publicDiscoveryStatus':200,'observedAt':int(time.time()),'credentialFilesOpened':0,'oauthGrantRequests':0}
    finally:signal.alarm(0);signal.signal(signal.SIGALRM,previous)


def runtime_pin(row):
    require(type(row)is dict and re.fullmatch('[a-f0-9]{64}',row.get('Id',''))is not None)
    s=row['State'];require(s['Running']is True and s['Paused']is False and s['Restarting']is False and s['Dead']is False)
    return {'containerId':row['Id'],'imageId':row['Image'],'pid':s['Pid'],'startedAt':s['StartedAt'],
        'restartCount':row['RestartCount'],'configHash':digest(row['Config']),'hostConfigHash':digest(row['HostConfig']),
        'mountsHash':digest(sorted(row['Mounts'],key=lambda m:m['Destination'])),'networkSettingsHash':digest(row['NetworkSettings'])}


def engine_get(binding,path):
    require(COUNTS['engineGetAttempts']<4 and (path=='/v1.44/containers/json?all=1' or re.fullmatch('/v1.44/containers/[a-f0-9]{64}/json',path)),
        'BOUNDED_NAT_PROVIDER_GET_REQUIRED')
    info=os.stat(binding['socketPath'],follow_symlinks=False)
    require(stat.S_ISSOCK(info.st_mode) and info.st_uid==0 and stat.S_IMODE(info.st_mode)in(0o600,0o660)
        and list((info.st_dev,info.st_ino,info.st_uid,info.st_gid,stat.S_IMODE(info.st_mode)))==binding['socketBinding'])
    COUNTS['engineGetAttempts']+=1;engine_path=binding['socketPath']
    class Local(http.client.HTTPConnection):
        def connect(self):
            self.sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);self.sock.settimeout(5);self.sock.connect(engine_path)
    connection=Local('localhost',timeout=5)
    try:
        connection.request('GET',path,headers={'Connection':'close'});response=connection.getresponse();raw=response.read(4194305)
        require(response.status==200 and len(raw)<=4194304,'BOUNDED_PROVIDER_INVENTORY_REQUIRED')
        current=os.stat(engine_path,follow_symlinks=False)
        require((info.st_dev,info.st_ino,info.st_uid,info.st_gid,info.st_mode)==(current.st_dev,current.st_ino,current.st_uid,current.st_gid,current.st_mode))
        return json.loads(raw)
    finally:connection.close()


def endpoint_owner(inventory,address):
    require(type(inventory)is list and len(inventory)<=512,'BOUNDED_PROVIDER_INVENTORY_REQUIRED')
    matches=[]
    for row in inventory:
        if row.get('State')!='running':continue
        networks=row.get('NetworkSettings',{}).get('Networks',{})
        if any(address in(network.get('IPAddress'),network.get('GlobalIPv6Address'))for network in networks.values()):matches.append(row['Id'])
    require(len(set(matches))==1,'EXACT_SINGLE_CURRENT_NAT_PROVIDER_REQUIRED')
    cid=matches[0];require(re.fullmatch('[a-f0-9]{64}',cid)is not None);return cid


def publication_matches(row,candidate,peer,port):
    address=candidate['address'];networks=row['NetworkSettings']['Networks'];assigned=False;found=False
    for network in networks.values():
        for field,ipam in(('IPAddress','IPv4Address'),('GlobalIPv6Address','IPv6Address')):
            if network.get(field)==address:
                found=True;assigned=assigned or (network.get('IPAMConfig')or{}).get(ipam)==address
    published=False
    for mapping in row['NetworkSettings'].get('Ports',{}).get(str(candidate['port'])+'/tcp')or[]:
        host=ipaddress.ip_address(mapping['HostIp']);original=ipaddress.ip_address(peer)
        if mapping['HostPort']==str(port)and host.version==original.version and (host.is_unspecified or host==original):published=True
    require(found and published,'CURRENT_NAT_PROVIDER_PUBLICATION_REQUIRED');return assigned


def compile_review(c,old_review,inputs,candidate,owner,proof,before,helper_module,source_pin,baseline):
    peer=c['ownerInputs']['iamProfile']['peer_addresses'][0];address=candidate['address']
    require(inputs['configurationHash']==CONFIG_HASH and inputs['reviewHash']==REVIEW_HASH and inputs['routes']['peerIsLocal']is True
        and proof['originalConfiguredPeerUsed']is True and proof['certificateChainAndHostnameVerified']is True
        and proof['publicDiscoveryMatched']is True and proof['flow']['kernelOriginAuthenticated']is True,
        'ORIGINAL_IAM_PHYSICAL_PATH_PROOF_REQUIRED')
    require(proof['flow']['original']['destination']==peer and proof['flow']['reply']['source']==address
        and proof['flow']['reply']['sourcePort']==candidate['port'],'EXACT_OBSERVED_PHYSICAL_TARGET_REQUIRED')
    expected=sorted(str(ipaddress.ip_network(ip+'/'+str(ipaddress.ip_address(ip).max_prefixlen)))
        for ip in c['ownerInputs']['iamProfile']['peer_addresses'])
    networks=helper_module.network_list(before.get('IPAddressAllow',''));require(networks is not None)
    observed=sorted(str(net)for net in networks)
    require(observed==expected and helper_module.permitted(peer,before)is True
        and helper_module.permitted(address,before)is False and not before.get('DropInPaths',''),
        'UNCHANGED_REVIEWED_LOGICAL_PEER_ALLOWLIST_REQUIRED')
    for parent in inputs['policies'][1:]:
        require(helper_module.permitted(address,parent['properties'])is True,'PARENT_POLICY_EXCLUDES_PROVIDER_PATH')
    projected=sorted(set(observed+[str(ipaddress.ip_network(address+'/'+str(ipaddress.ip_address(address).max_prefixlen)))]))
    require(len(projected)==len(observed)+1,'ONE_PHYSICAL_HOST_ADDRESS_ADDITION_REQUIRED')
    require(type(baseline['cumulativeAttempts'])is int and baseline['cumulativeAttempts']>=321
        and baseline['priorControlledAttempts']==321 and baseline['publications']==0,
        'RETAINED_NORMAL_OWNER_PROGRESS_REQUIRED')
    return {'schema':'ouf.registry-network-projection-review.v1','configurationHash':CONFIG_HASH,'installationReviewHash':REVIEW_HASH,
        'configurationBinding':{'path':c['destinations']['installationRoot']+'/configuration.json','sha256':CONFIG_HASH},
        'inputCaptureHash':INPUT_HASH,'sourcePin':source_pin,'sourceDependencies':{'legacyCapsuleHash':CAPSULE_HASH,
            'legacyClosureHash':CLOSURE_HASH,'captureHelperHash':CAPTURE_HELPER_HASH,'probeHelperHash':PROBE_HELPER_HASH},
        'verification':copy.deepcopy(c['verification']),'executables':copy.deepcopy(old_review['executables']),
        'unitPath':c['serviceUnitPath'],'unitHash':old_review['serviceUnit']['sha256'],'unitName':Path(c['serviceUnitPath']).name,
        'originalUnitProperties':copy.deepcopy(before),'originalAllowlist':observed,'projectedAllowlist':projected,
        'candidate':copy.deepcopy(candidate),'providerPin':runtime_pin(owner),'providerNetworkSettings':copy.deepcopy(owner['NetworkSettings']),
        'originProof':copy.deepcopy(proof),'baselineCumulativeAttempts':baseline['cumulativeAttempts'],
        'normalPolicyHash':digest(c['policy']),'maximumManagerMutationCommands':1,'maximumSeconds':900,
        'persistentHostNetworkProjection':True,'workerRestartAllowed':False,'ownerLedgerWritesAllowed':False,
        'newGrantBudgetAllowed':False,'logicalIssuerPeerUrlPortAndTrustChanged':False,'normalGrantMandateChanged':False,
        'runtimeAuthorityIssued':False,'targetApplyAuthorized':False,'automaticReplayAllowed':False,'budgetReset':False,'releaseAcceptance':False}


def scope(review):
    require(review['schema']=='ouf.registry-network-projection-review.v1' and review['configurationHash']==CONFIG_HASH
        and review['inputCaptureHash']==INPUT_HASH and review['maximumManagerMutationCommands']==1
        and review['maximumSeconds']==900 and review['workerRestartAllowed']is False
        and review['ownerLedgerWritesAllowed']is False and review['newGrantBudgetAllowed']is False
        and review['logicalIssuerPeerUrlPortAndTrustChanged']is False and review['normalGrantMandateChanged']is False)
    binding=review['configurationBinding'];require(binding['sha256']==CONFIG_HASH)
    c=json_at(binding['path'],CONFIG_HASH)
    require(binding['path']==c['destinations']['installationRoot']+'/configuration.json'
        and review['unitPath']==c['serviceUnitPath'] and review['unitName']==Path(c['serviceUnitPath']).name
        and review['verification']==c['verification'] and review['normalPolicyHash']==digest(c['policy']),
        'EXACT_INSTALLED_NETWORK_PROJECTION_TARGET_REQUIRED')
    profile=c['ownerInputs']['iamProfile'];peer=profile['peer_addresses'][0];port=urllib.parse.urlsplit(profile['issuer']).port or 443
    expected=sorted(str(ipaddress.ip_network(ip+'/'+str(ipaddress.ip_address(ip).max_prefixlen)))for ip in profile['peer_addresses'])
    require(review['originalAllowlist']==expected and review['originProof']['flow']['original']['destination']==peer
        and review['originProof']['flow']['original']['destinationPort']==port
        and review['originProof']['flow']['reply']['source']==review['candidate']['address']
        and review['originProof']['flow']['reply']['sourcePort']==review['candidate']['port']
        and review['originProof']['originalConfiguredPeerUsed']is True
        and review['originProof']['certificateChainAndHostnameVerified']is True
        and review['originProof']['publicDiscoveryMatched']is True
        and review['originProof']['flow']['kernelOriginAuthenticated']is True,
        'EXACT_ORIGINAL_ISSUER_PHYSICAL_PATH_SCOPE_REQUIRED')
    require(digest(review['providerNetworkSettings'])==review['providerPin']['networkSettingsHash'])
    publication_matches({'NetworkSettings':review['providerNetworkSettings']},review['candidate'],peer,port)
    require(set(review['projectedAllowlist'])==set(review['originalAllowlist'])|{
        str(ipaddress.ip_network(review['candidate']['address']+'/'+str(ipaddress.ip_address(review['candidate']['address']).max_prefixlen)))}
        and len(review['projectedAllowlist'])==len(review['originalAllowlist'])+1)
    return {'schema':'ouf.registry-network-projection-scope.v1','reviewHash':digest(review),'configurationHash':CONFIG_HASH,
        'providerPinHash':digest(review['providerPin']),'originProofHash':digest(review['originProof']),
        'beforeAllowlist':review['originalAllowlist'],'afterAllowlist':review['projectedAllowlist'],
        'maximumManagerMutationCommands':1,'workerRestartAllowed':False,'ownerLedgerWritesAllowed':False,
        'grantBudgetChanged':False,'iamPermissionChangesAllowed':False,'nativeRecoveryReplayAllowed':False}


class SignedProjection:
    def __init__(self,review,raw,human_path,human_hash,verifier):
        from tools.semantic_provider_deployment_authentication import DetachedAuthenticator
        require(type(verifier)is DetachedAuthenticator,'ACTUAL_EXISTING_ROLE_VERIFIER_REQUIRED')
        self.review=copy.deepcopy(review);self.raw=raw;self.human_path=human_path;self.human_hash=human_hash;self.verifier=verifier
        self.check()

    def check(self):
        from tools.semantic_provider_deployment_authentication import policy as current_policy
        human=json_at(self.human_path,self.human_hash);authority=json.loads(self.raw);ctx=self.review['verification']['context']
        require(encoded(authority)==self.raw and authority=={'schema':AUTHORITY_SCHEMA,'scope':scope(self.review),
            'issuedAt':human['issuedAt'],'expiresAt':human['expiresAt'],'installationRef':ctx['installationRef'],
            'entityRef':ctx['entityRef'],'automaticReplayAllowed':False,'budgetReset':False,'releaseAcceptance':False},
            'EXACT_NETWORK_PROJECTION_AUTHORITY_REQUIRED')
        require(set(human)=={'schema','reviewHash','authorityHash','decision','state','issuedAt','expiresAt'}
            and human['schema']==HUMAN_SCHEMA and human['reviewHash']==digest(self.review) and human['authorityHash']==sha(self.raw)
            and human['decision']==DECISION and human['state']=='ACTIVE' and type(human['issuedAt'])is int and type(human['expiresAt'])is int
            and human['expiresAt']-human['issuedAt']==900 and human['issuedAt']<=time.time()<human['expiresAt'],
            'FRESH_EXACT_FINITE_NETWORK_PROJECTION_MANDATE_REQUIRED')
        v=self.review['verification']
        require(self.verifier.policy_binding==v['trustPolicy'] and self.verifier.openssl_binding==v['openssl'])
        for role,key in(('DEPLOYMENT_INTENT','intentIssuerRef'),('FINAL_DEPLOYMENT_APPROVAL','approvalIssuerRef')):
            require(self.verifier(self.raw,role,ctx[key],ctx['installationRef'],ctx['entityRef'])is True,
                'CURRENT_DUAL_NETWORK_PROJECTION_SIGNATURES_REQUIRED')
        policy=current_policy(self.verifier.read_policy(),ctx['installationRef'],ctx['entityRef'],time.time())
        for role,key in(('DEPLOYMENT_INTENT','intentIssuerRef'),('FINAL_DEPLOYMENT_APPROVAL','approvalIssuerRef'),('CREATION_ATTESTATION','attestorRef')):
            keys=[item for item in policy['keys']if role in item['roles']and item['issuerRef']==ctx[key]
                and item['state']=='ACTIVE' and item['notBefore']<=human['issuedAt']]
            require(len(keys)==1 and keys[0]['expiresAt']>=human['expiresAt'],'WHOLE_PROJECTION_WINDOW_WITHIN_SCOPED_KEY_AUTHORITY_REQUIRED')
        return True


def issue(review,root,profile):
    from tools.semantic_provider_deployment_authentication import DetachedAuthenticator
    from tools.semantic_provider_deployment_signing import ExistingEd25519Signer
    prompt=('\nCorrezione permanente della proiezione IP del rinnovatore esistente.\nRevisione privata: '+str(root/'review.json')+
        '\nSHA256: '+digest(review)+'\nAggiunge un solo indirizzo fisico, provato dal kernel e dal TLS dell’issuer originale.'+
        '\nNessun riavvio, modifica IAM, nuovo budget o scrittura del registro del rinnovatore.'+
        ('\nIl frontend ha un indirizzo dinamico: un suo cambio richiedera riconciliazione della proiezione.'
            if review.get('physicalProjectionRequiresReconciliationIfEndpointChanges')else'')+
        '\nScrivi APPROVO '+digest(review)+' per autorizzare questa revisione esatta.\n> ')
    fd=os.open('/dev/tty',os.O_RDWR|os.O_NOCTTY|os.O_NOFOLLOW)
    try:
        require(stat.S_ISCHR(os.fstat(fd).st_mode) and os.isatty(fd),'CONTROLLING_NETWORK_REPAIR_TERMINAL_REQUIRED')
        termios.tcflush(fd,termios.TCIFLUSH);os.write(fd,prompt.encode());answer=bytearray()
        while len(answer)<=128:
            char=os.read(fd,1)
            if char in(b'',b'\n'):break
            answer.extend(char)
        require(bytes(answer)==('APPROVO '+digest(review)).encode(),'EXACT_NETWORK_PROJECTION_NOT_APPROVED')
    finally:os.close(fd)
    require(json_at(root/'review.json',digest(review))==review,'REVIEW_CHANGED_DURING_APPROVAL')
    signatures=exclusive_root(root,'authority');now=int(time.time());ctx=review['verification']['context'];v=review['verification']
    raw=encoded({'schema':AUTHORITY_SCHEMA,'scope':scope(review),'issuedAt':now,'expiresAt':now+900,
        'installationRef':ctx['installationRef'],'entityRef':ctx['entityRef'],'automaticReplayAllowed':False,'budgetReset':False,'releaseAcceptance':False})
    human={'schema':HUMAN_SCHEMA,'reviewHash':digest(review),'authorityHash':sha(raw),'decision':DECISION,'state':'ACTIVE',
        'issuedAt':now,'expiresAt':now+900}
    new_file(signatures,'authority.json',raw);new_file(signatures,'human.json',human)
    verifier=DetachedAuthenticator(v['trustPolicy'],str(signatures),v['openssl'])
    for role,key in(('DEPLOYMENT_INTENT','intentIssuerRef'),('FINAL_DEPLOYMENT_APPROVAL','approvalIssuerRef')):
        signer=ExistingEd25519Signer(profile['keyBindings']['installer'],profile['keyRefs']['installer'],verifier,
            {'role':role,'issuerRef':ctx[key],'installationRef':ctx['installationRef'],'entityRef':ctx['entityRef']})
        COUNTS['installationSigningOperations']+=1
        new_file(signatures,sha(raw)+'.'+role+'.json',signer.sign(raw))
    gate=SignedProjection(review,raw,str(signatures/'human.json'),digest(human),verifier)
    print(encoded({'schema':'ouf.registry-network-projection-issued.v1','reviewHash':digest(review),'authorityHash':sha(raw),
        'runtimeAuthorityIssued':True,'managerMutationAttempts':0,'automaticReplayAllowed':False,'budgetReset':False,'releaseAcceptance':False}).decode(),flush=True)
    return gate


def source_check(review):
    read(review['sourcePin']['path'],131072,review['sourcePin']['sha256'])
    read(CAPTURE_HELPER,65536,CAPTURE_HELPER_HASH);read(PROBE_HELPER,65536,PROBE_HELPER_HASH);read(CAPSULE,2097152,CAPSULE_HASH)
    read(review['unitPath'],65536,review['unitHash'])
    for name in('python','openssl','systemctl'):
        item=review['executables'][name];read(item['path'],67108864,item['sha256'])


def apply_projection(review,gate,root,helper_module,current_guard,attestor):
    require(type(gate)is SignedProjection and gate.review==review,'ACTUAL_EXACT_NETWORK_PROJECTION_GATE_REQUIRED')
    from tools.semantic_provider_deployment_signing import ExistingEd25519Signer
    ctx=review['verification']['context']
    require(type(gate)is SignedProjection and gate.review==review and type(attestor)is ExistingEd25519Signer
        and attestor.verifier is gate.verifier and attestor.scope=={'role':'CREATION_ATTESTATION','issuerRef':ctx['attestorRef'],
            'installationRef':ctx['installationRef'],'entityRef':ctx['entityRef']},'ACTUAL_EXACT_NETWORK_PROJECTION_GATE_REQUIRED')
    gate.check();source_check(review);current_guard('BEFORE_AUTHORITY')
    fresh=json_at(root/'fresh-origin-proof.json');original=review['originProof']['flow']['original']
    human=json_at(gate.human_path,gate.human_hash)
    require(fresh['schema']=='ouf.registry-original-iam-nat-flow-proof.v1'
        and type(fresh['observedAt'])is int and human['issuedAt']<=fresh['observedAt']<=time.time()
        and time.time()-fresh['observedAt']<=60 and fresh['certificateChainAndHostnameVerified']is True
        and fresh['publicDiscoveryMatched']is True and fresh['originalConfiguredPeerUsed']is True
        and fresh['flow']['kernelOriginAuthenticated']is True
        and fresh['flow']['original']['destination']==original['destination']
        and fresh['flow']['original']['destinationPort']==original['destinationPort']
        and fresh['flow']['reply']['source']==review['candidate']['address']
        and fresh['flow']['reply']['sourcePort']==review['candidate']['port'],'FRESH_APPROVED_PROVIDER_PATH_REQUIRED')
    program=review['executables']['systemctl'];binding={'path':program['path'],'resolved':str(Path(program['path']).resolve()),'sha256':program['sha256']}
    before=helper_module.unit_properties(binding,review['unitName'])
    require(before==review['originalUnitProperties'],'EFFECTIVE_UNIT_PROPERTIES_CHANGED_BEFORE_PROJECTION')
    new_file(root,'manager-effect-claim.json',{'reviewHash':digest(review),'maximumCommands':1,'attemptNotCompletion':True})
    gate.check();source_check(review);current_guard('BEFORE_EFFECT')
    require(COUNTS['managerMutationAttempts']==0,'SINGLE_NETWORK_PROJECTION_EFFECT_REQUIRED')
    gate.check()
    require(helper_module.unit_properties(binding,review['unitName'])==before,
        'CONCURRENT_EFFECTIVE_NETWORK_POLICY_CHANGE')
    require(time.time()-fresh['observedAt']<=60,'FRESH_PROVIDER_PROOF_EXPIRED_BEFORE_EFFECT')
    COUNTS['managerMutationAttempts']+=1
    result=subprocess.run([program['path'],'set-property',review['unitName'],'IPAddressAllow='+' '.join(review['projectedAllowlist'])],
        stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=15,
        env={'PATH':'/usr/bin:/bin','LC_ALL':'C'})
    require(result.returncode==0,'NETWORK_PROJECTION_EFFECT_REQUIRES_RECONCILIATION')
    after=helper_module.unit_properties(binding,review['unitName'])
    actual=helper_module.network_list(after['IPAddressAllow']);require(actual is not None)
    require(sorted(str(net)for net in actual)==review['projectedAllowlist']
        and all(after[key]==before[key]for key in('ActiveState','MainPID','NRestarts','ControlGroup','RootDirectory','IPAddressDeny','FragmentPath')),
        'LIVE_NETWORK_PROJECTION_READBACK_REQUIRED')
    drops=after.get('DropInPaths','').split();old=before.get('DropInPaths','').split();added=[path for path in drops if path not in old]
    require(len(added)==1 and added[0].endswith('/50-IPAddressAllow.conf') and added[0].startswith('/etc/systemd/system.control/'),
        'PERSISTENT_EXACT_NETWORK_PROJECTION_DROPIN_REQUIRED')
    drop_raw=read(added[0],65536);gate.check();source_check(review);current_guard('AFTER_EFFECT')
    receipt={'schema':'ouf.registry-network-projection-receipt.v1','reviewHash':digest(review),'authorityHash':sha(gate.raw),
        'configurationHash':CONFIG_HASH,'unitBaseHash':review['unitHash'],'providerPinHash':digest(review['providerPin']),
        'freshOriginProofHash':digest(fresh),
        'effectiveAllowlist':review['projectedAllowlist'],'dropInBinding':{'path':added[0],'sha256':sha(drop_raw)},
        'persistentProjectionInstalled':True,'workerRestarted':False,'normalGrantMandateChanged':False,
        'ownerLedgerWrites':0,'managerMutationAttempts':1,'automaticReplayAllowed':False,'budgetReset':False,'releaseAcceptance':False}
    raw=encoded(receipt);COUNTS['installationSigningOperations']+=1;signature=attestor.sign(raw)
    new_file(root,'receipt.json',raw);new_file(gate.verifier.signature_directory,sha(raw)+'.CREATION_ATTESTATION.json',signature)
    require(gate.verifier(raw,'CREATION_ATTESTATION',review['verification']['context']['attestorRef'],
        review['verification']['context']['installationRef'],review['verification']['context']['entityRef'])is True,
        'CURRENT_SIGNED_NETWORK_PROJECTION_RECEIPT_REQUIRED')
    return after


def ledger(c):
    row=json_at(Path(c['destinations']['ledgerRoot'])/'state.json',mutable=True)
    require(row['installationHash']==CONFIG_HASH and row['priorControlledAttempts']==321
        and type(row['attempts'])is int and row['cumulativeAttempts']==321+row['attempts'],
        'UNCHANGED_NORMAL_OWNER_COUNTER_LINEAGE_REQUIRED')
    return row


def public_progress(row):
    require(row['state']in('READY','RESERVED','DISPATCHING','PUBLISHING','ACTIVE','RETRY_WAIT','BLOCKED','REVOKED'))
    return {'schema':'ouf.registry-network-projection-owner-progress.v1','workerState':row['state'],
        'controlledCumulativeGrantAttempts':row['cumulativeAttempts'],'newOperationalGrantAttempts':row['attempts'],
        'publications':row['publications'],'lastPublishedWindowPositive':row['tokenExpiresWall']is not None and row['tokenExpiresWall']>time.time(),
        'serviceCredentialFilesOpened':0,'oauthGrantRequestsByRepair':0,'ownerLedgerWrites':0,
        'automaticReplayAllowed':False,'budgetReset':False,'originalSemanticGetSucceeded':False,'releaseAcceptance':False}


def wait_publication(c,seconds=330):
    until=time.monotonic()+seconds;last=None;emitted=0;row=ledger(c)
    while True:
        row=ledger(c);public=public_progress(row)
        if public!=last or time.monotonic()-emitted>=15:
            print(encoded(public).decode(),flush=True);last=public;emitted=time.monotonic()
        if row['state']=='ACTIVE' and row['publications']>=1:return row
        if row['state']in('BLOCKED','REVOKED')or time.monotonic()>=until:return row
        time.sleep(3)


def rebind_python(old_review):
    require(os.geteuid()==os.getegid()==0 and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode and len(sys.argv)==1,
        'ONE_ISOLATED_ROOT_NETWORK_PROJECTION_INVOCATION_REQUIRED')
    target=old_review['executables']['python'];read(target['path'],67108864,target['sha256'])
    if str(Path(sys.executable).resolve(strict=True))!=target['path']:
        script=str(Path(sys.argv[0]).resolve(strict=True));read(script,131072)
        os.execve(target['path'],[target['path'],'-I','-B','-S',script],
            {'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C','OPENSSL_CONF':'/dev/null'})


def operator():
    old_review=json_at(REVIEW,REVIEW_HASH);rebind_python(old_review)
    c=old_review['configuration'];require(digest(c)==CONFIG_HASH)
    install=Path(c['destinations']['installationRoot']);require(json_at(install/'configuration.json',CONFIG_HASH)==c)
    read(c['serviceUnitPath'],65536,old_review['serviceUnit']['sha256'])
    inputs=json_at(install/'network-policy-capture-v1'/'inputs.json',INPUT_HASH)
    require(inputs['configurationHash']==CONFIG_HASH and inputs['reviewHash']==REVIEW_HASH
        and len(inputs['candidates'])==1 and inputs['routes']['peerIsLocal']is True,
        'ONE_RETAINED_LOCAL_NAT_CANDIDATE_REQUIRED')
    candidate=inputs['candidates'][0];require(inputs['workerObservation']['controlledCumulativeGrantAttempts']>=398)
    source_path=str(Path(sys.argv[0]).resolve(strict=True));source_pin={'path':source_path,'sha256':sha(read(source_path,131072))}
    capture=helper(CAPTURE_HELPER,CAPTURE_HELPER_HASH,'ouf_projection_capture_dependencies')
    probe=helper(PROBE_HELPER,PROBE_HELPER_HASH,'ouf_projection_probe_dependencies')
    load_legacy()
    from tools.semantic_registry_recovery_execution.postboot_authority import authority_metadata
    from tools.semantic_policy_token_owner.iam_owner_action import stdlib_binding
    from tools.semantic_provider_deployment_signing import ExistingEd25519Signer
    retained_binding=old_review['proposal']['inputsBinding'];retained=json_at(retained_binding['path'],retained_binding['sha256'])
    public_authority=retained['review']['authorityInputs'];profile,_=authority_metadata(public_authority)
    require(digest(stdlib_binding())==public_authority['stdlibHash'],'RETAINED_INTERPRETER_STDLIB_CUSTODY_REQUIRED')
    operation_root=exclusive_root(install,'network-projection-repair-v1')
    new_file(operation_root,'claim.json',{'inputCaptureHash':INPUT_HASH,'sourcePin':source_pin,'automaticReplayAllowed':False,
        'maximumManagerMutationCommands':1,'maximumParentTlsConnections':2,'maximumParentPublicDiscoveryGets':2,
        'maximumVerificationProbeCgroupWrites':1,'maximumVerificationProbeMountJoins':1})
    capture.DEADLINE=time.monotonic()+60;program=old_review['executables']['systemctl']
    manager_binding={'path':program['path'],'resolved':str(Path(program['path']).resolve()),'sha256':program['sha256']}
    unit=Path(c['serviceUnitPath']).name;before=capture.unit_properties(manager_binding,unit)
    require(before==inputs['policies'][0]['properties'],'NETWORK_POLICY_CHANGED_SINCE_CAPTURE')
    require(before['ActiveState']=='active' and int(before['MainPID'])>1 and before['RootDirectory']==str(install/'sandbox'))
    baseline=ledger(c);require(baseline['cumulativeAttempts']>=inputs['workerObservation']['controlledCumulativeGrantAttempts'],
        'CAPTURED_COUNTER_HISTORY_MUST_BE_RETAINED')
    ca=read(c['tlsCa']['path'],4194304,c['tlsCa']['sha256'])
    original_profile=c['ownerInputs']['iamProfile'];peer=original_profile['peer_addresses'][0]
    port=urllib.parse.urlsplit(original_profile['issuer']).port or 443
    inventory=engine_get(inputs['engineBinding'],'/v1.44/containers/json?all=1')
    cid=endpoint_owner(inventory,candidate['address']);owner=engine_get(inputs['engineBinding'],'/v1.44/containers/'+cid+'/json')
    assigned=publication_matches(owner,candidate,peer,port);pin=runtime_pin(owner)
    proof=prove_origin(original_profile,ca,candidate)
    proposal=compile_review(c,old_review,inputs,candidate,owner,proof,before,capture,source_pin,baseline)
    proposal['physicalAddressExplicitlyAssigned']=assigned
    proposal['physicalProjectionRequiresReconciliationIfEndpointChanges']=not assigned
    # Recompile the exact private scope before asking the terminal to approve it.
    scope(proposal);new_file(operation_root,'review.json',proposal)
    print(encoded({'schema':'ouf.registry-network-projection-preparation.v1','status':'EXACT_KERNEL_PROVIDER_PROJECTION_REVIEW_PREPARED',
        'privateReviewPath':str(operation_root/'review.json'),'reviewHash':digest(proposal),'kernelNatPathProven':True,
        'originalIamTlsAndDiscoveryProven':True,'currentNatProviderEndpointEstablished':True,
        'physicalAddressExplicitlyAssigned':assigned,'projectionRequiresReconciliationIfEndpointChanges':not assigned,
        'priorControlledGrantAttempts':baseline['cumulativeAttempts'],'managerMutationAttempts':0,'serviceCredentialFilesOpened':0,
        'oauthGrantRequestsByRepair':0,'runtimeAuthorityIssued':False,'automaticReplayAllowed':False,'budgetReset':False,
        'originalSemanticGetSucceeded':False,'releaseAcceptance':False}).decode(),flush=True)
    gate=issue(proposal,operation_root,profile);ctx=c['verification']['context']
    attestor=ExistingEd25519Signer(profile['keyBindings']['attestor'],profile['keyRefs']['attestor'],gate.verifier,
        {'role':'CREATION_ATTESTATION','issuerRef':ctx['attestorRef'],'installationRef':ctx['installationRef'],'entityRef':ctx['entityRef']})
    capture.DEADLINE=time.monotonic()+60
    for parent in inputs['policies'][1:]:
        actual=capture.unit_properties(manager_binding,parent['unit'])
        require(actual==parent['properties'] and capture.permitted(candidate['address'],actual)is True,
            'UNCHANGED_PARENT_POLICY_FOR_PHYSICAL_PATH_REQUIRED')
    fresh=prove_origin(original_profile,ca,candidate);new_file(operation_root,'fresh-origin-proof.json',fresh)
    guard_phases=[]
    def current_guard(phase):
        expected=('BEFORE_AUTHORITY','BEFORE_EFFECT','AFTER_EFFECT')
        require(len(guard_phases)<3 and phase==expected[len(guard_phases)],'EXACT_NETWORK_EFFECT_GUARD_ORDER_REQUIRED')
        guard_phases.append(phase)
        require(json_at(REVIEW,REVIEW_HASH)==old_review and json_at(install/'configuration.json',CONFIG_HASH)==c)
        require(json_at(operation_root/'review.json',digest(proposal))==proposal)
        # One fresh provider read before effect, then one after effect.
        if phase in('BEFORE_EFFECT','AFTER_EFFECT'):
            current=engine_get(inputs['engineBinding'],'/v1.44/containers/'+cid+'/json')
            require(runtime_pin(current)==pin,'CURRENT_NAT_PROVIDER_GENERATION_CHANGED')
        current_ledger=ledger(c)
        require(current_ledger['cumulativeAttempts']>=baseline['cumulativeAttempts'],'NORMAL_OWNER_COUNTER_REGRESSION')
    # No
    # registry/caller/grant/ledger primitive is reachable from apply_projection.
    after=apply_projection(proposal,gate,operation_root,capture,current_guard,attestor)
    capture.DEADLINE=time.monotonic()+30
    verification=probe.in_worker_group(c,int(after['MainPID']),after['ControlGroup'],ca)
    new_file(operation_root,'network-verification.json',verification)
    require(verification['probe']['httpStatus']==200 and verification['probe']['discoveryMatchesConfiguredEndpoints']is True,
        'PROJECTED_WORKER_NETWORK_DISCOVERY_UNPROVEN')
    require(capture.unit_properties(manager_binding,unit)==after,'WORKER_MANAGER_CHANGED_AFTER_NETWORK_PROJECTION')
    row=wait_publication(c)
    require(row['state']=='ACTIVE' and row['publications']>=1,'PROJECTED_OWNER_INITIAL_PUBLICATION_UNPROVEN')
    capture.DEADLINE=time.monotonic()+15
    final_manager=capture.unit_properties(manager_binding,unit)
    require(final_manager['ActiveState']=='active' and int(final_manager['MainPID'])>1
        and sorted(str(net)for net in capture.network_list(final_manager['IPAddressAllow']))==proposal['projectedAllowlist'],
        'CURRENT_PROJECTED_OWNER_MANAGER_REQUIRED')
    result={'schema':'ouf.registry-network-projection-repair-result.v1','status':'NETWORK_PROJECTION_INSTALLED_OWNER_PUBLISHED',
        'complete':True,'privateReceiptPath':str(operation_root/'receipt.json'),'reviewHash':digest(proposal),
        'kernelNatPathProven':True,'originalIamTlsAndDiscoveryProven':True,'projectedWorkerDiscoveryStatus':200,
        'workerGenerationUnchanged':all(final_manager[key]==before[key]for key in('MainPID','NRestarts')),
        'workerRestartedByRepair':False,'managerRestarts':int(final_manager['NRestarts']),'persistentHostNetworkProjection':True,
        'controlledCumulativeGrantAttempts':row['cumulativeAttempts'],'newOperationalGrantAttempts':row['attempts'],'publications':row['publications'],
        'physicalAddressExplicitlyAssigned':assigned,'projectionRequiresReconciliationIfEndpointChanges':not assigned,
        'managerMutationAttempts':COUNTS['managerMutationAttempts'],'engineGetAttempts':COUNTS['engineGetAttempts'],
        'kernelFlowGetAttempts':COUNTS['conntrackGetAttempts'],'parentTlsConnections':COUNTS['tlsConnectionAttempts'],
        'parentPublicDiscoveryGets':COUNTS['publicDiscoveryGetAttempts'],'verificationProbeTlsConnections':1,
        'verificationProbePublicDiscoveryGets':1,'verificationProbeCgroupWrites':1,'verificationProbeMountNamespaceJoins':1,
        'installationSigningOperations':COUNTS['installationSigningOperations'],'installationSigningKeysRead':True,
        'serviceCredentialFilesOpened':0,'oauthGrantRequestsByRepair':0,'normalGrantMandateChanged':False,'ownerLedgerWrites':0,
        'containerLifecycleOperations':0,'registryOrCallerConfigurationWrites':0,'addressesPrinted':False,'credentialValuesPrinted':False,
        'permanentRenewalProven':False,'originalSemanticGetSucceeded':False,'applicationReadinessProven':False,
        'automaticReplayAllowed':False,'budgetReset':False,'releaseAcceptance':False}
    new_file(operation_root,'result.json',result);return result


if __name__=='__main__':
    try:print(encoded(operator()).decode(),flush=True)
    except Exception as error:
        reason=str(error)if type(error)is Denied and re.fullmatch('[A-Z0-9_]{1,110}',str(error))else'NETWORK_PROJECTION_EXECUTION_UNPROVEN'
        print(encoded({'schema':'ouf.registry-network-projection-repair-result.v1','status':'STOP_RECONCILE','reasonCode':reason,
            'complete':False,'attemptsNotCompletion':dict(COUNTS),'runtimeEffectsMayBePartial':COUNTS['managerMutationAttempts']>0,
            'automaticReplayAllowed':False,'budgetReset':False,'releaseAcceptance':False}).decode(),flush=True)
        raise SystemExit(2)
