#!/usr/bin/env python3
"""Read-only current IP policy, routing and static NAT candidates.

No connection probe, grant, policy write or runtime modification. Private
metadata evidence only; static rules do not prove packet traversal.
"""
import hashlib
import http.client
import select
import ipaddress
import json
import os
from pathlib import Path
import socket
import ssl
import stat
import subprocess
import sys
import time
import urllib.parse

REVIEW='/etc/ouf/deploy-snapshots/semantic-registry-operational-review-e4e54229fd43165b0f11f9779d8428ac56a69201cff91c36fe1445cd305eed0f/review.json'
REVIEW_SHA='b67488693c49241d8b6bdf1691216847bd07d7057895a26aa35946442ee450fe'
CONFIG_SHA='0b72275fcc2c51be0929ca0ba454de932ae4863af1b2410dd67bef61bf81e91a'
STATES={'READY','RESERVED','DISPATCHING','PUBLISHING','ACTIVE','RETRY_WAIT','BLOCKED','REVOKED'}
REASONS={'INSTALLED_NO_TOKEN_REQUESTED','UNKNOWN_PREVIOUS_GRANT_OR_PUBLICATION_OUTCOME',
 'UNDISPATCHED_RESERVATION_ABANDONED','CURRENT_PUBLICATION_READMITTED','EXISTING_TOKEN_RENEWAL_DUE',
 'NEW_BOOT_NATIVE_CUSTODY_RECHECKED','HOURLY_ATTEMPT_RATE_LIMIT','NEW_DISTINCT_ATTEMPT_RESERVED',
 'GRANT_DISPATCH_BARRIER_DURABLE','ADMITTED_TOKEN_NOT_YET_PUBLISHED','TOKEN_ATOMICALLY_PUBLISHED',
 'NO_SUBMISSION_PROVEN_BOUNDED_BACKOFF','GRANT_OR_PUBLICATION_OUTCOME_REQUIRES_RECONCILIATION'}


def require(ok):
    if not ok:raise ValueError('OBSERVATION_INPUT_UNPROVEN')


def encoded(value):return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def digest(raw):return hashlib.sha256(raw).hexdigest()


def read(path,maximum,expected=None,mutable=False):
    """Bounded no-follow root ancestry; mutable files are atomic FD snapshots."""
    path=Path(path);require(path.is_absolute() and '..' not in path.parts and len(path.parts)<=48)
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
        raw=bytes(raw);require(expected is None or digest(raw)==expected);return raw
    finally:
        for fd in reversed(fds):os.close(fd)


def object_at(path,expected=None,mutable=False):
    raw=read(path,2097152,expected,mutable);value=json.loads(raw)
    require(type(value)is dict and encoded(value)==raw);return value


def project(row,configuration_hash,now):
    require(row['schema']=='ouf.registry-operational-token-ledger.v1' and row['installationHash']==configuration_hash
        and row['state'] in STATES and row['reason'] in REASONS)
    for name in('attempts','priorControlledAttempts','cumulativeAttempts','publications','consecutiveFailures','version'):
        require(type(row[name])is int and row[name]>=0)
    require(row['priorControlledAttempts']==321 and row['cumulativeAttempts']==321+row['attempts']
        and row['publications']<=row['attempts'] and row['consecutiveFailures']<=row['attempts'])
    return {'state':row['state'],'reasonCode':row['reason'],'newOperationalGrantAttempts':row['attempts'],
        'controlledCumulativeGrantAttempts':row['cumulativeAttempts'],'publications':row['publications'],
        'consecutiveProvenNoSubmissionFailures':row['consecutiveFailures'],'version':row['version'],
        'secondsSinceLastTransition':max(0,int(now-row['lastWall'])),
        'nextAttemptInSeconds':None if row['nextWall'] is None else max(0,int(row['nextWall']-now)),
        'lastPublishedWindowPositive':row['tokenExpiresWall'] is not None and row['tokenExpiresWall']>now}


import re
import shlex

COUNTS={'nativeCommandAttempts':0,'engineGetAttempts':0}
DEADLINE=None

def bounded_run(argv,maximum=16777216):
    require(DEADLINE is not None and time.monotonic()<DEADLINE and COUNTS['nativeCommandAttempts']<12)
    COUNTS['nativeCommandAttempts']+=1
    process=subprocess.Popen(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,
        env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'})
    chunks=[];count=0;until=min(DEADLINE,time.monotonic()+5)
    try:
        fd=process.stdout.fileno()
        while True:
            remaining=until-time.monotonic();require(remaining>0)
            ready,_,_=select.select([fd],[],[],remaining);require(bool(ready))
            piece=os.read(fd,min(65536,maximum-count+1))
            if not piece:break
            count+=len(piece);require(count<=maximum);chunks.append(piece)
        code=process.wait(timeout=max(0.01,until-time.monotonic()))
        return code,b''.join(chunks)
    finally:
        if process.poll() is None:process.kill();process.wait(timeout=2)
        process.stdout.close()

def program(paths):
    for value in paths:
        path=Path(value)
        if not path.exists():continue
        resolved=path.resolve(strict=True);raw=read(resolved,67108864)
        info=resolved.stat();require(info.st_mode&0o111 and not info.st_mode&0o6000)
        return {'path':str(path),'resolved':str(resolved),'sha256':digest(raw)}
    return None

def invoke(binding,args,maximum=16777216):
    require(str(Path(binding['path']).resolve(strict=True))==binding['resolved'])
    read(binding['resolved'],67108864,binding['sha256'])
    return bounded_run([binding['path'],*args],maximum)

def network_list(value):
    try:return [ipaddress.ip_network(item,strict=False) for item in value.split()]
    except ValueError:return None

def permitted(address,properties):
    allow=network_list(properties.get('IPAddressAllow',''));deny=network_list(properties.get('IPAddressDeny',''))
    if allow is None or deny is None:return None
    ip=ipaddress.ip_address(address)
    return any(ip in net for net in allow if ip.version==net.version) or not any(ip in net for net in deny if ip.version==net.version)

def unit_properties(binding,name):
    require(re.fullmatch(r'[A-Za-z0-9_.@\\:-]+',name) is not None)
    fields='ActiveState,MainPID,NRestarts,ControlGroup,RootDirectory,Slice,IPAddressAllow,IPAddressDeny,IPIngressFilterPath,IPEgressFilterPath,BPFProgram,FragmentPath,DropInPaths'
    code,raw=invoke(binding,['show','--no-pager','--property='+fields,'--',name],16384)
    require(code==0)
    result=dict(line.split('=',1) for line in raw.decode('ascii').splitlines())
    require('IPAddressAllow' in result and 'IPAddressDeny' in result)
    return result

def route_data(ip_program,peer):
    code,raw=invoke(ip_program,['-j','address','show'],4194304);require(code==0)
    value=json.loads(raw);require(type(value)is list and len(value)<=4096)
    local=[]
    for interface in value:
        for row in interface.get('addr_info',[]):
            item=row.get('local')
            if type(item)is str:
                try:local.append(str(ipaddress.ip_address(item)))
                except ValueError:pass
    code,raw_route=invoke(ip_program,['-j','route','get',peer],65536);require(code==0)
    routes=json.loads(raw_route);require(type(routes)is list and 1<=len(routes)<=16)
    return {'localAddresses':sorted(set(local)),'routes':routes,'peerIsLocal':peer in local,
            'routeTypeLocal':any(row.get('type')=='local' for row in routes)}

def dnat_target(value,default_port):
    if value.startswith('['):
        close=value.index(']');address=value[1:close];port=value[close+1:]
        require(not port or port.startswith(':'));port=port[1:] if port else str(default_port)
    elif value.count(':')==1:
        address,port=value.rsplit(':',1)
    else:address,port=value,str(default_port)
    address=str(ipaddress.ip_address(address));require(port.isdigit() and 1<=int(port)<=65535)
    return address,int(port)

def parse_save(raw,peer,port):
    require(len(raw)<=16777216)
    rows=[];uncertain=0;inside=False;ip=ipaddress.ip_address(peer)
    for line in raw.decode('utf-8').splitlines():
        require(len(line)<=16384)
        if line.startswith('*'):inside=line=='*nat';continue
        if line=='COMMIT':inside=False;continue
        if not inside or not line.startswith('-A '):continue
        words=shlex.split(line);require(len(words)<=512)
        if '-j' not in words:continue
        jump=words[words.index('-j')+1]
        if jump!='DNAT':continue
        if '--to-destination' not in words:uncertain+=1;continue
        if '--dport' not in words:uncertain+=1;continue
        selected=words[words.index('--dport')+1]
        if selected!=str(port):
            if not selected.isdigit():uncertain+=1
            continue
        destination=True
        if '-d' in words:
            index=words.index('-d')
            try:destination=ip in ipaddress.ip_network(words[index+1],strict=False)
            except ValueError:uncertain+=1;continue
            if index>0 and words[index-1]=='!':destination=not destination
        if not destination:continue
        try:address,target_port=dnat_target(words[words.index('--to-destination')+1],port)
        except (ValueError,IndexError):uncertain+=1;continue
        rows.append({'source':'IPTABLES_NAT','chain':words[1],'address':address,'port':target_port,
            'ruleHash':digest(encoded(words)),'otherMatchConstraintsPresent':any(token in words for token in
                ('-s','-i','-o','--sport','--sports','--dports','--mark','--ctstate','--dst-type')),
            'chainTraversalProven':False})
        require(len(rows)<=256)
    return rows,uncertain

def parse_nft(raw,peer,port):
    require(len(raw)<=16777216);value=json.loads(raw);require(type(value)is dict and type(value.get('nftables'))is list)
    rows=[];uncertain=0;ip=ipaddress.ip_address(peer)
    for item in value['nftables']:
        rule=item.get('rule') if type(item)is dict else None
        if type(rule)is not dict:continue
        expr=rule.get('expr',[]);require(type(expr)is list and len(expr)<=256)
        targets=[part['dnat'] for part in expr if type(part)is dict and 'dnat'in part]
        if not targets:continue
        selected_port=None;destination=True
        for part in expr:
            match=part.get('match',{}) if type(part)is dict else {}
            left=match.get('left',{});payload=left.get('payload',{}) if type(left)is dict else {}
            if payload.get('protocol')=='tcp' and payload.get('field')=='dport' and match.get('op')=='==':
                selected_port=match.get('right')
            if payload.get('protocol') in('ip','ip6') and payload.get('field')=='daddr':
                try:
                    right=match['right']
                    if type(right)is dict and 'prefix'in right:right=str(right['prefix']['addr'])+'/'+str(right['prefix']['len'])
                    destination=ip in ipaddress.ip_network(str(right),strict=False)
                    if match.get('op')=='!=':destination=not destination
                    elif match.get('op')!='==':destination=None
                except (KeyError,ValueError):destination=None
        if not destination:
            if destination is None:uncertain+=1
            continue
        if selected_port!=port:
            if selected_port is None or type(selected_port)is not int:uncertain+=1
            continue
        for target in targets:
            try:
                require(type(target)is dict and type(target.get('addr'))is str)
                address=str(ipaddress.ip_address(target['addr']));target_port=target.get('port',port)
                require(type(target_port)is int and 1<=target_port<=65535)
                rows.append({'source':'NFT_NAT','chain':rule.get('chain',''),'address':address,'port':target_port,
                    'ruleHash':digest(encoded(rule)),'otherMatchConstraintsPresent':True,'chainTraversalProven':False})
            except ValueError:uncertain+=1
        require(len(rows)<=256)
    return rows,uncertain

def socket_guard(binding):
    info=os.stat(binding['socketPath'],follow_symlinks=False)
    require(stat.S_ISSOCK(info.st_mode) and info.st_uid==0 and stat.S_IMODE(info.st_mode) in(0o600,0o660)
        and list((info.st_dev,info.st_ino,info.st_uid,info.st_gid,stat.S_IMODE(info.st_mode)))==binding['socketBinding'])

def engine_get(binding,cid):
    require(re.fullmatch('[a-f0-9]{64}',cid) is not None and COUNTS['engineGetAttempts']<2)
    socket_guard(binding);COUNTS['engineGetAttempts']+=1;path=binding['socketPath']
    class Local(http.client.HTTPConnection):
        def connect(self):
            self.sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);self.sock.settimeout(5);self.sock.connect(path)
    connection=Local('localhost',timeout=5)
    try:
        connection.request('GET','/v1.44/containers/'+cid+'/json',headers={'Connection':'close'})
        response=connection.getresponse();raw=response.read(2097153)
        require(response.status==200 and len(raw)<=2097152);socket_guard(binding);return json.loads(raw)
    finally:connection.close()

def gateway_matches(row,pin):
    require(pin['bindingProfile']=='ouf.runtime-binding.mounts-sorted-destination.v1')
    observed={'containerId':row['Id'],'imageId':row['Image'],'pid':row['State']['Pid'],'startedAt':row['State']['StartedAt'],
        'configHash':digest(encoded(row['Config'])),'hostConfigHash':digest(encoded(row['HostConfig'])),
        'mountsHash':digest(encoded(sorted(row['Mounts'],key=lambda item:item['Destination']))),
        'networkSettingsHash':digest(encoded(row['NetworkSettings']))}
    require(observed==pin['binding'] and row['RestartCount']==pin['restartCount']
        and row['State']['Running']is True and row['State']['Paused']is False
        and row['State']['Restarting']is False and row['State']['Dead']is False)
    return observed

def classify_candidates(candidates,gateway,peer,port,policy):
    networks=gateway['NetworkSettings']['Networks'];published=gateway['NetworkSettings'].get('Ports',{})
    result=[]
    for candidate in candidates:
        item=dict(candidate);matches=[];static=False
        for network in networks.values():
            for field,ipam_field in(('IPAddress','IPv4Address'),('GlobalIPv6Address','IPv6Address')):
                if network.get(field)==item['address']:
                    matches.append(True);static=static or (network.get('IPAMConfig')or{}).get(ipam_field)==item['address']
        publication=False
        for mapping in published.get(str(item['port'])+'/tcp') or []:
            try:
                host=str(ipaddress.ip_address(mapping['HostIp']))
                wildcard=ipaddress.ip_address(host).is_unspecified and ipaddress.ip_address(host).version==ipaddress.ip_address(peer).version
                publication=publication or (mapping['HostPort']==str(port) and (host==peer or wildcard))
            except (ValueError,KeyError):pass
        item.update(matchesReviewedGatewayEndpoint=bool(matches),matchesReviewedPublishedPort=publication,
            gatewayAddressExplicitlyAssigned=static if matches else None,
            permittedByUnitIpPolicy=permitted(item['address'],policy))
        result.append(item)
    return result

def reserve_capture(root):
    parent=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        info=os.fstat(parent);require(info.st_uid==info.st_gid==0 and stat.S_IMODE(info.st_mode)==0o700)
        os.mkdir('network-policy-capture-v1',0o700,dir_fd=parent);os.fsync(parent)
    finally:os.close(parent)
    return root/'network-policy-capture-v1'

def save_private(root,value):
    raw=encoded(value);require(len(raw)<=33554432)
    directory=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        fd=os.open('inputs.json',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o400,dir_fd=directory)
        try:
            offset=0
            while offset<len(raw):offset+=os.write(fd,raw[offset:offset+65536])
            os.fsync(fd)
        finally:os.close(fd)
        os.fsync(directory)
    finally:os.close(directory)
    return str(root/'inputs.json'),digest(raw)

def capture():
    global DEADLINE
    require(os.geteuid()==os.getegid()==0 and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode and len(sys.argv)==1)
    DEADLINE=time.monotonic()+40
    review=object_at(REVIEW,REVIEW_SHA);c=review['configuration'];require(digest(encoded(c))==CONFIG_SHA)
    root=Path(c['destinations']['installationRoot']);require(object_at(root/'configuration.json',CONFIG_SHA)==c)
    read(c['serviceUnitPath'],65536,review['serviceUnit']['sha256'])
    binding=review['proposal']['inputsBinding'];require(binding['sha256']=='1ab900e9818543788df36f5bc7f101da99507dd01933bd10a8194137b5de42de')
    raw=read(binding['path'],16777216,binding['sha256']);inputs=json.loads(raw);require(encoded(inputs)==raw)
    context=inputs['prepared']['nativeContext'];pin=context['gateway']['pin'];cid=pin['binding']['containerId']
    unit=Path(c['serviceUnitPath']).name
    manager_program=review['executables']['systemctl']
    manager_binding={'path':manager_program['path'],'resolved':str(Path(manager_program['path']).resolve(strict=True)),'sha256':manager_program['sha256']}
    ip_program=program(('/usr/sbin/ip','/usr/bin/ip'));require(ip_program is not None)
    peer=c['ownerInputs']['iamProfile']['peer_addresses'][0];endpoint=urllib.parse.urlsplit(c['ownerInputs']['iamProfile']['issuer'])
    port=endpoint.port or 443;ipaddress.ip_address(peer)
    capture_root=reserve_capture(root)
    before=unit_properties(manager_binding,unit)
    require(before['ActiveState']=='active' and before['MainPID'].isdigit() and int(before['MainPID'])>1
        and before['FragmentPath']==c['serviceUnitPath'] and before['RootDirectory']==str(root/'sandbox'))
    first_gateway=engine_get(context['engineBinding'],cid);first_pin=gateway_matches(first_gateway,pin)
    policies=[{'unit':unit,'properties':before}];name=before.get('Slice','')
    while name:
        require(name not in [item['unit'] for item in policies] and len(policies)<5)
        current=unit_properties(manager_binding,name);policies.append({'unit':name,'properties':current})
        name=current.get('Slice','')
    routes=route_data(ip_program,peer);rules=[];unknown=0;observations=[];tools={'ip':ip_program}
    binary=program(('/usr/sbin/iptables-save','/sbin/iptables-save') if ipaddress.ip_address(peer).version==4 else('/usr/sbin/ip6tables-save','/sbin/ip6tables-save'))
    if binary is not None:
        code,raw=invoke(binary,['-t','nat']);observations.append({'source':'IPTABLES_NAT','exitZero':code==0,'sha256':digest(raw),'bytes':len(raw)})
        tools['iptables']=binary
        if code==0:
            rows,count=parse_save(raw,peer,port);rules.extend(rows);unknown+=count
    if not rules:
        binary=program(('/usr/sbin/nft','/usr/bin/nft'))
        if binary is not None:
            code,raw=invoke(binary,['--json','list','ruleset']);observations.append({'source':'NFT_NAT','exitZero':code==0,'sha256':digest(raw),'bytes':len(raw)})
            tools['nft']=binary
            if code==0:
                rows,count=parse_nft(raw,peer,port);rules.extend(rows);unknown+=count
    candidates=classify_candidates(rules,first_gateway,peer,port,before)
    second_gateway=engine_get(context['engineBinding'],cid);require(gateway_matches(second_gateway,pin)==first_pin)
    after=unit_properties(manager_binding,unit);require(after==before)
    ledger=project(object_at(Path(c['destinations']['ledgerRoot'])/'state.json',mutable=True),CONFIG_SHA,time.time())
    private={'schema':'ouf.registry-operational-network-policy-inputs.v1','configurationHash':CONFIG_SHA,
        'reviewHash':REVIEW_SHA,'peer':peer,'port':port,'policies':policies,'routes':routes,'natObservations':observations,
        'candidates':candidates,'unclassifiedNatRuleCount':unknown,'gatewayBinding':first_pin,'gatewayPin':pin,
        'gatewayNetworks':first_gateway['NetworkSettings']['Networks'],'gatewayPorts':first_gateway['NetworkSettings'].get('Ports',{}),
        'engineBinding':context['engineBinding'],'programs':tools,'workerObservation':ledger,
        'staticNatProjectionDoesNotProvePacketTraversal':True,'targetApplyAuthorized':False,'runtimeAuthorityIssued':False,
        'automaticReplayAllowed':False,'budgetReset':False}
    path,sha=save_private(capture_root,private)
    policy_projection=[{'ordinal':index,'configuredPeerPermitted':permitted(peer,item['properties']),
        'extraFilterProgramsConfigured':(True if any(item['properties'].get(key,'') for key in('IPIngressFilterPath','IPEgressFilterPath','BPFProgram')) else False if all(key in item['properties'] for key in('IPIngressFilterPath','IPEgressFilterPath','BPFProgram')) else None),
        'dropInsPresent':bool(item['properties'].get('DropInPaths',''))} for index,item in enumerate(policies)]
    candidate_projection=[{key:item[key] for key in('matchesReviewedGatewayEndpoint','matchesReviewedPublishedPort',
        'gatewayAddressExplicitlyAssigned','permittedByUnitIpPolicy','otherMatchConstraintsPresent','chainTraversalProven')} for item in candidates]
    return {'schema':'ouf.registry-operational-network-policy-capture-result.v1','status':'NETWORK_POLICY_AND_NAT_INPUTS_CAPTURED',
        'complete':True,'privateInputsPath':path,'privateInputsHash':sha,'workerObservation':ledger,
        'configuredPeerIsHostLocal':routes['peerIsLocal'],'routeTypeLocal':routes['routeTypeLocal'],
        'policyComparisons':policy_projection,'candidateCount':len(candidates),'candidateComparisons':candidate_projection,
        'unclassifiedNatRuleCount':unknown,'natRulesReadSuccessfully':any(row['exitZero'] for row in observations),
        'absenceOfCandidateIsNotProofOfNoNat':True,'externalCgroupFiltersNotExcluded':True,'gatewayIdentityEstablished':True,'staticNatProjectionDoesNotProvePacketTraversal':True,
        'engineGets':COUNTS['engineGetAttempts'],'maximumEngineGets':2,'nativeCommandAttempts':COUNTS['nativeCommandAttempts'],
        'maximumNativeCommandAttempts':12,'readOnlyRuntime':True,'credentialFilesOpened':0,'oauthRequests':0,
        'publicHttpRequests':0,'tlsConnections':0,'serviceManagerWrites':0,'operationalLedgerWrites':0,'containerLifecycleOperations':0,
        'addressesPrinted':False,'rawRulesPrinted':False,'rawErrorsPrinted':False,'runtimeAuthorityIssued':False,
        'targetApplyAuthorized':False,'automaticReplayAllowed':False,'budgetReset':False,
        'originalSemanticGetSucceeded':False,'applicationReadinessProven':False,'releaseAcceptance':False}

if __name__=='__main__':
    import signal
    def timeout(*_):raise TimeoutError()
    try:
        signal.signal(signal.SIGALRM,timeout);signal.alarm(45)
        result=capture();signal.alarm(0);print(encoded(result).decode(),flush=True)
    except Exception:
        print(encoded({'schema':'ouf.registry-operational-network-policy-capture-result.v1','status':'STOP_RECONCILE',
            'reasonCode':'NETWORK_POLICY_CAPTURE_UNPROVEN','attemptsNotCompletion':dict(COUNTS),
            'automaticReplayAllowed':False,'budgetReset':False,'releaseAcceptance':False}).decode(),flush=True)
        raise SystemExit(2)
