#!/usr/bin/env python3
"""One temporary probe joins the worker cgroup; no worker/configuration change.

Two maximum TLS connections: fresh host comparison, then probe in the existing
service cgroup/private root. One public discovery GET, no credentials or grant.
The probe is reaped; the existing worker may continue normal renewal.
"""
import hashlib
import ctypes
import http.client
import select
import signal
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


def host_tls(profile,ca):
    """One numeric peer, original SNI/CA, total deadline, no HTTP or bearer."""
    endpoint=urllib.parse.urlsplit(profile['issuer']);require(endpoint.scheme=='https' and endpoint.hostname and not endpoint.username)
    peer=profile['peer_addresses'][0];address=ipaddress.ip_address(peer)
    context=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT);context.load_verify_locations(cadata=ca.decode('ascii'))
    require(context.check_hostname and context.verify_mode==ssl.CERT_REQUIRED)
    result={'scope':'HOST_OUTSIDE_WORKER_CGROUP','phase':'TCP_CONNECT','tcpConnected':False,
            'tlsHandshakeAttempted':False,'certificateChainAndHostnameVerified':False,'errorClass':None,'errno':None}
    deadline=time.monotonic()+8
    try:
        with socket.socket(socket.AF_INET if address.version==4 else socket.AF_INET6,socket.SOCK_STREAM) as raw:
            raw.settimeout(max(0.001,deadline-time.monotonic()));raw.connect((peer,endpoint.port or 443));result['tcpConnected']=True
            result.update(phase='TLS_HANDSHAKE',tlsHandshakeAttempted=True)
            raw.settimeout(max(0.001,deadline-time.monotonic()))
            with context.wrap_socket(raw,server_hostname=endpoint.hostname) as secured:
                require(str(ipaddress.ip_address(secured.getpeername()[0]))==peer)
                result.update(phase='COMPLETE',certificateChainAndHostnameVerified=True)
    except (OSError,ValueError) as error:
        result['errorClass']=('CERTIFICATE_REJECTED' if isinstance(error,ssl.SSLCertVerificationError) else
            'TLS_ERROR' if isinstance(error,ssl.SSLError) else 'TIMEOUT' if isinstance(error,TimeoutError) else
            'CONNECTION_ERROR' if isinstance(error,OSError) else 'IDENTITY_UNPROVEN')
        result['errno']=error.errno if isinstance(error,OSError) and type(error.errno)is int else None
    return result


def discovery_tls(profile,ca):
    endpoint=urllib.parse.urlsplit(profile['issuer']);require(endpoint.scheme=='https' and endpoint.hostname and not endpoint.username)
    peer=profile['peer_addresses'][0];address=ipaddress.ip_address(peer)
    context=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT);context.load_verify_locations(cadata=ca.decode('ascii'))
    result={'scope':'WORKER_CGROUP_PRIVATE_ROOT_PROBE','phase':'TCP_CONNECT','tcpConnected':False,
        'certificateChainAndHostnameVerified':False,'httpGetAttempted':False,'httpStatus':None,
        'discoveryMatchesConfiguredEndpoints':False,'errorClass':None,'errno':None}
    deadline=time.monotonic()+10
    try:
        with socket.socket(socket.AF_INET if address.version==4 else socket.AF_INET6,socket.SOCK_STREAM) as raw:
            raw.settimeout(max(0.001,deadline-time.monotonic()));raw.connect((peer,endpoint.port or 443));result['tcpConnected']=True
            result['phase']='TLS_HANDSHAKE';raw.settimeout(max(0.001,deadline-time.monotonic()))
            with context.wrap_socket(raw,server_hostname=endpoint.hostname) as secured:
                require(str(ipaddress.ip_address(secured.getpeername()[0]))==peer)
                result['certificateChainAndHostnameVerified']=True;result['phase']='DISCOVERY_HTTP'
                path=endpoint.path+'/.well-known/openid-configuration'
                require(not any(ord(x)<33 or ord(x)>126 for x in path+endpoint.netloc))
                request=('GET '+path+' HTTP/1.1\r\nHost: '+endpoint.netloc+'\r\nAccept: application/json\r\nConnection: close\r\n\r\n').encode('ascii')
                secured.settimeout(max(0.001,deadline-time.monotonic()));result['httpGetAttempted']=True;secured.sendall(request)
                response=http.client.HTTPResponse(secured)
                try:
                    response.begin();result['httpStatus']=response.status
                    body=response.read(65537);require(len(body)<=65536)
                    if response.status==200 and response.getheader('Content-Type','').split(';')[0].strip().lower()=='application/json':
                        def unique(pairs):
                            value={}
                            for key,item in pairs:require(key not in value);value[key]=item
                            return value
                        value=json.loads(body,object_pairs_hook=unique)
                        result['discoveryMatchesConfiguredEndpoints']=(type(value)is dict and value.get('issuer')==profile['issuer']
                            and value.get('token_endpoint')==profile['token_endpoint'] and value.get('introspection_endpoint')==profile['introspection_endpoint'])
                    result['phase']='COMPLETE'
                finally:response.close()
    except (OSError,ValueError,http.client.HTTPException) as error:
        result['errorClass']=('CERTIFICATE_REJECTED' if isinstance(error,ssl.SSLCertVerificationError) else
            'TLS_ERROR' if isinstance(error,ssl.SSLError) else 'TIMEOUT' if isinstance(error,TimeoutError) else
            'CONNECTION_ERROR' if isinstance(error,OSError) else 'HTTP_PROTOCOL_ERROR' if isinstance(error,http.client.HTTPException) else 'DISCOVERY_UNPROVEN')
        result['errno']=error.errno if isinstance(error,OSError) and type(error.errno)is int else None
    return result


def proc_read(pid,name,maximum=16384):
    require(type(pid)is int and pid>1 and name in('stat','cgroup'))
    fd=os.open('/proc/'+str(pid)+'/'+name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        raw=os.read(fd,maximum+1);require(0<len(raw)<=maximum);return raw.decode('ascii')
    finally:os.close(fd)


def frame(pid,group,root):
    data=proc_read(pid,'stat');tail=data.rsplit(')',1)[1].split();require(len(tail)>=20)
    require(proc_read(pid,'cgroup').strip()=='0::'+group)
    net=os.stat('/proc/'+str(pid)+'/ns/net');host=os.stat('/proc/self/ns/net')
    require((net.st_dev,net.st_ino)==(host.st_dev,host.st_ino))
    observed=os.stat('/proc/'+str(pid)+'/root');expected=os.stat(root)
    require((observed.st_dev,observed.st_ino)==(expected.st_dev,expected.st_ino))
    mounts=os.stat('/proc/'+str(pid)+'/ns/mnt')
    return (int(tail[19]),observed.st_dev,observed.st_ino,net.st_dev,net.st_ino,mounts.st_dev,mounts.st_ino)


def cgroup_directory(group):
    require(type(group)is str and group.startswith('/') and '..'not in group.split('/') and len(group.split('/'))<=12)
    fd=os.open('/sys/fs/cgroup',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        for part in group.split('/')[1:]:
            require(part and all(x.isalnum() or x in '_.:-@\\' for x in part))
            child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd);os.close(fd);fd=child
        kind=os.open('cgroup.type',os.O_RDONLY|os.O_NOFOLLOW,dir_fd=fd)
        try:require(os.read(kind,128).strip()==b'domain')
        finally:os.close(kind)
        return fd
    except BaseException:os.close(fd);raise


def drop_capabilities(libc):
    class Header(ctypes.Structure):_fields_=[('version',ctypes.c_uint32),('pid',ctypes.c_int)]
    class Data(ctypes.Structure):_fields_=[('effective',ctypes.c_uint32),('permitted',ctypes.c_uint32),('inheritable',ctypes.c_uint32)]
    header=Header(0x20080522,0);data=(Data*2)()
    require(libc.prctl(38,1,0,0,0)==0 and libc.capset(ctypes.byref(header),ctypes.byref(data))==0)
    check=(Data*2)();require(libc.capget(ctypes.byref(header),ctypes.byref(check))==0)
    require(all(row.effective==row.permitted==row.inheritable==0 for row in check))


def in_worker_group(c,pid,group,ca):
    root=Path(c['destinations']['installationRoot'])/'sandbox';original=frame(pid,group,root)
    cfd=cgroup_directory(group);rootfd=os.open('/proc/'+str(pid)+'/root',os.O_RDONLY|os.O_DIRECTORY)
    mountfd=os.open('/proc/'+str(pid)+'/ns/mnt',os.O_RDONLY)
    start_r,start_w=os.pipe();result_r,result_w=os.pipe();libc=ctypes.CDLL(None,use_errno=True)
    descriptor_limit=3;descriptor_count=0
    with os.scandir('/proc/self/fd') as descriptors:
        for entry in descriptors:
            descriptor_count+=1;require(descriptor_count<=256 and entry.name.isdigit())
            number=int(entry.name);require(number<1048576);descriptor_limit=max(descriptor_limit,number+1)
    parent=os.getpid();child=None;reaped=False;membership_attempted=False
    try:
        child=os.fork()
        if child==0:
            try:
                require(libc.prctl(1,signal.SIGKILL,0,0,0)==0 and os.getppid()==parent)
                os.close(start_w);os.close(result_r)
                os.dup2(start_r,0);os.dup2(result_w,1)
                require(os.read(0,1)==b'G')
                require(libc.setns(mountfd,0x00020000)==0)
                os.fchdir(rootfd);os.chroot('.');os.chdir('/')
                # No inherited host-directory/socket descriptors, no signing-key
                # access outside this root, no capabilities or future privilege.
                os.closerange(3,descriptor_limit);os.close(2);drop_capabilities(libc)
                def timeout(*_):raise TimeoutError()
                signal.signal(signal.SIGALRM,timeout);signal.alarm(12)
                result=discovery_tls(c['ownerInputs']['iamProfile'],ca);signal.alarm(0)
                result['capabilitiesDropped']=True;result['privateRootEntered']=True;result['mountNamespaceJoined']=True
                payload=encoded(result);require(len(payload)<=4096);require(os.write(1,payload)==len(payload));os._exit(0)
            except BaseException:os._exit(2)
        os.close(start_r);start_r=None;os.close(result_w);result_w=None
        require(frame(pid,group,root)==original)
        member=os.open('cgroup.procs',os.O_WRONLY|os.O_NOFOLLOW,dir_fd=cfd)
        try:
            value=str(child).encode();membership_attempted=True;require(os.write(member,value)==len(value))
        finally:os.close(member)
        require(proc_read(child,'cgroup').strip()=='0::'+group and frame(pid,group,root)==original)
        os.write(start_w,b'G');os.close(start_w);start_w=None
        until=time.monotonic()+15;payload=bytearray()
        while True:
            remaining=until-time.monotonic();require(remaining>0)
            ready,_,_=select.select([result_r],[],[],remaining);require(bool(ready))
            part=os.read(result_r,4097-len(payload))
            if not part:break
            payload.extend(part);require(len(payload)<=4096)
        _,code=os.waitpid(child,0);reaped=True;require(os.waitstatus_to_exitcode(code)==0)
        result=json.loads(payload);require(type(result)is dict and encoded(result)==payload and frame(pid,group,root)==original)
        return {'probe':result,'probeProcessExited':True,'probeCgroupMembershipWrites':1,'probeMountNamespaceJoins':1,'workerGenerationUnchanged':True}
    finally:
        if child is not None and not reaped:
            try:os.kill(child,signal.SIGKILL)
            except ProcessLookupError:pass
            os.waitpid(child,0)
        for fd in(cfd,rootfd,mountfd,start_r,start_w,result_r,result_w):
            if fd is not None:
                try:os.close(fd)
                except OSError:pass


def manager(review,c):
    program=review['executables']['systemctl'];read(program['path'],67108864,program['sha256'])
    result=subprocess.run([program['path'],'show',Path(c['serviceUnitPath']).name,'--no-pager',
        '--property=ActiveState,MainPID,NRestarts,ControlGroup,RootDirectory'],stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=8,env={'PATH':'/usr/bin:/bin','LC_ALL':'C'})
    require(result.returncode==0 and len(result.stdout)<=8192)
    p=dict(line.split('=',1) for line in result.stdout.decode('ascii').splitlines())
    require(p['ActiveState']=='active' and p['MainPID'].isdigit() and int(p['MainPID'])>1
        and p['NRestarts'].isdigit() and p['RootDirectory']==c['destinations']['installationRoot']+'/sandbox'
        and Path(p['ControlGroup']).name==Path(c['serviceUnitPath']).name)
    return p


def reserve_probe(root):
    directory=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        info=os.fstat(directory);require(info.st_uid==info.st_gid==0 and stat.S_IMODE(info.st_mode)==0o700)
        fd=os.open('worker-network-comparison-v1.claim.json',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=directory)
        try:
            raw=encoded({'maximumTlsConnections':2,'maximumPublicDiscoveryGets':1,'oauthGrantRequests':0,
                'maximumProbeCgroupMembershipWrites':1,'maximumProbeMountNamespaceJoins':1,
                'workerSignalsAllowed':False,'automaticReplayAllowed':False})
            require(os.write(fd,raw)==len(raw));os.fsync(fd)
        finally:os.close(fd)
        os.fsync(directory)
    finally:os.close(directory)


def observe_network():
    require(os.geteuid()==os.getegid()==0 and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode and len(sys.argv)==1)
    review=object_at(REVIEW,REVIEW_SHA);c=review['configuration'];require(digest(encoded(c))==CONFIG_SHA)
    root=Path(c['destinations']['installationRoot']);require(object_at(root/'configuration.json',CONFIG_SHA)==c)
    read(c['serviceUnitPath'],65536,review['serviceUnit']['sha256'])
    first=manager(review,c);ledger=Path(c['destinations']['ledgerRoot'])/'state.json'
    before=project(object_at(ledger,mutable=True),CONFIG_SHA,time.time())
    ca=read(c['tlsCa']['path'],4194304,c['tlsCa']['sha256'])
    frame(int(first['MainPID']),first['ControlGroup'],root/'sandbox')
    reserve_probe(root)
    baseline=host_tls(c['ownerInputs']['iamProfile'],ca)
    result=in_worker_group(c,int(first['MainPID']),first['ControlGroup'],ca)
    second=manager(review,c);require(first==second)
    after=project(object_at(ledger,mutable=True),CONFIG_SHA,time.time())
    require(after['version']>=before['version'] and after['controlledCumulativeGrantAttempts']>=before['controlledCumulativeGrantAttempts'])
    return dict(result,schema='ouf.registry-operational-network-comparison.v1',status='WORKER_NETWORK_PROBE_COMPLETED',
        complete=True,before=before,after=after,hostTls=baseline,managerRestarts=int(second['NRestarts']),
        probeSharesNetworkCgroupAndRootOnly=True,workerSeccompAndEnvironmentNotReproduced=True,
        maximumTlsConnections=2,maximumPublicDiscoveryGets=1,credentialFilesOpened=0,oauthGrantRequests=0,
        serviceManagerWrites=0,workerSignalsSent=0,serviceConfigurationWrites=0,operationalLedgerWrites=0,
        readOnlyRuntime=False,addressesPrinted=False,rawErrorsPrinted=False,automaticReplayAllowed=False,
        budgetReset=False,applicationReadinessProven=False,originalSemanticGetSucceeded=False,releaseAcceptance=False)


if __name__=='__main__':
    try:print(encoded(observe_network()).decode(),flush=True)
    except Exception:
        print(encoded({'schema':'ouf.registry-operational-network-comparison.v1','status':'STOP_RECONCILE',
            'reasonCode':'NETWORK_COMPARISON_UNPROVEN','probeMembershipMayHaveBeenWritten':True,
            'networkAttemptsMayHaveOccurred':True,'automaticReplayAllowed':False,'budgetReset':False,
            'releaseAcceptance':False}).decode(),flush=True);raise SystemExit(2)

