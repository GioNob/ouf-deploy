#!/usr/bin/env python3
"""Installation-specific observation, one unauthenticated host TLS connection.

Does not run the capsule, take an owner lock, request a token, restart a
service or rewrite a ledger. The separate operational worker may keep running.
"""
import hashlib
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


def reserve(root):
    directory=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        info=os.fstat(directory);require(info.st_uid==info.st_gid==0 and stat.S_IMODE(info.st_mode)==0o700)
        fd=os.open('host-tls-observation-v1.claim.json',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=directory)
        try:
            payload=encoded({'schema':'ouf.registry-operational-host-tls-attempt.v1','maximumTlsConnections':1,
                'httpRequests':0,'oauthRequests':0,'attemptNotCompletion':True,'automaticReplayAllowed':False})
            require(os.write(fd,payload)==len(payload));os.fsync(fd)
        finally:os.close(fd)
        os.fsync(directory)
    finally:os.close(directory)


def observe():
    require(os.geteuid()==os.getegid()==0 and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode and len(sys.argv)==1)
    review=object_at(REVIEW,REVIEW_SHA);c=review['configuration'];require(digest(encoded(c))==CONFIG_SHA)
    root=Path(c['destinations']['installationRoot']);require(object_at(root/'configuration.json',CONFIG_SHA)==c)
    require(review['serviceUnit']['path']==c['serviceUnitPath'])
    read(c['serviceUnitPath'],65536,review['serviceUnit']['sha256'])
    program=review['executables']['systemctl'];read(program['path'],67108864,program['sha256'])
    ledger=Path(c['destinations']['ledgerRoot'])/'state.json'
    before=project(object_at(ledger,mutable=True),CONFIG_SHA,time.time())
    # This fixed claim cannot be reset by a random launch directory or restart.
    # Only observation evidence is created; no operational ledger is written.
    reserve(root)
    ca=read(c['tlsCa']['path'],4194304,c['tlsCa']['sha256'])
    tls=host_tls(c['ownerInputs']['iamProfile'],ca)
    result=subprocess.run([program['path'],'show',Path(c['serviceUnitPath']).name,'--no-pager',
        '--property=ActiveState,SubState,MainPID,NRestarts,Result,ExecMainStatus,RootDirectory,NoNewPrivileges'],
        stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=10,
        env={'PATH':'/usr/bin:/bin','LC_ALL':'C'})
    require(result.returncode==0 and len(result.stdout)<=8192)
    props=dict(line.split('=',1) for line in result.stdout.decode('ascii').splitlines())
    require(props['MainPID'].isdigit() and props['NRestarts'].isdigit() and props['ExecMainStatus'].isdigit())
    after=project(object_at(ledger,mutable=True),CONFIG_SHA,time.time())
    require(after['version']>=before['version'] and after['controlledCumulativeGrantAttempts']>=before['controlledCumulativeGrantAttempts'])
    return {'schema':'ouf.registry-operational-initial-publication-observation.v1','status':'CURRENT_OWNER_AND_HOST_TLS_OBSERVED',
        'complete':True,'before':before,'after':after,'hostTls':tls,
        'managerActive':props['ActiveState']=='active','managerProcessRunning':int(props['MainPID'])>0,
        'managerRestarts':int(props['NRestarts']),'managerExitStatusZero':props['ExecMainStatus']=='0',
        'managerPrivateRootMatchesReviewed':props['RootDirectory']==str(root/'sandbox'),
        'managerNoNewPrivileges':props['NoNewPrivileges']=='yes','serviceUnitBytesMatchReviewed':True,
        'hostTlsIsNotWorkerConnectivityProof':True,'workerMayContinueIndependently':True,
        'readOnlyRuntime':True,'credentialFilesOpened':0,'httpRequests':0,'oauthRequests':0,'maximumNewTlsConnections':1,
        'containerLifecycleOperations':0,'serviceManagerWrites':0,'operationalLedgerWrites':0,
        'addressesPrinted':False,'rawErrorsPrinted':False,'automaticReplayAllowed':False,'budgetReset':False,
        'applicationReadinessProven':False,'originalSemanticGetSucceeded':False,'releaseAcceptance':False}


if __name__=='__main__':
    try:print(encoded(observe()).decode(),flush=True)
    except Exception:
        print(encoded({'schema':'ouf.registry-operational-initial-publication-observation.v1','status':'STOP_RECONCILE',
            'reasonCode':'CURRENT_OBSERVATION_UNPROVEN','automaticReplayAllowed':False,'budgetReset':False,
            'releaseAcceptance':False,'tlsAttemptMayHaveOccurred':True}).decode(),flush=True);raise SystemExit(2)
