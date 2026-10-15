#!/usr/bin/env python3
"""Two pinned public discovery GETs; no secret/token read, grant or target writes."""
import errno
import hashlib
import http.client
import io
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import ssl
import stat
import subprocess
import time
import urllib.parse

CONTEXT=Path('/etc/ouf/deploy-snapshots/chatbot-file-cohort-signed-eff1b6915816bcfc409b16e1d24b9eb342b1c38e3d6ae80e362ac893c5480d0b')
AUTHORITY='2c35198422227b7db0894ca37ee4d70947ae56fcce813f8d0d1ab9a81c9b5733'
REVIEW='261f9e998acaded184ec9be41a1be1dbd862c4c8b3c57d961cce6820a578b184'
SOURCE='4a65b9326c15d9758ecba1793965617a2a92e43e'
PARENT=Path('/etc/ouf/deploy-snapshots')
UNIT='ouf-file-cohort-eff1b6915816bcfc409b16e1d24b9eb3.service'
CREDENTIAL_HASH='a9fa6304781bff2c9a795d16520881401a49124db869de87338f8978251436ae'
SESSION_HASH='2879325cd95434413f29dc4058d945e16d0bbc71eaf29d44176c705b5ca6ce0c'

def require(ok,code):
    if not ok:raise ValueError(code)

def encoded(value):return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def digest(value):return hashlib.sha256(encoded(value)).hexdigest()

def emit(check,**fields):
    print(json.dumps(dict(schema='ouf.chatbot-iam-http-close-readback.v1',check=check,readOnly=True,
        automaticRetry=False,budgetReset=False,**fields),sort_keys=True),flush=True)

def unique(rows):
    result={}
    for key,value in rows:
        require(key not in result,'DUPLICATE_JSON_KEY');result[key]=value
    return result

def read(path,maximum,expected=None):
    path=Path(path)
    require(path.is_absolute() and path.resolve()==path,'EXACT_PRIVATE_READ_PATH_REQUIRED')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        before=os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_uid==before.st_gid==0
            and stat.S_IMODE(before.st_mode)==0o600 and before.st_nlink==1
            and 0<before.st_size<=maximum,'BOUNDED_PRIVATE_REVIEW_REQUIRED')
        raw=bytearray()
        while len(raw)<=maximum:
            part=os.read(fd,min(65536,maximum+1-len(raw)))
            if not part:break
            raw.extend(part)
        identity=lambda v:(v.st_dev,v.st_ino,v.st_uid,v.st_gid,v.st_mode,v.st_nlink,v.st_size,v.st_mtime_ns,v.st_ctime_ns)
        require(len(raw)==before.st_size and identity(before)==identity(os.fstat(fd))==identity(path.lstat()),
            'PRIVATE_READ_CHANGED')
        require(expected is None or hashlib.sha256(raw).hexdigest()==expected,'PRIVATE_READ_HASH_DRIFT')
        return json.loads(raw,object_pairs_hook=unique)
    finally:os.close(fd)

def error_fields(error):
    result={'errorClass':type(error).__name__}
    if isinstance(error,OSError) and type(error.errno)is int:
        result.update(errno=error.errno,errnoName=errno.errorcode.get(error.errno,'UNKNOWN'))
    if type(error)is ValueError and re.fullmatch('[A-Z][A-Z0-9_]{0,127}',str(error)):result['reason']=str(error)
    return result

class Deadline:
    def __init__(self):self.end=time.monotonic()+10
    def remaining(self):
        left=self.end-time.monotonic()
        if left<=0:raise TimeoutError()
        return left

class Raw(io.RawIOBase):
    def __init__(self,sock,deadline,retain):
        super().__init__();self.sock,self.deadline=sock,deadline
        self.stream=sock.makefile('rb',buffering=0) if retain else None
    def readable(self):return True
    def readinto(self,buffer):
        self.sock.settimeout(self.deadline.remaining())
        return self.stream.readinto(buffer) if self.stream is not None else self.sock.recv_into(buffer)
    def close(self):
        if not self.closed:
            try:
                if self.stream is not None:self.stream.close()
            finally:super().close()

class Wrapped:
    def __init__(self,sock,deadline,retain):self.sock,self.deadline,self.retain=sock,deadline,retain
    def sendall(self,data):self.sock.settimeout(self.deadline.remaining());return self.sock.sendall(data)
    def makefile(self,mode):
        require(mode=='rb','RESPONSE_READ_STREAM_ONLY')
        return io.BufferedReader(Raw(self.sock,self.deadline,self.retain))
    def close(self):self.sock.close()

class Connection(http.client.HTTPConnection):
    def __init__(self,host,port,peer,context,deadline,retain):
        super().__init__(host,port,timeout=deadline.remaining())
        self.peer,self.context,self.deadline,self.retain=peer,context,deadline,retain;self.observed=None
    def connect(self):
        raw=socket.create_connection((self.peer,self.port),timeout=self.deadline.remaining())
        try:
            raw.settimeout(self.deadline.remaining())
            secured=self.context.wrap_socket(raw,server_hostname=self.host)
            require(str(ipaddress.ip_address(secured.getpeername()[0]))==self.peer,'PINNED_TLS_PEER_DRIFT')
            self.observed=secured;self.sock=Wrapped(secured,self.deadline,self.retain)
        except Exception:raw.close();raise

def probe(profile,context,retain):
    url=urllib.parse.urlsplit(profile['issuer']);deadline=Deadline()
    connection=Connection(url.hostname,url.port or 443,profile['peer_addresses'][0],context,deadline,retain)
    result={'mode':'RETAIN_NATIVE_FILE_REFERENCE' if retain else 'RETAINED_ADAPTER_BEHAVIOR',
        'method':'GET','operation':'PUBLIC_DISCOVERY','maximumSeconds':10}
    response=None
    try:
        connection.request('GET',url.path+'/.well-known/openid-configuration',
            headers={'Host':url.netloc,'Accept':'application/json','Connection':'close'})
        response=connection.getresponse()
        result.update(httpStatus=response.status,httpVersion=response.version,
            responseWillClose=bool(response.will_close),connectionCloseHeader=response.getheader('Connection','').lower()=='close',
            socketClosedBeforeBody=connection.observed.fileno()<0)
        require(response.status==200,'PUBLIC_DISCOVERY_HTTP_STATUS_UNPROVEN')
        require(response.getheader('Content-Type','').split(';',1)[0].strip().lower()=='application/json',
            'PUBLIC_DISCOVERY_JSON_REQUIRED')
        raw=response.read(65537);deadline.remaining()
        require(0<len(raw)<=65536,'BOUNDED_PUBLIC_DISCOVERY_REQUIRED')
        value=json.loads(raw,object_pairs_hook=unique)
        require(type(value)is dict and value.get('issuer')==profile['issuer']
            and value.get('token_endpoint')==profile['token_endpoint']
            and value.get('introspection_endpoint')==profile['introspection_endpoint'],
            'PUBLIC_DISCOVERY_IDENTITY_DRIFT')
        result.update(bodyReadPass=True,discoveryIdentityPass=True)
    except Exception as error:result.update(bodyReadPass=False,**error_fields(error))
    finally:
        if response is not None:response.close()
        connection.close()
        result['socketClosedAfterCleanup']=connection.observed is None or connection.observed.fileno()<0
    emit('PINNED_PUBLIC_DISCOVERY',**result)
    return result

def main():
    require(os.geteuid()==0,'ROOT_READ_ACCESS_REQUIRED')
    emit('BEGIN',serviceMutations=0,databaseMutations=0,iamAdminCalls=0,grantRequests=0,maximumPublicGetRequests=2)
    review=read(CONTEXT/'review.json',262144,REVIEW)
    require(review['sourceClosure']['declaration']['sourceCommit']==SOURCE,'EXACT_RETAINED_SOURCE_REQUIRED')
    authority=read(CONTEXT/'authority.json',131072,AUTHORITY);process=review['scopes']['finiteActionProcess']
    require(authority['finiteActionProcess']==process and process['authorityDirectory']==str(CONTEXT)
        and process['unit']==UNIT,'EXACT_PROCESS_BINDING_REQUIRED')
    require(all(authority[key]==scope for key,scope in review['scopes'].items()),'SIGNED_SCOPE_DRIFT')
    state=subprocess.run(['/usr/bin/systemctl','show',UNIT,'--property=ActiveState,MainPID'],
        stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=10)
    require(state.returncode==0 and len(state.stdout)<=8192,'STOPPED_PROCESS_READ_REQUIRED')
    values=dict(line.split('=',1) for line in state.stdout.decode('ascii').splitlines() if '='in line)
    require(values.get('ActiveState')in('inactive','failed') and values.get('MainPID')=='0',
        'CURRENT_PROCESS_MUST_BE_STOPPED')
    bundle=read(process['bundle']['path'],8388608,process['bundle']['sha256']);prepared=bundle['prepared']
    require(digest(prepared)==review['privateInputHashes']['preparedInputs'],'PREPARED_INPUTS_DRIFT')
    owner=prepared['owner'];profile=owner['iamProfile'];scopes=review['scopes']
    require(profile['issuer']=='https://auth.ouf-lab.it/realms/ouf'
        and profile['token_endpoint']==profile['issuer']+'/protocol/openid-connect/token'
        and profile['introspection_endpoint']==profile['token_endpoint']+'/introspect'
        and type(profile['peer_addresses'])is list and 1<=len(profile['peer_addresses'])<=8
        and all(str(ipaddress.ip_address(v))==v for v in profile['peer_addresses']),
        'EXACT_PINNED_PUBLIC_DISCOVERY_PROFILE_REQUIRED')
    context=ssl.create_default_context()
    trust=digest(sorted(hashlib.sha256(raw).hexdigest() for raw in context.get_ca_certs(binary_form=True)))
    require(context.check_hostname and context.verify_mode==ssl.CERT_REQUIRED and trust==owner['tlsTrustSetHash'],
        'CURRENT_TLS_TRUST_SET_DRIFT')
    credential_operation=scopes['policyTokenFirstControlledGrant']['credentialOperation']
    session_operation=scopes['policyTokenFirstControlledGrant']['sessionOperation']
    require(all(type(v)is str and re.fullmatch('[0-9a-f]{64}',v)for v in (credential_operation,session_operation)),
        'EXACT_LOGICAL_OPERATION_IDS_REQUIRED')
    credential=read(PARENT/('policy-token-credential-transaction-'+credential_operation+'.private.json'),262144,CREDENTIAL_HASH)
    session=read(PARENT/('policy-token-first-gap-session-'+session_operation+'.private.json'),262144,SESSION_HASH)
    require(credential['scope']==scopes['policyTokenCredentialReestablishment']
        and credential['state']=='NEW_CREDENTIAL_CUSTODIED_NOT_RUNTIME_ACCEPTED'
        and credential['iamMutationAttemptConsumed']is True and credential['credentialPublished']is True,
        'EXACT_COMPLETED_CREDENTIAL_TRANSACTION_REQUIRED')
    require(session['scope']==scopes['policyTokenAccountingGapMigration'] and session['sessionDecisionHash']==AUTHORITY
        and session['state']=='NEW_FINITE_SESSION' and session['attemptSlotsConsumed']==0,
        'EXACT_UNUSED_FIRST_GRANT_SESSION_REQUIRED')
    require(not os.path.lexists(PARENT/('policy-token-first-controlled-grant-'+session_operation+'.private.json')),
        'FIRST_GRANT_RECEIPT_MUST_BE_ABSENT')
    destination=Path(scopes['policyTokenCredentialReestablishment']['destination'])
    require(str(destination)=='/etc/ouf/policy-token/credentials/semantic' and destination.resolve()==destination,
        'EXACT_CREDENTIAL_DIRECTORY_REQUIRED')
    names=os.listdir(destination);info=(destination/'client-secret').lstat()
    require(names==['client-secret'] and stat.S_ISREG(info.st_mode) and info.st_uid==info.st_gid==0
        and stat.S_IMODE(info.st_mode)==0o400 and info.st_nlink==1 and 0<info.st_size<=4096,
        'CUSTODIED_CREDENTIAL_METADATA_REQUIRED')
    emit('RETAINED_CREDENTIAL_METADATA',contentRead=False,uid=info.st_uid,gid=info.st_gid,
        modeOctal=format(stat.S_IMODE(info.st_mode),'04o'),device=info.st_dev,inode=info.st_ino,
        links=info.st_nlink,bytes=info.st_size,completedMutationAttempts=1)
    emit('RETAINED_FIRST_SESSION',attemptSlotsConsumed=0,createdAt=session['createdAt'],expiresAt=session['expiresAt'],
        expiredNow=time.time()>=session['expiresAt'],newBudgetIssued=False)
    before=(CREDENTIAL_HASH,SESSION_HASH)
    old=probe(profile,context,False);fixed=probe(profile,context,True)
    read(PARENT/('policy-token-credential-transaction-'+credential_operation+'.private.json'),262144,before[0])
    read(PARENT/('policy-token-first-gap-session-'+session_operation+'.private.json'),262144,before[1])
    emit('END',serviceMutations=0,databaseMutations=0,iamAdminCalls=0,grantRequests=0,
        publicGetRequestsAttempted=2,credentialOrTokenFilesRead=False,sourceBodiesExecuted=False,
        authorityRenewed=False,retainedRecordsUnchanged=True,correctedPublicDiscoveryPass=fixed['bodyReadPass'],
        originalEbadfReproduced=old.get('errno')==errno.EBADF,chatbotEndToEndProven=False)

if __name__=='__main__':
    try:main()
    except Exception as error:
        emit('READ_BLOCKED',**error_fields(error));raise SystemExit(1)
