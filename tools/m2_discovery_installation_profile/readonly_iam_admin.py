"""Existing admin bearer, GET-only in the exact Keycloak network namespace.

Never invoke kcadm: its ensureToken can refresh even for GET. Read only the
reviewed private session through a pinned /proc root, minimize it in memory,
and send the existing bearer over stdin to a fixed GET-only native child.
No refresh token, password, client secret, cache write or token endpoint exists
in the child protocol. Expiry or denial stops without authentication/retry.
"""
import hashlib,os,re,stat,subprocess,time
from pathlib import Path
from .custody_capture import attrs,decode,digest,encoded,process_pin,require
from .private_review import absolute,hashed
from tools.semantic_target_review.prepare_application_runtime_inputs import file_bytes

SCHEMA='ouf.discovery-existing-admin-get-only.v1'
CHILD=r'''
import ctypes,http.client,json,os,signal,sys,urllib.parse
signal.alarm(7)
try:
 raw=sys.stdin.buffer.read(32769);assert 0<len(raw)<=32768
 v=json.loads(raw);assert set(v)=={'port','path','query','token'}
 assert type(v['port']) is int and 1<=v['port']<=65535
 assert type(v['path']) is str and v['path'].startswith('/admin/realms/') and len(v['path'])<=1024
 assert type(v['query']) is dict and len(v['query'])<=2
 assert type(v['token']) is str and 0<len(v['token'])<=16384 and all(c.isalnum() or c in '._-' for c in v['token'])
 fd=int(sys.argv[1]);libc=ctypes.CDLL(None,use_errno=True)
 if libc.setns(fd,0x40000000)!=0:raise OSError(ctypes.get_errno(),'SETNS_DENIED')
 os.close(fd)
 c=http.client.HTTPConnection('127.0.0.1',v['port'],timeout=5)
 try:
  path=v['path']+('?' + urllib.parse.urlencode(v['query']) if v['query'] else '')
  c.request('GET',path,headers={'Authorization':'Bearer '+v['token'],'Accept':'application/json','Connection':'close'})
  r=c.getresponse();raw=r.read(262145);assert r.status==200 and 0<len(raw)<=262144
  sys.stdout.buffer.write(raw);sys.stdout.buffer.flush()
 finally:c.close()
except BaseException:os._exit(2)
os._exit(0)
'''


def validate(value):
    require(type(value) is dict and set(value)=={'schema','python','sessionFile','sessionServer','adminRealm','port'}
        and value['schema']==SCHEMA and type(value['port']) is int and 1<=value['port']<=65535
        and value['sessionServer']=='http://localhost:'+str(value['port'])
        and type(value['adminRealm']) is str and re.fullmatch('[A-Za-z0-9_.-]{1,64}',value['adminRealm']),
        'EXPLICIT_EXISTING_ADMIN_GET_ONLY_PROFILE_REQUIRED')
    p=value['python'];require(type(p) is dict and set(p)=={'path','sha256','maximumBytes'} and hashed(p['sha256'])
        and type(p['maximumBytes']) is int and 0<p['maximumBytes']<=67108864,'PINNED_GET_ONLY_IAM_PYTHON_REQUIRED');absolute(p['path'])
    f=value['sessionFile'];require(type(f) is dict and set(f)=={'containerPath','sha256','metadataHash','maximumBytes'}
        and hashed(f['sha256']) and hashed(f['metadataHash']) and type(f['maximumBytes']) is int and 0<f['maximumBytes']<=262144,
        'EXPLICIT_REVIEWED_PRIVATE_ADMIN_SESSION_FILE_REQUIRED');path=absolute(f['containerPath'])
    require(len(path.parts)>=4 and path.name=='kcadm.config','EXACT_REVIEWED_ADMIN_SESSION_CONTAINER_PATH_REQUIRED')
    return digest(value)


def session_file(profile,pin,budget):
    """Follow only the independently pinned proc-root link; no child symlinks."""
    validate(profile);budget.check();pid=pin['pid'];require(process_pin(pid)==pin,'CURRENT_ADMIN_SESSION_PROCESS_CHANGED')
    ref=profile['sessionFile'];parts=Path(ref['containerPath']).parts[1:];root=None;fd=None
    try:
        root=os.open('/proc/'+str(pid)+'/root',os.O_PATH|os.O_DIRECTORY|os.O_CLOEXEC)
        for part in parts[:-1]:
            child=os.open(part,os.O_PATH|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=root)
            os.close(root);root=child
        fd=os.open(parts[-1],os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=root)
        before=os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and stat.S_IMODE(before.st_mode) in (0o400,0o600)
            and before.st_nlink==1 and 0<before.st_size<=ref['maximumBytes'] and digest(attrs(before))==ref['metadataHash'],
            'CURRENT_PRIVATE_ADMIN_SESSION_CUSTODY_CHANGED')
        raw=os.read(fd,ref['maximumBytes']+1)
        require(len(raw)==before.st_size and hashlib.sha256(raw).hexdigest()==ref['sha256']
            and attrs(os.fstat(fd))==attrs(before)==attrs(os.stat(parts[-1],dir_fd=root,follow_symlinks=False)),
            'CURRENT_PRIVATE_ADMIN_SESSION_BYTES_CHANGED')
    finally:
        if fd is not None:os.close(fd)
        if root is not None:os.close(root)
    require(process_pin(pid)==pin,'CURRENT_ADMIN_SESSION_PROCESS_CHANGED');budget.check();return raw


def read_session(profile,pin,budget):
    raw=session_file(profile,pin,budget);v=decode(raw)
    require(type(v) is dict and v.get('serverUrl')==profile['sessionServer'] and v.get('realm')==profile['adminRealm']
        and type(v.get('endpoints')) is dict,'CURRENT_REVIEWED_ADMIN_SESSION_SELECTION_REQUIRED')
    endpoints=v['endpoints'].get(profile['sessionServer'])
    require(type(endpoints) is dict and type(endpoints.get(profile['adminRealm'])) is dict,
        'CURRENT_REVIEWED_ADMIN_SESSION_SELECTION_REQUIRED')
    selected=endpoints[profile['adminRealm']];token=selected.get('token');expires=selected.get('expiresAt')
    require(type(token) is str and re.fullmatch('[A-Za-z0-9_.-]{1,16384}',token)
        and type(expires) is int and expires>int(time.time()*1000)+7000,
        'CURRENT_EXISTING_ADMIN_BEARER_REQUIRED_NO_REFRESH')
    # Forward neither the complete session record nor its refresh/secret fields.
    return {'token':token,'expiresAt':expires,'sessionFileHash':profile['sessionFile']['sha256']}


def dispatch(profile,pin,session,path,query,budget):
    validate(profile);budget.check();require(process_pin(pin['pid'])==pin,'CURRENT_GET_ONLY_IAM_PROCESS_CHANGED')
    require(type(session) is dict and set(session)=={'token','expiresAt','sessionFileHash'}
        and session['sessionFileHash']==profile['sessionFile']['sha256'] and type(session['expiresAt']) is int
        and session['expiresAt']>int(time.time()*1000)+7000,'CURRENT_EXISTING_ADMIN_BEARER_REQUIRED_NO_REFRESH')
    require(type(path) is str and re.fullmatch(r'/admin/realms/[A-Za-z0-9_.-]+/clients/[a-f0-9-]{36}(?:/(?:service-account-user|default-client-scopes|optional-client-scopes|client-secret|evaluate-scopes/generate-example-access-token))?',path)
        and type(query) is dict and set(query)<={'userId','scope'} and all(type(v) is str and 0<len(v)<=4096 for v in query.values()),
        'CLOSED_GET_ONLY_IAM_ADMIN_PATH_REQUIRED')
    p=profile['python'];file_bytes(p['path'],0,{0o755},limit=p['maximumBytes'],expected=p['sha256'])
    fd=os.open('/proc/'+str(pin['pid'])+'/ns/net',os.O_RDONLY|os.O_CLOEXEC)
    try:
        require([os.fstat(fd).st_dev,os.fstat(fd).st_ino]==pin['namespaces']['net'],'CURRENT_GET_ONLY_IAM_NAMESPACE_CHANGED')
        payload=encoded({'port':profile['port'],'path':path,'query':query,'token':session['token']})
        require(len(payload)<=32768,'BOUNDED_GET_ONLY_IAM_PAYLOAD_REQUIRED')
        result=subprocess.run([p['path'],'-I','-B','-S','-c',CHILD,str(fd)],input=payload,
            stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,pass_fds=(fd,),timeout=budget.remaining(8),
            env={'PATH':'/usr/bin:/bin','LC_ALL':'C'})
        require(result.returncode==0 and 0<len(result.stdout)<=262144,'CURRENT_READONLY_ADMIN_GET_UNPROVEN_NO_REFRESH')
        require(process_pin(pin['pid'])==pin and [os.fstat(fd).st_dev,os.fstat(fd).st_ino]==pin['namespaces']['net'],
            'CURRENT_GET_ONLY_IAM_PROCESS_OR_NAMESPACE_CHANGED')
        budget.check();return decode(result.stdout)
    finally:os.close(fd)
