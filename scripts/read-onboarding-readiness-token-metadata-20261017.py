#!/usr/bin/env python3
"""Read only the two configured Ingestion token channels; never call readiness."""
import ast, base64, hashlib, json, os, re, shlex, signal, stat, sys, time
from pathlib import Path

BOOT = Path('/etc/ouf/deploy-snapshots/semantic-mcp-update-executor-code-yrvtskkt/execute.py')
BOOT_HASH = 'b02d9737af6d143903910654d34e91a1a82a52b6082d2429d5dbfd070d160af2'
CONFIG = '/run/secrets/ingestion-summary.properties'

def require(ok, code):
    if not ok: raise ValueError(code)

def emit(check, **data):
    print(json.dumps(dict(schema='ouf.onboarding-readiness-token-metadata.v1',
        check=check, readOnly=True, automaticRetry=False, budgetReset=False,
        credentialValuesPrinted=False, serviceMutations=0, readinessCalls=0,
        **data), sort_keys=True), flush=True)

def identity(s):
    return tuple(getattr(s,k) for k in ('st_dev','st_ino','st_mode','st_uid','st_gid',
        'st_nlink','st_size','st_mtime_ns','st_ctime_ns'))

def bounded(root, target, maximum):
    p=Path(target)
    require(p.is_absolute() and '..' not in p.parts and str(p)==target, 'EXACT_FILE_PATH_REQUIRED')
    fds=[os.dup(root)]
    try:
        for part in p.parts[1:-1]:
            fds.append(os.open(part, os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW, dir_fd=fds[-1]))
        fds.append(os.open(p.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=fds[-1]))
        before=os.fstat(fds[-1])
        require(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and
            0<before.st_size<=maximum, 'BOUNDED_REGULAR_FILE_REQUIRED')
        raw=os.read(fds[-1],maximum+1)
        require(len(raw)==before.st_size and identity(before)==identity(os.fstat(fds[-1])), 'FILE_CHANGED')
        return raw
    finally:
        for fd in reversed(fds): os.close(fd)

def covered(actual,target):
    matches=[m for m in actual['Mounts'] if target==m['Destination'] or
        target.startswith(m['Destination'].rstrip('/')+'/')]
    require(bool(matches),'SELECTED_MOUNT_REQUIRED')
    mount=max(matches,key=lambda m:len(m['Destination']))
    require(mount.get('Type')=='bind' and mount.get('RW') is False,'READ_ONLY_BIND_REQUIRED')

def normal(s): return re.sub('[^a-z0-9]','',s.lower())

def properties(actual,root):
    env={}
    for row in actual['Config'].get('Env') or []:
        key,value=row.split('=',1)
        require(key not in env,'DUPLICATE_ENVIRONMENT_KEY'); env[key]=value
    values={}
    def add(key,value):
        if isinstance(value,(str,bool,int,float)):
            values.setdefault(normal(key),set()).add(str(value))
    for key,value in env.items(): add(key,value)
    def flatten(obj,prefix='',depth=0):
        require(isinstance(obj,dict) and depth<=16,'BOUNDED_JSON_OBJECT_REQUIRED')
        for key,value in obj.items():
            name=prefix+'.'+key if prefix else key
            if isinstance(value,dict): flatten(value,name,depth+1)
            else: add(name,value)
    if env.get('SPRING_APPLICATION_JSON'): flatten(json.loads(env['SPRING_APPLICATION_JSON']))
    selectors={k:v for k,v in env.items() if v and normal(k) in
        {'springconfiglocation','springconfigadditionallocation','springconfigimport'}}
    require(len(selectors)==1 and next(iter(selectors)) in
        {'SPRING_CONFIG_LOCATION','SPRING_CONFIG_ADDITIONAL_LOCATION'} and
        next(iter(selectors.values())) in ('file:'+CONFIG,'optional:file:'+CONFIG),
        'EXACT_RETAINED_CONFIG_SELECTION_REQUIRED')
    covered(actual,CONFIG); raw=bounded(root,CONFIG,262144)
    require(b'\\' not in raw and b'${' not in raw and b'\x00' not in raw,'LITERAL_CONFIG_REQUIRED')
    seen=set()
    for line in raw.decode().splitlines():
        if not line.strip() or line.lstrip().startswith(('#','!')): continue
        m=re.fullmatch(r'[ \t]*([A-Za-z0-9_.-]+)[ \t]*[=:][ \t]*([^\r\n]*)',line)
        require(m is not None,'LITERAL_PROPERTY_REQUIRED')
        key=normal(m[1]); require(key not in seen,'DUPLICATE_PROPERTY'); seen.add(key)
        add(m[1],m[2].strip())
    argv=(actual['Config'].get('Entrypoint') or [])+(actual['Config'].get('Cmd') or [])
    for key in ('JAVA_TOOL_OPTIONS','JDK_JAVA_OPTIONS','JAVA_OPTS'): argv+=shlex.split(env.get(key,''))
    for arg in argv:
        if arg.startswith(('-D','--')) and '=' in arg:
            k,v=arg[2:].split('=',1); add(k,v)
    return values,hashlib.sha256(raw).hexdigest()

def token_metadata(raw):
    parts=raw.decode('ascii').strip().split('.')
    require(len(parts)==3 and all(re.fullmatch('[A-Za-z0-9_-]+',v) for v in parts),'JWT_SHAPE_REQUIRED')
    claims=json.loads(base64.urlsafe_b64decode(parts[1]+'='*((-len(parts[1]))%4)))
    expiry=claims.get('exp'); require(type(expiry) is int,'JWT_EXPIRY_REQUIRED')
    return dict(expiryEpoch=expiry,expiredAtRead=expiry<=time.time(),
        claimsAreMetadataOnly=True,signatureVerifiedLocally=False)

def main():
    require(os.geteuid()==0 and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode,
        'ISOLATED_ROOT_READER_REQUIRED')
    signal.signal(signal.SIGALRM,lambda *_:(_ for _ in ()).throw(ValueError('READ_DEADLINE')))
    signal.alarm(35)
    host=os.open('/',os.O_RDONLY|os.O_DIRECTORY)
    try: raw=bounded(host,str(BOOT),131072)
    finally: os.close(host)
    require(hashlib.sha256(raw).hexdigest()==BOOT_HASH,'RETAINED_HELPER_HASH_CHANGED')
    ns={'__name__':'metadata_read_only'}; exec(compile(raw,'<verified-read-only-helpers>','exec'),ns)
    old=ns['read'](ns['CONTEXT']/'review.json',8388608,ns['REVIEW'])
    binding=old['scopes']['finiteActionProcess']['bundle']
    prepared=ns['read'](binding['path'],8388608,binding['sha256'])['prepared']
    engine=prepared['engine']; actual=ns['engine_get'](engine,'containers','ouf-ingestion')
    require(actual is not None and actual['State']['Running'],'INGESTION_RUNNING_REQUIRED')
    pin=ns['runtime_pin'](actual); pid=actual['State']['Pid']
    def process_pin():
        s=Path('/proc/'+str(pid)+'/stat').read_text()
        return (s[s.rfind(')')+2:].split()[19],os.readlink('/proc/'+str(pid)+'/ns/mnt'))
    process=process_pin(); root=os.open('/proc/'+str(pid)+'/root',os.O_RDONLY|os.O_DIRECTORY)
    rows=[]
    try:
        values,config_hash=properties(actual,root)
        for channel,key in [('activation','ouf.ingestion.activation.token-file'),
                            ('authorization','ouf.authorization.registry-token-file')]:
            found=values.get(normal(key),set())-set([''])
            require(len(found)<=1,'CONFLICTING_TOKEN_SELECTION')
            if not found:
                rows.append(dict(channel=channel,configured=False)); continue
            target=next(iter(found)); covered(actual,target)
            rows.append(dict(channel=channel,configured=True,**token_metadata(bounded(root,target,65536))))
        require(process==process_pin(),'PROCESS_GENERATION_CHANGED')
    finally: os.close(root)
    require(pin==ns['runtime_pin'](ns['engine_get'](engine,'containers','ouf-ingestion')),
        'CONTAINER_GENERATION_CHANGED')
    emit('INGESTION_TOKEN_CHANNELS',generationStableAcrossReads=True,containerId=actual['Id'],
        imageId=actual['Image'],configFileSha256=config_hash,channels=rows,
        maximumCredentialFiles=2,claimsProveEffectiveAuthorization=False)
    emit('END',complete=True,readinessReconciled=False,approvalReplayed=False)

if __name__=='__main__':
    emit('BEGIN',maximumSeconds=35,maximumEngineReads=2,maximumCredentialFiles=2)
    try: main()
    except Exception as error:
        reason=str(error) if type(error) is ValueError and re.fullmatch('[A-Z_]+',str(error)) else type(error).__name__
        emit('STOP',reason=reason,exceptionMessagePrinted=False)
