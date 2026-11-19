#!/usr/bin/env python3
"""Installation-specific metadata read; no runtime policy refresh or replay."""
import hashlib, http.client, json, os, re, signal, socket, stat, sys, time
from pathlib import Path
from urllib.parse import quote

CONTEXT=Path('/etc/ouf/deploy-snapshots/chatbot-file-cohort-signed-16e5f80e40d09772048f1575850b643a69d4d46520db1a56ccd79a7b1a9e055b')

REVIEW='07ee9e8adf0d645018fb70212884f43c22e85cf3c7288bd78dad5bf0d02413bc'

AUTHORITY='a604f4981d38dc19977e551402674b70146bca8768df07c631c2054c6cc727ca'

SOURCE='d7bbb768970aad1a001ca4d085bcc87c58a29cec'

UNIT='ouf-file-cohort-16e5f80e40d09772048f1575850b643a.service'

def emit(check,**values):
    fixed=dict(schema='ouf.chatbot-semantic-policy-binding.v1',check=check,readOnly=True,
        automaticRetry=False,budgetReset=False,acceptanceGranted=False)
    require(not set(values)&set(fixed),'RESERVED_OUTPUT_FIELD')
    print(json.dumps({**fixed,**values},sort_keys=True),flush=True)

class ReadDenied(Exception):pass

def require(ok,code):
    if not ok:raise ReadDenied(code)

def encoded(v):return json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False).encode()

def digest(v):return hashlib.sha256(encoded(v)).hexdigest()

def identity(s):return tuple(getattr(s,k)for k in ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))

def unique(rows):
    d={}
    for k,v in rows:require(k not in d,'DUPLICATE_JSON_KEY');d[k]=v
    return d

def read(path,maximum=262144,expected=None):
    path=Path(path);require(path.is_absolute()and path.resolve()==path,'EXACT_READ_PATH_REQUIRED')
    for parent in path.parents:
        s=parent.lstat();require(stat.S_ISDIR(s.st_mode)and s.st_uid==0 and not s.st_mode&0o022,'ROOT_CONTROLLED_ANCESTRY_REQUIRED')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        s=os.fstat(fd);require(stat.S_ISREG(s.st_mode)and s.st_uid==s.st_gid==0 and stat.S_IMODE(s.st_mode)==0o600
            and s.st_nlink==1 and 0<s.st_size<=maximum,'PRIVATE_BOUNDED_RECORD_REQUIRED')
        raw=bytearray()
        while len(raw)<=maximum:
            part=os.read(fd,min(65536,maximum+1-len(raw)))
            if not part:break
            raw.extend(part)
        require(len(raw)==s.st_size and identity(s)==identity(os.fstat(fd))==identity(path.lstat()),'READ_DRIFT')
        require(expected is None or hashlib.sha256(raw).hexdigest()==expected,'READ_HASH_DRIFT')
        return json.loads(raw,object_pairs_hook=unique,parse_constant=lambda _:(_ for _ in ()).throw(ReadDenied('NONFINITE_JSON')))
    finally:os.close(fd)

def runtime_pin(actual):
    mounts=actual['Mounts']
    require(type(mounts)is list and all(type(m)is dict and type(m.get('Destination'))is str for m in mounts)
        and len({m['Destination'] for m in mounts})==len(mounts),'DUPLICATE_OR_INVALID_MOUNT')
    return {'containerId':actual['Id'],'imageId':actual['Image'],
        'pid':actual['State']['Pid'],'startedAt':actual['State']['StartedAt'],
        'mountsHash':digest(sorted(mounts,key=lambda m:m['Destination'])),
        **{name+'Hash':digest(actual[key])for name,key in
           (('config','Config'),('hostConfig','HostConfig'),('networkSettings','NetworkSettings'))}}

def engine_get(engine,kind,reference):
    require(kind in ('containers','images') and type(reference)is str and
        re.fullmatch(r'[A-Za-z0-9_.:-]{1,128}',reference),'FIXED_ENGINE_GET_REQUIRED')
    path=engine['socketPath'];pin=tuple(engine['socketBinding'])
    def guard():
        s=os.stat(path,follow_symlinks=False)
        require(stat.S_ISSOCK(s.st_mode) and s.st_uid==0 and
            (s.st_dev,s.st_ino,s.st_uid,s.st_gid,stat.S_IMODE(s.st_mode))==pin,'ENGINE_SOCKET_DRIFT')
    guard()
    class Local(http.client.HTTPConnection):
        def connect(self):
            self.sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
            self.sock.settimeout(10);self.sock.connect(path)
    conn=Local('localhost',timeout=10)
    try:
        conn.request('GET','/v1.44/'+kind+'/'+quote(reference,safe='')+'/json')
        reply=conn.getresponse();raw=reply.read(2097153)
        require(reply.status in (200,404) and len(raw)<=2097152,'ENGINE_READ_UNAVAILABLE');guard()
        return None if reply.status==404 else json.loads(raw,object_pairs_hook=unique)
    finally:conn.close()

REGISTRY='790c62742c92eabc095d4ab22f2070e0c40a41e4a219685a7d8120e4661e4e5d'
FIELDS=('BUNDLE_FILE','BUNDLE_ID','BUNDLE_VERSION','BUNDLE_SHA256','REGISTRY_URL',
        'REGISTRY_TOKEN_FILE','REFRESH_SECONDS','MAX_STALENESS_SECONDS')

def environment(rows):
    require(type(rows)is list and len(rows)<=512,'BOUNDED_ENVIRONMENT_REQUIRED')
    result={}
    for row in rows:
        require(type(row)is str and len(row)<=65536 and '='in row,'ENVIRONMENT_SHAPE_INVALID')
        k,v=row.split('=',1)
        require(re.fullmatch('[A-Za-z_][A-Za-z0-9_]*',k) and k not in result,'ENVIRONMENT_KEY_INVALID')
        result[k]=v
    return result

def projection(actual):
    require(actual.get('Id')==REGISTRY and actual.get('State',{}).get('Running')is True
        and type(actual['State'].get('Pid'))is int and actual['State']['Pid']>0,
        'EXACT_RUNNING_REGISTRY_REQUIRED')
    runtime_pin(actual)
    env=environment(actual['Config'].get('Env')or[])
    values={}
    # Spring relaxed environment binding admits both underscore spellings.
    for field in FIELDS:
        names={'OUF_AUTHORIZATION_'+field,'OUF_AUTHORIZATION_'+field.replace('_','')}
        found=[env[k]for k in names if k in env]
        require(len(found)<=1,'AUTHORIZATION_ENV_ALIAS_AMBIGUOUS')
        values[field]=found[0]if found else None
    out={'explicitEnvironmentFields':[f for f in FIELDS if values[f]is not None],
         'credentialFilesRead':0,'policyFilesRead':0,'effectivePolicyProven':False,
         'configurationValuesPrinted':False}
    for field in ('BUNDLE_VERSION','REFRESH_SECONDS','MAX_STALENESS_SECONDS'):
        v=values[field]
        out[field.lower()+'ValidInteger']=v is not None and re.fullmatch('[0-9]{1,10}',v)is not None
        if out[field.lower()+'ValidInteger']:out[field.lower()]=int(v)
    for field in ('BUNDLE_FILE','REGISTRY_TOKEN_FILE'):
        v=values[field]
        valid=type(v)is str and v.startswith('/') and str(Path(v))==v and '..'not in Path(v).parts
        matches=[m for m in actual['Mounts']if valid and
            (v==m['Destination']or v.startswith(m['Destination'].rstrip('/')+'/'))]
        matches.sort(key=lambda m:len(m['Destination']),reverse=True)
        out[field.lower()+'AbsolutePath']=valid
        out[field.lower()+'CoveredByReadOnlyMount']=bool(matches and matches[0].get('RW')is False)
    v=values['BUNDLE_SHA256']
    out['bundleSha256ShapeValid']=type(v)is str and re.fullmatch('[a-f0-9]{64}',v)is not None
    # Only equality against the previously observed public policy hash is exposed.
    out['matchesObservedPolicy40Hash']=v=='d4e2478ce91c0bb2d2d36144dab1305ad137b7ae4c74e218f07e70604ade57bc'
    out['registryUrlConfigured']=bool(values['REGISTRY_URL'])
    out['overrideChannelsPresent']=[k for k in ('JAVA_TOOL_OPTIONS','JDK_JAVA_OPTIONS','_JAVA_OPTIONS',
        'SPRING_APPLICATION_JSON','SPRING_CONFIG_LOCATION','SPRING_CONFIG_ADDITIONAL_LOCATION','SPRING_CONFIG_IMPORT','SPRING_PROFILES_ACTIVE')if k in env]
    # Arguments can include credentials: expose only a presence flag.
    args=(actual['Config'].get('Entrypoint')or[])+(actual['Config'].get('Cmd')or[])
    require(type(args)is list and all(type(x)is str for x in args),'ARGUMENTS_SHAPE_INVALID')
    out['authorizationArgumentOverridePresent']=any('ouf.authorization.'in a or 'ouf.authorization-'in a for a in args)
    out['otherAuthorizationEnvironmentKeysPresent']=any(k.startswith('OUF_AUTHORIZATION_')and
        k not in {'OUF_AUTHORIZATION_'+f for f in FIELDS}|{'OUF_AUTHORIZATION_'+f.replace('_','')for f in FIELDS}for k in env)
    out['loadedSnapshotProven']=False
    return out

def main():
    require(os.geteuid()==0 and sys.flags.isolated,'ROOT_ISOLATED_READER_REQUIRED');signal.alarm(120)
    emit('BEGIN',maximumSeconds=120,maximumEngineReads=2,databaseCalls=0,grantRequests=0,
         iamCalls=0,mcpCalls=0,serviceMutations=0,gatewayWrites=0,credentialFilesRead=0,policyFilesRead=0)
    review=read(CONTEXT/'review.json',8388608,REVIEW)
    authority=read(CONTEXT/'authority.json',131072,AUTHORITY)
    require(review['sourceClosure']['declaration']['sourceCommit']==SOURCE and
        all(authority[k]==v for k,v in review['scopes'].items()),'RETAINED_AUTHORITY_BINDING_DRIFT')
    process=review['scopes']['finiteActionProcess']
    require(process['unit']==UNIT and process['authorityDirectory']==str(CONTEXT),'PROCESS_BINDING_DRIFT')
    bundle=read(process['bundle']['path'],8388608,process['bundle']['sha256']);p=bundle['prepared']
    require(bundle['declaration']==review['sourceClosure']['declaration'] and
        digest(p)==review['privateInputHashes']['preparedInputs'],'PREPARED_INPUT_DRIFT')
    actual=engine_get(p['engine'],'containers',REGISTRY)
    require(actual is not None,'REGISTRY_ABSENT')
    result=projection(actual);pin=runtime_pin(actual)
    after=engine_get(p['engine'],'containers',REGISTRY)
    require(after is not None and runtime_pin(after)==pin,'REGISTRY_GENERATION_DRIFT')
    read(CONTEXT/'review.json',8388608,REVIEW);read(CONTEXT/'authority.json',131072,AUTHORITY)
    read(process['bundle']['path'],8388608,process['bundle']['sha256'])
    emit('REGISTRY_AUTHORIZATION_BINDING',**result,generationStableAcrossReads=True,
        authorityExpiredAtRead=time.time()>=authority['expiresAt'],installationSpecific=True)
    emit('END',complete=True,completedTechnicalPhases=8,functionalMilestonesProven=0,
        reconciliationPerformed=False,runtimeAuthorityIssued=False,automaticPolicyRefresh=False)

if __name__=='__main__':
    try:main()
    except Exception as error:
        reason=str(error)if type(error)is ReadDenied else type(error).__name__
        emit('STOP',reason=reason if re.fullmatch('[A-Za-z_][A-Za-z0-9_]{0,100}',reason)else'UNCLASSIFIED',
             exceptionMessagePrinted=False,reconciliationPerformed=False)
        sys.exit(2)


