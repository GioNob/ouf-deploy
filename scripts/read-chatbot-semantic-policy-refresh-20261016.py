#!/usr/bin/env python3
"""Installation-specific metadata read; no runtime policy refresh or replay."""
import base64, hashlib, http.client, json, os, re, signal, socket, ssl, stat, sys, time
from pathlib import Path
from urllib.parse import quote, urlsplit

CONTEXT=Path('/etc/ouf/deploy-snapshots/chatbot-file-cohort-signed-16e5f80e40d09772048f1575850b643a69d4d46520db1a56ccd79a7b1a9e055b')

REVIEW='07ee9e8adf0d645018fb70212884f43c22e85cf3c7288bd78dad5bf0d02413bc'

AUTHORITY='a604f4981d38dc19977e551402674b70146bca8768df07c631c2054c6cc727ca'

SOURCE='d7bbb768970aad1a001ca4d085bcc87c58a29cec'

UNIT='ouf-file-cohort-16e5f80e40d09772048f1575850b643a.service'

def emit(check,**values):
    fixed=dict(schema='ouf.chatbot-semantic-policy-refresh-readback.v3',check=check,readOnly=True,
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
def environment(rows):
    require(type(rows)is list and len(rows)<=512,'BOUNDED_ENVIRONMENT_REQUIRED')
    result={}
    for row in rows:
        require(type(row)is str and len(row)<=65536 and '='in row,'ENVIRONMENT_SHAPE_INVALID')
        k,v=row.split('=',1)
        require(re.fullmatch('[A-Za-z_][A-Za-z0-9_]*',k) and k not in result,'ENVIRONMENT_KEY_INVALID')
        result[k]=v
    return result

def setting(env,field):
    names={'OUF_AUTHORIZATION_'+field,'OUF_AUTHORIZATION_'+field.replace('_','')}
    found=[env[k]for k in names if k in env]
    require(len(found)==1 and bool(found[0]),'EXACT_AUTHORIZATION_SETTING_REQUIRED')
    return found[0]

def selected(actual,prepared):
    require(actual.get('Id')==REGISTRY and actual['State'].get('Running')is True,'EXACT_RUNNING_REGISTRY_REQUIRED')
    runtime_pin(actual)
    current=environment(actual['Config']['Env'])
    reviewed=environment(prepared['registry']['creationRequest']['Env'])
    url=setting(current,'REGISTRY_URL');token=setting(current,'REGISTRY_TOKEN_FILE')
    require(url==setting(reviewed,'REGISTRY_URL') and token==setting(reviewed,'REGISTRY_TOKEN_FILE'),
            'REVIEWED_REFRESH_BINDING_DRIFT')
    u=urlsplit(url);origin=urlsplit(prepared['authorization']['plan']['selection']['origin'])
    checks={'https':u.scheme=='https','hostnamePresent':bool(u.hostname),
        'noEmbeddedCredentials':not u.username and not u.password,
        'noFragmentOrQuery':not u.fragment and not u.query,
        'exactPolicyBundleContractPath':u.path=='/internal/capabilities/v1/authorization/policy-bundle/active',
        'sameApprovedOrigin':(u.scheme,u.hostname,u.port or 443)==(origin.scheme,origin.hostname,origin.port or 443)}
    emit('ENDPOINT_BINDING_CHECKS',**checks,equalsReviewedRegistryUrl=True,urlValuesPrinted=False)
    require(all(checks.values()),
        'SELECTED_AUTHORIZATION_HTTPS_ORIGIN_REQUIRED')
    require(token.startswith('/') and str(Path(token))==token and '..'not in Path(token).parts,
            'EXACT_TOKEN_TARGET_REQUIRED')
    matches=[m for m in actual['Mounts']if token==m['Destination']or token.startswith(m['Destination'].rstrip('/')+'/')]
    matches.sort(key=lambda m:len(m['Destination']),reverse=True)
    require(bool(matches)and matches[0].get('Type')=='bind'and matches[0].get('RW')is False,
            'EXACT_READONLY_TOKEN_BIND_REQUIRED')
    mount=matches[0];source=mount['Source']+token[len(mount['Destination']):]
    host=prepared['registry']['creationRequest']['HostConfig']
    approved=any(row.get('Type')=='bind'and row.get('Source')==mount['Source']
        and row.get('Target')==mount['Destination']and row.get('ReadOnly')is True for row in host.get('Mounts')or[])
    approved=approved or any(row==mount['Source']+':'+mount['Destination']+':ro' for row in host.get('Binds')or[])
    require(approved,'REVIEWED_TOKEN_MOUNT_DRIFT')
    require(Path(source).is_absolute() and '..'not in Path(source).parts,'EXACT_TOKEN_SOURCE_REQUIRED')
    require(actual['Config'].get('User')=='10001:10001','RETAINED_REGISTRY_UID_REQUIRED')
    return u,source

def credential(path):
    # Only the selected rotating workload token; no secret/key fallback.
    path=Path(path);fds=[];ancestors=[]
    try:
        parent=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);fds.append(parent)
        for name in path.parts[1:-1]:
            child=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent);fds.append(child)
            st=os.fstat(child)
            require(st.st_uid==0 and not st.st_mode&0o022,'TOKEN_ANCESTRY_CUSTODY_REQUIRED')
            ancestors.append((parent,name,child,identity(st)));parent=child
        directory=os.fstat(parent)
        require((directory.st_uid,directory.st_gid,stat.S_IMODE(directory.st_mode))==(0,10001,0o750),
                'TOKEN_OUTPUT_DIRECTORY_CUSTODY_REQUIRED')
        fd=os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent);fds.append(fd)
        st=os.fstat(fd)
        emit('TOKEN_CUSTODY_METADATA',uid=st.st_uid,gid=st.st_gid,modeOctal=format(stat.S_IMODE(st.st_mode),'04o'),
            regularFile=stat.S_ISREG(st.st_mode),singleLink=st.st_nlink==1,sizeWithinBound=0<st.st_size<=65536,
            tokenBytesRead=0,credentialValuesPrinted=False)
        require(stat.S_ISREG(st.st_mode) and (st.st_uid,st.st_gid,stat.S_IMODE(st.st_mode))==(0,10001,0o440)
            and st.st_nlink==1 and 0<st.st_size<=65536,
            'PRIVATE_WORKLOAD_TOKEN_REQUIRED')
        raw=os.read(fd,65537)
        require(len(raw)==st.st_size and identity(st)==identity(os.fstat(fd))
            ==identity(os.stat(path.name,dir_fd=parent,follow_symlinks=False)),'TOKEN_READ_DRIFT')
        for parent,name,child,seal in ancestors:
            # Directory timestamps can change with independent token publication.
            pin=lambda s:identity(s)[:6]
            require(seal[:6]==pin(os.fstat(child))==pin(os.stat(name,dir_fd=parent,follow_symlinks=False)),
                    'TOKEN_ANCESTRY_DRIFT')
        token=raw.decode('ascii').strip()
        require(token and len(token)<=16384 and not any(c.isspace()for c in token),'WORKLOAD_TOKEN_SHAPE_INVALID')
        parts=token.split('.');require(len(parts)==3,'JWT_WORKLOAD_TOKEN_REQUIRED')
        claims=json.loads(base64.urlsafe_b64decode(parts[1]+'='*(-len(parts[1])%4)),object_pairs_hook=unique)
        exp=claims.get('exp');require(type(exp)is int,'JWT_EXPIRY_REQUIRED')
        return token,{'expiredAtRead':time.time()>=exp,'expiryEpoch':exp,
            'signatureVerifiedLocally':False,'claimsAreMetadataOnly':True}
    finally:
        for fd in reversed(fds):os.close(fd)

def fetch_policy(url,token):
    # One GET via the already selected public HTTPS Authorization binding.
    # Default CA/hostname verification, no proxy, redirect, refresh or retry.
    conn=http.client.HTTPSConnection(url.hostname,url.port or 443,timeout=10,context=ssl.create_default_context())
    try:
        conn.request('GET',url.path,headers={'Authorization':'Bearer '+token,'Accept':'application/json'})
        reply=conn.getresponse();status=reply.status
        if status!=200:return {'httpStatus':status,'activePolicyResponseProven':False}
        raw=reply.read(5*1024*1024+65537)
        require(len(raw)<=5*1024*1024+65536,'ACTIVE_ENVELOPE_TOO_LARGE')
        doc=json.loads(raw,object_pairs_hook=unique)
        require(type(doc)is dict and set(doc)<={'bundleId','bundleVersion','activatedAt','bundle','contentHash'},
            'ACTIVE_ENVELOPE_SHAPE_CHANGED')
        bundle=doc['bundle'];require(type(bundle)is dict and type(doc['bundleVersion'])is int,'ACTIVE_BUNDLE_REQUIRED')
        caps=bundle['capabilities'];grants=bundle['grants']
        require(type(caps)is list and type(grants)is list and len(caps)<=10000 and len(grants)<=10000,
            'ACTIVE_BUNDLE_CARDINALITY_LIMIT')
        target={'ouf.semantic.propose','ouf.semantic.proposal.read'}
        counts={cap:sum(1 for g in grants if g.get('capabilityId')==cap)for cap in sorted(target)}
        compact=json.dumps(bundle,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode()
        return {'httpStatus':200,'activePolicyResponseProven':True,'bundleVersion':doc['bundleVersion'],
            'returnedHashMatchesObservedPolicy40':doc.get('contentHash')=='d4e2478ce91c0bb2d2d36144dab1305ad137b7ae4c74e218f07e70604ade57bc',
            'compactBundleHashMatchesEnvelope':hashlib.sha256(compact).hexdigest()==doc.get('contentHash'),
            'capabilitiesDeclared':{cap:any(c.get('capabilityId')==cap for c in caps)for cap in sorted(target)},
            'configuredGrantCounts':counts,'registryLoadedSnapshotProven':False}
    finally:conn.close()

def main():
    require(os.geteuid()==0 and sys.flags.isolated,'ROOT_ISOLATED_READER_REQUIRED');signal.alarm(120)
    emit('BEGIN',maximumSeconds=120,maximumEngineReads=2,maximumPolicyGets=1,
        maximumCredentialFiles=1,grantRequests=0,iamCalls=0,mcpCalls=0,databaseCalls=0,serviceMutations=0)
    review=read(CONTEXT/'review.json',8388608,REVIEW);authority=read(CONTEXT/'authority.json',131072,AUTHORITY)
    require(review['sourceClosure']['declaration']['sourceCommit']==SOURCE and
        all(authority[k]==v for k,v in review['scopes'].items()),'RETAINED_AUTHORITY_BINDING_DRIFT')
    process=review['scopes']['finiteActionProcess']
    require(process['unit']==UNIT and process['authorityDirectory']==str(CONTEXT),'PROCESS_BINDING_DRIFT')
    bundle=read(process['bundle']['path'],8388608,process['bundle']['sha256']);p=bundle['prepared']
    require(bundle['declaration']==review['sourceClosure']['declaration']and
        digest(p)==review['privateInputHashes']['preparedInputs'],'PREPARED_INPUT_DRIFT')
    actual=engine_get(p['engine'],'containers',REGISTRY);require(actual is not None,'REGISTRY_ABSENT')
    pin=runtime_pin(actual);url,path=selected(actual,p)
    token,metadata=credential(path)
    emit('TOKEN_METADATA',**metadata,credentialFilesRead=1,credentialValuesPrinted=False)
    try:result=fetch_policy(url,token)
    except (OSError,TimeoutError,http.client.HTTPException):result={'transportProven':False,'rawErrorPrinted':False}
    finally:token=None
    after=engine_get(p['engine'],'containers',REGISTRY)
    require(after is not None and runtime_pin(after)==pin,'REGISTRY_GENERATION_DRIFT')
    read(CONTEXT/'review.json',8388608,REVIEW);read(CONTEXT/'authority.json',131072,AUTHORITY)
    read(process['bundle']['path'],8388608,process['bundle']['sha256'])
    emit('CONFIGURED_POLICY_GET',**result,hostTransportOnly=True,registryTransportProven=False,
        noPolicyInstalledByReader=True,rawResponsePrinted=False)
    emit('END',complete=True,completedTechnicalPhases=8,functionalMilestonesProven=0,
        runtimeAuthorityIssued=False,reconciliationPerformed=False,automaticPolicyRefresh=False)

if __name__=='__main__':
    try:main()
    except Exception as error:
        reason=str(error)if type(error)is ReadDenied else type(error).__name__
        emit('STOP',reason=reason if re.fullmatch('[A-Za-z_][A-Za-z0-9_]{0,100}',reason)else'UNCLASSIFIED',
             exceptionMessagePrinted=False,reconciliationPerformed=False)
        sys.exit(2)

