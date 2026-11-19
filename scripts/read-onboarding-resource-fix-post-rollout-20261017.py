#!/usr/bin/env python3
"""Installation-specific completed single-Onboarding audit-fix readback and dependency GETs."""
import base64, hashlib, http.client, json, os, re, shlex, signal, ssl, stat, sys, time
from urllib.parse import urlsplit, quote, urlencode
from pathlib import Path

BOOT = Path('/etc/ouf/deploy-snapshots/semantic-mcp-update-executor-code-yrvtskkt/execute.py')
BOOT_HASH = 'b02d9737af6d143903910654d34e91a1a82a52b6082d2429d5dbfd070d160af2'
CONFIG = '/run/secrets/ingestion-summary.properties'
ROLLOUT = Path('/etc/ouf/deploy-snapshots/onboarding-audit-execution-i220f2c0')
ROLLOUT_REVIEW = None
CONFIGURATION_HASH = 'sha256:ae7f46b4214d09c55a9885530920026258f0dcd588462c353b06d82185e12c9b'
SOURCE_ID = 'teatri-csv-6609b245'
ONBOARDING_VERSION = '9860853e-e8f3-4b93-b9d2-03521a039962'
def digest(value):return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()).hexdigest()
def configuration_path():
    return '/api/internal/v1/onboarding/ingestion-configuration?'+urlencode({'sourceId':SOURCE_ID,'onboardingVersionId':ONBOARDING_VERSION,'configurationHash':CONFIGURATION_HASH})

def require(ok, code):
    if not ok: raise ValueError(code)

def emit(check, **data):
    print(json.dumps(dict(schema='ouf.onboarding-resource-fix-post-rollout-read.v1',
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
    review=ns['read'](ROLLOUT/'review.json',8388608,ROLLOUT_REVIEW)
    plan=ns['read'](ROLLOUT/'execution-plan.json',8388608)
    decision=ns['read'](ROLLOUT/'decision.json',131072)
    mandate=ns['read'](ROLLOUT/'human.json',131072)
    authority=ns['read'](ROLLOUT/'authority.json',131072)
    review_hash=digest(review)
    require(review.get('kind')=='ONBOARDING_AUDIT_FIX'
        and review.get('predecessorHistoryHash')=='b0e04a406ccda2dbfc6dd5743373866fa5ac1417b42ebfcbd57b2c3b6370e3ca'
        and digest(review['sourceClosure'])==review['sourceClosureHash']
        and review['sourceClosure']['declaration']['sourceCommit']=='ed1fd76d5b77e4033f90b4010d4ca1e08f44ecea'
        and authority['scopedExecution']['reviewHash']==review_hash==decision['reviewHash']==mandate['intakeHash']
        and mandate['executionAuthorityHash']==digest(authority)
        and authority['scopedExecution']['approvalRef']==decision['approvalRef']==mandate['approvalRef']
        and decision.get('decision')=='APPROVE_EXACT_FINITE_SCOPED_ACTION',
        'EXACT_COMPLETED_RESOURCE_FIX_REVIEW_LINKS_REQUIRED')
    scope=review['scopes']['onboardingAuditUpdate']
    require(digest(plan)==scope['planHash'] and plan['engine']==prepared['engine'],'EXACT_APPROVED_ROLLOUT_PLAN_REQUIRED')
    record=ns['read'](ROLLOUT/'recovery.json',65536)
    require(record.get('schema')=='ouf.onboarding-audit-update-journal.v1'
        and record.get('scopeHash')==digest(scope) and record.get('authorityHash')==digest(authority)
        and record.get('incidentState')=='RECOVERED' and record.get('version')==29
        and record.get('nextStage')==len(scope['stages'])==len(record['effects'])
        and [e['stage'] for e in record['effects']]==scope['stages']
        and all(e['state']=='APPLIED' for e in record['effects'])
        and record['effects'][-1]['stage']=='VERIFY_FINAL','COMPLETE_RETAINED_ROLLOUT_REQUIRED')
    final=record['effects'][-1]['evidence']['applications']
    engine=prepared['engine']
    require(set(plan['replacements'])=={'onboarding'} and plan['maximumGatewayWrites']==0,
        'EXACT_SINGLE_ONBOARDING_FIX_SCOPE_REQUIRED')
    current=ns['engine_get'](engine,'containers',plan['replacements']['onboarding']['name'])
    require(current is not None and current['State']['Running'] is True
        and ns['runtime_pin'](current)==final['onboarding']['runtimeBinding']
        and current['Config'].get('Labels',{}).get('org.opencontainers.image.revision')=='e02def25b47f653a1800db854594c73fadd9ba87',
        'AUDIT_FIX_ONBOARDING_GENERATION_CHANGED')
    onboarding_pin=ns['runtime_pin'](current)
    retained=plan['unchangedIngestionRuntimeBinding']
    actual=ns['engine_get'](engine,'containers',retained['containerId'])
    require(actual is not None and actual['State']['Running'] is True
        and ns['runtime_pin'](actual)==retained,'RETAINED_INGESTION_GENERATION_CHANGED')
    require(record['effects'][-1]['evidence']['routeMapHash']==digest(plan['gateway']['beforeRoutes'])
        =='31ad562fa32c98472ee262bb0d8a800e3626443762e913b7863cce359e219d1d',
        'RETAINED_ROUTE_MAP_EVIDENCE_CHANGED')
    emit('ROLLOUT_READBACK',journalVersion=29,complete=True,applicationGenerationsMatch=True,
        reviewSha256=review_hash,rootArtifactReviewLinksMatch=True,reviewSignaturesVerifiedLocally=False,
        retainedRouteMapHash=record['effects'][-1]['evidence']['routeMapHash'],
        sourceActivationProven=False,semanticDispatchPerformed=False)

    require(actual is not None and actual['State']['Running'],'INGESTION_RUNNING_REQUIRED')
    pin=ns['runtime_pin'](actual); pid=actual['State']['Pid']
    def process_pin():
        s=Path('/proc/'+str(pid)+'/stat').read_text()
        return (s[s.rfind(')')+2:].split()[19],os.readlink('/proc/'+str(pid)+'/ns/mnt'))
    process=process_pin(); root=os.open('/proc/'+str(pid)+'/root',os.O_RDONLY|os.O_DIRECTORY)
    rows=[]
    origin=prepared['authorization']['plan']['selection']['origin']
    u=urlsplit(origin)
    require(u.scheme=='https' and u.hostname and not u.username and not u.password and not u.query and not u.fragment and u.path in ('','/'),'REVIEWED_HTTPS_ORIGIN_REQUIRED')
    def get(path,raw):
        token=raw.decode('ascii').strip()
        require(token and len(token)<=16384 and not any(c.isspace() for c in token),'WORKLOAD_TOKEN_SHAPE_REQUIRED')
        conn=http.client.HTTPSConnection(u.hostname,u.port or 443,timeout=5,context=ssl.create_default_context())
        try:
            conn.request('GET',path,headers={'Authorization':'Bearer '+token,'Accept':'application/json'})
            response=conn.getresponse(); body=response.read(2097153)
            require(len(body)<=2097152,'BOUNDED_RESPONSE_REQUIRED')
            try: data=json.loads(body)
            except (ValueError,UnicodeError): data={}
            if not isinstance(data,dict): data={}
            safe={'httpStatus':response.status,'hostTransportOnly':True,'responseValuesPrinted':False}
            for key in ('code','errorCode','reason'):
                value=data.get(key)
                if isinstance(value,str) and re.fullmatch('[A-Z][A-Z0-9_:.-]{0,119}',value): safe[key]=value
            safe['ownerAuthorizationDeniedDetail']=data.get('detail')=='Owner authorization denied'
            safe['bundleVersion']=data.get('bundleVersion') if type(data.get('bundleVersion')) is int else None
            safe['approvedConfigurationReturned']=response.status==200 and data.get('state')=='APPROVED' and str(data.get('onboardingVersionId',data.get('onboarding_version_id','')))==ONBOARDING_VERSION
            safe['exactConfigurationHashReturned']=response.status==200 and data.get('configuration_hash',data.get('configurationHash'))==CONFIGURATION_HASH
            return safe
        finally: conn.close()
    try:
        values,config_hash=properties(actual,root)
        for channel,key in [('activation','ouf.ingestion.activation.token-file'),
                            ('authorization','ouf.authorization.registry-token-file')]:
            found=values.get(normal(key),set())-set([''])
            require(len(found)<=1,'CONFLICTING_TOKEN_SELECTION')
            if not found:
                rows.append(dict(channel=channel,configured=False)); continue
            target=next(iter(found)); covered(actual,target)
            token=bounded(root,target,65536); metadata=token_metadata(token)
            result=dict(channel=channel,configured=True,**metadata)
            if metadata['expiredAtRead']:
                result['requestSkipped']='TOKEN_EXPIRED'
            else:
                path=(configuration_path()
                    if channel=='activation' else '/internal/capabilities/v1/authorization/policy-bundle/active')
                result['configuredGatewayEqualsReviewedOrigin']=(values.get(normal('ouf.ingestion.activation.gateway-url'),set())=={origin}) if channel=='activation' else None
                if channel=='authorization':
                    selected=values.get(normal('ouf.authorization.registry-url'),set())
                    require(selected=={origin.rstrip('/')+path},'REVIEWED_POLICY_ENDPOINT_REQUIRED')
                result['get']=get(path,token)
            rows.append(result)
        require(process==process_pin(),'PROCESS_GENERATION_CHANGED')
    finally: os.close(root)
    require(pin==ns['runtime_pin'](ns['engine_get'](engine,'containers','ouf-ingestion')),
        'CONTAINER_GENERATION_CHANGED')
    emit('INGESTION_DEPENDENCIES',generationStableAcrossReads=True,containerId=actual['Id'],
        imageId=actual['Image'],configFileSha256=config_hash,channels=rows,
        maximumCredentialFiles=2,maximumGatewayGets=2,claimsProveEffectiveAuthorization=False,
        loadedSnapshotProven=False,sourceCommitLabel=actual['Config'].get('Labels',{}).get('org.opencontainers.image.revision'))
    require(onboarding_pin==ns['runtime_pin'](ns['engine_get'](engine,'containers',onboarding_pin['containerId'])),
        'ONBOARDING_GENERATION_CHANGED_DURING_GET')
    require(ns['read'](ROLLOUT/'recovery.json',65536)==record
        and digest(ns['read'](ROLLOUT/'review.json',8388608))==review_hash
        and ns['read'](ROLLOUT/'authority.json',131072)==authority,'ROLLOUT_HISTORY_CHANGED_DURING_READ')
    emit('END',complete=True,readinessReconciled=False,approvalReplayed=False)

if __name__=='__main__':
    emit('BEGIN',maximumSeconds=35,maximumEngineReads=4,maximumCredentialFiles=2,maximumGatewayGets=2)
    try: main()
    except Exception as error:
        reason=str(error) if type(error) is ValueError and re.fullmatch('[A-Z_]+',str(error)) else type(error).__name__
        emit('STOP',reason=reason,exceptionMessagePrinted=False)
