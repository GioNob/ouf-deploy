"""Classify references in the sealed request; no source file read or acceptance."""
import hashlib,json,os,re,signal,sys,types
PLANNER_HASH='c89caa119ef7c4fea07ac6a65dd5d2b173c144cf6a802e646929418acc859d56'
class Denied(ValueError):pass
def require(ok,reason):
    if not ok:raise Denied(reason)
def planner(raw):
    require(type(raw) is bytes and len(raw)<=131072 and hashlib.sha256(raw).hexdigest()==PLANNER_HASH,'EXACT_SOURCE_USAGE_PLANNER_REQUIRED')
    p=types.ModuleType('sealed_source_usage_planner');exec(compile(raw,'<sealed-source-usage-planner>','exec'),p.__dict__);return p
def references(request,old):
    """Variable NAMES only. A textual reference never establishes its writer."""
    env=request.get('Env') or [];require(type(env) is list and len(env)<=256,'BOUNDED_SOURCE_USAGE_ENV_REQUIRED')
    parsed={}
    for row in env:
        require(type(row) is str and '=' in row and len(row)<=65536,'BOUNDED_SOURCE_USAGE_ENV_ROW_REQUIRED')
        key,value=row.split('=',1)
        require(re.fullmatch('[A-Za-z_][A-Za-z0-9_]{0,127}',key) and key not in parsed,'EXACT_SOURCE_USAGE_ENV_KEYS_REQUIRED')
        parsed[key]=value
    result=[]
    for index,item in enumerate(old):
        binding=item['binding'];target=binding['Destination'];records=item['sourceMetadata']
        source_type=binding['Type'];matches=[]
        for key,value in parsed.items():
            # Only exact path references, with supported file/configtree URI
            # prefixes. Never scan arbitrary credentials or print env values.
            path=value
            for prefix in ('file:','configtree:'):
                if path.startswith(prefix):path=path[len(prefix):];break
            if path==target or path==target+'/':kind='MOUNT_TARGET_REFERENCE'
            elif records[0]['kind']=='directory' and len(records)==2 and path==target+'/'+records[1]['path']:kind='RETAINED_MEMBER_REFERENCE'
            else:continue
            matches.append({'environmentKey':key,'matchKind':kind})
        matches.sort(key=lambda row:row['environmentKey'])
        result.append({'mountIndex':index,'mountType':source_type,'sourceKind':records[0]['kind'],
                       'environmentReferences':matches,'referenceCount':len(matches),'writerIdentityProven':False})
    return result
def collect(p,atomic):
    before=p.review_scope(p.PARENT);raw=atomic.read(p.PARENT/'intake.json',0)
    p.require(p.sha(raw)==p.PARENT_HASH,'EXACT_SOURCE_USAGE_PARENT_REQUIRED');manifest=p.decode(raw)
    p.require(set(manifest.get('fileHashes',{}))==set(p.NAMES),'EXACT_SOURCE_USAGE_FILE_SET_REQUIRED')
    files={n:atomic.read(p.PARENT/n,0) for n in p.NAMES}
    p.require(manifest['fileHashes']=={n:p.sha(v) for n,v in files.items()},'SOURCE_USAGE_PRIVATE_FILE_HASH_DRIFT')
    atomic.verify(p.PARENT,files,raw,0)
    p.require(p.sha(files[p.NAMES[0]])==p.REQUEST_HASH,'EXACT_SOURCE_USAGE_REQUEST_BYTES_REQUIRED')
    request=p.decode(files[p.NAMES[0]]);shape=p.request_mount_shape(request);old=p.decode(files[p.NAMES[2]])
    p.require(type(old) is list and len(old)==2 and tuple(p.sha(p.encoded(v['sourceMetadata'])) for v in old)==p.METADATA_HASHES,'EXACT_SOURCE_USAGE_METADATA_SEALS_REQUIRED')
    result=references(request,old)
    atomic.verify(p.PARENT,files,raw,0);p.require(p.review_scope(p.PARENT)==before,'SOURCE_USAGE_PARENT_SCOPE_CHANGED')
    return {'status':'RETAINED_V11_SOURCE_USAGE_REFERENCES_CAPTURED_NOT_WRITER_PROOF','baselineIntakeHash':p.PARENT_HASH,
            'requestMountShape':shape,'retainedSourceUsage':result}
def main():
    report={'schema':'ouf.retained-v11-source-usage.v1','maxReadSeconds':120,'mountedSourceContentBytesRead':0,
            'protectedFileWrites':0,'environmentValuesPrinted':False,'sourcePathsPrinted':False,'memberNamesPrinted':False,
            'writerIdentityProven':False,'baselineRefreshed':False,'automaticRetry':False,'r12Touched':False,'budgetReset':False,
            'containerLifecycleOperations':0,'databaseQueries':0,'databaseWrites':0,'providerCalls':0,'dnsQueries':0,'firewallWrites':0,
            'signaturesIssued':0,'runtimeAuthorityIssued':False,'completeSixMountClosureProven':False,
            'applicationCutoverAuthorized':False,'productionApplyReady':False,'observationsAreHistorical':True,'notReleaseAcceptance':True}
    p=None
    try:
        require(os.geteuid()==0 and sys.flags.isolated and sys.dont_write_bytecode and len(sys.argv)==1,'ISOLATED_ROOT_SOURCE_USAGE_REQUIRED')
        def deadline(*_):raise Denied('SOURCE_USAGE_READ_DEADLINE')
        signal.signal(signal.SIGALRM,deadline);signal.alarm(120)
        p=planner(globals().get('__planner_source__'));atomic=p.atomic_source(globals().get('__atomic_source__'))
        report.update(collect(p,atomic));code=0
    except Exception as e:
        reason=str(e);trusted=type(e) is Denied or p is not None and type(e) is p.Denied
        report.update(status='RETAINED_V11_SOURCE_USAGE_BLOCKED',reason=reason if trusted and re.fullmatch('[A-Z][A-Z0-9_]{0,120}',reason) else 'SOURCE_USAGE_UNPROVEN');code=1
    finally:signal.alarm(0)
    print('OUF_RETAINED_V11_SOURCE_USAGE='+json.dumps(report,sort_keys=True));return code
if __name__=='__main__':raise SystemExit(main())
