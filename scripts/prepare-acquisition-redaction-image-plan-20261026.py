#!/usr/bin/env python3
"""Prepare exact two READ-replica image/native plans from sealed input and CI ZIPs.

File-only operation. No Engine, namespace join, key, credential, IAM or SQL I/O.
"""
import copy,gzip,hashlib,importlib.util,ipaddress,json,os,re,shutil,signal,stat,sys,zipfile
from pathlib import Path
INPUT_ROOT=Path('/etc/ouf/deploy-snapshots/acquisition-redaction-update-inputs-v1')
INPUT_HASH='9bbe7298c2eff0be51bf943919c9db0044413256b08efe620a503f79aef4d7d2'
CASE_HASH='db8577ab3082fbc2308ae0a6d33eb55fffc85e3020f99a8623cf69b165d849aa'
ROOT=Path('/etc/ouf/deploy-snapshots/acquisition-redaction-image-plan-9bbe7298c2eff0be-v1')
COUNTS={'privateMetadataReads':0,'ciZipReads':0,'nativeArchivesPrepared':0,'engineGets':0,'containerWrites':0,'imageImports':0}
MEMBERS={'image.tar.gz','image-id.txt','acquisition-image-config.json','source-commit.txt','SHA256SUMS'}
LIMIT=1024*1024*1024
class Stop(RuntimeError):pass
def require(ok,code):
    if not ok:raise Stop(code)
def encoded(v):return json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def sha(raw):return hashlib.sha256(raw).hexdigest()
def digest(v):return sha(encoded(v))
def decode(raw):
    def unique(rows):
        out={}
        for k,v in rows:require(k not in out,'DUPLICATE_PLAN_KEY');out[k]=v
        return out
    return json.loads(raw,object_pairs_hook=unique,parse_constant=lambda _:require(False,'NONFINITE_PLAN_JSON'))
def frame(s):return tuple(getattr(s,k)for k in('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
def ancestry(path):
    require(path.is_absolute()and path.resolve()==path,'CANONICAL_PLAN_PATH_REQUIRED')
    for part in(path,*path.parents):
        s=part.lstat();require(stat.S_ISDIR(s.st_mode)and s.st_uid==s.st_gid==0 and not s.st_mode&0o022,'ROOT_PLAN_ANCESTRY_REQUIRED')
def sync(path):
    fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(fd)
    finally:os.close(fd)
def put(path,value):
    raw=value if isinstance(value,bytes)else encoded(value)
    require(len(raw)<=64*1024*1024,'BOUNDED_PLAN_OUTPUT_REQUIRED')
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o400)
    with os.fdopen(fd,'wb')as out:
        os.fchmod(out.fileno(),0o400);out.write(raw);out.flush();os.fsync(out.fileno())
    sync(path.parent)
def private(root,path,expected=None):
    require(COUNTS['privateMetadataReads']<2,'TWO_EXACT_PRIVATE_PLAN_READS_ONLY')
    COUNTS['privateMetadataReads']+=1;put(root/('private-read-'+str(COUNTS['privateMetadataReads'])+'-claim.json'),{'path':str(path),'attemptNotCompletion':True})
    ancestry(path.parent);fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        before=os.fstat(fd);require(stat.S_ISREG(before.st_mode)and before.st_uid==before.st_gid==0 and before.st_nlink==1 and stat.S_IMODE(before.st_mode)in(0o400,0o600)and 0<before.st_size<=6*1024*1024,'PROTECTED_CAPTURE_METADATA_REQUIRED')
        raw=b''
        while len(raw)<before.st_size:
            part=os.read(fd,min(65536,before.st_size-len(raw)));require(part,'COMPLETE_CAPTURE_METADATA_REQUIRED');raw+=part
        require(frame(before)==frame(os.fstat(fd))==frame(path.lstat()),'CAPTURE_METADATA_CHANGED')
        require(expected is None or sha(raw)==expected,'EXACT_CAPTURE_BYTES_REQUIRED')
        return decode(raw),{'path':str(path),'metadata':list(frame(before)),'sha256':sha(raw)}
    finally:os.close(fd)
def helper(name,folder):
    spec=importlib.util.spec_from_file_location('mcp_plan_'+name,folder/(name+'.py'));m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m

def stage_zip(root,path,role,case):
    d=case['artifacts'][role];COUNTS['ciZipReads']+=1
    put(root/'zip-read-claim.json',{'sha256':d['zipSha256'],'maximumBytes':d['zipBytes'],'attemptNotCompletion':True})
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb')as stream:
        before=os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode)and before.st_uid>0 and before.st_nlink==1
                and stat.S_IMODE(before.st_mode)==0o400 and before.st_size==d['zipBytes'],'EXACT_PRIVATE_TRANSPORT_ZIP_REQUIRED')
        h=hashlib.sha256()
        for block in iter(lambda:stream.read(65536),b''):h.update(block)
        require(h.hexdigest()==d['zipSha256'],'EXACT_CI_ZIP_DIGEST_REQUIRED');stream.seek(0);hashes={}
        with zipfile.ZipFile(stream)as z:
            rows=z.infolist()
            require(len(rows)==len(MEMBERS)and{r.filename for r in rows}==MEMBERS,'EXACT_TWO_READ_ZIP_MEMBERS_REQUIRED')
            for row in rows:
                require(not row.is_dir()and stat.S_IFMT(row.external_attr>>16)in(0,stat.S_IFREG)
                        and 0<row.file_size<=(220*1024*1024 if row.filename=='image.tar.gz'else 2*1024*1024),'BOUNDED_REGULAR_CI_MEMBER_REQUIRED')
                raw=z.read(row);require(len(raw)==row.file_size,'COMPLETE_CI_MEMBER_REQUIRED')
                put(root/row.filename,raw);hashes[row.filename]=sha(raw)
        require(frame(before)==frame(os.fstat(stream.fileno()))==frame(path.lstat()),'CI_ZIP_CHANGED_DURING_STAGING')
    checks={}
    for line in(root/'SHA256SUMS').read_text().splitlines():
        require(re.fullmatch('[a-f0-9]{64}  [A-Za-z0-9_.-]+',line),'EXACT_CI_CHECKSUM_SYNTAX_REQUIRED')
        h,name=line.split('  ');require(name not in checks,'UNIQUE_CI_CHECKSUM_REQUIRED');checks[name]=h
    require(set(checks)==MEMBERS-{'SHA256SUMS'}and all(hashes[k]==v for k,v in checks.items()),'ALL_CI_MEMBER_DIGESTS_REQUIRED')
    require((root/'source-commit.txt').read_text().strip()==d['sourceCommit'],'EXACT_CI_SOURCE_REQUIRED')
    image=(root/'image-id.txt').read_text().strip()
    require(re.fullmatch('sha256:[a-f0-9]{64}',image),'EXACT_CI_CONFIGURATION_ID_REQUIRED')
    images=decode((root/'acquisition-image-config.json').read_bytes())
    require(type(images)is list and len(images)==1 and images[0]['Id']==image,'ONE_EXACT_CI_IMAGE_REQUIRED')
    config=images[0]['Config']
    require(config['User']==d['user']and config['Entrypoint']==d['entrypoint'],'QUALIFIED_ISOLATED_READ_ENTRYPOINT_REQUIRED')
    receipt={'schema':'ouf.acquisition-redaction-image-staged.v1','role':role,'descriptor':d,'fileHashes':hashes,'configurationImageId':image,'capturedInputsHash':INPUT_HASH}
    put(root/'staged-receipt.json',receipt)
    return receipt,images[0]

def replacement(role,actual,image,p,mac):
    request=p.config_copy(actual);config=image['Config'];old=actual['Config'];host=copy.deepcopy(actual['HostConfig'])
    require(old['User']==config['User']and old['Entrypoint']==config['Entrypoint'],'EXACT_EXISTING_ISOLATED_READ_LAUNCH_REQUIRED')
    require(host.get('ReadonlyRootfs')is True and host.get('AutoRemove')is False and type(host.get('Memory'))is int and host['Memory']>=0
            and not host.get('Privileged')and not host.get('Devices')and not host.get('DeviceRequests')and not host.get('CapAdd')
            and 'ALL'in(host.get('CapDrop')or[])and 'no-new-privileges:true'in(host.get('SecurityOpt')or[]),'EXACT_HARDENED_RETAINED_READ_HOST_POLICY_REQUIRED')
    require(host.get('OomKillDisable')is None or type(host.get('OomKillDisable'))is bool,'TYPED_RETAINED_READ_OOM_POLICY_REQUIRED')
    for mount in actual['Mounts']:
        require(mount['RW']is False or mount['Type']=='tmpfs'and mount['Destination']=='/tmp','ONLY_RETAINED_READONLY_DATA_MOUNTS_REQUIRED')
    require(not host.get('PortBindings')and not host.get('PublishAllPorts'),'NO_NEW_READ_HOST_PORTS_REQUIRED')
    labels=copy.deepcopy(old.get('Labels')or{});defaults=config.get('Labels')or{}
    require(all(k.startswith('org.opencontainers.image.')or labels.get(k)==v for k,v in defaults.items()),'ONLY_OCI_IMAGE_LABEL_DELTA_ALLOWED')
    labels.update(defaults)
    require(set(p.env(config))<=set(p.env(old)),'NO_NEW_IMAGE_ENV_DEFAULTS_ALLOWED')
    restore=copy.deepcopy(host['RestartPolicy']);host['RestartPolicy']={'Name':'no','MaximumRetryCount':0}
    name=actual['Name'].removeprefix('/');network_value=next(iter(actual['NetworkSettings']['Networks'].values()))
    net=p.network(actual,[name,*(network_value.get('Aliases')or[])],preserve_mac=True)
    endpoint=net['request']['EndpointsConfig'][net['name']]
    ipam=copy.deepcopy(network_value.get('IPAMConfig')or{})
    require(type(ipam)is dict and set(ipam)<={'IPv4Address','IPv6Address','LinkLocalIPs'},'CLOSED_RETAINED_READ_IPAM_REQUIRED')
    for source,target,version in(('IPAddress','IPv4Address',4),('GlobalIPv6Address','IPv6Address',6)):
        address=network_value.get(source)
        if address:
            parsed=ipaddress.ip_address(address)
            require(parsed.version==version and not parsed.is_unspecified and not parsed.is_multicast
                    and ipam.get(target)in(None,'',address),'EXACT_RETAINED_READ_ENDPOINT_ADDRESS_REQUIRED');ipam[target]=address
    endpoint['IPAMConfig']=ipam
    request.update(Image=image['Id'],Labels=labels,HostConfig=host,NetworkingConfig=net['request'])
    require(request['Env']==old['Env']and request.get('Cmd')==old.get('Cmd'),'READ_ENV_AND_APPLICATION_ARGS_PRESERVED_REQUIRED')
    # Previously installed READ replicas may be endpoint-only. Do not assert
    # the old MCP's legacy-present frame for a different container generation.
    declared=old.get('MacAddress')
    if type(declared)is str and declared:
        mac_policy=mac.policy(actual)
    else:
        require('MacAddress'not in old or declared is None or type(declared)is str and declared=='',
                'TYPED_ENDPOINT_ONLY_CONFIG_MAC_REQUIRED')
        mac_policy={'profile':'ENDPOINT_ONLY_CONFIG_EXACT_AFTER_STOP_AND_DETACH_V1',
                    'configurationMacState':'ABSENT'if'MacAddress'not in old else'NULL'if declared is None else'EMPTY_STRING',
                    'originalConfigHash':digest(old),'detachedConfigHash':digest(old),
                    'originalEndpointSetHash':digest(actual['NetworkSettings']['Networks']),'originalHashesRewritten':False}
    return {'role':role,'name':name,'retiredName':name+'-retained-redaction-'+INPUT_HASH[:12],
            'oldBinding':p.stable_binding(actual),'request':request,'restoreRestartPolicy':restore,
            'network':{'name':net['name'],'id':net['id']},'oldNativeHostConfig':actual['HostConfig'],
            'legacyConfigMacDetachPolicy':mac_policy,'networkMacPolicy':'RETAIN_EXACT_ENDPOINT_AFTER_OLD_STOP_AND_DETACH',
            'oldRetainedStopped':True,'automaticRollbackAllowed':False,'resourcePolicyChanged':False}

def compile_plan(inputs,receipts,images,p,mac):
    roles={'gateway','postgres','ingestion','udp','ingestion-read','udp-read','mcp'}
    require(inputs['schema']=='ouf.acquisition-redaction-update-inputs.v1'
            and set(inputs['currentObservations'])==set(inputs['currentProcessPins'])==roles
            and inputs['counts']=={'bytes':72997,'engineGets':10,'privateMetadataReads':4},'EXACT_TWO_READ_CAPTURE_REQUIRED')
    require(set(images)==set(receipts)=={'ingestion','udp'}and inputs['candidateSourceCommits']=={r:receipts[r]['descriptor']['sourceCommit']for r in images},'EXACT_TWO_CANDIDATE_SOURCES_REQUIRED')
    info=inputs['engineInfo'];require(info['ServerVersion']=='29.8.1','QUALIFIED_ENGINE_VERSION_REQUIRED')
    native=['driver-type','io.containerd.snapshotter.v1']in(info.get('DriverStatus')or[])
    require(native or info['Driver']=='overlay2','QUALIFIED_ENGINE_STORE_REQUIRED')
    return {'schema':'ouf.acquisition-redaction-frozen-plan.v1','capturedInputsHash':INPUT_HASH,
            'stagedReceiptHashes':{r:digest(v)for r,v in receipts.items()},'bootId':inputs['bootId'],
            'engineBinding':inputs['engineBinding'],'engineInfoHash':digest(info),
            'nativeIdentityProfile':'CONFIG_AND_NATIVE_MANIFEST'if native else'CONFIG_DIGEST',
            'currentProcessPins':copy.deepcopy(inputs['currentProcessPins']),
            'existingApplications':{r:p.stable_binding(v)for r,v in inputs['currentObservations'].items()},
            'readReplacements':{r:replacement(r,inputs['currentObservations'][r+'-read'],images[r],p,mac)for r in images},
            'retainedCaptureCounts':copy.deepcopy(inputs['counts']),'retainedMcpCounts':copy.deepcopy(inputs['retainedMcpCounts']),
            'mcpUnchanged':True,'gatewayUnchanged':True,'originalWorkersUnchanged':True,'registryWorkerTouched':False,
            'databaseMigrationsAuthorized':False,'credentialFileReadsAuthorized':False,'grantChangesAuthorized':False,
            'acquisitionCallsAuthorized':False,'runtimeAuthorityIssued':False,'executionEntryQualified':False,
            'automaticReplayAllowed':False,'budgetReset':False,'applicationE2EProven':False,'releaseAcceptance':False}

def prepare(downloads,folder,*,root=ROOT,input_root=INPUT_ROOT,qualified=None):
    require(os.geteuid()==os.getegid()==0,'ROOT_IMAGE_PLAN_REQUIRED');ancestry(root.parent)
    require(not os.path.lexists(root),'IMAGE_PLAN_SCOPE_CONSUMED_NO_REPLAY');root.mkdir(mode=0o700);root.chmod(0o700);sync(root.parent)
    put(root/'claim.json',{'schema':'ouf.acquisition-redaction-image-plan-claim.v1','capturedInputsHash':INPUT_HASH,
                         'maximumSeconds':300,'engineGets':0,'containerWrites':0,'imageImports':0,'automaticReplayAllowed':False})
    inputs,sealed=private(root,input_root/'inputs.json',INPUT_HASH)
    result,result_seal=private(root,input_root/'result.json')
    require(result['status']=='ACQUISITION_REDACTION_UPDATE_INPUTS_CAPTURED_NOT_AUTHORIZED'and result['complete']is True
            and result['inputsHash']==INPUT_HASH and result['counts']==inputs['counts']and result['containerWrites']==0
            and result['runtimeAuthorityIssued']is False,'POSITIVE_REDACTION_CAPTURE_RESULT_REQUIRED')
    case=decode((folder/'case.json').read_bytes());require(digest(case)==CASE_HASH,'EXACT_TWO_ARTIFACT_CASE_REQUIRED')
    require(shutil.disk_usage(root).free>=3*1024*1024*1024,'IMAGE_PLAN_DISK_HEADROOM_REQUIRED')
    p=helper('plan_helper',folder);mac=helper('retained_mac',folder);custody=helper('image_custody',folder)
    receipts={};images={}
    for role in('ingestion','udp'):
        target=root/role;target.mkdir(mode=0o700);target.chmod(0o700)
        receipts[role],images[role]=stage_zip(target,downloads/(role+'.zip'),role,case)
    plan=compile_plan(inputs,receipts,images,p,mac);put(root/'frozen-plan.json',plan)
    native_images={};native=plan['nativeIdentityProfile']=='CONFIG_AND_NATIVE_MANIFEST'
    for role in('ingestion','udp'):
        target=root/role;expanded=target/'expanded.tar'
        fd=os.open(expanded,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o400)
        with os.fdopen(fd,'w+b')as output,gzip.open(target/'image.tar.gz','rb')as zipped:
            os.fchmod(output.fileno(),0o400);total=0
            while block:=zipped.read(1048576):
                total+=len(block);require(total<=LIMIT,'BOUNDED_IMAGE_GZIP_EXPANSION');output.write(block)
            output.flush();os.fsync(output.fileno());output.seek(0);checksum,_=custody.hashed(output,LIMIT)
            audit=custody.archive(output,checksum,images[role]['Id'],case['artifacts'][role]['sourceCommit'],ci_source_binding={
                'schema':'ouf.acquisition-image-source-by-qualified-ci-manifest.v1','sourceCommit':case['artifacts'][role]['sourceCommit'],
                'imageId':images[role]['Id'],'compressedArchiveSha256':receipts[role]['fileHashes']['image.tar.gz'],
                'stagedReceiptHash':digest(receipts[role]),'frozenPlanHash':digest(plan)})
            require(all(audit['imageConfig'].get(k)==images[role]['Config'].get(k)for k in custody.FIELDS),'ARCHIVED_AND_INSPECTED_CONFIG_MATCH_REQUIRED')
            native_path=target/'native.tar';fd=os.open(native_path,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o400)
            with os.fdopen(fd,'w+b')as out:
                os.fchmod(out.fileno(),0o400);derived=custody.tagless_archive(output,out,audit,containerd=native)
                out.flush();os.fsync(out.fileno());metadata=list(frame(os.fstat(out.fileno())))
            if native:audit['nativeIdentity']=custody.native_identity(audit)
        identity={'configurationImageId':images[role]['Id'],'nativeImageId':custody.runtime_image_id(audit),
                  'derivedArchiveSha256':derived['derivedArchiveSha256'],'archiveBytes':derived['archiveBytes']}
        if qualified is not None:
            require(qualified['schema']=='ouf.acquisition-redaction-native-qualification.v1'
                    and qualified['caseHash']==CASE_HASH and qualified['profiles']['containerd'if native else'classic'][role]==identity,
                    'INDEPENDENTLY_QUALIFIED_NATIVE_BYTES_REQUIRED')
        native_images[role]={'identity':identity,'audit':audit,'archive':{'path':str(native_path),'sha256':derived['derivedArchiveSha256'],
                            'bytes':derived['archiveBytes'],'metadata':metadata}}
        COUNTS['nativeArchivesPrepared']+=1
    native_plan={'schema':'ouf.acquisition-redaction-native-image-plan.v1','frozenPlanHash':digest(plan),'proposal':plan,
                 'nativeImages':native_images,'historySeals':[sealed,result_seal],'executionEntryQualified':False,
                 'runtimeAuthorityIssued':False,'automaticReplayAllowed':False,'budgetReset':False}
    for seal in(sealed,result_seal):require(list(frame(Path(seal['path']).lstat()))==seal['metadata'],'ORIGINAL_CAPTURE_SEAL_CHANGED')
    put(root/'native-plan.json',native_plan)
    output={'schema':'ouf.acquisition-redaction-image-plan-prepared.v1','status':'ACQUISITION_REDACTION_IMAGES_AND_PLAN_PREPARED_NOT_AUTHORIZED',
            'complete':True,'contextPath':str(root),'inputsHash':INPUT_HASH,'frozenPlanHash':digest(plan),'nativePlanHash':digest(native_plan),
            'nativeImages':{r:v['identity']for r,v in native_images.items()},'counts':dict(COUNTS),'runtimeAuthorityIssued':False,
            'executionEntryQualified':False,'currentRuntimeRevalidated':False,'currentApplicationPolicyOrLabelsObserved':False,
            'continuationAuthorized':False,'containerWrites':0,'imageImports':0,'oauthRequests':0,'credentialFileReads':0,
            'installationSigningKeysRead':False,'sqlSessions':0,'sourceActivations':0,'acquisitionsExecuted':0,
            'registryWorkerTouched':False,'applicationE2EProven':False,'releaseAcceptance':False,'automaticReplayAllowed':False,'budgetReset':False}
    put(root/'result.json',output);return output

def main():
    try:
        require(len(sys.argv)==2 and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode,'ISOLATED_EXACT_DOWNLOAD_DIRECTORY_REQUIRED')
        folder=Path(__file__).resolve().parent;ancestry(folder)
        for name in('prepare.py','case.json','qualification.json','plan_helper.py','retained_mac.py','image_custody.py'):
            info=(folder/name).lstat();require(stat.S_ISREG(info.st_mode)and info.st_uid==info.st_gid==0 and info.st_nlink==1
                        and stat.S_IMODE(info.st_mode)==0o400,'ROOT_PROTECTED_SOURCE_CLOSURE_REQUIRED')
        qualification=decode((folder/'qualification.json').read_bytes())
        signal.signal(signal.SIGALRM,lambda *_:(_ for _ in()).throw(Stop('FINITE_IMAGE_PREPARATION_WINDOW_EXPIRED')));signal.alarm(300)
        result=prepare(Path(sys.argv[1]),folder,qualified=qualification)
    except BaseException as error:
        reason=str(error)if type(error)is Stop and re.fullmatch('[A-Z0-9_]{1,120}',str(error))else'PRIVATE_IMAGE_PLAN_FAILURE_RECONCILE'
        result={'schema':'ouf.acquisition-redaction-image-plan-prepared.v1','status':'STOP_RECONCILE','complete':False,
                'reasonCode':reason,'contextPath':str(ROOT),'counts':dict(COUNTS),'runtimeAuthorityIssued':False,
                'automaticReplayAllowed':False,'budgetReset':False,'applicationE2EProven':False,'releaseAcceptance':False}
        if ROOT.exists()and not(ROOT/'result.json').exists():put(ROOT/'result.json',result)
    finally:signal.alarm(0)
    print(json.dumps(result,sort_keys=True,separators=(',',':')),flush=True);return 0 if result['complete']else 2

if __name__=='__main__':raise SystemExit(main())
