#!/usr/bin/env python3
"""Stage one exact CI ZIP and compile a private MCP-only plan. No runtime I/O.

Only the new capture inputs/result are read. Shared modules are pure helpers;
no consumed controller or entrypoint is imported or executed. No Engine socket,
namespace, credential, signing key, IAM, SQL, route or application is accessed.
"""
import copy,gzip,hashlib,importlib.util,json,os,re,shutil,signal,stat,sys,zipfile
from pathlib import Path

INPUT_ROOT=Path('/etc/ouf/deploy-snapshots/mcp-denial-update-inputs-9a374dd07745f059-v1')
INPUT_HASH='fb4b7c9ae832e779192f1ff6e032e49c696752e182a57b8e9464f5a76000b3e4'
ROOT=Path('/etc/ouf/deploy-snapshots/mcp-denial-image-plan-fb4b7c9ae832e779-v1')
SOURCE='9a374dd07745f059de3ad39757c68f02db6d29c3'
IMAGE='sha256:ffc78ca5e7fc1a1941cd4c4347d43e061df97d06c9fca44df0e8a5c47b5b839d'
ZIP_HASH='6c31a1b5698942ddbb47b96ec1b49860c690c44aac8106beb1ca4b1ed7bba56a'
ARCHIVE_HASH='19fd036f973e52734d209d20671240f8973cd55d7183968ce605254b94cbd5bb'
CAP_HASH='f2a6f20ff15969c068b87cbd15cf8485e5680f63123d60e90b58c7a09b7b37ae'
MEMBERS={'image.tar.gz','image-id.txt','image-config.json','source-commit.txt','SHA256SUMS','capabilities.json'}
COUNTS={'privateMetadataReads':0,'ciZipReads':0,'nativeArchivesPrepared':0,'engineGets':0,'containerWrites':0,'imageImports':0}

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
def stage_zip(root,path):
    COUNTS['ciZipReads']+=1;put(root/'zip-read-claim.json',{'sha256':ZIP_HASH,'maximumBytes':9617218,'attemptNotCompletion':True})
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb')as stream:
        before=os.fstat(fd);require(stat.S_ISREG(before.st_mode)and before.st_nlink==1 and before.st_size==9617218,'EXACT_CI_ZIP_SIZE_REQUIRED')
        h=hashlib.sha256()
        for block in iter(lambda:stream.read(65536),b''):h.update(block)
        require(h.hexdigest()==ZIP_HASH,'EXACT_CI_ZIP_DIGEST_REQUIRED');stream.seek(0);hashes={}
        with zipfile.ZipFile(stream)as z:
            rows=z.infolist();require(len(rows)==len(MEMBERS)and{r.filename for r in rows}==MEMBERS,'EXACT_CI_ZIP_MEMBER_SET_REQUIRED')
            for row in rows:
                require(not row.is_dir()and stat.S_IFMT(row.external_attr>>16)in(0,stat.S_IFREG)and 0<row.file_size<=(16*1024*1024 if row.filename=='image.tar.gz'else 2*1024*1024),'BOUNDED_REGULAR_CI_MEMBER_REQUIRED')
                raw=z.read(row);require(len(raw)==row.file_size,'COMPLETE_CI_MEMBER_REQUIRED');put(root/row.filename,raw);hashes[row.filename]=sha(raw)
        require(frame(before)==frame(os.fstat(fd))==frame(path.lstat()),'CI_ZIP_CHANGED_DURING_STAGING')
    checks={}
    for line in(root/'SHA256SUMS').read_text().splitlines():
        require(re.fullmatch('[a-f0-9]{64}  [A-Za-z0-9_.-]+',line),'EXACT_CI_CHECKSUM_SYNTAX_REQUIRED');h,name=line.split('  ');require(name not in checks,'UNIQUE_CI_CHECKSUM_REQUIRED');checks[name]=h
    require(set(checks)==MEMBERS-{'SHA256SUMS'}and all(hashes[k]==v for k,v in checks.items()),'ALL_CI_MEMBER_DIGESTS_REQUIRED')
    require(hashes['image.tar.gz']==ARCHIVE_HASH and hashes['capabilities.json']==CAP_HASH and(root/'source-commit.txt').read_text().strip()==SOURCE and(root/'image-id.txt').read_text().strip()==IMAGE,'EXACT_CI_IMAGE_SOURCE_REQUIRED')
    return {'schema':'ouf.mcp-denial-image-staged.v1','sourceCommit':SOURCE,'workflowRun':40284011851,'artifactId':12633545900,'artifactZipSha256':ZIP_HASH,'configurationImageId':IMAGE,'fileHashes':hashes,'capturedInputsHash':INPUT_HASH,'rootProtected':True,'imageImports':0,'targetUpdateAuthorized':False}
def compile_plan(inputs,receipt,image,p,mac):
    require(inputs['schema']=='ouf.mcp-denial-update-inputs.v1'and inputs['candidate']['sourceCommit']==SOURCE and inputs['candidate']['imageId']==IMAGE,'EXACT_DIAGNOSTIC_CAPTURE_REQUIRED')
    require(inputs['counts']=={'bytes':65041,'engineGets':9,'privateMetadataReads':5}and inputs['installedCounts']=={'adminGets':9,'adminPuts':2,'engineGets':306,'engineWrites':22,'imageLoadAttempts':3,'ownerConfigurationReads':83,'quarantineStops':2,'readinessGets':8,'serviceCredentialFileReads':3},'EXACT_CAPTURE_AND_INSTALLATION_HISTORY_REQUIRED')
    require(set(inputs['currentObservations'])==set(inputs['currentProcessPins'])=={'gateway','postgres','ingestion','udp','ingestion-read','udp-read','mcp'},'EXACT_SEVEN_ROLE_PLAN_REQUIRED')
    require(image['Id']==IMAGE and image['Config']['User']=='10005:10005'and image['Config']['Entrypoint']==['/usr/local/bin/ouf-mcp']and image['Config']['Cmd']==['server'],'EXACT_CANDIDATE_LAUNCH_REQUIRED')
    actual=inputs['currentObservations'];mcp=actual['mcp'];replacement=p.mcp_replacement(mcp,image,INPUT_HASH)
    replacement['retiredName']=replacement['name']+'-retained-mcp-diagnostics-'+INPUT_HASH[:12]
    # Same narrow legacy projection as the retained history. This pure compiler
    # never treats absent/empty/null/foreign legacy values as proof of detach.
    legacy=mac.policy(mcp)
    defaults=image['Config'].get('Labels')or{};old_labels=mcp['Config'].get('Labels')or{}
    require(all(k.startswith('org.opencontainers.image.')for k in set(defaults)-set(old_labels)),'NO_UNREVIEWED_IMAGE_LABEL_ADDITIONS')
    require(set(p.env(image['Config']))<=set(p.env(mcp['Config'])),'NO_UNREVIEWED_IMAGE_ENV_DEFAULT_ADDITIONS')
    info=inputs['engineInfo'];require(info['ServerVersion']=='29.8.1','QUALIFIED_ENGINE_VERSION_REQUIRED')
    native=['driver-type','io.containerd.snapshotter.v1']in(info.get('DriverStatus')or[])
    require(native or info['Driver']=='overlay2','QUALIFIED_ENGINE_STORE_REQUIRED')
    return {'schema':'ouf.mcp-denial-image-frozen-plan.v1','capturedInputsHash':INPUT_HASH,'stagedReceiptHash':digest(receipt),
            'bootId':inputs['bootId'],'engineBinding':inputs['engineBinding'],'engineInfoHash':digest(info),
            'nativeIdentityProfile':'CONFIG_AND_NATIVE_MANIFEST'if native else'CONFIG_DIGEST',
            'currentProcessPins':copy.deepcopy(inputs['currentProcessPins']),
            'retainedInstallationCounts':copy.deepcopy(inputs['installedCounts']),'retainedCaptureCounts':copy.deepcopy(inputs['counts']),
            'existingApplications':{role:p.stable_binding(value)for role,value in actual.items()},'mcpReplacement':replacement,
            'legacyConfigMacDetachPolicy':legacy,'sourceCommit':SOURCE,'configurationImageId':IMAGE,
            'additionalExistingToolSchemaChange':'PR78 HUMAN CAPABILITIES schema restoration',
            'applicationChanges':'PR79 bounded local authorization-denial diagnostic projection for the two acquisition READ tools',
            'normalMcpOAuthBootstrapMayOccur':True,'normalMcpManifestCatalogueUpdateMayOccur':True,
            'oneMcpManagerOnly':True,'oldMcpRetainedStopped':True,'automaticRollbackAllowed':False,
            'originalsAndReadReplicasUnchanged':True,'gatewayAndRegistryChanges':False,'databaseMigrationsAuthorized':False,
            'credentialFileReadsAuthorized':False,'acquisitionCallsAuthorized':False,'grantChangesAuthorized':False,
            'runtimeAuthorityIssued':False,'targetUpdateAuthorized':False,'executionEntryQualified':False,
            'automaticReplayAllowed':False,'budgetReset':False,'applicationE2EProven':False,'releaseAcceptance':False}
def prepare(download,folder,*,root=ROOT,input_root=INPUT_ROOT):
    require(os.geteuid()==os.getegid()==0,'ROOT_IMAGE_PLAN_REQUIRED');ancestry(root.parent)
    require(not os.path.lexists(root),'IMAGE_PLAN_SCOPE_CONSUMED_NO_REPLAY');root.mkdir(mode=0o700);os.chmod(root,0o700);sync(root.parent)
    put(root/'claim.json',{'schema':'ouf.mcp-denial-image-plan-claim.v1','capturedInputsHash':INPUT_HASH,'maximumSeconds':120,'engineGets':0,'containerWrites':0,'imageImports':0,'automaticReplayAllowed':False})
    inputs,sealed=private(root,input_root/'inputs.json',INPUT_HASH);result,result_seal=private(root,input_root/'result.json')
    require(result['status']=='MCP_DIAGNOSTIC_UPDATE_INPUTS_CAPTURED_NOT_AUTHORIZED'and result['complete']is True and result['inputsHash']==INPUT_HASH and result['counts']==inputs['counts']and result['containerWrites']==0 and result['runtimeAuthorityIssued']is False,'POSITIVE_CAPTURE_RESULT_REQUIRED')
    require(shutil.disk_usage(root).free>=256*1024*1024,'IMAGE_PLAN_DISK_HEADROOM_REQUIRED')
    receipt=stage_zip(root,download);put(root/'staged-receipt.json',receipt)
    images=decode((root/'image-config.json').read_bytes());require(type(images)is list and len(images)==1,'ONE_CI_IMAGE_INSPECTION_REQUIRED')
    p=helper('plan_helper',folder);mac=helper('retained_mac',folder);custody=helper('image_custody',folder)
    plan=compile_plan(inputs,receipt,images[0],p,mac);put(root/'frozen-plan.json',plan)
    expanded=root/'expanded.tar'
    fd=os.open(expanded,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o400)
    with os.fdopen(fd,'w+b')as output,gzip.open(root/'image.tar.gz','rb')as zipped:
        os.fchmod(output.fileno(),0o400);total=0
        while block:=zipped.read(65536):
            total+=len(block);require(total<=64*1024*1024,'BOUNDED_IMAGE_GZIP_EXPANSION');output.write(block)
        output.flush();os.fsync(output.fileno());output.seek(0);checksum,_=custody.hashed(output,64*1024*1024)
        audit=custody.archive(output,checksum,IMAGE,SOURCE,ci_source_binding={'schema':'ouf.acquisition-image-source-by-qualified-ci-manifest.v1','sourceCommit':SOURCE,'imageId':IMAGE,'compressedArchiveSha256':ARCHIVE_HASH,'stagedReceiptHash':digest(receipt),'frozenPlanHash':digest(plan)})
        require(audit['imageConfig']['User']==images[0]['Config']['User']and audit['imageConfig']['Entrypoint']==images[0]['Config']['Entrypoint']and audit['imageConfig']['Cmd']==images[0]['Config']['Cmd'],'ARCHIVED_AND_INSPECTED_LAUNCH_MATCH_REQUIRED')
        target=root/'native.tar';native=plan['nativeIdentityProfile']=='CONFIG_AND_NATIVE_MANIFEST'
        outfd=os.open(target,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o400)
        with os.fdopen(outfd,'w+b')as out:
            os.fchmod(out.fileno(),0o400);derived=custody.tagless_archive(output,out,audit,containerd=native);out.flush();os.fsync(out.fileno());native_metadata=list(frame(os.fstat(out.fileno())))
        if native:audit['nativeIdentity']=custody.native_identity(audit)
    COUNTS['nativeArchivesPrepared']+=1
    expected_id='sha256:9a1af5be94ff3dda4084b829e824482c5cf863525375c6f104a3fe89517e781e'if native else IMAGE
    expected_archive='dafe0b0be9bf78717061923b1d1fe9feab2f01b81fd1e432a8b7a35a7677bcc3'if native else'a7fd7391aca2d63207339c5cac689b221ea4759d25dc7a0ed112fdad41eba0fb'
    require(custody.runtime_image_id(audit)==expected_id and derived['derivedArchiveSha256']==expected_archive,'INDEPENDENTLY_QUALIFIED_NATIVE_BYTES_REQUIRED')
    native_plan={'schema':'ouf.mcp-denial-native-image-plan.v1','frozenPlanHash':digest(plan),'proposal':plan,'imageAudit':audit,
                 'nativeImageId':custody.runtime_image_id(audit),'nativeArchive':{'path':str(target),'sha256':derived['derivedArchiveSha256'],'bytes':derived['archiveBytes'],'metadata':native_metadata},
                 'historySeals':[sealed,result_seal],'executionEntryQualified':False,'runtimeAuthorityIssued':False,'targetUpdateAuthorized':False,'automaticReplayAllowed':False,'budgetReset':False}
    for seal in(sealed,result_seal):require(list(frame(Path(seal['path']).lstat()))==seal['metadata'],'ORIGINAL_CAPTURE_SEAL_CHANGED')
    put(root/'native-plan.json',native_plan)
    result={'schema':'ouf.mcp-denial-image-plan-prepared.v1','status':'MCP_DIAGNOSTIC_IMAGE_AND_PLAN_PREPARED_NOT_AUTHORIZED','complete':True,'contextPath':str(root),'inputsHash':INPUT_HASH,'frozenPlanHash':digest(plan),'nativePlanHash':digest(native_plan),'nativeImageId':native_plan['nativeImageId'],'candidateSourceCommit':SOURCE,'counts':dict(COUNTS),
            'currentRuntimeRevalidated':False,'configurationValuesPrinted':False,'installationSigningKeysRead':False,'credentialFileReads':0,'oauthRequests':0,'sqlSessions':0,'gatewayRequests':0,'registryWorkerTouched':False,'acquisitionsExecuted':0,'sourceActivations':0,'runtimeAuthorityIssued':False,'continuationAuthorized':False,'executionEntryQualified':False,'applicationE2EProven':False,'releaseAcceptance':False,'automaticReplayAllowed':False,'budgetReset':False}
    put(root/'result.json',result);return result
def main():
    try:
        require(len(sys.argv)==2 and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode,'ISOLATED_IMAGE_PLAN_ENTRY_REQUIRED')
        signal.signal(signal.SIGALRM,lambda *_:require(False,'FINITE_IMAGE_PLAN_TIMEOUT'));signal.alarm(120)
        print(encoded(prepare(Path(sys.argv[1]),Path(__file__).resolve().parent)).decode(),flush=True);return 0
    except Exception as error:
        reason=str(error)if isinstance(error,Stop)and re.fullmatch('[A-Z0-9_]{1,120}',str(error))else'IMAGE_PLAN_UNPROVEN'
        print(encoded({'schema':'ouf.mcp-denial-image-plan-prepared.v1','status':'STOP_RECONCILE','reasonCode':reason,'complete':False,'privateStagingMayBePartial':True,'counts':COUNTS,'runtimeAuthorityIssued':False,'automaticReplayAllowed':False,'budgetReset':False,'applicationE2EProven':False,'releaseAcceptance':False}).decode(),flush=True);return 2
    finally:signal.alarm(0)
if __name__=='__main__':raise SystemExit(main())
