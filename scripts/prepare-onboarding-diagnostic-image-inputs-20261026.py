#!/usr/bin/env python3
"""Stage one exact diagnostic CI ZIP and bind private execution inputs. No runtime I/O.

Only the new capture inputs/result are read. The image custody module is a pure helper;
no consumed controller or entrypoint is imported or executed. No Engine socket,
namespace, credential, signing key, IAM, SQL, route or application is accessed.
"""
import copy,gzip,hashlib,importlib.util,json,os,re,shutil,signal,stat,sys,zipfile
from pathlib import Path

INPUT_ROOT=Path('/etc/ouf/deploy-snapshots/onboarding-diagnostic-current-inputs-20261026-v1')
INPUT_HASH='5909d1003e88231c1d41a799a12539127d27386f79a04ed345ad9d29eaaddb6d'
ROOT=Path('/etc/ouf/deploy-snapshots/onboarding-diagnostic-image-inputs-5909d1003e88231c-v1')
SOURCE='a5ed8b05c264a8221783a6e323ba00117aed891d'
TESTED='692277b1bf5def4a2b5b1ba4fb6770c16b136fb5'
IMAGE='sha256:83c33ec95ac827edc389f7411b30d1ed85aef8bcec30986f5e19605ab7960a94'
ZIP_HASH='318a6370e4bedb6d17d5d5d8a9bbdf959ee7051196a51a425d334a324afc71a6'
ARCHIVE_HASH='54e78b838eee2626c6dad615bd18cea726886174c24758bbd7db92d91653ef18'
MEMBERS={'image.tar.gz','manifest.json','SHA256SUMS'}
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
    COUNTS['ciZipReads']+=1;put(root/'zip-read-claim.json',{'sha256':ZIP_HASH,'maximumBytes':210887971,'attemptNotCompletion':True})
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb')as stream:
        before=os.fstat(fd);require(stat.S_ISREG(before.st_mode)and before.st_nlink==1 and before.st_size==210887971,'EXACT_CI_ZIP_SIZE_REQUIRED')
        h=hashlib.sha256()
        for block in iter(lambda:stream.read(1048576),b''):h.update(block)
        require(h.hexdigest()==ZIP_HASH,'EXACT_CI_ZIP_DIGEST_REQUIRED');stream.seek(0);hashes={}
        with zipfile.ZipFile(stream)as z:
            rows=z.infolist();require(len(rows)==3 and{r.filename for r in rows}==MEMBERS,'EXACT_CI_ZIP_MEMBER_SET_REQUIRED')
            for row in rows:
                maximum=210886343 if row.filename=='image.tar.gz'else 131072
                require(not row.is_dir()and stat.S_IFMT(row.external_attr>>16)in(0,stat.S_IFREG)and 0<row.file_size<=maximum,'BOUNDED_REGULAR_CI_MEMBER_REQUIRED')
                h=hashlib.sha256();size=0;outfd=os.open(root/row.filename,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o400)
                with z.open(row)as src,os.fdopen(outfd,'wb')as out:
                    os.fchmod(out.fileno(),0o400)
                    while block:=src.read(1048576):
                        size+=len(block);require(size<=maximum,'ZIP_EXPANSION_BOUND');h.update(block);out.write(block)
                    out.flush();os.fsync(out.fileno())
                require(size==row.file_size,'COMPLETE_CI_MEMBER_REQUIRED');hashes[row.filename]=h.hexdigest()
        require(frame(before)==frame(os.fstat(fd))==frame(path.lstat()),'CI_ZIP_CHANGED_DURING_STAGING')
    require((root/'SHA256SUMS').read_text()==ARCHIVE_HASH+'  image.tar.gz\n'and hashes['image.tar.gz']==ARCHIVE_HASH,'EXACT_ARCHIVE_CHECKSUM_REQUIRED')
    manifest=decode((root/'manifest.json').read_bytes())
    require(manifest['schema']=='ouf.onboarding-tested-image.v1'and manifest['reviewedSourceCommit']==SOURCE and manifest['testedCommit']==TESTED
        and manifest['testedTree']=='7c1142043abece26250a1f8c48aea57e9c2e8948'and manifest['workflowRunId']=='40363741161'
        and manifest['imageId']==IMAGE and manifest['imageRevisionLabel']==TESTED and manifest['archiveBytes']==210886343
        and manifest['archiveSha256']==ARCHIVE_HASH and manifest['targetApplyAuthorized']is False,'EXACT_CI_IMAGE_SOURCE_MANIFEST_REQUIRED')
    return {'schema':'ouf.onboarding-diagnostic-image-staged.v1','reviewedSourceCommit':SOURCE,'testedCommit':TESTED,'applicationSourceEquivalent':True,
        'onlySourceDifference':'.github/workflows/qualify-v35-native-deploy.yml','artifactId':12668879487,'workflowRun':40363741161,
        'artifactZipSha256':ZIP_HASH,'configurationImageId':IMAGE,'fileHashes':hashes,'capturedInputsHash':INPUT_HASH,'targetUpdateAuthorized':False}
def validate_capture(inputs,result):
    require(inputs['schema']=='ouf.onboarding-diagnostic-current-inputs.v1'and result['schema']=='ouf.onboarding-diagnostic-current-input-capture-result.v1'
        and result['status']=='ONBOARDING_DIAGNOSTIC_CURRENT_INPUTS_CAPTURED_NOT_AUTHORIZED'and result['complete']is True
        and result['inputsHash']==INPUT_HASH and result['counts']==inputs['counts']=={'bytes':127338,'engineGets':3,'privateMetadataReads':3}
        and result['containerWrites']==0 and result['runtimeAuthorityIssued']is False and result['automaticReplayAllowed']is False
        and result['budgetReset']is False and inputs['retainedInstalledSource']=='194b586508c6661b40a74d9c7f99ed3b876f5fbc','EXACT_COMPLETED_CAPTURE_REQUIRED')
    info=inputs['engineInfo'];require(info['ServerVersion']=='29.8.1'and ['driver-type','io.containerd.snapshotter.v1']in(info.get('DriverStatus')or[]),'QUALIFIED_NATIVE_ENGINE_PROFILE_REQUIRED')
    actual=inputs['onboardingObservation'];require(actual['State']['Running']is True and actual['State']['Pid']==inputs['onboardingProcessPin']['pid'],'CAPTURED_RUNNING_OWNER_REQUIRED')
    require(actual['Config'].get('User')in('10003','10003:10003'),'RETAINED_OWNER_UID_REQUIRED')
    return actual
def prepare(download,folder,*,root=ROOT,input_root=INPUT_ROOT):
    require(os.geteuid()==os.getegid()==0,'ROOT_IMAGE_INPUTS_REQUIRED');ancestry(root.parent)
    require(not os.path.lexists(root),'IMAGE_INPUT_SCOPE_CONSUMED_NO_REPLAY');root.mkdir(mode=0o700);os.chmod(root,0o700);sync(root.parent)
    put(root/'claim.json',{'schema':'ouf.onboarding-diagnostic-image-inputs-claim.v1','capturedInputsHash':INPUT_HASH,'maximumSeconds':300,'engineGets':0,'containerWrites':0,'imageImports':0,'automaticReplayAllowed':False})
    inputs,sealed=private(root,input_root/'inputs.json',INPUT_HASH);result,result_seal=private(root,input_root/'result.json')
    actual=validate_capture(inputs,result)
    require(shutil.disk_usage(root).free>=2*1024*1024*1024,'TWO_GIB_FREE_FOR_EXACT_IMAGE_CUSTODY_REQUIRED')
    receipt=stage_zip(root,download);put(root/'staged-receipt.json',receipt)
    custody=helper('image_custody',folder)
    expanded=root/'expanded.tar';fd=os.open(expanded,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o400)
    with os.fdopen(fd,'w+b')as output,gzip.open(root/'image.tar.gz','rb')as zipped:
        os.fchmod(output.fileno(),0o400);total=0
        while block:=zipped.read(1048576):
            total+=len(block);require(total<=600*1024*1024,'BOUNDED_IMAGE_GZIP_EXPANSION');output.write(block)
        output.flush();os.fsync(output.fileno());output.seek(0);checksum,_=custody.hashed(output,600*1024*1024)
        require(checksum=='5ca73392fca74d9e22fceb1ce88dcfc7c99acf842ef6124748cab55dd047ee3f','EXACT_ORIGINAL_EXPANDED_ARCHIVE_REQUIRED')
        audit=custody.archive(output,checksum,IMAGE,TESTED)
        require(audit['imageConfig'].get('User')=='10003:10003'and audit['imageConfig'].get('Entrypoint')==['java','-jar','/app/application.jar'],'EXACT_TESTED_OWNER_LAUNCH_REQUIRED')
        target=root/'native.tar';outfd=os.open(target,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o400)
        with os.fdopen(outfd,'w+b')as out:
            os.fchmod(out.fileno(),0o400);derived=custody.tagless_archive(output,out,audit,containerd=True);out.flush();os.fsync(out.fileno());native_metadata=list(frame(os.fstat(out.fileno())))
        audit['nativeIdentity']=custody.native_identity(audit)
    require(custody.runtime_image_id(audit)=='sha256:074bd16ec8ebd98cbf1ee085af9767a5f7e322072a541e85bd37925002fa5df2'
        and derived['derivedArchiveSha256']=='87585bd8d50f8d955ef1abc26c43df52a481ac89df2ed2722ace3765aad1b071'and derived['archiveBytes']==441989120,'EXACT_NATIVE_BYTES_REQUIRED')
    COUNTS['nativeArchivesPrepared']+=1
    private_inputs={'schema':'ouf.onboarding-diagnostic-private-execution-inputs.v1','capturedInputsHash':INPUT_HASH,
        'bootId':inputs['bootId'],'engineBinding':inputs['engineBinding'],'engineInfoHash':digest(inputs['engineInfo']),
        'currentOnboarding':actual,'currentProcessPin':inputs['onboardingProcessPin'],'stagedReceipt':receipt,
        'reviewedSourceCommit':SOURCE,'testedCommit':TESTED,'imageAudit':audit,'nativeImageId':custody.runtime_image_id(audit),
        'nativeArchive':{'path':str(target),'sha256':derived['derivedArchiveSha256'],'bytes':derived['archiveBytes'],'metadata':native_metadata},
        'historySeals':[sealed,result_seal],'lifecyclePlanCompiled':False,'executionEntryQualified':False,'currentRuntimeRevalidated':False,
        'mountSourceContentIdentityProven':False,'runtimeAuthorityIssued':False,'targetUpdateAuthorized':False,
        'automaticReplayAllowed':False,'budgetReset':False,'applicationE2EProven':False,'releaseAcceptance':False}
    for seal in(sealed,result_seal):require(list(frame(Path(seal['path']).lstat()))==seal['metadata'],'ORIGINAL_CAPTURE_SEAL_CHANGED')
    put(root/'execution-inputs.json',private_inputs)
    output={'schema':'ouf.onboarding-diagnostic-image-inputs-prepared.v1','status':'ONBOARDING_DIAGNOSTIC_IMAGE_INPUTS_PREPARED_NOT_AUTHORIZED','complete':True,
        'contextPath':str(root),'inputsHash':INPUT_HASH,'executionInputsHash':digest(private_inputs),'nativeImageId':private_inputs['nativeImageId'],
        'reviewedSourceCommit':SOURCE,'testedCommit':TESTED,'counts':dict(COUNTS),'credentialFileReads':0,'oauthRequests':0,'sqlSessions':0,
        'lifecyclePlanCompiled':False,'executionEntryQualified':False,'currentRuntimeRevalidated':False,'runtimeAuthorityIssued':False,
        'continuationAuthorized':False,'applicationE2EProven':False,'releaseAcceptance':False,'automaticReplayAllowed':False,'budgetReset':False}
    put(root/'result.json',output);return output
def main():
    try:
        require(len(sys.argv)==2 and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode,'ISOLATED_IMAGE_PLAN_ENTRY_REQUIRED')
        signal.signal(signal.SIGALRM,lambda *_:require(False,'FINITE_IMAGE_INPUT_TIMEOUT'));signal.alarm(300)
        print(encoded(prepare(Path(sys.argv[1]),Path(__file__).resolve().parent)).decode(),flush=True);return 0
    except Exception as error:
        reason=str(error)if isinstance(error,Stop)and re.fullmatch('[A-Z0-9_]{1,120}',str(error))else'IMAGE_PLAN_UNPROVEN'
        print(encoded({'schema':'ouf.onboarding-diagnostic-image-inputs-prepared.v1','status':'STOP_RECONCILE','reasonCode':reason,'complete':False,'privateStagingMayBePartial':True,'counts':COUNTS,'runtimeAuthorityIssued':False,'automaticReplayAllowed':False,'budgetReset':False,'applicationE2EProven':False,'releaseAcceptance':False}).decode(),flush=True);return 2
    finally:signal.alarm(0)
if __name__=='__main__':raise SystemExit(main())
