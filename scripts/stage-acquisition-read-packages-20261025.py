#!/usr/bin/env python3
"""Stage exact CI artifacts privately. No Engine, SQL, IAM or application calls."""
import hashlib,json,os,re,shutil,signal,stat,sys,tarfile,zipfile
from pathlib import Path

CASE={'inputsPath': '/etc/ouf/deploy-snapshots/acquisition-evidence-current-inputs-v1/inputs.json', 'inputsHash': 'c40ba6dc86e8be72ddcda2eaef65fe3eb8aa9f24b8ec4b0d5758b0bfeacf1da6', 'artifacts': {'ingestion': {'repository': 'GioNob/ouf-ingestion-runtime', 'commit': '3ab998feb55ba0681d30635cdac35fac0f78e5db', 'runId': 40170276524, 'artifactId': 12590122027, 'zipBytes': 140853808, 'zipSha256': 'db1db79a1d4f5efd37004bc9ddb84789269b361a8278f991a21ddabdbc331ac9', 'imageId': 'sha256:3ae64b05d4fe93c8409605177444fb4f8edbfa4dd847d0de6247a7cd6cd35539', 'user': '10002:10002', 'entrypoint': ['java', '-Dloader.main=it.comune.trieste.ouf.evidence.IngestionAcquisitionReadApplication', '-cp', '/app/app.jar', 'org.springframework.boot.loader.launch.PropertiesLauncher'], 'cmd': None, 'imageConfigFile': 'acquisition-image-config.json', 'members': ['image.tar.gz', 'image-id.txt', 'acquisition-image-config.json', 'source-commit.txt', 'SHA256SUMS']}, 'udp': {'repository': 'GioNob/ouf-udp-object-resolution', 'commit': 'b6a9f36a4f98ae8a2aab3bd055e5703bd84a8fb7', 'runId': 40170281418, 'artifactId': 12589789326, 'zipBytes': 122368069, 'zipSha256': 'c38246d7bc5a6fdb16482b06fc19521f1c58ca652dac1f7ea69fe29f513c2412', 'imageId': 'sha256:97b67ccfd19764e19ce2bc690775696582c5256ddac5bc5182972d857c362878', 'user': '10004:10004', 'entrypoint': ['java', '-Dloader.main=it.comune.trieste.ouf.evidence.UdpAcquisitionReadApplication', '-cp', '/app/app.jar', 'org.springframework.boot.loader.launch.PropertiesLauncher'], 'cmd': None, 'imageConfigFile': 'acquisition-image-config.json', 'members': ['image.tar.gz', 'image-id.txt', 'acquisition-image-config.json', 'source-commit.txt', 'SHA256SUMS']}, 'mcp': {'repository': 'GioNob/ouf-mcp-server', 'commit': 'bd60ccd092b51557b280e533c8db6b3f98842f9e', 'runId': 40170429531, 'artifactId': 12589824695, 'zipBytes': 9616803, 'zipSha256': '9a4d629d729f30853ca9902e40c9c2474f6e9ea538fcb306eb3b955db106e860', 'imageId': 'sha256:20bbbe2968b01bc18bf053985e7e5ca3f7ea7265e7467439f5275af2753f26f3', 'user': '10005:10005', 'entrypoint': ['/usr/local/bin/ouf-mcp'], 'cmd': ['server'], 'imageConfigFile': 'image-config.json', 'members': ['image.tar.gz', 'image-id.txt', 'image-config.json', 'source-commit.txt', 'SHA256SUMS', 'capabilities.json']}, 'gateway': {'repository': 'GioNob/ouf-api-gateway', 'commit': 'efe71dd9bef9d5ee70c0ef2acb11ea4169649baa', 'runId': 40170951051, 'artifactId': 12590580438, 'zipBytes': 84613, 'zipSha256': 'dfcf3426786b5f371346ea5f4c5c64d8f1e47409000b784d23ccb47028c6e01d', 'members': ['source.tar.gz', 'source-commit.txt', 'SHA256SUMS']}}}
class Stop(RuntimeError):pass
def require(ok,code):
    if not ok:raise Stop(code)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def frame(s):return(s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
def encode(value):return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def unique(pairs):
    result={}
    for k,v in pairs:require(k not in result,'DUPLICATE_JSON_KEY');result[k]=v
    return result
def decode(raw):return json.loads(raw,object_pairs_hook=unique,parse_constant=lambda _:(_ for _ in()).throw(Stop('NONFINITE_JSON')))
def ancestry(path):
    require(path.is_absolute()and'..'not in path.parts,'ABSOLUTE_PRIVATE_PATH_REQUIRED')
    for part in(path,*path.parents):
        s=part.lstat();require(stat.S_ISDIR(s.st_mode)and s.st_uid==0 and not s.st_mode&0o022,'ROOT_ANCESTRY_REQUIRED')
def protected(path,expected):
    ancestry(path.parent);s=path.lstat();require(stat.S_ISREG(s.st_mode)and s.st_uid==s.st_gid==0 and s.st_nlink==1 and stat.S_IMODE(s.st_mode)in(0o400,0o600)and s.st_size<=8*1024*1024,'PROTECTED_INPUT_REQUIRED')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        before=os.fstat(fd);raw=os.read(fd,before.st_size+1)
        require(frame(s)==frame(before)==frame(os.fstat(fd))==frame(path.lstat())and len(raw)==before.st_size,'INPUT_CHANGED')
        require(sha(raw)==expected,'EXACT_CAPTURED_INPUTS_REQUIRED');return decode(raw)
    finally:os.close(fd)
def put(path,data):
    raw=data if isinstance(data,bytes)else encode(data)
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o400)
    try:
        with os.fdopen(os.dup(fd),'wb')as out:out.write(raw);out.flush();os.fsync(out.fileno())
    finally:os.close(fd)
def copy_member(z,info,target,limit):
    require(0<=info.file_size<=limit,'ZIP_MEMBER_SIZE_BOUND')
    fd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o400);digest=hashlib.sha256();count=0
    try:
        with z.open(info)as source,os.fdopen(os.dup(fd),'wb')as out:
            while chunk:=source.read(65536):
                count+=len(chunk);require(count<=limit,'ZIP_EXPANSION_BOUND');digest.update(chunk);out.write(chunk)
            require(count==info.file_size,'ZIP_MEMBER_TRUNCATED');out.flush();os.fsync(out.fileno())
    finally:os.close(fd)
    return digest.hexdigest()
def open_zip(path,expected):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK);stream=os.fdopen(fd,'rb')
    try:
        before=os.fstat(fd);require(stat.S_ISREG(before.st_mode)and before.st_nlink==1 and 0<before.st_size<=220*1024*1024,'BOUNDED_REGULAR_ARCHIVE_REQUIRED')
        digest=hashlib.sha256()
        while chunk:=stream.read(65536):digest.update(chunk)
        require(digest.hexdigest()==expected,'EXACT_CI_ZIP_HASH_REQUIRED');stream.seek(0)
        return stream,before
    except BaseException:stream.close();raise

def verify_image(path,descriptor):
    wanted=descriptor['imageId'];require(re.fullmatch('sha256:[a-f0-9]{64}',wanted)is not None,'CLOSED_IMAGE_ID_REQUIRED')
    manifest=None;config=None;total=0;names=set()
    with tarfile.open(path,'r|gz')as archive:
        for entry in archive:
            name=entry.name.removeprefix('./');parts=Path(name).parts
            require(not entry.name.startswith('/')and'..'not in parts and name not in names and len(names)<10000,'BOUNDED_SAFE_IMAGE_ARCHIVE_REQUIRED');names.add(name)
            require(entry.isdir()or entry.isfile(),'IMAGE_ARCHIVE_LINK_FORBIDDEN')
            total+=entry.size;require(0<=entry.size<=768*1024*1024 and total<=1024*1024*1024,'IMAGE_EXPANSION_BOUND')
            if name in('manifest.json',wanted[7:]+'.json','blobs/sha256/'+wanted[7:]):
                require(entry.isfile()and entry.size<=2*1024*1024,'BOUNDED_IMAGE_METADATA_REQUIRED')
                raw=archive.extractfile(entry).read(entry.size+1);require(len(raw)==entry.size,'COMPLETE_IMAGE_METADATA_REQUIRED')
                if name=='manifest.json':manifest=decode(raw)
                else:require(sha(raw)==wanted[7:],'IMAGE_CONFIG_DIGEST_REQUIRED');config=decode(raw)
    require(isinstance(manifest,list)and len(manifest)==1 and config is not None,'ONE_EXACT_IMAGE_REQUIRED')
    require(manifest[0].get('Config')in(wanted[7:]+'.json','blobs/sha256/'+wanted[7:]),'IMAGE_MANIFEST_CONFIG_REQUIRED')
    require(all(layer in names for layer in manifest[0].get('Layers',[])),'ALL_IMAGE_LAYERS_REQUIRED')
    c=config['config'];require(c.get('User')==descriptor['user']and c.get('Entrypoint')==descriptor['entrypoint']and c.get('Cmd')==descriptor.get('cmd'),'REVIEWED_IMAGE_LAUNCH_REQUIRED')
    return c

def verify_source(path):
    names=set();total=0
    with tarfile.open(path,'r|gz')as archive:
        for entry in archive:
            name=entry.name.removeprefix('./');parts=Path(name).parts
            require(not entry.name.startswith('/')and'..'not in parts and name not in names and len(names)<3000,'BOUNDED_SAFE_SOURCE_REQUIRED');names.add(name)
            require(entry.isdir()or entry.isfile(),'SOURCE_ARCHIVE_LINK_FORBIDDEN')
            total+=entry.size;require(0<=entry.size<=2*1024*1024 and total<=32*1024*1024,'SOURCE_EXPANSION_BOUND')
    require({'tools/materialize_acquisition_read.py','tools/lua/execute_acquisition_read.lua','tools/delegation_functions.py','ouf-config/routes/northbound/acquisition-ingestion-read.yaml','ouf-config/routes/northbound/acquisition-udp-read.yaml','ouf-config/source-runtime/acquisition-ingestion-read.yaml','ouf-config/source-runtime/acquisition-udp-read.yaml'}<=names,'COMPLETE_ADDITIVE_COMPILER_REQUIRED')

def stage(downloads,case,root):
    require(os.geteuid()==os.getegid()==0,'ROOT_STAGING_REQUIRED');ancestry(root.parent)
    require(not os.path.lexists(root),'PACKAGE_SCOPE_CONSUMED_NO_REPLAY');root.mkdir(mode=0o700)
    put(root/'claim.json',{'schema':'ouf.acquisition-read-package-claim.v1','caseHash':sha(encode(case)),'automaticReplayAllowed':False,'targetApplyAuthorized':False})
    inputs=protected(Path(case['inputsPath']),case['inputsHash']);require(inputs.get('schema')=='ouf.acquisition-read-current-private-inputs.v1','EXACT_INPUT_SCHEMA_REQUIRED')
    require(inputs.get('authenticationDeclarations',{}).get('mcp',{}).get('clientCredentialsDeclared')is True,'SINGLE_EXISTING_MCP_CLIENT_CREDENTIALS_DECLARATION_REQUIRED')
    roles=case['artifacts'];require(set(roles)=={'ingestion','udp','mcp','gateway'},'FOUR_PINNED_ARTIFACTS_REQUIRED')
    require(shutil.disk_usage(root).free>sum(d['zipBytes']for d in roles.values())+64*1024*1024,'PACKAGE_DISK_HEADROOM_REQUIRED')
    receipts={}
    for role,descriptor in roles.items():
        folder=root/role;folder.mkdir(mode=0o700)
        stream,before=open_zip(downloads/(role+'.zip'),descriptor['zipSha256'])
        try:
            with zipfile.ZipFile(stream)as archive:
                infos=archive.infolist();expected=set(descriptor['members'])
                require(all(re.fullmatch('[A-Za-z0-9_.-]{1,80}',name)for name in expected),'CLOSED_MEMBER_NAMES_REQUIRED')
                require(len(infos)==len(expected)and{v.filename for v in infos}==expected,'CLOSED_ZIP_MEMBERS_REQUIRED')
                hashes={}
                for info in infos:
                    require(not info.is_dir()and stat.S_IFMT(info.external_attr>>16)in(0,stat.S_IFREG),'REGULAR_ZIP_MEMBERS_REQUIRED')
                    limit=200*1024*1024 if info.filename=='image.tar.gz'else 8*1024*1024 if info.filename=='source.tar.gz'else 2*1024*1024
                    hashes[info.filename]=copy_member(archive,info,folder/info.filename,limit)
            require(frame(before)==frame(os.fstat(stream.fileno()))==frame((downloads/(role+'.zip')).lstat()),'CI_ARCHIVE_CHANGED')
        finally:stream.close()
        lines=(folder/'SHA256SUMS').read_text().splitlines();checks={}
        for line in lines:
            require(re.fullmatch('[a-f0-9]{64}  [A-Za-z0-9_.-]+',line)is not None,'CLOSED_CHECKSUM_MANIFEST_REQUIRED')
            digest,name=line.split('  ');require(name not in checks,'UNIQUE_CHECKSUM_ENTRY_REQUIRED');checks[name]=digest
        require(set(checks)==set(hashes)-{'SHA256SUMS'}and all(hashes[name]==digest for name,digest in checks.items()),'ALL_CI_MEMBER_CHECKSUMS_REQUIRED')
        require((folder/'source-commit.txt').read_text().strip()==descriptor['commit'],'PINNED_CI_SOURCE_COMMIT_REQUIRED')
        if role=='gateway':verify_source(folder/'source.tar.gz')
        else:
            require((folder/'image-id.txt').read_text().strip()==descriptor['imageId'],'PINNED_IMAGE_ID_REQUIRED')
            config=verify_image(folder/'image.tar.gz',descriptor);observed=decode((folder/descriptor['imageConfigFile']).read_bytes())
            require(isinstance(observed,list)and len(observed)==1 and observed[0]['Id']==descriptor['imageId']and all(observed[0]['Config'].get(k)==v for k,v in config.items()),'CI_INSPECT_AND_ARCHIVED_IMAGE_CONFIG_MATCH_REQUIRED')
            defaults={'Labels':None,'AttachStderr':False,'Hostname':'','Volumes':None,'Image':'','AttachStdin':False,'OnBuild':None,'Tty':False,'StdinOnce':False,'AttachStdout':False,'OpenStdin':False,'Domainname':''}
            extras=set(observed[0]['Config'])-set(config)
            require(extras<=set(defaults)and all(observed[0]['Config'][k]==defaults[k]for k in extras),'ONLY_EXPLICIT_DOCKER_INSPECT_DEFAULTS_ALLOWED')
        receipts[role]={'sourceCommit':descriptor['commit'],'artifactId':descriptor['artifactId'],'zipSha256':descriptor['zipSha256'],'fileHashes':hashes,'imageId':descriptor.get('imageId')}
    protected(Path(case['inputsPath']),case['inputsHash'])
    result={'schema':'ouf.acquisition-read-packages-staged.v1','status':'ACQUISITION_READ_PACKAGES_STAGED_NOT_APPLIED','complete':True,'packagePath':str(root),'caseHash':sha(encode(case)),'capturedInputsHash':case['inputsHash'],'capturedInputsBound':True,'currentRuntimeRevalidated':False,'rootProtected':True,'artifacts':receipts,'imageImports':0,'engineGetAttempts':0,'containerWrites':0,'sqlSessions':0,'oauthRequests':0,'serviceCredentialFilesOpened':0,'privateSigningKeysRead':0,'sourceActivations':0,'databaseMigrations':0,'humanBudgetsGranted':0,'runtimeAuthorityIssued':False,'runtimeEffectsDispatched':0,'targetApplyAuthorized':False,'applicationReadinessProven':False,'applicationE2EProven':False,'releaseAcceptance':False,'automaticReplayAllowed':False,'budgetReset':False}
    put(root/'complete.json',result);return result

def main():
    try:
        require(sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode and len(sys.argv)==2,'ISOLATED_ROOT_STAGE_WITH_ONE_DOWNLOAD_DIRECTORY_REQUIRED')
        signal.signal(signal.SIGALRM,lambda *_:(_ for _ in()).throw(Stop('FINITE_PACKAGE_STAGING_TIMEOUT')));signal.alarm(300)
        require(bool(CASE),'QUALIFIED_CASE_REQUIRED')
        root=Path('/etc/ouf/deploy-snapshots/acquisition-read-packages-'+sha(encode(CASE))[:16])
        result=stage(Path(sys.argv[1]),CASE,root);print(json.dumps(result,sort_keys=True,separators=(',',':')));return 0
    except Exception as failure:
        reason=str(failure)if isinstance(failure,Stop)and re.fullmatch('[A-Z0-9_]{1,120}',str(failure))else'PACKAGE_STAGING_UNPROVEN'
        print(json.dumps({'schema':'ouf.acquisition-read-packages-staged.v1','status':'STOP_RECONCILE','reasonCode':reason,'complete':False,'privateStagingMayBePartial':True,'imageImports':0,'engineGetAttempts':0,'containerWrites':0,'sqlSessions':0,'oauthRequests':0,'runtimeAuthorityIssued':False,'targetApplyAuthorized':False,'automaticReplayAllowed':False,'budgetReset':False,'releaseAcceptance':False},sort_keys=True,separators=(',',':')));return 2
    finally:signal.alarm(0)
if __name__=='__main__':raise SystemExit(main())
