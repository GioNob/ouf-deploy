#!/usr/bin/env python3
"""Stage the exact host192 package and v3 candidate, without collection.

Reuse unchanged qualified binary from the old protected package; verify every
byte against both manifests. No old input, receipt, scope or credential copy
is modified. Guards copied from the qualified capacity helper9bfb77f3.
"""
import base64,hashlib,json,os,stat,sys,zlib
from pathlib import Path

OLD=Path('/var/lib/ouf-g0-network-preparation-20261106')
DEST=Path('/var/lib/ouf-g0-host192-preparation-20261106')
OLD_MANIFEST='1e542f786ac1606cf72f273bc079eaa5b06b6bd22a210d615c10d13a9d9f8adf'
NEW_OPERATION='seaweedfs-g0-20261106-v2'
PRIOR={
 'result':{'path':str(OLD/'evidence/seaweedfs-g0-20261106-v1/result.json'),'sha256':'09f6c8791f35a459d6325a9d42d808acd72d7bbee23e0f54ff7d68a7224f63c2'},
 'claim':{'path':str(OLD/'evidence/seaweedfs-g0-20261106-v1/claim.private.json'),'sha256':'5bf27b0cd677efa3c4fb101e8431c84f6abcc622d1f28bc34ae5ee5a91ff6688'},
 'decision':{'path':str(OLD/'inputs/capacity-directory-preparation-20261106/collection-decision.private.json'),'sha256':'4a474ef3c8a67742f7148afff4b1d8da2691a1f603d9d767dcd6fbf887dce3d4'},
 'input':{'path':str(OLD/'inputs/capacity-directory-preparation-20261106/package-input.collection.json'),'sha256':'aa002304872db4408f1910f76f18c8634e372d619428e2fb746f3e9754e86664'},
}
# Filled only from the independently verified CI package; public code/docs only.
PAYLOAD='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'
NEW_MANIFEST='1496517d24b65aaa20dce7cdb3bb4440ffbf2bc620c3dfd0ffffc17ea22b0f69'
class Held(ValueError):
    pass

def require(ok, code):
    if not ok:
        raise Held(code)

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def encode(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()

def identity(info):
    return tuple(getattr(info, k) for k in ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid',
                 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns'))

def directory(path):
    path = Path(path)
    require(path.is_absolute() and str(path) == os.path.normpath(path), 'CAPACITY_CANONICAL_PATH')
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in ('', *path.parts[1:]):
            if part:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                os.close(fd)
                fd = child
            info = os.fstat(fd)
            require(info.st_uid == 0 and not info.st_mode & 0o022, 'CAPACITY_ROOT_PROTECTED_ANCESTRY')
        return fd
    except BaseException:
        os.close(fd)
        raise

def read(path, limit, private=True):
    path = Path(path)
    parent = directory(path.parent)
    fd = None
    try:
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_uid == 0 and before.st_nlink == 1
                and 0 < before.st_size <= limit and not before.st_mode & 0o022,
                'CAPACITY_BOUNDED_ROOT_FILE')
        if private:
            require(stat.S_IMODE(before.st_mode) == 0o600, 'CAPACITY_PRIVATE_FILE_MODE')
        raw = os.read(fd, limit + 1)
        require(len(raw) == before.st_size and identity(before) == identity(os.fstat(fd))
                == identity(os.stat(path.name, dir_fd=parent, follow_symlinks=False)), 'CAPACITY_FILE_CHANGED')
        return raw
    finally:
        if fd is not None:
            os.close(fd)
        os.close(parent)

def verify_bundle(bundle, expected):
    raw = read(bundle / 'package-manifest.json', 262144, private=False)
    require(sha(raw) == expected, 'CAPACITY_EXACT_PACKAGE_MANIFEST')
    manifest = json.loads(raw)
    require(manifest.get('schema') == 'ouf.storage-g0-package.v1'
            and manifest.get('runtimeAuthorityIssued') is False, 'CAPACITY_PACKAGE_SCHEMA')
    expected_files = set(manifest['files']) | {'package-manifest.json'}
    observed = set()
    for root, dirs, files in os.walk(bundle, followlinks=False):
        require(len(observed) <= 64, 'CAPACITY_BOUNDED_PACKAGE')
        for name in dirs:
            require(not (Path(root) / name).is_symlink(), 'CAPACITY_PACKAGE_DIRECTORY_LINK')
        observed.update(str((Path(root) / name).relative_to(bundle)) for name in files)
    require(observed == expected_files, 'CAPACITY_EXACT_PACKAGE_FILE_SET')
    for name, digest in manifest['files'].items():
        p = Path(name)
        require(not p.is_absolute() and '..' not in p.parts, 'CAPACITY_PACKAGE_MEMBER')
        require(sha(read(bundle / p, 64 << 20, private=False)) == digest, 'CAPACITY_PACKAGE_SOURCE_CHANGED')

def put(root, name, value):
    raw = encode(value)
    parent = directory(root)
    fd = None
    try:
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
        with os.fdopen(os.dup(fd), 'wb') as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.fsync(parent)
    finally:
        if fd is not None:
            os.close(fd)
        os.close(parent)

def prepare(old_bundle,destination,old_manifest,new_manifest_raw,overrides,prior,operation,preflight=None):
    require(os.geteuid()==os.getegid()==0,'HOST192_ROOT_ONLY')
    if os.path.lexists(destination):
        report=json.loads(read(destination/'preparation.json',65536))
        report['existingPreparationReadOnly']=True
        return report
    verify_bundle(old_bundle,old_manifest)
    manifest=json.loads(new_manifest_raw)
    require(manifest['reconciledHostProfileLimits']['hostContainers']==192
            and manifest['reconciledHostProfileLimits']['engineGets']==386
            and manifest['reconciledHostProfileLimits']['priorEngineGets']==53,
            'HOST192_EXACT_PROFILE')
    require(set(prior)=={'result','claim','decision','input'},'HOST192_PRIOR_RECEIPT_SET')
    for ref in prior.values():require(sha(read(Path(ref['path']),65536))==ref['sha256'],'HOST192_PRIOR_RECEIPT_CHANGED')
    old_input=json.loads(read(Path(prior['input']['path']),65536))
    require(old_input['operationId']!=operation and old_input['schema']=='ouf.storage-g0-package-input.v2',
            'HOST192_DISTINCT_OPERATION')
    files={}
    require(set(overrides)<=set(manifest['files']),'HOST192_NO_EXTRA_CODE')
    for name,digest in manifest['files'].items():
        rel=Path(name);require(not rel.is_absolute() and '..' not in rel.parts,'HOST192_PACKAGE_PATH')
        raw=overrides[name] if name in overrides else read(old_bundle/rel,64<<20,private=False)
        require(sha(raw)==digest,'HOST192_EXACT_NEW_PACKAGE_MEMBER');files[name]=raw
    config=json.loads(json.dumps(old_input))
    config.update(schema='ouf.storage-g0-package-input.v3',operationId=operation,
                  collectionDecisionRef=None,priorAttemptFiles=prior)
    connections={}
    for key,path in old_input['connectionFiles'].items():
        value=json.loads(read(Path(path),16384));value['operationId']=operation+'-'+key
        connections[key]=value;config['connectionFiles'][key]=str(destination/'inputs'/(key+'.json'))
    network=json.loads(read(Path(old_input['networkBindingFile']),65536));network['operationId']=operation
    config['networkBindingFile']=str(destination/'inputs/network.json')
    # No provider/collection scope. A partial preparation is preserved permanently.
    parent=directory(destination.parent)
    try:os.mkdir(destination.name,0o700,dir_fd=parent);os.fsync(parent)
    finally:os.close(parent)
    put(destination,'claim.json',{'schema':'ouf.storage-g0-host192-preparation-claim.v1',
        'oldManifestSha256':old_manifest,'newManifestSha256':sha(new_manifest_raw),
        'priorAttemptFiles':prior,'operationId':operation,'automaticReplayAllowed':False,
        'providerRequests':0,'runtimeAuthorityIssued':False})
    for name in ('package','inputs'):(destination/name).mkdir(mode=0o700)
    bundle=destination/'package'
    files['package-manifest.json']=new_manifest_raw
    for name,raw in files.items():
        target=bundle/name;target.parent.mkdir(parents=True,mode=0o700,exist_ok=True)
        fd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,
                   0o500 if name=='bin/inventory' else 0o400)
        try:
            with os.fdopen(os.dup(fd),'wb') as out:out.write(raw);out.flush();os.fsync(out.fileno())
        finally:os.close(fd)
    for folder in [p for p in bundle.rglob('*') if p.is_dir()]+[bundle,destination/'inputs',destination]:
        fd=directory(folder)
        try:os.fsync(fd)
        finally:os.close(fd)
    for key,value in connections.items():put(destination/'inputs',key+'.json',value)
    put(destination/'inputs','network.json',network)
    candidate=destination/'inputs/package-input.review.json';put(candidate.parent,candidate.name,config)
    verify_bundle(bundle,sha(new_manifest_raw))
    if preflight is None:
        sys.path.insert(0,str(bundle))
        from tools.storage_planning.g0_package import preflight
    checked=preflight(candidate,bundle,sha(new_manifest_raw))[-1]
    require(checked['limits']==manifest['reconciledHostProfileLimits']
            and checked['reconciledPriorAttempt']['cumulativeEngineGets']==53
            and 'COLLECTION_DECISION_REFERENCE' in checked['operatorInputsMissing']
            and not checked['targetCommandAuthorized'],'HOST192_CHECK_NOT_ADMISSION')
    for ref in prior.values():require(sha(read(Path(ref['path']),65536))==ref['sha256'],'HOST192_PRIOR_CHANGED_DURING_PREPARATION')
    put(destination/'inputs','preflight.private.json',checked)
    report={'schema':'ouf.storage-g0-host192-preparation-result.v1',
        'status':'HOST192_STAGED_LOCAL_CHECK_PASSED_SEPARATE_DECISION_REQUIRED',
        'operationId':operation,'candidateInputFile':str(candidate),'inputSha256':checked['inputSha256'],
        'manifestSha256':sha(new_manifest_raw),'limits':checked['limits'],
        'operatorInputsMissing':checked['operatorInputsMissing'],'priorAttemptReceiptsBound':4,
        'priorAttemptPreserved':True,'originalBundleModified':False,'credentialsCopied':0,
        'localCredentialFilesValidated':5,'providerRequests':0,'collectionScopeCreated':False,
        'runtimeAuthorityIssued':False,'targetCommandAuthorized':False,
        'automaticReplayAllowed':False,'g0Complete':False,'acceptanceCreditAdded':0}
    put(destination,'preparation.json',report)
    return report


def main():
    try:
        require(len(sys.argv)==1 and sys.flags.isolated and sys.flags.no_site
                and sys.dont_write_bytecode,'HOST192_ISOLATED_ENTRY')
        os.umask(0o077)
        payload=json.loads(zlib.decompress(base64.b64decode(PAYLOAD)))
        manifest=base64.b64decode(payload['manifest'])
        require(sha(manifest)==NEW_MANIFEST,'HOST192_PINNED_MANIFEST')
        overrides={k:base64.b64decode(v) for k,v in payload['overrides'].items()}
        result=prepare(OLD/'package',DEST,OLD_MANIFEST,manifest,overrides,PRIOR,NEW_OPERATION)
        print(json.dumps(result,sort_keys=True));return 0
    except Exception as error:
        reason=str(error) if isinstance(error,Held) else 'HOST192_PREPARATION_HELD_PRESERVE_PARTIAL'
        print(json.dumps({'status':'HELD','reason':reason,'providerRequests':0,
                          'runtimeAuthorityIssued':False,'automaticReplayAllowed':False},sort_keys=True))
        return 1


if __name__=='__main__':raise SystemExit(main())
