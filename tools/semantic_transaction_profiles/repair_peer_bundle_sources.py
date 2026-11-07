"""Pure source revision: hash-bound public Engine peer OCI is not a credential.

The consumed draft and earlier repair stay byte exact. Only a peer's config.json
under its runtime-reported CID directory can use root0644; authority, keys,
journals and candidate-private inputs retain their original private readers.
"""
import hashlib

PEER='tools/semantic_provider_peer_bindings.py'
ORIGINAL_SHA='4d99b60459d7122b5126d8424fb6233a9f3de15858219cd9061131b23f45af8b'
READER='''
def read_peer_bundle(path, expected, private_reader):
    """Read one exact expected peer OCI; never generalize private auth IO."""
    try:
        return private_reader(path)
    except RuntimeError as error:
        # These are the source-bound readers' exact custody denials. Unknown
        # failures never trigger a different reader or a retry.
        if str(error) not in ('PRIVATE_FILE_REQUIRED','PRIVATE_AUTHENTICATION_INPUT_REQUIRED',
                              'PRIVATE_DRIVER_FILE_REQUIRED'):
            raise
    from pathlib import Path
    import os,stat
    p=Path(path)
    require(p.is_absolute() and '..' not in p.parts and p.name=='config.json'
        and p.parent.name==expected['containerId'],'EXACT_ENGINE_PEER_BUNDLE_PATH_REQUIRED')
    for parent in (p.parent,*p.parent.parents):
        info=parent.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid==0 and not info.st_mode&0o022,
            'ROOT_OWNED_ENGINE_PEER_BUNDLE_ANCESTOR_REQUIRED')
    def stamp(info):
        return tuple(getattr(info,k) for k in ('st_dev','st_ino','st_uid','st_gid','st_mode',
            'st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
    fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        before=os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_uid==before.st_gid==0
            and stat.S_IMODE(before.st_mode)==0o644 and before.st_nlink==1
            and 0<before.st_size<=131072,'ROOT_OWNED_READONLY_ENGINE_PEER_OCI_REQUIRED')
        raw=os.read(fd,131073)
        require(len(raw)==before.st_size and stamp(before)==stamp(os.fstat(fd))
            and stamp(before)==stamp(p.lstat()),'ENGINE_PEER_OCI_CHANGED_DURING_READ')
    finally:os.close(fd)
    require(digest(json.loads(raw))==expected['applicationHash'],'PEER_COMPLETE_OCI_DRIFT')
    return raw

'''


def repair(sources):
    result=dict(sources)
    if hashlib.sha256(sources[PEER]).hexdigest()!=ORIGINAL_SHA:
        raise ValueError('ORIGINAL_PEER_BUNDLE_SOURCE_HASH_DRIFT')
    code=sources[PEER].decode();site='def collect(expected, runtime_root, runtime_binding, commands, run, read_bundle, generation, budget):'
    if code.count(site)!=1:raise ValueError('EXACT_PEER_READER_REVISION_SITE_REQUIRED')
    code=code.replace(site,READER+'\n'+site)
    old='expected = declaration(expected); cid = expected[\'containerId\']'
    if code.count(old)!=1:raise ValueError('EXACT_PEER_COLLECT_READER_SITE_REQUIRED')
    code=code.replace(old,old+"\n    private_reader=read_bundle\n    read_bundle=lambda path:read_peer_bundle(path,expected,private_reader)")
    compile(code,PEER,'exec');result[PEER]=code.encode();return result
