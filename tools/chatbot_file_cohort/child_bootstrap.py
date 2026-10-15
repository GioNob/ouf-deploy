"""Private systemd entry: verified bytes only, no source-path import fallback."""
import base64
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import types


def require(ok, reason):
    if not ok:
        raise RuntimeError(reason)


def unique(rows):
    value = {}
    for key,item in rows:
        require(key not in value, 'CHILD_DUPLICATE_JSON_KEY')
        value[key] = item
    return value


def encoded(value):
    return json.dumps(value,sort_keys=True,separators=(',', ':'),allow_nan=False).encode()


def read(path, limit):
    target = Path(path)
    require(target.is_absolute() and '..' not in target.parts and str(target) == str(path),
            'CHILD_EXACT_PRIVATE_ARTIFACT_PATH_REQUIRED')
    held = []
    flags = os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_NONBLOCK
    parent = os.open('/',flags)
    held.append(parent)
    ancestry = []
    try:
        for name in target.parts[1:-1]:
            fd = os.open(name,flags,dir_fd=parent)
            held.append(fd)
            info = os.fstat(fd)
            require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode&0o022,
                    'CHILD_ROOT_CONTROLLED_ANCESTRY_REQUIRED')
            ancestry.append((parent,name,fd,(info.st_dev,info.st_ino,info.st_uid,info.st_gid,info.st_mode)))
            parent = fd
        info = os.fstat(parent)
        require(info.st_uid == info.st_gid == 0 and stat.S_IMODE(info.st_mode) == 0o700,
                'CHILD_PRIVATE_ARTIFACT_PARENT_REQUIRED')
        fd = os.open(target.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent)
        held.append(fd)
        before = os.fstat(fd)
        pin = lambda row:(row.st_dev,row.st_ino,row.st_mode,row.st_uid,row.st_gid,row.st_nlink,
                          row.st_size,row.st_mtime_ns,row.st_ctime_ns)
        require(stat.S_ISREG(before.st_mode) and before.st_uid == before.st_gid == 0
                and stat.S_IMODE(before.st_mode) == 0o600 and before.st_nlink == 1
                and 0 < before.st_size <= limit, 'CHILD_PRIVATE_ARTIFACT_CUSTODY_REQUIRED')
        raw = bytearray()
        while len(raw) <= limit:
            part = os.read(fd,min(65536,limit+1-len(raw)))
            if not part:
                break
            raw.extend(part)
        require(len(raw) == before.st_size and pin(before) == pin(os.fstat(fd))
                == pin(os.stat(target.name,dir_fd=parent,follow_symlinks=False)), 'CHILD_ARTIFACT_READ_DRIFT')
        for directory,name,fd,expected in ancestry:
            current = os.stat(name,dir_fd=directory,follow_symlinks=False)
            require(expected == (current.st_dev,current.st_ino,current.st_uid,current.st_gid,current.st_mode),
                    'CHILD_ARTIFACT_ANCESTRY_CHANGED')
        return bytes(raw)
    finally:
        for fd in reversed(held):
            os.close(fd)


def main():
    require(sys.flags.isolated and sys.dont_write_bytecode and sys.flags.no_site
            and os.geteuid() == os.getegid() == 0 and len(sys.argv) == 3,
            'ISOLATED_ROOT_FINITE_CHILD_ENTRY_REQUIRED')
    bundle_path, context = sys.argv[1:]
    review_raw = read(str(Path(context)/'review.json'),262144)
    review = json.loads(review_raw,object_pairs_hook=unique)
    process = review['scopes']['finiteActionProcess']
    require(process['authorityDirectory'] == context and process['bundle']['path'] == bundle_path
            and process['argv'] == [sys.executable,'-I','-B','-S',str(Path(__file__)),bundle_path,context],
            'CHILD_EXACT_REVIEWED_COMMAND_REQUIRED')
    bootstrap_raw = read(str(Path(__file__)),131072)
    require(hashlib.sha256(bootstrap_raw).hexdigest() == process['bootstrap']['sha256'],
            'CHILD_BOOTSTRAP_SOURCE_HASH_DRIFT')
    bundle_raw = read(bundle_path,8388608)
    require(hashlib.sha256(bundle_raw).hexdigest() == process['bundle']['sha256'],
            'CHILD_SOURCE_BUNDLE_HASH_DRIFT')
    bundle = json.loads(bundle_raw,object_pairs_hook=unique)
    require(type(bundle) is dict and set(bundle) == {'schema','declaration','loader','sources','prepared'}
            and bundle['schema'] == 'ouf.chatbot-file-cohort-closed-source-bundle.v1'
            and bundle['declaration'] == review['sourceClosure']['declaration'],
            'CHILD_COMPLETE_REVIEWED_SOURCE_BUNDLE_REQUIRED')
    declaration = bundle['declaration']
    loader = base64.b64decode(bundle['loader'],validate=True)
    require(hashlib.sha256(loader).hexdigest() == declaration['loaderHash'], 'CHILD_LOADER_HASH_DRIFT')
    require(set(bundle['sources']) == set(declaration['sourceHashes']), 'CHILD_COMPLETE_SOURCE_SET_REQUIRED')
    sources = {name:base64.b64decode(body,validate=True) for name,body in bundle['sources'].items()}
    require(all(hashlib.sha256(body).hexdigest() == declaration['sourceHashes'][name] for name,body in sources.items())
            and hashlib.sha256(encoded(bundle['prepared'])).hexdigest() == review['privateInputHashes']['preparedInputs'],
            'CHILD_REVIEWED_SOURCE_OR_INPUT_BYTES_CHANGED')
    runtime = types.ModuleType('qualified_chatbot_cohort_loader')
    exec(compile(loader,'<qualified-chatbot-cohort-loader>','exec'),runtime.__dict__)
    entry, actual = runtime.load_entry(declaration['sourceCommit'],sources,loader,
        hashlib.sha256(encoded(declaration)).hexdigest(),declaration['sourcePins'])
    require(actual == declaration, 'CHILD_EXECUTING_CLOSURE_DRIFT')
    entry.child_main(bundle['prepared'],sources,actual,context)


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        # The delivery already persists its bounded public reason. Startup
        # failures must not send arbitrary exception bodies to the journal.
        print(json.dumps({'schema':'ouf.chatbot-file-cohort-child-exit.v1',
            'phase':'FINITE_CHILD_FAILED','exceptionType':type(error).__name__,
            'privateDiagnosticPrinted':False},sort_keys=True),flush=True)
        raise SystemExit(1)
