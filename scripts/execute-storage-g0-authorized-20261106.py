#!/usr/bin/env python3
"""One operator-authorized G0 entry; existing collector and budgets unchanged.

Giovanni explicitly authorized OUF-G0-COLLECT-20261106-01 in conversation.
This records an operator decision, never HUMAN/THS authentication or a grant.
File guards below are byte-for-byte function copies from the qualified capacity
helper at9bfb77f3; they do not execute that helper or create data directories.
"""
import hashlib,json,os,re,stat,sys
from pathlib import Path

STAGING = Path('/var/lib/ouf-g0-network-preparation-20261106')
MANIFEST_SHA = '1e542f786ac1606cf72f273bc079eaa5b06b6bd22a210d615c10d13a9d9f8adf'
INPUT_SHA = '6b5a2ba087cd5bfbc956f3bb240cf103b0bbf8d0aeaebb14d6a10f9aaaa22af1'
DECISION = 'OUF-G0-COLLECT-20261106-01'
OPERATION = 'seaweedfs-g0-20261106-v1'
INSTALLATION = 'ouf-retained-14e42ac9'
MISSING = {'OPERATOR_ACCESS','OPERATOR_CUSTODY','OPERATOR_WINDOW','OPERATOR_WRITERS'}

REUSED_BINDINGS = {
    'connection:ingestion': 'a8886bbd14fed01aa863179a3364946fcc577139b973e414239cbd59346bcc75',
    'connection:onboarding': '6578413567754d9598ff3e53eabd64fe4d22228f0d01f09366f3b26002164952',
    'connection:s3': '42dba0ef889090707f48566340a06e20cb504b9c98ec6fc2442b6a8a55e1f512',
    'connection:udp': '6ab5f2a0f7fdddbae7f09ea8d3192038226254404d982b233c7cdd6807715ca0',
    'network': 'c0700c8f6b35e6e00d58458c39ccc24a0c3994298a822e74a046ac3bd00e4ecb',
    'operator:runtime': 'c958f52f6fc25c07a42a0a2b48ddab2f185316895dc449df1a14defe6b22ba97',
}

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

def execute(staging, bundle, manifest_sha, input_sha, preflight, invoke, *,
            operation=OPERATION, installation=INSTALLATION, expected_bindings=REUSED_BINDINGS):
    require(os.geteuid() == os.getegid() == 0, 'COLLECTION_ROOT_ONLY')
    scope = staging / 'evidence' / operation
    parent = staging / 'inputs/capacity-directory-preparation-20261106'
    original = parent / 'package-input.review.json'
    candidate = parent / 'package-input.collection.json'
    decision_file = parent / 'collection-decision.private.json'
    # Reentry can only read a completed public summary, never providers/credentials.
    if os.path.lexists(scope):
        report = json.loads(read(scope / 'result.json', 65536))
        require(report.get('schema') == 'ouf.storage-g0-package-result.v1'
                and report.get('scopeConsumed') is True, 'COLLECTION_EXISTING_RESULT_INVALID')
        report['existingResultReadOnly'] = True
        return report
    require(not os.path.lexists(candidate) and not os.path.lexists(decision_file),
            'COLLECTION_ENTRY_ALREADY_CONSUMED_PRESERVE_PARTIAL')
    verify_bundle(bundle, manifest_sha)
    raw = read(original, 65536)
    require(sha(raw) == input_sha, 'COLLECTION_APPROVED_INPUT_CHANGED')
    config = json.loads(raw)
    require(config['collectionDecisionRef'] is None and config['operationId'] == operation
            and config['installationRef'] == installation
            and config['outputParent'] == str(staging / 'evidence'), 'COLLECTION_EXACT_SCOPE')
    prior = json.loads(read(parent / 'preflight.private.json', 65536))
    require(prior['inputSha256'] == input_sha and prior['packageManifestSha256'] == manifest_sha,
            'COLLECTION_PRIOR_CHECK_BINDING')
    current = preflight(original, bundle, manifest_sha)[-1]
    require(current['boundInputSha256'] == prior['boundInputSha256']
            and current['limits'] == prior['limits']
            and current['inputSha256'] == input_sha
            and current['targetReads'] == 0
            and current['runtimeAuthorityIssued'] is False
            and set(current['operatorInputsMissing']) == MISSING | {'COLLECTION_DECISION_REFERENCE'},
            'COLLECTION_BOUND_INPUT_DRIFT')
    require(all(current['boundInputSha256'].get(k) == v for k,v in expected_bindings.items()),
            'COLLECTION_REUSED_BINDING_CHANGED')
    require(read(original, 65536) == raw, 'COLLECTION_INPUT_CHANGED_DURING_CHECK')
    config['collectionDecisionRef'] = DECISION
    decision = {'schema':'ouf.storage-g0-operator-decision.v1', 'decisionRef':DECISION,
        'provenance':'EXPLICIT_USER_CONVERSATION_AUTHORIZATION', 'actorDeclared':'Giovanni',
        'userReply':'autorizzo', 'date':'2026-11-06', 'baseInputSha256':input_sha,
        'executionInputSha256':sha(encode(config)), 'packageManifestSha256':manifest_sha,
        'boundInputSha256':current['boundInputSha256'], 'limits':current['limits'],
        'scope':str(scope), 'runtimeAuthorityIssued':False, 'authenticatedHumanApproval':False,
        'automaticReplayAllowed':False, 'approvalScope':'ONE_BOUNDED_READ_ONLY_G0_COLLECTION'}
    # Exclusive durable decision is the local entry claim, before input creation.
    put(parent, decision_file.name, decision)
    put(parent, candidate.name, config)
    checked = preflight(candidate, bundle, manifest_sha)[-1]
    require(checked['inputSha256'] == decision['executionInputSha256']
            and checked['boundInputSha256'] == current['boundInputSha256']
            and checked['limits'] == current['limits']
            and set(checked['operatorInputsMissing']) == MISSING,
            'COLLECTION_FINAL_BINDING_DRIFT_PRESERVE_PARTIAL')
    require(read(original, 65536) == raw, 'COLLECTION_ORIGINAL_CHANGED_PRESERVE_PARTIAL')
    return invoke(candidate, bundle, manifest_sha)


def main():
    try:
        require(len(sys.argv) == 1 and sys.flags.isolated and sys.flags.no_site
                and sys.dont_write_bytecode and os.geteuid() == os.getegid() == 0,
                'COLLECTION_ISOLATED_ROOT_ENTRY')
        os.umask(0o077)
        bundle = STAGING / 'package'
        verify_bundle(bundle, MANIFEST_SHA)
        sys.path.insert(0, str(bundle))
        from tools.storage_planning.g0_package import preflight
        def invoke(candidate, root, digest):
            # Exact qualified CLI, no shell, no new provider implementation.
            os.execve('/usr/bin/python3', ['/usr/bin/python3','-I','-B','-S',
                str(root/'launch.py'),'collect',str(candidate),'--package-sha256',digest],
                {'PATH':'/usr/bin:/bin','LANG':'C.UTF-8'})
        report = execute(STAGING, bundle, MANIFEST_SHA, INPUT_SHA, preflight, invoke)
        print(json.dumps(report,sort_keys=True))
        return 0 if report.get('technicalCaptureComplete') else 1
    except Exception as error:
        reason = str(error) if isinstance(error, Held) else 'COLLECTION_ENTRY_HELD_PRESERVE_PARTIAL'
        print(json.dumps({'status':'HELD','reason':reason,'automaticReplayAllowed':False,
                          'runtimeAuthorityIssued':False,'acceptanceCreditAdded':0},sort_keys=True))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
