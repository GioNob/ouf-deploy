#!/usr/bin/env python3
"""One operator-authorized G0 entry; existing collector and budgets unchanged.

Giovanni explicitly authorized OUF-G0-COLLECT-20261106-02 in conversation.
This records an operator decision, never HUMAN/THS authentication or a grant.
File guards below are byte-for-byte function copies from the qualified capacity
helper at9bfb77f3; they do not execute that helper or create data directories.
"""
import hashlib,json,os,re,stat,sys
from pathlib import Path

STAGING = Path('/var/lib/ouf-g0-host192-preparation-20261106')
OUTPUT_PARENT = Path('/var/lib/ouf-g0-network-preparation-20261106/evidence')
MANIFEST_SHA = '1496517d24b65aaa20dce7cdb3bb4440ffbf2bc620c3dfd0ffffc17ea22b0f69'
INPUT_SHA = 'dc0ab6d4bf36c03b8086ecbae1be1c3e2e381c94152be01dd1ff6bfbfcd04f6e'
DECISION = 'OUF-G0-COLLECT-20261106-02'
OPERATION = 'seaweedfs-g0-20261106-v2'
INSTALLATION = 'ouf-retained-14e42ac9'
MISSING = {'OPERATOR_ACCESS','OPERATOR_CUSTODY','OPERATOR_WINDOW','OPERATOR_WRITERS'}

REUSED_BINDINGS = {
    "operator:runtime": "c958f52f6fc25c07a42a0a2b48ddab2f185316895dc449df1a14defe6b22ba97",
    "priorAttempt:result": "09f6c8791f35a459d6325a9d42d808acd72d7bbee23e0f54ff7d68a7224f63c2",
    "priorAttempt:claim": "5bf27b0cd677efa3c4fb101e8431c84f6abcc622d1f28bc34ae5ee5a91ff6688",
    "priorAttempt:decision": "4a474ef3c8a67742f7148afff4b1d8da2691a1f603d9d767dcd6fbf887dce3d4",
    "priorAttempt:input": "aa002304872db4408f1910f76f18c8634e372d619428e2fb746f3e9754e86664"
}
EXPECTED_LIMITS = json.loads('{"attempts":1,"automaticReplayAllowed":false,"databaseBytesEach":33554432,"databaseExports":3,"databaseRowsPerSection":10000,"engineBytes":33554432,"engineGets":386,"hostContainers":192,"priorControls":17,"priorEngineGets":53,"s3Bodies":256,"s3BodyBytes":67108864,"s3Requests":3000,"s3WireBytes":134217728,"seconds":900}')

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
            operation=OPERATION, installation=INSTALLATION, expected_bindings=REUSED_BINDINGS,
            output_parent=OUTPUT_PARENT):
    require(os.geteuid() == os.getegid() == 0, 'COLLECTION_ROOT_ONLY')
    scope = output_parent / operation
    parent = staging / 'inputs'
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
    require(config.get('schema') == 'ouf.storage-g0-package-input.v3'
            and config['collectionDecisionRef'] is None and config['operationId'] == operation
            and config['installationRef'] == installation
            and config['outputParent'] == str(output_parent), 'COLLECTION_EXACT_SCOPE')
    prior = json.loads(read(parent / 'preflight.private.json', 65536))
    require(prior['inputSha256'] == input_sha and prior['packageManifestSha256'] == manifest_sha,
            'COLLECTION_PRIOR_CHECK_BINDING')
    current = preflight(original, bundle, manifest_sha)[-1]
    require(current['boundInputSha256'] == prior['boundInputSha256']
            and current['limits'] == prior['limits'] == EXPECTED_LIMITS
            and current['reconciledPriorAttempt']['cumulativeEngineGets'] == 53
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
        'userReply':'Autorizzo la raccolta', 'date':'2026-11-06', 'baseInputSha256':input_sha,
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
