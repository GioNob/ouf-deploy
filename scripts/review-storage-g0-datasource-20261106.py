#!/usr/bin/env python3
"""One redacted local investigation of the three observed datasource holds.

Does not select credentials, relax the preparer, contact providers or read S3
secrets. The exact installed preparation bundle supplies existing pin readers.
"""
import hashlib
import hmac
import json
import os
from pathlib import Path
import stat
import sys
import time

STAGING = Path('/var/lib/ouf-g0-network-preparation-20261106')
MANIFEST_SHA = '541115aa70b073803ebe88a809a91a2f263bd7bd62d9708d297d37519e931bb2'
SCOPE = 'datasource-review-20261106'
PREFIXES = {'onboarding': 'OUF_ONB', 'udp': 'OUF_UDP', 'ingestion': 'OUF_ING'}
CONFIG_KEYS = ('SPRING_APPLICATION_JSON', 'SPRING_CONFIG_LOCATION', 'SPRING_CONFIG_ADDITIONAL_LOCATION')
JAVA_KEYS = ('JAVA_TOOL_OPTIONS', 'JDK_JAVA_OPTIONS', 'JAVA_OPTS')
KNOWN_DATASOURCE = (
    'SPRING_DATASOURCE_URL', 'SPRING_DATASOURCE_USERNAME',
    'SPRING_DATASOURCE_PASSWORD', 'SPRING_DATASOURCE_DRIVER_CLASS_NAME',
    'SPRING_DATASOURCE_TYPE', 'SPRING_DATASOURCE_JNDI_NAME',
    'SPRING_DATASOURCE_HIKARI_JDBC_URL', 'SPRING_DATASOURCE_HIKARI_USERNAME',
    'SPRING_DATASOURCE_HIKARI_PASSWORD', 'SPRING_DATASOURCE_HIKARI_MAXIMUM_POOL_SIZE',
    'SPRING_DATASOURCE_HIKARI_MINIMUM_IDLE', 'SPRING_DATASOURCE_HIKARI_CONNECTION_TIMEOUT',
    'SPRING_DATASOURCE_HIKARI_VALIDATION_TIMEOUT', 'SPRING_DATASOURCE_HIKARI_MAX_LIFETIME',
    'SPRING_DATASOURCE_HIKARI_IDLE_TIMEOUT', 'SPRING_DATASOURCE_HIKARI_POOL_NAME',
)


def require(ok, code):
    if not ok:
        raise ValueError(code)


def protected(path):
    for p in (path, *path.parents):
        s = p.lstat()
        require(stat.S_ISDIR(s.st_mode) and s.st_uid == 0 and not s.st_mode & 0o022,
                'REVIEW_PROTECTED_ANCESTRY')


def code_bytes(path):
    protected(path.parent)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        s = os.fstat(fd)
        require(stat.S_ISREG(s.st_mode) and s.st_uid == s.st_gid == 0
                and stat.S_IMODE(s.st_mode) == 0o400 and s.st_nlink == 1
                and 0 < s.st_size <= 1048576, 'REVIEW_CODE_CUSTODY')
        b = os.read(fd, 1048577)
        def identity(info):
            return tuple(getattr(info, key) for key in (
                'st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink',
                'st_size', 'st_mtime_ns', 'st_ctime_ns'))
        require(len(b) == s.st_size and identity(s) == identity(os.fstat(fd))
                == identity(path.lstat()), 'REVIEW_CODE_CHANGED')
        return b
    finally:
        os.close(fd)


def verify_bundle(bundle):
    protected(bundle)
    raw = code_bytes(bundle / 'tool-manifest.json')
    require(hashlib.sha256(raw).hexdigest() == MANIFEST_SHA, 'REVIEW_EXACT_MANIFEST')
    manifest = json.loads(raw)
    expected = set(manifest['files']) | {'tool-manifest.json'}
    # Reject extra importable code, symlinks and unexpected directories as well.
    expected_dirs = {str(p) for n in expected for p in Path(n).parents if str(p) != '.'}
    observed = set()
    pending = [bundle]
    while pending:
        directory = pending.pop()
        with os.scandir(directory) as entries:
            for entry in entries:
                p = Path(entry.path)
                rel = str(p.relative_to(bundle))
                if entry.is_dir(follow_symlinks=False):
                    require(rel in expected_dirs, 'REVIEW_TOOL_DIRECTORY_SET')
                    protected(p)
                    pending.append(p)
                else:
                    require(rel in expected, 'REVIEW_TOOL_FILE_SET')
                    observed.add(rel)
    require(observed == expected, 'REVIEW_TOOL_FILE_SET')
    for name, sha in manifest['files'].items():
        require(hashlib.sha256(code_bytes(bundle / name)).hexdigest() == sha,
                'REVIEW_EXACT_INSTALLED_SOURCE')
    return json.loads(code_bytes(bundle / 'releases/storage-g0-input-preparation-profile-20261106.json'))


def classify(role, env):
    prefix = PREFIXES[role]
    pairs = {}
    for ouf_suffix, spring_suffix in (('URL', 'URL'), ('USER', 'USERNAME'), ('PASSWORD', 'PASSWORD')):
        a, b = prefix + '_DB_' + ouf_suffix, 'SPRING_DATASOURCE_' + spring_suffix
        both = a in env and b in env
        pairs[ouf_suffix.lower()] = {
            'oufPresent': a in env, 'springPresent': b in env,
            'oufNonempty': bool(env.get(a)), 'springNonempty': bool(env.get(b)),
            'byteEqual': hmac.compare_digest(env[a].encode(), env[b].encode()) if both else None,
            'springExactOufPlaceholder': env.get(b) == '${' + a + '}',
        }
    ds = [k for k in env if k.startswith('SPRING_DATASOURCE_')]
    return {
        'connectionPairs': pairs,
        'knownDatasourceVariablesPresent': [k for k in KNOWN_DATASOURCE if k in env],
        'otherDatasourceVariableCount': sum(k not in KNOWN_DATASOURCE for k in ds),
        'configurationVariablesPresent': [k for k in CONFIG_KEYS if k in env],
        'javaVariablesMentioningDatasource': [k for k in JAVA_KEYS if 'datasource' in env.get(k, '').lower()],
        'effectiveConfigurationProven': False,
    }


def review(staging, profile, m, *, env_reader=None, pin_reader=None, boot_reader=None, clock=time.monotonic):
    require(os.geteuid() == os.getegid() == 0, 'REVIEW_ROOT_REQUIRED')
    m.protected(staging / 'inputs')
    scope = staging / 'inputs' / SCOPE
    if os.path.lexists(scope):
        result = m.decode(m.read_private(scope / 'result.json', 65536))
        result['existingResultReadOnly'] = True
        return result
    old_path = staging / 'inputs' / m.DRAFT / 'result.json'
    old_raw = m.read_private(old_path, 65536)
    old = m.decode(old_raw)
    require(old.get('schema') == 'ouf.storage-g0-input-draft-result.v1'
            and old.get('status') == 'PRIVATE_INPUT_DRAFT_PREPARED_REVIEW_REQUIRED'
            and old.get('connectionDraftsPrepared') == ['s3']
            and old.get('missingInputs', []).count('INPUTS_DATASOURCE_OVERRIDE_REQUIRES_REVIEW') == 3
            and old.get('providerRequests') == 0 and old.get('runtimeAuthorityIssued') is False,
            'REVIEW_EXPECTED_THREE_DATABASE_HOLDS')
    scope.mkdir(mode=0o700)
    m.put(scope / 'claim.json', m.encoded({
        'schema': 'ouf.storage-g0-datasource-review-claim.v1', 'maximumAttempts': 1,
        'maximumEnvironmentReads': 3, 'maximumEnvironmentBytesPerRead': 131072,
        'maximumSeconds': 15, 'priorResultSha256': m.sha(old_raw),
        'automaticReplayAllowed': False, 'providerRequests': 0,
    }))
    until = clock() + 15
    env_reader = env_reader or m.live_environment
    pin_reader = pin_reader or m.process_pin
    boot_reader = boot_reader or (lambda: Path('/proc/sys/kernel/random/boot_id').read_text().strip())
    result = {
        'schema': 'ouf.storage-g0-datasource-review.v1', 'status': 'HELD', 'roles': {},
        'processEnvironmentsRead': 0, 'providerRequests': 0, 'credentialFilesWritten': 0,
        'connectionDraftsChanged': False, 'collectionScopeCreated': False,
        'runtimeAuthorityIssued': False, 'targetInputCheckPassed': False,
        'g0Complete': False, 'acceptanceCreditAdded': 0, 'automaticReplayAllowed': False,
    }
    try:
        seed_path = Path(profile['seedPath'])
        seed_raw = m.read_private(seed_path, 2 << 20)
        seed = m.decode(seed_raw)
        selected = m.bindings(seed, profile)

        def guard():
            require(clock() < until, 'REVIEW_DEADLINE')
            require(boot_reader() == seed['bootId'], 'REVIEW_BOOT_CHANGED')
            for role in PREFIXES:
                pin = selected[role]['pin']
                require(pin_reader(pin['pid']) == pin, 'REVIEW_PROCESS_CHANGED')

        rows = {}
        for role in PREFIXES:
            guard()
            result['processEnvironmentsRead'] += 1
            env = env_reader(selected[role]['pin']['pid'])
            guard()
            rows[role] = classify(role, env)
        guard()
        require(m.read_private(seed_path, 2 << 20) == seed_raw
                and m.read_private(old_path, 65536) == old_raw, 'REVIEW_INPUT_CHANGED')
        result['roles'] = rows
        result['status'] = 'DATASOURCE_OVERRIDE_METADATA_OBSERVED_REVIEW_REQUIRED'
        result['originalPreparationResultPreserved'] = True
    except Exception as e:
        # Never expose an exception incorporating a private path or value.
        codes = {'REVIEW_DEADLINE', 'REVIEW_BOOT_CHANGED', 'REVIEW_PROCESS_CHANGED', 'REVIEW_INPUT_CHANGED'}
        result['reason'] = str(e) if str(e) in codes else 'REVIEW_LOCAL_OBSERVATION_UNPROVEN'
    m.put(scope / 'result.json', m.encoded(result))
    return result


def main():
    try:
        require(len(sys.argv) == 1 and os.geteuid() == os.getegid() == 0
                and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode,
                'REVIEW_ISOLATED_ROOT_ENTRY')
        os.umask(0o077)
        bundle = STAGING / 'input-tools-6c9de0f4'
        profile = verify_bundle(bundle)
        sys.path.insert(0, str(bundle))
        from tools.storage_planning import g0_input_draft as m
        result = review(STAGING, profile, m)
    except Exception:
        result = {'status': 'HELD', 'reason': 'REVIEW_ENTRY_OR_EXISTING_SCOPE_UNPROVEN',
                  'providerRequests': 0, 'runtimeAuthorityIssued': False}
    print(json.dumps(result, sort_keys=True))
    return 0 if result['status'] == 'DATASOURCE_OVERRIDE_METADATA_OBSERVED_REVIEW_REQUIRED' else 1


if __name__ == '__main__':
    raise SystemExit(main())
