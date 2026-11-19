#!/usr/bin/env python3
"""Two hash-bound retained metadata reads; no current service request or replay."""
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import stat
import sys

READER = '/home/oufadmin/ouf-postboot-stop-read.CDTQuD6j/read.py'
READER_HASH = 'f35e044d2e44eb286607f6c8a8c8dd6dc55a741f06766c61f0e079ac5563c916'
TARGET = '/run/secrets/ingestion-summary.properties'
EXPECTED_ENV = {'gatewayUrl': 'OUF_INGESTION_ACTIVATION_GATEWAY_URL',
                'tokenFile': 'OUF_INGESTION_ACTIVATION_TOKEN_FILE'}


def require(ok):
    if not ok:
        raise ValueError()


def read_verified_reader(path=READER):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 < before.st_size <= 32768)
        with os.fdopen(os.dup(fd), 'rb') as stream:
            raw = stream.read(32769)
        identity = lambda info: (info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
        require(len(raw) == before.st_size and identity(before) == identity(os.fstat(fd))
                == identity(os.stat(path, follow_symlinks=False))
                and hashlib.sha256(raw).hexdigest() == READER_HASH)
        return raw
    finally:
        os.close(fd)


def configuration_shape(config, host):
    env = {}
    entries = config.get('Env') or []
    require(type(entries) is list and len(entries) <= 256)
    for item in entries:
        require(type(item) is str and 0 < len(item) <= 65536 and '=' in item)
        key, value = item.split('=', 1)
        require(key not in env); env[key] = value
    selectors = {key: env[key] for key in ('SPRING_CONFIG_LOCATION', 'SPRING_CONFIG_ADDITIONAL_LOCATION',
                                         'SPRING_CONFIG_IMPORT') if env.get(key)}
    expected = {key: bool(env.get(name)) for key, name in EXPECTED_ENV.items()}
    keys_present = {key: name in env for key, name in EXPECTED_ENV.items()}
    file_selected = len(selectors) == 1 and next(iter(selectors)) in (
        'SPRING_CONFIG_LOCATION', 'SPRING_CONFIG_ADDITIONAL_LOCATION') and next(iter(selectors.values())) in (
            'file:' + TARGET, 'optional:file:' + TARGET)
    binds = []
    for item in host.get('Binds') or []:
        require(type(item) is str and len(item) <= 8192)
        parts = item.split(':')
        if len(parts) == 3 and parts[1] == TARGET:
            binds.append('ro' in parts[2].split(','))
    for item in host.get('Mounts') or []:
        if item.get('Target') == TARGET:
            binds.append(item.get('Type') == 'bind' and item.get('ReadOnly') is True)
    overrides = {'gatewayUrl': False, 'tokenFile': False, 'springConfiguration': False}
    args = config.get('Cmd') or []
    require(type(args) is list and len(args) <= 256)
    for arg in args:
        require(type(arg) is str and len(arg) <= 65536)
        name = re.sub('[^a-z0-9]', '', arg.split('=', 1)[0].lower())
        overrides['gatewayUrl'] |= name in ('oufingestionactivationgatewayurl', 'doufingestionactivationgatewayurl')
        overrides['tokenFile'] |= name in ('oufingestionactivationtokenfile', 'doufingestionactivationtokenfile')
        overrides['springConfiguration'] |= name.startswith(('springconfig', 'dspringconfig', 'springprofiles'))
    return {'legacyExpectedEnvironmentPresent': expected,
        'legacyEnvironmentKeysPresent': keys_present,
        'legacyEnvironmentLookupWouldRaiseKeyError': not all(keys_present.values()),
        'legacyEnvironmentLookupWouldFail': not all(expected.values()),
        'knownPropertiesFileSelected': file_selected,
        'knownPropertiesReadOnlyBindPresent': len(binds) == 1 and binds[0] is True,
        'springSelectorNames': sorted(selectors), 'commandLineOverridesPresent': overrides,
        'additionalConfigurationChannelsPresent': {name: bool(env.get(name)) for name in (
            'SPRING_APPLICATION_JSON', 'JAVA_TOOL_OPTIONS', 'JDK_JAVA_OPTIONS', '_JAVA_OPTIONS')},
        'valuesPrinted': False, 'sourcePathsPrinted': False}


def file_metadata(binding, resolve=False):
    if binding is None:
        return {'configured': False, 'hashVerified': False}
    try:
        path = binding['path']
        require(type(path) is str and path.startswith('/') and len(path) <= 4096
                and '..' not in Path(path).parts)
        selected = Path(path).resolve(strict=True) if resolve else Path(path)
        info = selected.stat(follow_symlinks=False)
        observed = [info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode,
                    info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns]
        return {'configured': True, 'present': True, 'regularFile': stat.S_ISREG(info.st_mode),
            'metadataComparisonAvailable': 'metadata' in binding,
            'metadataMatchesRetained': observed == binding['metadata'] if 'metadata' in binding else None,
            'hashVerified': False}
    except (OSError, ValueError, KeyError, TypeError) as error:
        result = {'configured': True, 'present': False, 'hashVerified': False,
            'exceptionClass': type(error).__name__}
        if isinstance(error, OSError) and type(error.errno) is int:
            result['errno'] = error.errno
        return result


def main():
    output = {'schema': 'ouf.semantic-registry-postboot-config-read-result.v1', 'readOnly': True,
        'engineGets': 0, 'adminGets': 0, 'oauthRequests': 0, 'databaseCalls': 0,
        'credentialFilesOpened': 0, 'propertiesFileOpened': False, 'applicationEntryInvoked': False,
        'runtimeAuthorityIssued': False, 'runtimeEffectsDispatched': 0, 'automaticReplayAllowed': False,
        'budgetReset': False, 'releaseAcceptance': False, 'rootCauseEstablished': False,
        'reviewedFrameIsCurrentRuntimeObservation': False, 'metadataReadOperations': 0}
    output.update(addressesPrinted=False, rawMessagesPrinted=False, rawTracebacksPrinted=False,
        credentialValuesPrinted=False, serviceReadinessEstablished=False)
    shared = None; sources = {}
    try:
        require(len(sys.argv) == 1 and os.geteuid() == os.getegid() == 0
                and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode)
        signal.signal(signal.SIGALRM, lambda *_: (_ for _ in ()).throw(TimeoutError()))
        signal.alarm(20)
        output['stage'] = 'VERIFY_RETAINED_READER'
        shared = {'__name__': 'verified_retained_stop_reader'}
        exec(compile(read_verified_reader(), '<verified-retained-stop-reader>', 'exec'), shared)
        output['stage'] = 'VERIFY_RETAINED_CAPSULE'
        case, manifest, loader, sources = shared['unpack'](shared['read_capsule']())
        output['stage'] = 'PRELOAD_WITHOUT_APPLICATION_ENTRY'
        Files = shared['preload'](manifest, loader, sources); files = Files()
        preparation = case['preparation']
        output['stage'] = 'READ_EXACT_RETAINED_INPUTS'
        reference = preparation['retainedInputs']; output['metadataReadOperations'] = 1
        inputs, _ = files.json(reference['path'], reference['sha256'], maximum=8388608)
        output['stage'] = 'READ_EXACT_PATCH_REVIEW'; output['metadataReadOperations'] = 2
        review, _ = files.json(preparation['patchContext'] + '/review.json',
            inputs['proposal']['retainedPatchReviewHash'], maximum=8388608)
        native = review['executionReview']; bundle = native['preparedInputs']
        require(shared['digest'](bundle) == native['preparedInputsHash'])
        frame = bundle['ingestionFrame']; require(frame['module'] == 'ingestion')
        request = frame['requestTemplate']
        output['configurationShape'] = configuration_shape(request, request['HostConfig'])
        admin = native['gatewayTransportProfile']
        output['selectedFileMetadata'] = {
            'GATEWAY_CONFIG': file_metadata(admin['config']),
            'GATEWAY_ADMIN_KEY': file_metadata(admin['adminKey']),
            'ADMIN_PYTHON_PROGRAM': file_metadata(admin['pythonExecutable'], resolve=True),
            'DATABASE_DOCKER_PROGRAM': file_metadata(native['databaseControlProfile']['dockerExecutable'], resolve=True)}
        output['selectedFileContentsRead'] = False
        output.update(stage='RETAINED_CALLER_CONFIGURATION_CLASSIFIED', complete=True,
            status='RETAINED_CALLER_CONFIGURATION_OBSERVED', metadataBytesRead=files.bytes)
        code = 0
    except Exception as error:
        output.update(status='STOP_RECONCILE', complete=False)
        output['safeExceptionChain'] = shared['safe_error'](error, sources) if shared and 'safe_error' in shared else [
            {'exceptionClass': type(error).__name__ if type(error).__name__ in (
                'ValueError', 'FileNotFoundError', 'PermissionError', 'OSError', 'TimeoutError') else 'OTHER'}]
        code = 2
    finally:
        signal.alarm(0)
    print(json.dumps(output, sort_keys=True, separators=(',', ':')), flush=True)
    return code


if __name__ == '__main__':
    raise SystemExit(main())
