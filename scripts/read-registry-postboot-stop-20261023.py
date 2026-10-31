#!/usr/bin/env python3
"""Diagnose one retained stop; never enter the recovery application.

Only the exact retained capsule may be preloaded, without calling execute.
Observe fixed preparation markers and at most six hash-bound metadata files.
No exception messages, locals, private values, arbitrary paths or native calls.
"""
import ast
import base64
import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import signal
import stat
import sys

CAPSULE = '/home/oufadmin/ouf-registry-postboot-review.nMPgRpwq/capsule.py'
CAPSULE_HASH = '75162f0e9f1e3848392b23c1754751b18a45c529ce139e0550c347de0c67b17a'
DECLARATION_HASH = '552c027f549c9bbcd9912e7dce5aab69b1ffaa040092df0e9736cdeac45921ac'
CLOSURE_HASH = '7d352295d288dce2e01dec1c3c558d7159513751765a448d93b7430a19b04993'
PARENT = '/etc/ouf/deploy-snapshots'
SCHEMA = 'ouf.semantic-registry-postboot-stop-read-result.v1'
MAX_METADATA_BYTES = 25165824
ERROR_CLASSES = frozenset(('AttributeError', 'KeyError', 'TypeError', 'ValueError', 'RuntimeError',
    'ImportError', 'ModuleNotFoundError', 'OSError', 'FileNotFoundError', 'FileExistsError',
    'PermissionError', 'NotADirectoryError', 'TimeoutError', 'JSONDecodeError',
    'RecoveryDenied', 'RuntimeDenied', 'Stop'))
STOP_CODES = frozenset(('BOUNDED_RETAINED_CAPSULE_REQUIRED', 'RETAINED_CAPSULE_CHANGED',
    'EXACT_FAILED_CAPSULE_HASH_REQUIRED', 'ONE_RETAINED_CAPSULE_ASSIGNMENT_REQUIRED',
    'EXACT_RETAINED_CAPSULE_ASSIGNMENTS_REQUIRED', 'EXACT_RETAINED_DECLARATION_REQUIRED',
    'BOUNDED_RETAINED_SOURCE_PAYLOAD_REQUIRED', 'EXACT_RETAINED_SOURCE_BYTES_REQUIRED',
    'SAME_PRELOADED_ENTRY_REQUIRED', 'EXACT_DIAGNOSTIC_DIRECTORY_REQUIRED',
    'PROTECTED_DIAGNOSTIC_ANCESTRY_REQUIRED', 'PROTECTED_DIAGNOSTIC_DIRECTORY_REQUIRED',
    'PROTECTED_RETAINED_MARKER_REQUIRED', 'RETAINED_MARKERS_CHANGED_DURING_READ',
    'EXACT_HASH_BOUND_DIAGNOSTIC_METADATA_REQUIRED', 'DIAGNOSTIC_METADATA_BUDGET',
    'SAME_LINEAGE_BUNDLE_REQUIRED', 'SAME_DIAGNOSTIC_PATCH_PACKET_REQUIRED',
    'ISOLATED_ROOT_NO_ARGUMENT_DIAGNOSTIC_REQUIRED', 'DIAGNOSTIC_DEADLINE',
    'CURRENT_DIAGNOSTIC_BOOT_REQUIRED', 'DIAGNOSTIC_BOOT_CHANGED'))


class Stop(Exception):
    pass


def require(ok, reason):
    if not ok:
        raise Stop(reason)


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def digest(value):
    return hashlib.sha256(encoded(value)).hexdigest()


def identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def read_capsule(path=CAPSULE):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                and 0 < before.st_size <= 524288, 'BOUNDED_RETAINED_CAPSULE_REQUIRED')
        with os.fdopen(os.dup(fd), 'rb') as stream:
            raw = stream.read(524289)
        require(len(raw) == before.st_size and identity(before) == identity(os.fstat(fd))
                == identity(os.stat(path, follow_symlinks=False)), 'RETAINED_CAPSULE_CHANGED')
        return raw
    finally:
        os.close(fd)


def unpack(raw, expected=CAPSULE_HASH):
    require(hashlib.sha256(raw).hexdigest() == expected, 'EXACT_FAILED_CAPSULE_HASH_REQUIRED')
    values = {}
    for node in ast.parse(raw).body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            name = node.targets[0].id
            require(name not in values, 'ONE_RETAINED_CAPSULE_ASSIGNMENT_REQUIRED')
            values[name] = ast.literal_eval(node.value)
    require(set(values) == {'CASE', 'DELIVERY', 'DELIVERY_HASH', 'PACKED', 'BOOTSTRAP'},
            'EXACT_RETAINED_CAPSULE_ASSIGNMENTS_REQUIRED')
    delivery = values['DELIVERY']; manifest = delivery['nativeDeclaration']
    require(digest(delivery) == values['DELIVERY_HASH'] == DECLARATION_HASH
            and digest(manifest) == CLOSURE_HASH
            and digest(values['CASE']) == delivery['caseHash'], 'EXACT_RETAINED_DECLARATION_REQUIRED')
    with gzip.GzipFile(fileobj=io.BytesIO(base64.b64decode(values['PACKED'], validate=True))) as stream:
        payload = stream.read(12582913)
    require(0 < len(payload) <= 12582912, 'BOUNDED_RETAINED_SOURCE_PAYLOAD_REQUIRED')
    payload = json.loads(payload)
    loader = payload['loader'].encode()
    sources = {name: text.encode() for name, text in payload['sources'].items()}
    require(hashlib.sha256(loader).hexdigest() == manifest['loaderHash']
            and set(sources) == set(manifest['sourceHashes']) and len(sources) == 105
            and all(hashlib.sha256(raw).hexdigest() == manifest['sourceHashes'][name]
                    for name, raw in sources.items()), 'EXACT_RETAINED_SOURCE_BYTES_REQUIRED')
    return values['CASE'], manifest, loader, sources


def safe_error(error, sources):
    """Use only closed class labels and exact sealed code identities; no str(error)."""
    allowed = {'<verified-postboot-loader>': 'SEALED_LOADER'}
    allowed.update({'<sealed-registry-postboot:' + name + '>': name for name in sources})
    result, seen = [], set()
    while error is not None and id(error) not in seen and len(result) < 4:
        seen.add(id(error)); frames = []; trace = error.__traceback__
        for _ in range(32):
            if trace is None:
                break
            frame = trace.tb_frame; module = allowed.get(frame.f_code.co_filename)
            if module is not None:
                frames.append({'module': module, 'line': trace.tb_lineno})
            trace = trace.tb_next
        name = type(error).__name__
        row = {'exceptionClass': name if name in ERROR_CLASSES else 'OTHER', 'sealedFrames': frames[-8:]}
        if isinstance(error, OSError) and type(error.errno) is int and 0 < error.errno < 4096:
            row['errno'] = error.errno
        result.append(row)
        error = error.__cause__ if error.__cause__ is not None else error.__context__
    return result


def preload(manifest, loader, sources):
    namespace = {}
    exec(compile(loader, '<verified-postboot-loader>', 'exec'), namespace)
    entry, actual = namespace['load_entry'](manifest['sourceCommit'], sources, loader,
        digest(manifest), manifest['sourcePins'])
    require(actual == manifest and callable(entry.execute), 'SAME_PRELOADED_ENTRY_REQUIRED')
    # Deliberately return only Files, never the entry/controller callable.
    return sys.modules['tools.semantic_registry_recovery_execution.postboot_prepare'].Files


def open_directory(path):
    require(path.is_absolute() and str(PurePosixPath(path)) == str(path)
            and '..' not in path.parts, 'EXACT_DIAGNOSTIC_DIRECTORY_REQUIRED')
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in path.parts[1:]:
            info = os.fstat(fd)
            require(info.st_uid == 0 and not info.st_mode & 0o022, 'PROTECTED_DIAGNOSTIC_ANCESTRY_REQUIRED')
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd); fd = child
        info = os.fstat(fd)
        require(info.st_uid == 0 and not info.st_mode & 0o022, 'PROTECTED_DIAGNOSTIC_DIRECTORY_REQUIRED')
        return fd
    except BaseException:
        os.close(fd)
        raise


def markers(root):
    try:
        fd = open_directory(root)
    except FileNotFoundError:
        return {'preparationDirectoryPresent': False, 'markerMeaning': 'ATTEMPT_NOT_COMPLETION'}
    try:
        values = {}; pins = {}; root_before = identity(os.fstat(fd))
        names = ['claim.json', *('engine-get-' + str(i) + '.json' for i in range(1, 13)),
                 'admin-get.json', 'frozen-get.json', 'source', 'prepared.json', 'review.json']
        for name in names:
            try:
                info = os.stat(name, dir_fd=fd, follow_symlinks=False)
            except FileNotFoundError:
                values[name] = False
                pins[name] = None
                continue
            expected = stat.S_ISDIR(info.st_mode) if name == 'source' else stat.S_ISREG(info.st_mode)
            require(expected and info.st_uid == 0 and not info.st_mode & 0o022,
                    'PROTECTED_RETAINED_MARKER_REQUIRED')
            values[name] = True
            pins[name] = identity(info)
        for name, before in pins.items():
            try:
                after = identity(os.stat(name, dir_fd=fd, follow_symlinks=False))
            except FileNotFoundError:
                after = None
            require(after == before, 'RETAINED_MARKERS_CHANGED_DURING_READ')
        require(root_before == identity(os.fstat(fd)) == identity(root.lstat()),
                'RETAINED_MARKERS_CHANGED_DURING_READ')
        return {'preparationDirectoryPresent': True, 'claimPresent': values['claim.json'],
            'engineAttemptMarkers': [i for i in range(1, 13) if values['engine-get-' + str(i) + '.json']],
            'adminAttemptMarkerPresent': values['admin-get.json'],
            'frozenGetAttemptMarkerPresent': values['frozen-get.json'],
            'sourceDirectoryPresent': values['source'], 'preparedPresent': values['prepared.json'],
            'reviewPresent': values['review.json'], 'markerMeaning': 'ATTEMPT_NOT_COMPLETION'}
    finally:
        os.close(fd)


def metadata_shapes(case, files, output):
    """Six exact hash-bound files at most. Only fixed field-presence checks escape."""
    checks = output['retainedShapeChecks'] = []
    count = total = 0

    def read(label, path, sha):
        nonlocal count, total
        require(type(path) is str and path.startswith(PARENT + '/') and '..' not in PurePosixPath(path).parts
                and str(PurePosixPath(path)) == path and re.fullmatch('[a-f0-9]{64}', sha) is not None,
                'EXACT_HASH_BOUND_DIAGNOSTIC_METADATA_REQUIRED')
        require(count < 6 and total < MAX_METADATA_BYTES, 'DIAGNOSTIC_METADATA_BUDGET')
        output['metadataStage'] = label
        count += 1; output['metadataReadOperations'] = count
        value, profile = files.json(path, sha, maximum=min(8388608, MAX_METADATA_BYTES - total))
        total += profile['metadata'][6]; output['metadataBytesRead'] = total
        return value

    def field(label, value, *keys):
        for index, key in enumerate(keys):
            if type(value) is not dict or key not in value:
                checks.append({'id': label, 'present': False, 'missingAt': index})
                return None
            value = value[key]
        checks.append({'id': label, 'present': True})
        return value

    inputs = read('RETAINED_INPUTS', case['retainedInputs']['path'], case['retainedInputs']['sha256'])
    historical = read('HISTORICAL_REVIEW', case['historicalReview']['path'], case['historicalReview']['sha256'])
    binding = field('HISTORICAL_OWNER_BUNDLE_BINDING', historical, 'scopes', 'finiteActionProcess', 'bundle')
    proposal = field('INPUT_PROPOSAL', inputs, 'proposal')
    field('INPUT_REGISTRY', inputs, 'registryInputs'); field('INPUT_PLAN', inputs, 'candidateContract')
    field('HISTORICAL_PREPARED_HASH', historical, 'privateInputHashes', 'preparedInputs')
    if type(binding) is dict:
        require(binding.get('sha256') == case['lineageReceipt']['historicalBundleHash'], 'SAME_LINEAGE_BUNDLE_REQUIRED')
        bundle = read('OWNER_BUNDLE', binding['path'], binding['sha256'])
        field('PREPARED_REGISTRY', bundle, 'prepared', 'registry')
        field('PREPARED_OWNER_HOST_INPUT', bundle, 'prepared', 'owner', 'hostInputBinding')
        field('PREPARED_OWNER_BINDING', bundle, 'prepared', 'owner', 'binding')
    if type(proposal) is not dict:
        return
    for label, keys in [('PROPOSAL_REGISTRY_ID', ('registry', 'containerId')),
                        ('PROPOSAL_GATEWAY_ID', ('gatewayBinding', 'containerId')),
                        ('PROPOSAL_ENGINE_BINDING', ('engineBinding',))]:
        field(label, proposal, *keys)
    patch = case['patchContext']
    review_sha = field('PROPOSAL_PATCH_REVIEW_HASH', proposal, 'retainedPatchReviewHash')
    journal_sha = field('PROPOSAL_PATCH_JOURNAL_HASH', proposal, 'retainedPatchJournalHash')
    if type(review_sha) is not str or type(journal_sha) is not str:
        return
    review = read('PATCH_REVIEW', patch + '/review.json', review_sha)
    journal = read('PATCH_JOURNAL', patch + '/recovery.json', journal_sha)
    native = field('PATCH_EXECUTION_REVIEW', review, 'executionReview')
    effects = field('PATCH_EFFECTS', journal, 'effects')
    if type(effects) is list:
        for stage, label in [('ingestion.CREATE_REPLACEMENT', 'PATCH_CALLER_CREATE_RESOURCE'),
                             ('ingestion.START_REPLACEMENT', 'PATCH_CALLER_START_RESOURCE')]:
            rows = [row for row in effects if type(row) is dict and row.get('stage') == stage]
            field(label, rows[0] if len(rows) == 1 else None, 'nativeResource', 'containerId')
    if type(native) is not dict:
        return
    field('PATCH_GATEWAY_TRANSPORT', native, 'gatewayTransportProfile')
    field('PATCH_DATABASE_PROGRAM', native, 'databaseControlProfile', 'dockerExecutable')
    binding = field('PATCH_PACKET_BINDING', native, 'packetBinding')
    if type(binding) is dict:
        require(binding.get('path') == patch + '/packet.json', 'SAME_DIAGNOSTIC_PATCH_PACKET_REQUIRED')
        packet = read('PATCH_PACKET', binding['path'], binding['sha256'])
        field('PATCH_RETAINED_GATEWAY_CONFIG', packet, 'retainedGatewayConfig')
    output['metadataStage'] = 'FIXED_RETAINED_SHAPE_CHECKS_FINISHED'


def base():
    return {'schema': SCHEMA, 'readOnly': True, 'applicationEntryInvoked': False,
        'engineGets': 0, 'adminGets': 0, 'databaseCalls': 0, 'oauthRequests': 0,
        'credentialFilesOpened': 0, 'runtimeEffectsDispatched': 0, 'runtimeAuthorityIssued': False,
        'automaticReplayAllowed': False, 'budgetReset': False, 'releaseAcceptance': False,
        'rawMessagesPrinted': False, 'rawTracebacksPrinted': False, 'localsPrinted': False,
        'addressesPrinted': False, 'serviceReadinessEstablished': False,
        'metadataReadOperations': 0, 'metadataBytesRead': 0}


def main():
    output = base(); sources = {}
    try:
        require(len(sys.argv) == 1 and os.geteuid() == os.getegid() == 0
                and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode,
                'ISOLATED_ROOT_NO_ARGUMENT_DIAGNOSTIC_REQUIRED')
        signal.signal(signal.SIGALRM, lambda *_: (_ for _ in ()).throw(Stop('DIAGNOSTIC_DEADLINE')))
        signal.alarm(20)
        output['diagnosticStage'] = 'RETAINED_CAPSULE_VERIFICATION'
        case, manifest, loader, sources = unpack(read_capsule())
        output['capsuleHashVerified'] = True
        output['pythonVersion'] = list(sys.version_info[:3])
        output['diagnosticStage'] = 'ISOLATED_SOURCE_PRELOAD'
        Files = preload(manifest, loader, sources)
        output['sealedPreloadSucceeded'] = True
        preparation = case['preparation']
        boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
        require(re.fullmatch('[a-f0-9-]{36}', boot) is not None, 'CURRENT_DIAGNOSTIC_BOOT_REQUIRED')
        root = Path(PARENT) / ('semantic-registry-postboot-inputs-' + digest({
            'case': preparation, 'closure': digest(manifest), 'boot': boot}))
        output['diagnosticStage'] = 'RETAINED_PREPARATION_MARKERS'
        output['preparationMarkers'] = markers(root)
        output['diagnosticStage'] = 'EXACT_RETAINED_METADATA_SHAPES'
        metadata_shapes(preparation, Files(), output)
        require(Path('/proc/sys/kernel/random/boot_id').read_text().strip() == boot, 'DIAGNOSTIC_BOOT_CHANGED')
        output.update(status='RETAINED_STOP_INPUTS_OBSERVED', complete=True,
            originalFailureReproduced=False, rootCauseEstablished=False)
        code = 0
    except Exception as error:
        output.update(status='STOP_RECONCILE', complete=False, safeExceptionChain=safe_error(error, sources),
            originalFailureReproduced=False, rootCauseEstablished=False)
        if type(error) is Stop and len(error.args) == 1 and error.args[0] in STOP_CODES:
            output['reasonCode'] = error.args[0]
        code = 2
    finally:
        signal.alarm(0)
    print(encoded(output).decode(), flush=True)
    return code


if __name__ == '__main__':
    raise SystemExit(main())
