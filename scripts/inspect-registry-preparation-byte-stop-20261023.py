#!/usr/bin/env python3
"""Read retained stop metadata only; never execute capsule or enter application."""
import ast
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import time

CAPSULE = '/home/oufadmin/ouf-registry-postboot-review.VhaPF4P9/capsule.py'
CAPSULE_HASH = '5ffd39fd9f1fe3db361711de5fbe74be5a43e5298d2c3a5970fbe5f3ad97b62e'
CLOSURE_HASH = 'a895f58ddb334389f7e15d4287991bfc81593871061a354e0b482604d936dc62'
DECLARATION_HASH = 'b3dbd027bbe1e49356d77fea71e7d3b52bb47d0d8145468942c6ee9605468233'
PARENT = '/etc/ouf/deploy-snapshots'


def require(ok, reason):
    if not ok: raise ValueError(reason)


def encoded(v): return json.dumps(v, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()
def digest(v): return hashlib.sha256(encoded(v)).hexdigest()
def identity(v): return (v.st_dev, v.st_ino, v.st_uid, v.st_gid, v.st_mode, v.st_nlink, v.st_size, v.st_mtime_ns, v.st_ctime_ns)


class Reader:
    def __init__(self): self.reads = 0; self.bytes = 0; self.until = time.monotonic() + 30

    def raw(self, path, maximum, sha=None, private=True):
        require(time.monotonic() < self.until and self.reads < 20, 'BOUNDED_METADATA_READ_REQUIRED')
        # Traverse protected ancestry through held descriptors, refusing links.
        path = Path(path)
        require(path.is_absolute() and '..' not in path.parts, 'EXACT_METADATA_PATH_REQUIRED')
        fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            for part in path.parts[1:-1]:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                info = os.fstat(child)
                require(not info.st_mode & 0o022 and (info.st_uid == 0 or not private), 'PROTECTED_METADATA_ANCESTRY_REQUIRED')
                os.close(fd); fd = child
            leaf = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
            try:
                before = os.fstat(leaf)
                require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and not before.st_mode & 0o022
                    and (before.st_uid == 0 or not private) and 0 < before.st_size <= maximum,
                    'BOUNDED_PROTECTED_METADATA_REQUIRED')
                chunks = []; count = 0
                while count <= before.st_size:
                    block = os.read(leaf, min(65536, before.st_size + 1 - count))
                    if not block: break
                    chunks.append(block); count += len(block)
                raw = b''.join(chunks)
                require(len(raw) == before.st_size and identity(before) == identity(os.fstat(leaf))
                    == identity(os.stat(path.name, dir_fd=fd, follow_symlinks=False)), 'METADATA_CHANGED')
            finally: os.close(leaf)
        finally: os.close(fd)
        self.reads += 1; self.bytes += len(raw)
        require(self.bytes <= 16777216 and (sha is None or hashlib.sha256(raw).hexdigest() == sha), 'METADATA_HASH_OR_BYTE_BOUND')
        return raw

    def json(self, path, sha=None, maximum=8388608):
        raw = self.raw(path, maximum, sha); value = json.loads(raw)
        require(type(value) is dict and encoded(value) == raw, 'CANONICAL_METADATA_REQUIRED')
        return value


def artifact(path):
    try: info = path.lstat()
    except FileNotFoundError: return {'present': False}
    require(info.st_uid == 0 and not info.st_mode & 0o022 and not stat.S_ISLNK(info.st_mode), 'PROTECTED_ARTIFACT_REQUIRED')
    require(stat.S_ISDIR(info.st_mode) or (stat.S_ISREG(info.st_mode) and info.st_nlink == 1), 'REGULAR_ARTIFACT_REQUIRED')
    return {'present': True, 'directory': stat.S_ISDIR(info.st_mode), 'bytes': info.st_size}


def inspect(reader):
    raw = reader.raw(CAPSULE, 658692, CAPSULE_HASH, private=False)
    values = {}
    for node in ast.parse(raw).body:
        if isinstance(node, ast.Assign):
            require(len(node.targets) == 1 and isinstance(node.targets[0], ast.Name)
                and node.targets[0].id not in values, 'EXACT_CAPSULE_DECLARATIONS_REQUIRED')
            values[node.targets[0].id] = ast.literal_eval(node.value)
    require(set(values) == {'CASE', 'DELIVERY', 'DELIVERY_HASH', 'PACKED', 'BOOTSTRAP'}, 'EXACT_CAPSULE_FIELDS_REQUIRED')
    case = values['CASE']['preparation']; delivery = values['DELIVERY']; manifest = delivery['nativeDeclaration']
    require(digest(delivery) == values['DELIVERY_HASH'] == DECLARATION_HASH
        and digest(manifest) == CLOSURE_HASH and digest(values['CASE']) == delivery['caseHash'], 'CAPSULE_BINDINGS_REQUIRED')
    require(case['privateParent'] == PARENT, 'EXACT_PRIVATE_PARENT_REQUIRED')
    boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    require(re.fullmatch('[0-9a-f-]{36}', boot) is not None, 'CURRENT_BOOT_REQUIRED')
    root = Path(PARENT) / ('semantic-registry-postboot-inputs-' + digest({
        'retainedFrozenResponseHash': case['frozenWireRecovery']['response']['sha256'], 'boot': boot, 'purpose': 'FROZEN_WIRE_V1'}))
    require(artifact(root).get('directory') is True, 'RETAINED_PREPARATION_ROOT_REQUIRED')
    claim = reader.json(str(root / 'claim.json'), maximum=16384)
    require(claim == {'schema': 'ouf.semantic-registry-postboot-preparation-case.v1', 'caseHash': digest(case),
        'sourceClosureHash': CLOSURE_HASH, 'bootId': boot, 'maximumEngineGets': 12, 'maximumAdminGets': 1,
        'maximumFrozenGets': 1, 'automaticReplayAllowed': False, 'runtimeAuthorityIssued': False,
        'maximumTlsHandshakes': 1, 'maximumMetadataReads': 256}, 'EXACT_FAILED_PREPARATION_CLAIM_REQUIRED')
    attempts = []
    for n in range(1, 13):
        path = root / ('engine-get-' + str(n) + '.json')
        if artifact(path)['present']:
            row = reader.json(str(path), maximum=16384)
            require(set(row) == {'attempt', 'requestPathHash'} and type(row['attempt']) is int and row['attempt'] == n
                and re.fullmatch('[0-9a-f]{64}', row['requestPathHash']) is not None, 'EXACT_ENGINE_MARKER_REQUIRED')
            attempts.append(n)
    require(attempts == list(range(1, len(attempts) + 1)), 'CONTIGUOUS_ENGINE_MARKERS_REQUIRED')
    artifacts = {name: artifact(root / name) for name in ('admin-get.json', 'tls-handshake.json', 'frozen-get.json',
        'frozen-response.json', 'source', 'prepared.json', 'review.json')}
    ref = case['historicalReview']; history = reader.json(ref['path'], ref['sha256'])
    sizes = {}
    for name in ('python', 'docker', 'openssl'):
        pin = history['sourceClosure']['executables'][name]
        require(type(pin['path']) is str and pin['path'].startswith('/') and '..' not in Path(pin['path']).parts,
            'EXACT_RETAINED_EXECUTABLE_PATH_REQUIRED')
        info = artifact(Path(pin['path']))
        require(info['present'] and not info['directory'] and 0 < info['bytes'] <= 67108864, 'RETAINED_EXECUTABLE_SIZE_REQUIRED')
        sizes[name] = info['bytes']
    require(Path('/proc/sys/kernel/random/boot_id').read_text().strip() == boot, 'BOOT_CHANGED')
    return {'schema': 'ouf.semantic-registry-preparation-byte-stop-observation.v1', 'status': 'RETAINED_BYTE_STOP_METADATA_OBSERVED',
        'engineAttemptMarkers': attempts, 'markerMeaning': 'ATTEMPT_NOT_COMPLETION', 'artifacts': artifacts,
        'retainedExecutableSizesOnly': sizes, 'executableBytesOpened': 0, 'existingPreparationByteLimit': 167772160,
        'metadataReads': reader.reads, 'metadataBytesRead': reader.bytes,
        'currentExecutableHashVerified': False, 'failedReadIdentified': False, 'capsuleExecuted': False,
        'addressesPrinted': False, 'credentialFilesOpened': 0, 'readOnly': True, 'engineGets': 0, 'adminGets': 0,
        'oauthRequests': 0, 'databaseCalls': 0, 'runtimeEffectsDispatched': 0, 'runtimeAuthorityIssued': False,
        'automaticReplayAllowed': False, 'budgetReset': False, 'releaseAcceptance': False, 'serviceReadinessEstablished': False}


def main():
    try:
        require(os.geteuid() == os.getegid() == 0 and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode
            and len(sys.argv) == 1, 'ISOLATED_ROOT_METADATA_READER_REQUIRED')
        result = inspect(Reader())
    except Exception as error:
        reason = str(error)
        if re.fullmatch('[A-Z][A-Z0-9_]{0,127}', reason) is None: reason = 'METADATA_OBSERVATION_UNPROVEN_PRIVATE_DETAILS_REDACTED'
        result = {'schema': 'ouf.semantic-registry-preparation-byte-stop-observation.v1', 'status': 'STOP_RECONCILE',
            'reasonCode': reason, 'automaticReplayAllowed': False, 'budgetReset': False, 'runtimeEffectsDispatched': 0}
    print(json.dumps(result, sort_keys=True, separators=(',', ':')), flush=True)
    return 0 if result['status'] == 'RETAINED_BYTE_STOP_METADATA_OBSERVED' else 2


if __name__ == '__main__': raise SystemExit(main())
