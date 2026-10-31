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

CAPSULE = '/home/oufadmin/ouf-registry-postboot-review.LduMidpc/capsule.py'
CAPSULE_HASH = 'f6ab800de6ca9452258cf967dd0e194b81b620a35dff0ef357f7fdf93f45f02c'
CLOSURE_HASH = '4fb611d8ffcf4446aeb25df7777dfb66fefb964c63f375863471072b8d7d2f27'
DECLARATION_HASH = 'c0d3bedb36ab56d4f116a4a264e49a1310b366d0ec9aadbd5a6d715331c6bdc8'
PREPARATION_ROOT = '/etc/ouf/deploy-snapshots/semantic-registry-postboot-inputs-ed5451cb23ed2a28c1dbb7585cccfe64fb2837e2d33c81d2a43c1e31f243d5c2'
PREPARATION_HASH = '90748d593e5292420ce967c256d757364ba8637dc0f79619c688585a2f1e5f5d'
REVIEW_HASH = 'cf5191895f1e67b86bdc98b7aa9e10b1292d3f8589a653839116e7c2816ba3c9'
AUTHORITY_HASH = '9d8f36e7f6a942fee95278148399a1a3d140fe0b660809a465edd85f2820d607'
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


def inside(value):
    require(type(value) is str and value.startswith(PARENT + '/') and '..' not in Path(value).parts
            and str(Path(value)) == value, 'EXACT_REVIEW_BOUND_PRIVATE_PATH_REQUIRED')
    return Path(value)


def optional(reader, path, maximum=131072):
    try: path.lstat()
    except FileNotFoundError: return None
    return reader.json(str(path), maximum=maximum)


def closed(value, allowed): return value if type(value) is str and value in allowed else 'OTHER_OR_ABSENT'


def shape(value):
    obj = type(value) is dict
    return {'object': obj, 'string': type(value) is str,
        'exactKeys': obj and set(value) == {'schema', 'sha256', 'entries', 'bytes'},
        'schemaMatches': obj and value.get('schema') == 'ouf.semantic-rootfs-seal.v1',
        'sha256WellFormed': obj and type(value.get('sha256')) is str and re.fullmatch('[0-9a-f]{64}', value['sha256']) is not None,
        'entries': value['entries'] if obj and type(value.get('entries')) is int and 0 < value['entries'] <= 100000 else None,
        'bytes': value['bytes'] if obj and type(value.get('bytes')) is int and 0 <= value['bytes'] <= 8589934592 else None}


def inspect(reader):
    # Parse only literal assignments; do not execute the loader or application.
    raw = reader.raw(CAPSULE, 1048576, CAPSULE_HASH, private=False)
    values = {node.targets[0].id: ast.literal_eval(node.value) for node in ast.parse(raw).body
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name)}
    require(set(values) == {'CASE', 'DELIVERY', 'DELIVERY_HASH', 'PACKED', 'BOOTSTRAP'}, 'EXACT_RETAINED_CAPSULE_FIELDS_REQUIRED')
    manifest = values['DELIVERY']['nativeDeclaration']
    require(digest(values['DELIVERY']) == values['DELIVERY_HASH'] == DECLARATION_HASH and digest(manifest) == CLOSURE_HASH
        and digest(values['CASE']) == values['DELIVERY']['caseHash'], 'EXACT_RETAINED_CAPSULE_BINDINGS_REQUIRED')
    root = inside(PREPARATION_ROOT)
    prepared = reader.json(str(root / 'prepared.json'), PREPARATION_HASH, maximum=16777216)
    review = reader.json(str(root / 'review.json'), REVIEW_HASH)
    require(review['currentContext'] == prepared['nativeContext'] and review['ownerContext'] == prepared['ownerContext']
        and review['sourceClosureHash'] == digest(prepared['sourceClosure']) == CLOSURE_HASH
        and prepared['sourceClosure'] == manifest and review['sourceClosure'] == manifest, 'EXACT_COMPLETED_REVIEW_INPUTS_REQUIRED')
    boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    require(review['bootId'] == boot, 'SAME_RETAINED_BOOT_REQUIRED')
    receipt = reader.json(str(root / 'authority/receipt.json'), maximum=131072)
    require(receipt.get('schema') == 'ouf.semantic-registry-postboot-issued-authority.v1'
        and receipt.get('authorityHash') == AUTHORITY_HASH and receipt.get('reviewHash') == REVIEW_HASH
        and receipt.get('runtimeAuthorityIssued') is True, 'EXACT_ISSUED_AUTHORITY_RECEIPT_REQUIRED')
    context = prepared['nativeContext']; plan = context['plan']; execution = inside(context['executionRoot'])
    require(execution.name == 'semantic-registry-recovery-' + plan['logicalOperationRef'], 'EXACT_RECOVERY_OPERATION_ROOT_REQUIRED')
    journal = reader.json(str(execution / 'recovery.json'), maximum=1048576)
    require(journal['logicalOperationRef'] == plan['logicalOperationRef'] and journal['authorityHash'] == AUTHORITY_HASH
        and journal['bootId'] == boot and type(journal['nextStage']) is int and 0 <= journal['nextStage'] <= 12
        and type(journal['effects']) is list and len(journal['effects']) <= 12, 'EXACT_RETAINED_RECOVERY_JOURNAL_REQUIRED')
    require(type(journal.get('readAttempts')) is int and 0 <= journal['readAttempts'] <= 128
        and type(journal.get('expiresUnix')) is int and 0 < journal['expiresUnix'] < 1099511627776,
        'BOUNDED_RETAINED_READ_AND_EXPIRY_FIELDS_REQUIRED')
    effects = []
    for n, effect in enumerate(journal['effects']):
        require(effect['stage'] == plan['stages'][n]['name'], 'EXACT_ORDERED_EFFECTS_REQUIRED')
        effects.append({'ordinal': n, 'state': closed(effect.get('state'), ('PENDING','CLAIMED','APPLIED','UNKNOWN','FAILED')),
            'nativeRequestAttempted': effect.get('nativeRequestAttempted') is True,
            'nativeResponse204': effect.get('nativeResponse204') is True,
            'nativeAttestationAttempted': effect.get('nativeAttestationAttempted') is True})
    owner_scope = review['scopes']['semanticRegistryPostbootOwner']; owner_root = inside(owner_scope['journalPath'])
    owner = reader.json(str(owner_root / 'recovery.json'), maximum=65536)
    require(owner['contextRef'] == owner_scope['contextRef'] and owner['generationRef'] == owner_scope['generationRef']
        and type(owner['attempts']) is int and 0 <= owner['attempts'] <= 1
        and owner['controlledPredecessorGrantAttempts'] == 319
        and owner['controlledCumulativeGrantAttempts'] == 319 + owner['attempts'], 'EXACT_RETAINED_OWNER_ACCOUNTING_REQUIRED')
    reads = reader.json(str(execution / 'native-reads.json'), maximum=8192)
    scope = review['scopes']['semanticRegistryRecoveryReads']; counts = reads['counts']
    require(reads['scopeHash'] == digest(scope) and reads['authorityHash'] == AUTHORITY_HASH
        and set(counts) == set(scope['maximumRequests']) and all(type(v) is int and 0 <= v <= scope['maximumRequests'][k]
            for k,v in counts.items()), 'EXACT_RETAINED_NATIVE_READ_COUNTERS_REQUIRED')
    frame = optional(reader, execution / 'node/frame-policy.json')
    observed = optional(reader, execution / 'node/paused-observation.json', maximum=1048576)
    acceptance = optional(reader, execution / 'node/paused-acceptance.json')
    recipe = context['nodeRecipe']; expected = recipe['expectedRootfsSeal']
    observed_seal = observed.get('rootfsSeal') if observed is not None else None
    require(reader.json(str(execution / 'recovery.json'), maximum=1048576) == journal
        and reader.json(str(owner_root / 'recovery.json'), maximum=65536) == owner
        and reader.json(str(execution / 'native-reads.json'), maximum=8192) == reads
        and Path('/proc/sys/kernel/random/boot_id').read_text().strip() == boot, 'STOP_METADATA_CHANGED_DURING_OBSERVATION')
    return {'schema': 'ouf.semantic-registry-rootfs-stop-metadata.v1', 'status': 'RETAINED_ROOTFS_STOP_METADATA_OBSERVED',
        'checkpoint': journal['nextStage'], 'recoveryState': closed(journal.get('state'), ('READY','IN_FLIGHT','COMPLETE','BLOCKED','RECONCILE_REQUIRED')),
        'effects': effects, 'readAttempts': journal.get('readAttempts'), 'nativeReadCounts': counts,
        'newGenerationRecorded': type(journal.get('newGeneration')) is dict,
        'framePolicyRetained': frame is not None, 'pausedObservationRetained': observed is not None,
        'pausedAcceptanceRetained': acceptance is not None, 'expectedSealShape': shape(expected),
        'retainedObservedSealShape': shape(observed_seal),
        'retainedSealMatchesExpected': observed_seal == expected if observed is not None else None,
        'ownerState': closed(owner.get('state'), ('NEW','ACTIVE','BLOCKED','CANCELLED','PAUSED_EXHAUSTED','RECONCILE_REQUIRED','PUBLISHING')),
        'retainedServiceGrantAttempts': owner['attempts'], 'retainedControlledGrantAttempts': owner['controlledCumulativeGrantAttempts'],
        'signedWindowExpiredAtObservation': time.time() >= journal['expiresUnix'],
        'journalObservationIsCurrentOwnerAdmission': False, 'currentContainerStateObserved': False,
        'currentRootfsRead': False, 'rootfsMismatchCauseEstablished': False, 'capsuleExecuted': False,
        'addressesPrinted': False, 'credentialFilesOpened': 0, 'metadataReads': reader.reads, 'metadataBytesRead': reader.bytes,
        'engineGets': 0, 'adminGets': 0, 'oauthRequests': 0, 'databaseCalls': 0, 'runtimeEffectsDispatched': 0,
        'runtimeAuthorityIssued': False, 'readOnly': True, 'automaticReplayAllowed': False, 'budgetReset': False,
        'serviceReadinessEstablished': False, 'releaseAcceptance': False}


def main():
    try:
        require(os.geteuid() == os.getegid() == 0 and sys.flags.isolated and sys.flags.no_site
            and sys.dont_write_bytecode and len(sys.argv) == 1, 'ISOLATED_ROOT_METADATA_READER_REQUIRED')
        result = inspect(Reader())
    except Exception as error:
        reason = str(error)
        if re.fullmatch('[A-Z][A-Z0-9_]{0,127}', reason) is None: reason = 'ROOTFS_STOP_METADATA_UNPROVEN_PRIVATE_DETAILS_REDACTED'
        result = {'schema': 'ouf.semantic-registry-rootfs-stop-metadata.v1', 'status': 'STOP_RECONCILE',
            'reasonCode': reason, 'automaticReplayAllowed': False, 'budgetReset': False, 'runtimeEffectsDispatched': 0}
    print(json.dumps(result, sort_keys=True, separators=(',', ':')), flush=True)
    return 0 if result['status'] == 'RETAINED_ROOTFS_STOP_METADATA_OBSERVED' else 2


if __name__ == '__main__': raise SystemExit(main())
