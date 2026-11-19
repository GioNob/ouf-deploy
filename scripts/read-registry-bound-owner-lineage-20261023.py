#!/usr/bin/env python3
"""Bounded retained metadata reconciliation, never an owner/runtime admission."""
import hashlib
import json
import os
from pathlib import PurePosixPath
import re
import signal
import stat
import sys
import time

PARENT = '/etc/ouf/deploy-snapshots'
INPUTS = PARENT + '/semantic-registry-history-capture-r5cc0fjv/inputs.json'
INPUTS_HASH = '8facd750a673d25c14bfc1a58c8c0ae28d63d8a5ce487ab956b8f2b23dc902c9'
CONTEXT = PARENT + '/chatbot-file-cohort-signed-16e5f80e40d09772048f1575850b643a69d4d46520db1a56ccd79a7b1a9e055b'
REVIEW_HASH = '07ee9e8adf0d645018fb70212884f43c22e85cf3c7288bd78dad5bf0d02413bc'
SOURCE = 'd7bbb768970aad1a001ca4d085bcc87c58a29cec'
BOOT = '/proc/sys/kernel/random/boot_id'
CANDIDATES = (
    '/etc/ouf/deploy-snapshots/chatbot-file-intake-0188d923fe197a6102097abc8b3af26a94e0175923a23fcca008801acd0b9e3d/attempt-533e63ca03292c116a1e8936/postgrant-worker',
    '/etc/ouf/deploy-snapshots/chatbot-file-intake-7f2ade604c8f084451674a0453a0ba3db8f8cda55dcda37c2ed446cb182e1149/attempt-cd07518e1cc3a56fc9cd8b68/postgrant-worker',
    '/etc/ouf/deploy-snapshots/chatbot-file-intake-890b78dc63521133a1535514e8aed82df7256328b9290c4562ffdc90a36ccb72/attempt-0c7ba37ca25b32ec9532f68a/postgrant-worker',
    '/etc/ouf/deploy-snapshots/chatbot-file-intake-9ca1c537e02de4fb2fa988edd244a46613fa115332d9a16de32db4fd0bd49991/attempt-c2f25d09db010c998273f8a0/postgrant-worker',
    '/etc/ouf/deploy-snapshots/chatbot-file-intake-9f754dbcf7caf450d1d1eef50c0288f2102cfac191a65cfc60a5c1fcbf60ba5e/attempt-f8d38137fc4cca9d36910c19/postgrant-worker',
    '/etc/ouf/deploy-snapshots/chatbot-file-intake-9f754dbcf7caf450d1d1eef50c0288f2102cfac191a65cfc60a5c1fcbf60ba5e/attempt-f8d38137fc4cca9d36910c19/semantic-functional-worker-2af1928d087c14a1215b19e34ea916ea28fcf91a3426caf6ab326bf4d0491fd6',
    '/etc/ouf/deploy-snapshots/chatbot-file-intake-9f754dbcf7caf450d1d1eef50c0288f2102cfac191a65cfc60a5c1fcbf60ba5e/attempt-f8d38137fc4cca9d36910c19/semantic-functional-worker-4d73f23481b322c6fc046734f9a50a7251ddafe5d6d3d794129d9728305e8ad6',
    '/etc/ouf/deploy-snapshots/chatbot-file-intake-9f754dbcf7caf450d1d1eef50c0288f2102cfac191a65cfc60a5c1fcbf60ba5e/attempt-f8d38137fc4cca9d36910c19/semantic-functional-worker-8c46ccca7a6f04d33004cfb9d788c694bd509e72e057837b3c5f6548cc22e93c',
    '/etc/ouf/deploy-snapshots/chatbot-file-intake-9f754dbcf7caf450d1d1eef50c0288f2102cfac191a65cfc60a5c1fcbf60ba5e/attempt-f8d38137fc4cca9d36910c19/semantic-functional-worker-b5e3f4acbf15a2dc6fe3004686fcebf987efd7cd068fdd67789a0096f2a0ca15',
    '/etc/ouf/deploy-snapshots/chatbot-file-intake-9f754dbcf7caf450d1d1eef50c0288f2102cfac191a65cfc60a5c1fcbf60ba5e/attempt-f8d38137fc4cca9d36910c19/semantic-functional-worker-ba5c401d9fa8030d91ae58e3f70a1ba89abfd4092c8b2884bf96c95747df6377',
    '/etc/ouf/deploy-snapshots/chatbot-file-intake-9f754dbcf7caf450d1d1eef50c0288f2102cfac191a65cfc60a5c1fcbf60ba5e/attempt-f8d38137fc4cca9d36910c19/semantic-functional-worker-beefc7f2ee79fa70c5b416d6d3efe68d3b08d15f9bb07c96c3e837995b627803',
    '/etc/ouf/deploy-snapshots/chatbot-file-intake-9f754dbcf7caf450d1d1eef50c0288f2102cfac191a65cfc60a5c1fcbf60ba5e/attempt-f8d38137fc4cca9d36910c19/semantic-functional-worker-e787ac35c3c3ff3cf3c6a33f528e38ebf4da313ffe2e38540c1d3ee9242f95fb',
    '/etc/ouf/deploy-snapshots/chatbot-file-intake-9f754dbcf7caf450d1d1eef50c0288f2102cfac191a65cfc60a5c1fcbf60ba5e/attempt-f8d38137fc4cca9d36910c19/semantic-functional-worker-ec7d462632c821d48dfc7aae409ff57282d77901ebd2991119bb6ebd00272748',
    '/etc/ouf/deploy-snapshots/chatbot-file-intake-9f754dbcf7caf450d1d1eef50c0288f2102cfac191a65cfc60a5c1fcbf60ba5e/attempt-f8d38137fc4cca9d36910c19/semantic-functional-worker-f9d572dde0b549b11f7a704e765e9568dbfef9525b58d085efcf0459ee158d84',
    '/etc/ouf/deploy-snapshots/chatbot-file-intake-a861526474956c81633d8e85cb50c633084ed932a8065cb9fdcdafc88dd6c6b2/attempt-a2a9f03de96ca4eacbfd61ba/postgrant-worker',
    '/etc/ouf/deploy-snapshots/chatbot-file-intake-c228da198b608f6bf8461bf73dfc283c59334aaa80b2f0308be09c010df43fce/attempt-6d2badee67d6b4c261a188a1/postgrant-worker',
    '/etc/ouf/deploy-snapshots/chatbot-file-intake-d7f970d08b585000ca92e850e4c2743336a1645a398cf66ab9eb48c5b1b60b8a/attempt-73cbfcaea1d634de836486a4/postgrant-worker',
    '/etc/ouf/deploy-snapshots/chatbot-file-intake-f7682c9433bfa6aa90d348f58e7e428a868be78171b209efef47fc85cae57182/attempt-c4ba96d36a267747ec2f8b94/postgrant-worker',
)  # Fixed owner-pasted paths; no discovery.
SCHEMA = 'ouf.semantic-registry-bound-owner-lineage-result.v1'
GOVERNED = 'ouf.policy-token-governed-worker-session.v1'
MEMBERS = {'recovery.json': 65536, 'owner-session.json': 131072,
           'owner-admission.json': 8192, 'owner-first-grant.json': 16384}
MAX_FILES, MAX_READS, MAX_BYTES = 75, 150, 33554432


class Stop(Exception):
    pass


def require(ok, reason):
    if not ok:
        raise Stop(reason)


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def digest(value):
    return hashlib.sha256(encoded(value)).hexdigest()


def hashed(value):
    return type(value) is str and re.fullmatch('[a-f0-9]{64}', value) is not None


def unique(items):
    result = {}
    for key, value in items:
        require(key not in result, 'DUPLICATE_JSON_KEY')
        result[key] = value
    return result


def decode(raw):
    def nonfinite(_):
        raise Stop('NONFINITE_JSON_NUMBER')
    try:
        result = json.loads(raw, object_pairs_hook=unique, parse_constant=nonfinite)
        require(type(result) is dict, 'JSON_OBJECT_REQUIRED')
        return result
    except (ValueError, UnicodeError, RecursionError):
        raise Stop('INVALID_JSON_METADATA') from None


def exact_path(path, parent):
    require(type(path) is str and len(path) <= 4096 and path.startswith(parent + '/')
            and str(PurePosixPath(path)) == path and '..' not in PurePosixPath(path).parts,
            'METADATA_PATH_OUTSIDE_EXACT_SCOPE')
    return path


def identity(info):
    return (info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


class Reader:
    """Open each protected component by dirfd; retain identities through recheck."""
    def __init__(self, parent=PARENT):
        self.parent = parent
        self.allowed = {INPUTS: 8388608, CONTEXT + '/review.json': 262144}
        self.reads = self.bytes = 0
        self.records = {}
        self.deadline = time.monotonic() + 12

    def allow(self, path, limit):
        exact_path(path, self.parent)
        require(path not in self.allowed, 'DUPLICATE_METADATA_REFERENCE')
        require(len(self.allowed) < MAX_FILES, 'METADATA_FILE_LIMIT')
        self.allowed[path] = limit

    def raw(self, path):
        require(path in self.allowed, 'UNAPPROVED_METADATA_READ')
        require(self.reads < MAX_READS and time.monotonic() < self.deadline,
                'READ_OR_DEADLINE_LIMIT')
        limit = self.allowed[path]
        self.reads += 1
        fds = []
        ancestors = []
        try:
            fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            fds.append(fd)
            parts = PurePosixPath(path).parts[1:]
            for component in parts[:-1]:
                before = os.fstat(fd)
                require(before.st_uid == 0 and not before.st_mode & 0o022,
                        'UNPROTECTED_METADATA_ANCESTOR')
                child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                fds.append(child)
                observed = os.fstat(child)
                require(stat.S_ISDIR(observed.st_mode) and observed.st_uid == 0
                        and not observed.st_mode & 0o022, 'UNPROTECTED_METADATA_ANCESTOR')
                ancestors.append((fd, component, child, identity(observed)))
                fd = child
            leaf = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
            fds.append(leaf)
            before = os.fstat(leaf)
            require(stat.S_ISREG(before.st_mode) and before.st_uid == before.st_gid == 0
                    and not before.st_mode & 0o077 and before.st_nlink == 1
                    and 0 < before.st_size <= limit, 'UNPROTECTED_OR_UNBOUNDED_METADATA')
            raw = bytearray()
            while len(raw) <= before.st_size:
                block = os.read(leaf, min(65536, before.st_size + 1 - len(raw)))
                if not block:
                    break
                raw.extend(block)
            self.bytes += len(raw)
            require(self.bytes <= MAX_BYTES, 'METADATA_BYTE_LIMIT')
            require(len(raw) == before.st_size and identity(before) == identity(os.fstat(leaf))
                    == identity(os.stat(parts[-1], dir_fd=fd, follow_symlinks=False)), 'METADATA_DRIFT')
            for parent_fd, name, child_fd, saved in ancestors:
                require(saved == identity(os.fstat(child_fd))
                        == identity(os.stat(name, dir_fd=parent_fd, follow_symlinks=False)),
                        'METADATA_ANCESTRY_DRIFT')
            return bytes(raw), identity(before), tuple(x[3] for x in ancestors)
        except OSError:
            raise Stop('METADATA_UNAVAILABLE_OR_UNSAFE') from None
        finally:
            for fd in reversed(fds):
                os.close(fd)

    def read(self, path, expected=None):
        require(path not in self.records, 'DUPLICATE_METADATA_READ')
        raw, file_id, parents = self.raw(path)
        sha = hashlib.sha256(raw).hexdigest()
        require(expected is None or sha == expected, 'PINNED_METADATA_HASH_DRIFT')
        value = decode(raw)
        require(digest(value) == sha, 'CANONICAL_RETAINED_METADATA_REQUIRED')
        self.records[path] = (sha, file_id, parents)
        return value

    def verify(self):
        for path, before in self.records.items():
            raw, file_id, parents = self.raw(path)
            require((hashlib.sha256(raw).hexdigest(), file_id, parents) == before,
                    'METADATA_CHANGED_DURING_OBSERVATION')


def boot_identity():
    fd = os.open(BOOT, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        value = os.read(fd, 128).decode('ascii').strip()
        require(re.fullmatch('[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}', value) is not None,
                'CURRENT_BOOT_IDENTITY_REQUIRED')
        return value
    finally:
        os.close(fd)


def counter(value):
    return type(value) is int and 0 <= value <= 1000000


def candidate(reader, path, boot):
    records = {}
    for name, maximum in MEMBERS.items():
        member = path + '/' + name
        reader.allow(member, maximum)
        records[name] = reader.read(member)
    row, session, marker, first = (records[n] for n in MEMBERS)
    require(row.get('schema') == 'ouf.bounded-recovery.v1'
            and marker.get('schema') == 'ouf.policy-token-owner-admission.v1'
            and set(marker) == {'schema', 'ownerProfileHash', 'contextRef', 'generationRef',
                'version', 'state', 'tokenHash', 'blockedAttempt'}
            and counter(marker.get('version'))
            and (marker.get('tokenHash') is None or hashed(marker['tokenHash']))
            and (marker.get('blockedAttempt') is None or counter(marker['blockedAttempt']))
            and session.get('schema') in {GOVERNED, *('ouf.policy-token-new-finite-worker-session.v' + str(n)
                    for n in (1, 2, 3, 4, 5, 6, 8, 9, 10))}, 'UNSUPPORTED_OWNER_METADATA_SCHEMA')
    require(all(hashed(row.get(k)) and row[k] == session.get(k) == marker.get(k)
                for k in ('contextRef', 'generationRef'))
            and hashed(marker.get('ownerProfileHash')) and hashed(session.get('logicalOwnerScopeHash'))
            and row.get('workerSessionHash') == digest(session)
            and row.get('policyHash') == digest(session.get('policy')),
            'OWNER_RECORD_BINDING_DRIFT')
    require(row.get('state') == 'CANCELLED' and row.get('reason') == 'CANCELLED_BY_OWNER'
            and marker.get('state') == 'BLOCKED', 'OBSERVED_CANCELLED_BLOCKED_STATE_CHANGED')
    attempts, prior, cumulative = (row.get(k) for k in
            ('attempts', 'controlledPredecessorGrantAttempts', 'controlledCumulativeGrantAttempts'))
    require(all(counter(v) for v in (attempts, prior, cumulative)) and prior >= 1
            and type(session.get('policy', {}).get('max_attempts')) is int
            and attempts <= session.get('policy', {}).get('max_attempts', -1) <= 128
            and cumulative == prior + attempts and session.get('predecessorGrantAttempts') == prior,
            'EXACT_PER_SESSION_ACCOUNTING_REQUIRED')
    require(first.get('state') == 'TOKEN_PUBLISHED_NOT_RUNTIME_ACCEPTED'
            and type(first.get('attemptSlotsConsumed')) is int
            and first.get('attemptSlotsConsumed') == 1 and first.get('gapRemainsOpen') is True
            and first.get('historicalAccountingReconciled') is False
            and first.get('legacyHistoricalGrantAttempts') is None
            and row.get('firstGrantReceiptHash') == digest(first)
            and session.get('predecessorFirstGrantOperation') == first.get('operation')
            and session.get('predecessorFirstGrantScopeHash') == first.get('scopeHash')
            and hashed(first.get('operation')) and hashed(first.get('scopeHash')),
            'FIRST_GRANT_LINEAGE_DRIFT')
    require(row.get('bootId') == first.get('bootId') and type(row.get('bootId')) is str
            and re.fullmatch('[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}', row['bootId']) is not None,
            'RETAINED_BOOT_BINDING_DRIFT')
    require(session.get('automaticBudgetRenewalAllowed') is False
            and session.get('consumedClaimReplayAllowed') is False
            and session.get('legacyHistoryDisposition') == 'UNKNOWN_RETAINED_NOT_RECONCILED'
            and row.get('legacyHistory') == {'state': 'UNKNOWN', 'cumulativeGrantAttemptCount': None,
                'reconciled': False, 'gapRemainsOpen': True}, 'UNKNOWN_HISTORY_MUST_REMAIN_UNRESOLVED')
    if session['schema'] == GOVERNED:
        require(session.get('controlledHistoryProfile') == row.get('controlledHistoryProfile')
                == 'ouf.policy-token-governed-worker-continuation.v1'
                and session.get('firstGrantReceiptHash') == digest(first)
                and session.get('maximumCumulativeGrantAttempts') == prior + session['policy']['max_attempts'],
                'GOVERNED_HISTORY_BINDING_DRIFT')
        refs = session.get('predecessorRecordHashes', {})
        predecessor = (refs.get('recovery.json'), refs.get('owner-session.json'))
    else:
        require(session['schema'] == 'ouf.policy-token-new-finite-worker-session.v' + str(prior),
                'LEGACY_SESSION_COUNTER_PROFILE_DRIFT')
        predecessor = (session.get('predecessorCancelledWorkerHash'), session.get('predecessorWorkerSessionHash'))
        if prior != 1:
            require(session.get('controlledHistoryProfile') == row.get('controlledHistoryProfile')
                    == 'ouf.policy-token-cancelled-worker-continuation.v1'
                    and row.get('predecessorCancelledWorkerHash') == predecessor[0]
                    and row.get('predecessorWorkerSessionHash') == predecessor[1],
                    'LEGACY_PREDECESSOR_BINDING_DRIFT')
    require(prior == 1 or all(hashed(x) for x in predecessor), 'EXACT_PREDECESSOR_BINDINGS_REQUIRED')
    return {'path': path, 'records': records, 'predecessor': predecessor,
            'rowHash': digest(row), 'sessionHash': digest(session), 'sameCurrentBoot': row['bootId'] == boot}


def reconcile(reader, boot, candidates=CANDIDATES):
    require(1 <= len(candidates) <= 18 and len(set(candidates)) == len(candidates),
            'EXACT_BOUNDED_CANDIDATE_SET_REQUIRED')
    inputs = reader.read(INPUTS, INPUTS_HASH)
    review = reader.read(CONTEXT + '/review.json', REVIEW_HASH)
    historical = inputs.get('historicalBinding', {})
    require(inputs.get('schema') == 'ouf.semantic-registry-recovery-private-historical-inputs.v1'
            and inputs.get('kind') == 'OFFLINE_COMPOSITION_INPUTS_NOT_EXECUTABLE_AUTHORITY'
            and historical.get('reviewHash') == REVIEW_HASH
            and historical.get('historicalDeploymentChainBound') is True
            and historical.get('historicalAuthorityReactivated') is False
            and review['sourceClosure']['declaration']['sourceCommit'] == SOURCE,
            'EXACT_RETAINED_HISTORICAL_CHAIN_REQUIRED')
    bundle_ref = review['scopes']['finiteActionProcess']['bundle']
    bundle_path = exact_path(bundle_ref['path'], reader.parent)
    require(PurePosixPath(bundle_path).name == 'child-bundle.json' and hashed(bundle_ref.get('sha256')),
            'EXACT_HISTORICAL_BUNDLE_REFERENCE_REQUIRED')
    reader.allow(bundle_path, 8388608)
    bundle = reader.read(bundle_path, bundle_ref['sha256'])
    prepared = bundle['prepared']
    registry, owner = prepared['registry'], prepared['owner']
    require(bundle['declaration'] == review['sourceClosure']['declaration']
            and digest(prepared) == review['privateInputHashes']['preparedInputs']
            and historical.get('preparedBundleHash') == bundle_ref['sha256']
            and registry == inputs.get('registryInputs')
            and digest(registry) == review['scopes']['applicationRegistryCutover']['preparedHash'],
            'HISTORICAL_PREPARED_INPUT_BINDING_DRIFT')
    binding, mounted = owner['binding'], registry['nodeRecipe']['renewableToken']
    require(set(binding) == {'endpoint', 'client_id', 'scope', 'output_directory', 'output_member',
                'output_gid', 'minimum_remaining', 'maximum_token_seconds'}
            and mounted.get('source') == binding['output_directory']
            and mounted.get('fileName') == binding['output_member']
            and mounted.get('gid') == binding['output_gid']
            and mounted.get('ownerBindingHash') == digest(binding), 'REGISTRY_OWNER_OUTPUT_BINDING_MISMATCH')
    scope = review['scopes']['policyTokenOwnerInstallation']
    signed_session = review['scopes']['policyTokenFiniteWorkerSession']
    require(scope.get('schema') == 'ouf.policy-token-owner-installation.v1'
            and scope.get('journalPath') in candidates
            and scope.get('workerSessionScopeHash') == digest(signed_session)
            and hashed(scope.get('firstGrantReceiptHash'))
            and review['scopes']['tokenOwnerRuntime'].get('ownerBindingHash') == scope.get('ownerBindingHash'),
            'EXACT_HISTORICAL_OWNER_ANCHOR_REQUIRED')
    rows = [candidate(reader, exact_path(path, reader.parent), boot) for path in candidates]
    anchor = next(i for i, row in enumerate(rows) if row['path'] == scope['journalPath'])
    seed = rows[anchor]['records']
    require(seed['owner-session.json'] == signed_session
            and seed['owner-admission.json']['ownerProfileHash'] == scope['ownerBindingHash']
            and digest(seed['owner-first-grant.json']) == scope['firstGrantReceiptHash']
            and all(scope.get(k) == owner.get(k) == seed['recovery.json'].get(k)
                    for k in ('contextRef', 'generationRef')), 'HISTORICAL_OWNER_METADATA_DRIFT')
    logical = signed_session['logicalOwnerScopeHash']
    first_hash = scope['firstGrantReceiptHash']
    related = {i for i, row in enumerate(rows)
               if row['records']['owner-session.json']['logicalOwnerScopeHash'] == logical
               and digest(row['records']['owner-first-grant.json']) == first_hash}
    require(all((row['records']['owner-session.json']['logicalOwnerScopeHash'] == logical)
                == (digest(row['records']['owner-first-grant.json']) == first_hash) for row in rows),
            'AMBIGUOUS_CREDENTIAL_LINEAGE')
    edges = {}
    for i in related:
        matches = [j for j in related if (rows[j]['rowHash'], rows[j]['sessionHash']) == rows[i]['predecessor']]
        require(len(matches) <= 1 and i not in matches, 'AMBIGUOUS_PREDECESSOR_LINK')
        if matches:
            j = matches[0]
            require(rows[i]['records']['recovery.json']['controlledPredecessorGrantAttempts']
                    == rows[j]['records']['recovery.json']['controlledCumulativeGrantAttempts'],
                    'LINKED_CUMULATIVE_ACCOUNTING_DRIFT')
            edges[i] = j
    require(len(set(edges.values())) == len(edges), 'BRANCHED_CREDENTIAL_LINEAGE')
    for start in related:
        seen = set()
        while start in edges:
            require(start not in seen, 'CYCLIC_CREDENTIAL_LINEAGE')
            seen.add(start)
            start = edges[start]
    connected = {anchor}
    while True:
        expanded = connected | {i for i, j in edges.items() if j in connected} | {j for i, j in edges.items() if i in connected}
        if expanded == connected:
            break
        connected = expanded
    require(connected == related, 'RETAINED_LINEAGE_LINK_INCOMPLETE')
    roots = related - set(edges)
    require(len(roots) == 1 and rows[next(iter(roots))]['records']['recovery.json']
            ['controlledPredecessorGrantAttempts'] == 1, 'FIRST_CONTROLLED_GRANT_ANCESTOR_LINK_REQUIRED')
    terminals = related - set(edges.values())
    require(len(terminals) == 1, 'AMBIGUOUS_BOUNDED_TERMINAL_RECORD')
    reader.verify()
    observations = []
    for i in sorted(related):
        item, row = rows[i], rows[i]['records']['recovery.json']
        observations.append({'candidateOrdinal': i, 'recoveryHash': item['rowHash'],
            'sessionHash': item['sessionHash'], 'predecessorCandidateOrdinal': edges.get(i),
            'attempts': row['attempts'], 'controlledPredecessorGrantAttempts': row['controlledPredecessorGrantAttempts'],
            'controlledCumulativeGrantAttempts': row['controlledCumulativeGrantAttempts'],
            'sameCurrentBoot': item['sameCurrentBoot'], 'retainedFirstGrantSameCurrentBoot': item['sameCurrentBoot'],
            'recoveryState': 'CANCELLED', 'admissionState': 'BLOCKED', 'currentOwnerIdentityEstablished': False})
    return {**base(), 'status': 'HISTORICAL_CREDENTIAL_LINEAGE_RECONCILED', 'complete': True,
        'historicalInputsHash': INPUTS_HASH, 'historicalReviewHash': REVIEW_HASH,
        'historicalBundleHash': bundle_ref['sha256'], 'historicalOwnerAnchorOrdinal': anchor,
        'credentialOutputBindingHash': digest(binding), 'logicalOwnerScopeHash': logical,
        'firstGrantReceiptHash': first_hash, 'historicalCredentialOutputBindingEstablished': True,
        'boundedLineageStartsAtFirstControlledGrant': True,
        'candidateCount': len(rows), 'relatedCandidateCount': len(related),
        'boundedTerminalRecordOrdinal': next(iter(terminals)), 'boundedTerminalIsCurrentAuthority': False,
        'metadataLineage': observations, 'historicalAccountingReconciled': False,
        'legacyHistoricalGrantAttempts': None, 'otherOwnersNotExcluded': True,
        'metadataReadOperations': reader.reads, 'metadataBytesRead': reader.bytes,
        'maximumMetadataReads': MAX_READS, 'maximumMetadataBytes': MAX_BYTES}


def base():
    return {'schema': SCHEMA, 'readOnly': True, 'currentOwnerIdentityEstablished': False,
        'currentOwnerSelected': False, 'currentOwnerAdmissionProven': False,
        'credentialFilesOpened': 0, 'credentialValuesPrinted': False, 'rawMetadataPrinted': False,
        'addressesPrinted': False, 'secretPathsPrinted': False, 'directoryScans': 0,
        'engineGets': 0, 'databaseCalls': 0, 'oauthRequests': 0, 'programsInvoked': 0,
        'locksReadOrAcquired': 0, 'runtimeEffectsDispatched': 0, 'runtimeAuthorityIssued': False,
        'automaticReplayAllowed': False, 'budgetReset': False, 'activationResubmitted': False,
        'targetApplyAuthorized': False, 'rootCauseEstablished': False, 'releaseAcceptance': False}


def main():
    reader = None
    try:
        require(len(sys.argv) == 1 and os.geteuid() == os.getegid() == 0
                and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode,
                'ROOT_ISOLATED_NO_SITE_NO_BYTECODE_NO_ARGUMENTS_REQUIRED')
        signal.signal(signal.SIGALRM, lambda *_: (_ for _ in ()).throw(Stop('WHOLE_OPERATION_DEADLINE')))
        signal.alarm(15)
        boot = boot_identity()
        reader = Reader()
        result = reconcile(reader, boot)
        require(boot_identity() == boot, 'CURRENT_BOOT_CHANGED')
        signal.alarm(0)
        print(encoded(result).decode())
        return 0
    except Exception as error:
        signal.alarm(0)
        reason = str(error) if type(error) is Stop else 'UNCONFIRMED_METADATA_STRUCTURE'
        if not re.fullmatch('[A-Z][A-Z0-9_]{0,127}', reason):
            reason = 'UNCONFIRMED_METADATA_STRUCTURE'
        print(encoded({**base(), 'status': 'STOP_RECONCILE', 'complete': False,
            'reasonCode': reason, 'metadataReadOperations': reader.reads if reader else 0,
            'metadataBytesRead': reader.bytes if reader else 0}).decode())
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
