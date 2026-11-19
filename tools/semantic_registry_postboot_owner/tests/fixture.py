"""Disposable retained-metadata fixture; never a target preparation helper."""
import copy
import dataclasses
import hashlib
import importlib
import os
from pathlib import Path
import stat

from tools.semantic_registry_postboot_owner import contract as c


def file_profile(path):
    path = Path(path).resolve()
    def metadata(s):
        return [s.st_dev, s.st_ino, s.st_uid, s.st_gid, s.st_mode, s.st_nlink, s.st_size, s.st_mtime_ns, s.st_ctime_ns]
    return {'path': str(path), 'sha256': hashlib.sha256(path.read_bytes()).hexdigest(), 'metadata': metadata(path.stat()),
        'ancestors': [{'path': str(p), 'identity': [s.st_dev, s.st_ino, s.st_uid, s.st_gid, s.st_mode]}
            for p in reversed(path.parents) for s in [p.stat()]]}


def write(path, value):
    path = Path(path); path.write_bytes(c.encoded(value)); path.chmod(0o600)


def make_context(root, binding, iam_profile, tls_trust_hash, credential_path, recovery,
                 source_closure_hash, *, source_paths=None, budget=None):
    """Construct exact fixture lineage 1->129->257->319; no source/network effects.

    Caller owns real disposable credential/output/typed authority and signed
    recovery. This helper supplies metadata, not approval or a successful gate.
    """
    root = Path(root); root.mkdir(mode=0o700, parents=True, exist_ok=True); root.chmod(0o700)
    predecessor = root/'retained-owner'; predecessor.mkdir(mode=0o700)
    if dataclasses.is_dataclass(binding):
        binding = dataclasses.asdict(binding)
    if dataclasses.is_dataclass(iam_profile):
        iam_profile = dataclasses.asdict(iam_profile)
    # JSON normalization follows the actual private preparation writer.
    binding = __import__('json').loads(c.encoded(binding)); iam_profile = __import__('json').loads(c.encoded(iam_profile))
    first = {'state': 'TOKEN_PUBLISHED_NOT_RUNTIME_ACCEPTED', 'attemptSlotsConsumed': 1,
        'gapRemainsOpen': True, 'historicalAccountingReconciled': False, 'legacyHistoricalGrantAttempts': None,
        'bootId': '11111111-2222-3333-4444-555555555555', 'operation': 'a'*64, 'scopeHash': 'b'*64}
    logical = c.digest({'disposableFixture': str(root), 'binding': binding})
    rows = []; all_records = []
    for ordinal, prior, attempts in ((0,1,128), (1,129,128), (2,257,62)):
        context_ref = c.digest({'fixtureContext': ordinal}); generation_ref = c.digest({'fixtureGeneration': ordinal})
        session = {'schema': 'ouf.policy-token-governed-worker-session.v1', 'logicalOwnerScopeHash': logical,
            'contextRef': context_ref, 'generationRef': generation_ref,
            'predecessorFirstGrantOperation': first['operation'], 'predecessorFirstGrantScopeHash': first['scopeHash'],
            'firstGrantReceiptHash': c.digest(first), 'policy': {'max_attempts': 128},
            'predecessorGrantAttempts': prior,
            'fenceBinding': {'path': str(root/('semantic-functional-session-'+logical+'.fence.json')),
                'value': {'schema': 'ouf.semantic-functional-session-fence.v1', 'logicalOwnerScopeHash': logical,
                    'reviewHash': c.digest({'review': ordinal}), 'journalPath': str(predecessor),
                    'predecessorWorkerHash': c.digest({'predecessor': ordinal}), 'active': True}}}
        row = {'schema': 'ouf.bounded-recovery.v1', 'state': 'CANCELLED', 'reason': 'CANCELLED_BY_OWNER',
            'contextRef': context_ref, 'generationRef': generation_ref, 'workerSessionHash': c.digest(session),
            'policyHash': c.digest(session['policy']), 'firstGrantReceiptHash': c.digest(first),
            'bootId': first['bootId'], 'legacyHistory': copy.deepcopy(c.LEGACY), 'attempts': attempts,
            'controlledPredecessorGrantAttempts': prior, 'controlledCumulativeGrantAttempts': prior+attempts}
        marker = {'schema': 'ouf.policy-token-owner-admission.v1', 'ownerProfileHash': c.digest({'oldProfile': ordinal}),
            'contextRef': context_ref, 'generationRef': generation_ref, 'version': 1,
            'state': 'BLOCKED', 'tokenHash': None, 'blockedAttempt': attempts}
        all_records.append(dict(zip(c.RECORDS, (row,session,marker,copy.deepcopy(first)))))
        rows.append({'candidateOrdinal': ordinal, 'recoveryHash': c.digest(row), 'sessionHash': c.digest(session),
            'predecessorCandidateOrdinal': None if ordinal == 0 else ordinal-1,
            'recoveryState': 'CANCELLED', 'admissionState': 'BLOCKED', 'sameCurrentBoot': False,
            'retainedFirstGrantSameCurrentBoot': False, 'attempts': attempts,
            'controlledPredecessorGrantAttempts': prior, 'controlledCumulativeGrantAttempts': prior+attempts})
    retained = all_records[-1]
    for name, value in retained.items():
        write(predecessor/name,value)
    for name in ('recovery.lock','invocation.lock'):
        (predecessor/name).write_bytes(b''); (predecessor/name).chmod(0o600)
    fence = retained['owner-session.json']['fenceBinding']; write(fence['path'], fence['value'])
    receipt = {'schema': 'ouf.semantic-registry-bound-owner-lineage-result.v1',
        'status': 'HISTORICAL_CREDENTIAL_LINEAGE_RECONCILED', 'complete': True,
        'historicalCredentialOutputBindingEstablished': True, 'boundedLineageStartsAtFirstControlledGrant': True,
        'boundedTerminalIsCurrentAuthority': False, 'currentOwnerIdentityEstablished': False,
        'currentOwnerAdmissionProven': False, 'historicalAccountingReconciled': False,
        'legacyHistoricalGrantAttempts': None, 'metadataLineage': rows, 'relatedCandidateCount': 3,
        'boundedTerminalRecordOrdinal': 2, 'historicalOwnerAnchorOrdinal': 0,
        'firstGrantReceiptHash': c.digest(first), 'logicalOwnerScopeHash': logical,
        'credentialOutputBindingHash': c.digest(binding)}
    source_paths = source_paths or {name: importlib.import_module(name).__file__ for name in c.SOURCE_FILES}
    source = {name: file_profile(source_paths[name]) for name in c.SOURCE_FILES}
    s = Path(credential_path).stat()
    credential_metadata = [s.st_dev, s.st_ino, s.st_uid, s.st_gid, s.st_mode,
        s.st_nlink, s.st_size, s.st_mtime_ns, s.st_ctime_ns]
    output = Path(binding['output_directory']).stat()
    return {'schema': c.CONTEXT, 'lineageReceipt': receipt, 'predecessorJournalPath': str(predecessor),
        'retainedRecords': retained, 'ownerInputs': {'binding': binding, 'iamProfile': iam_profile,
            'tlsTrustHash': tls_trust_hash, 'credentialPath': str(credential_path), 'credentialMetadata': credential_metadata,
            'outputDirectoryIdentity': {'device': output.st_dev, 'inode': output.st_ino}},
        'recovery': copy.deepcopy(recovery), 'sourceClosureHash': source_closure_hash, 'sourceFiles': source,
        'budget': budget or {'maximumGrantAttempts': 1, 'maximumSeconds': 900,
            'attemptTimeoutSeconds': 30, 'intervalSeconds': 60}}
