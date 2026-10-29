"""One signed handoff from exact cancelled lineage into a new current-boot owner.

The old journal and first-grant receipt are never changed. A globally shared
predecessor-fence claim is consumed before any new-directory/fence mutation;
partial installation is retained, never adopted or automatically resumed.
"""
import hashlib
import json
import os
from pathlib import Path
import time

from .contract import compile_scope, initial_record, digest, encoded, require
from .owner import authority_guard, source_guard, retained_guard, credential_custody, configuration
from tools.semantic_lease_recovery.recovery_journal import Journal
from tools.semantic_policy_token_owner.producer import protected_directory
from tools.semantic_policy_token_owner.installed_owner import LegacyWriterFence, read_private, unique


def publish_once(directory, name, value):
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600, dir_fd=directory)
    try:
        raw = encoded(value); position = 0
        while position < len(raw):
            count = os.write(fd, raw[position:]); require(count > 0, 'POSTBOOT_PRIVATE_WRITE_UNPROVEN'); position += count
        os.fsync(fd); os.fsync(directory)
    finally:
        os.close(fd)


def install(context, authority, raw, gate_witness, *, clock=lambda: (time.time(), time.monotonic())):
    require(os.geteuid() == os.getegid() == 0, 'ROOT_POSTBOOT_OWNER_INSTALLER_REQUIRED')
    scope = authority_guard(context, authority, raw, gate_witness)
    source_guard(context); retained_guard(context); credential_custody(context); LegacyWriterFence().guard()
    initial_proof = gate_witness.observe(stage='PREGRANT')
    previous = scope['predecessorFenceBinding']; following = scope['fenceBinding']
    fence_path = Path(following['path']); root = Path(scope['journalPath'])
    predecessor = Journal(scope['predecessorJournalPath'])
    require(root.parent == predecessor.root.parent == fence_path.parent,
            'ONE_CANONICAL_POSTBOOT_PARENT_REQUIRED')
    # The exact pre-existing invocation lock also serializes other legacy or
    # governed handoffs of this predecessor. Its successor claim name matches
    # their protocol, so different profiles cannot each claim the same parent.
    with predecessor.invocation(), protected_directory(root.parent) as parent:
        retained_guard(context)
        old = read_private(parent, fence_path.name, 16384)
        require(json.loads(old, object_pairs_hook=unique) == previous['value'], 'POSTBOOT_PREDECESSOR_FENCE_CHANGED')
        require(not os.path.lexists(root), 'POSTBOOT_EXISTING_INSTALLATION_REQUIRES_RECONCILIATION')
        authority_guard(context, authority, raw, gate_witness)
        require(gate_witness.observe(stage='PREGRANT') == initial_proof, 'POSTBOOT_GATE_CHANGED_BEFORE_INSTALLATION')
        claim_name = fence_path.name + '.successor-' + digest(previous['value']) + '.claim.json'
        claim = {'schema': 'ouf.semantic-registry-postboot-owner-installation-claim.v1',
            'authorityHash': hashlib.sha256(raw).hexdigest(), 'scopeHash': digest(scope),
            'contextHash': scope['contextHash'], 'predecessor': previous, 'successor': following,
            'initialGateWitnessHash': digest(initial_proof), 'budgetReset': False, 'automaticReplayAllowed': False}
        publish_once(parent, claim_name, claim)
        # Every following failure leaves the claim consumed. Never remove it or
        # rewrite/initialize an existing worker directory as error recovery.
        os.mkdir(root.name, 0o700, dir_fd=parent); os.fsync(parent)
        journal = Journal(root)
        wall, mono = clock(); signed = json.loads(raw, object_pairs_hook=unique)
        require(signed['issuedAt'] <= wall < signed['expiresAt'], 'CURRENT_POSTBOOT_INSTALLATION_WINDOW_REQUIRED')
        row = initial_record(context, initial_proof, wall, mono)
        profile_hash = digest(configuration(context, journal))
        receipt = {'schema': 'ouf.semantic-registry-postboot-owner-installation.v1',
            'contextHash': scope['contextHash'], 'scopeHash': digest(scope), 'authorityHash': hashlib.sha256(raw).hexdigest(),
            'journalDirectoryIdentity': list(journal.directory_id), 'initialGateWitnessHash': digest(initial_proof),
            'firstGrantReceiptHash': scope['firstGrantReceiptHash'], 'predecessorGrantAttempts': scope['predecessorGrantAttempts'],
            'currentSessionBootId': scope['currentSessionBootId'], 'retainedFirstGrantBootId': scope['retainedFirstGrantBootId'],
            'runtimeAuthorityIssued': False, 'oauthRequests': 0, 'budgetReset': False}
        with protected_directory(root) as directory:
            publish_once(directory, 'owner-session.json', scope)
            publish_once(directory, 'owner-first-grant.json', context['retainedRecords']['owner-first-grant.json'])
            publish_once(directory, 'owner-admission.json', {'schema': 'ouf.policy-token-owner-admission.v1',
                'ownerProfileHash': profile_hash, 'contextRef': scope['contextRef'], 'generationRef': scope['generationRef'],
                'version': 0, 'state': 'BLOCKED', 'tokenHash': None, 'blockedAttempt': None})
            publish_once(directory, 'installation.json', receipt)
        journal.initialize(row)
        authority_guard(context, authority, raw, gate_witness); source_guard(context); retained_guard(context)
        require(gate_witness.observe(stage='PREGRANT') == initial_proof
                and read_private(parent, fence_path.name, 16384) == old,
                'POSTBOOT_GATE_OR_GLOBAL_FENCE_CHANGED_BEFORE_HANDOFF')
        temporary = fence_path.name + '.postboot-' + digest(following['value'])
        publish_once(parent, temporary, following['value'])
        authority_guard(context, authority, raw, gate_witness)
        require(read_private(parent, fence_path.name, 16384) == old, 'POSTBOOT_FENCE_CHANGED_AT_HANDOFF')
        os.replace(temporary, fence_path.name, src_dir_fd=parent, dst_dir_fd=parent); os.fsync(parent)
        require(json.loads(read_private(parent, fence_path.name, 16384), object_pairs_hook=unique) == following['value']
                and journal.read() == row, 'POSTBOOT_INSTALLATION_READBACK_UNPROVEN')
        retained_guard(context)
        return receipt
