"""Actual current-boot SERVICE credential owner; no historical-owner adoption."""
import copy
import dataclasses
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import sys
import time

from .contract import (SCOPE, RECORDS, SOURCE_FILES, HISTORY, PROFILE, LEGACY,
                       compile_scope, digest, require)
from tools.semantic_registry_recovery_execution.authorization import cutover_type
from tools.semantic_registry_recovery_execution.bootstrap import BootstrapGateWitness
from tools.semantic_lease_recovery.bounded_recovery import Policy, Permanent
from tools.semantic_lease_recovery.recovery_journal import Journal
from tools.semantic_policy_token_owner.producer import (DomainOwner, Binding, CredentialFile,
    HttpsGrant, TokenRenewalAdapter, protected_directory)
from tools.semantic_policy_token_owner.iam_admission import IamProfile, PinnedIamOpener, OnlineIamAdmission
from tools.semantic_policy_token_owner.installed_owner import AdmissionStore, LegacyWriterFence, read_private, unique
from tools.ingestion_readiness_patch_execution import private_file


def boot_identity():
    return Path('/proc/sys/kernel/random/boot_id').read_text().strip()


def authority_guard(context, authority, raw, gate_witness):
    scope = compile_scope(context)
    require(type(authority) is cutover_type() and type(raw) is bytes
            and type(gate_witness) is BootstrapGateWitness
            and gate_witness.lifecycle.authority.authority is authority
            and gate_witness.lifecycle.authority.raw == raw
            and authority.expected['sourceClosureHash'] == scope['sourceClosureHash']
            and authority(raw) is True and json.loads(raw, object_pairs_hook=unique).get(SCOPE) == scope
            and scope['currentSessionBootId'] == boot_identity(), 'CURRENT_EXACT_POSTBOOT_OWNER_AUTHORITY_REQUIRED')
    return scope


def source_guard(context):
    for name in sorted(SOURCE_FILES):
        binding = context['sourceFiles'][name]
        require(binding['metadata'][2:4] == [0, 0]
                and all(item['identity'][2] == 0 for item in binding['ancestors']),
                'ROOT_CONTROLLED_POSTBOOT_EXECUTING_SOURCE_REQUIRED')
        with private_file.opened(binding, maximum=131072):
            module = sys.modules.get(name)
            require(module is not None, 'POSTBOOT_EXECUTING_SOURCE_NOT_PRELOADED')
            qualified = getattr(module, '__qualified_source_sha256__', None)
            if qualified is None:
                require(getattr(module, '__file__', None) is not None
                        and str(Path(module.__file__).resolve()) == binding['path'],
                        'POSTBOOT_LOADED_MODULE_SOURCE_IDENTITY_REQUIRED')
            else:
                require(qualified == binding['sha256'], 'POSTBOOT_LOADED_CAPSULE_SOURCE_HASH_CHANGED')


def retained_guard(context):
    with protected_directory(context['predecessorJournalPath']) as directory:
        for name in RECORDS:
            raw = read_private(directory, name, 131072)
            require(hashlib.sha256(raw).hexdigest() == digest(context['retainedRecords'][name]),
                    'POSTBOOT_RETAINED_PREDECESSOR_CHANGED')


def credential_custody(context):
    owner = context['ownerInputs']; path = Path(owner['credentialPath'])
    with protected_directory(path.parent) as directory:
        info = os.stat(path.name, dir_fd=directory, follow_symlinks=False)
        require(private_file.metadata(info) == owner['credentialMetadata']
                and stat.S_ISREG(info.st_mode) and info.st_uid == info.st_gid == 0
                and stat.S_IMODE(info.st_mode) == 0o400 and info.st_nlink == 1 and 0 < info.st_size <= 4096,
                'EXACT_EXISTING_POSTBOOT_CREDENTIAL_CUSTODY_REQUIRED')
    binding = owner['binding']
    with protected_directory(binding['output_directory'], gid=binding['output_gid'], mode=0o750) as directory:
        info = os.fstat(directory)
        require(owner['outputDirectoryIdentity'] == {'device': info.st_dev, 'inode': info.st_ino},
                'RETAINED_POSTBOOT_TOKEN_OUTPUT_DIRECTORY_CHANGED')


def configuration(context, journal):
    scope = compile_scope(context)
    return {'schema': 'ouf.semantic-registry-postboot-owner-binding.v1', 'contextHash': scope['contextHash'],
        'workerSessionHash': digest(scope), 'ownerInputsHash': scope['ownerInputsHash'],
        'journalPath': str(journal.root), 'journalDirectoryIdentity': list(journal.directory_id),
        'contextRef': scope['contextRef'], 'generationRef': scope['generationRef'],
        'sourceClosureHash': scope['sourceClosureHash'], 'currentSessionBootId': scope['currentSessionBootId']}


def invocation_held(journal):
    """The coordinating process must hold this exact worker lifetime flock."""
    with protected_directory(journal.root) as directory:
        info = os.stat('invocation.lock', dir_fd=directory, follow_symlinks=False)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == info.st_gid == 0
                and stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1,
                'POSTBOOT_INVOCATION_LOCK_CUSTODY_REQUIRED')
        key = (os.major(info.st_dev), os.minor(info.st_dev), info.st_ino)
        fd = os.open('/proc/locks', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            raw = os.read(fd, 2097153)
        finally:
            os.close(fd)
        require(len(raw) <= 2097152, 'BOUNDED_POSTBOOT_INVOCATION_LOCK_OBSERVATION_REQUIRED')
        matches = []
        for line in raw.decode('ascii').splitlines():
            fields = line.split()
            if len(fields) != 8 or fields[1:4] != ['FLOCK', 'ADVISORY', 'WRITE']:
                continue
            match = re.fullmatch('([0-9a-fA-F]+):([0-9a-fA-F]+):([0-9]+)', fields[5])
            if match and (int(match[1], 16), int(match[2], 16), int(match[3])) == key:
                matches.append(fields[4:5] + fields[6:8])
        require(matches == [[str(os.getpid()), '0', 'EOF']], 'LIVE_SAME_PROCESS_POSTBOOT_WORKER_INVOCATION_REQUIRED')


class PostbootTokenOwner(DomainOwner):
    def __init__(self, context, authority, raw, gate_witness, *, observer=False,
                 clock=lambda: (time.time(), time.monotonic()), transport=None):
        require(type(observer) is bool, 'EXPLICIT_POSTBOOT_OBSERVER_KIND_REQUIRED')
        self.inputs = copy.deepcopy(context)
        self.scope = authority_guard(context, authority, raw, gate_witness)
        self.authority, self.raw, self.gate_witness, self.observer = authority, bytes(raw), gate_witness, observer
        self.clock = clock
        source_guard(context); retained_guard(context); credential_custody(context)
        self.journal = Journal(self.scope['journalPath'])
        self.configuration = configuration(context, self.journal)
        self.profile_hash = digest(self.configuration)
        self.context, self.generation = self.scope['contextRef'], self.scope['generationRef']
        inputs = context['ownerInputs']
        self.binding = Binding(**inputs['binding']); profile = copy.deepcopy(inputs['iamProfile'])
        for name in ('required_scopes', 'allowed_scopes', 'peer_addresses'):
            profile[name] = tuple(profile[name])
        self.profile = IamProfile(**profile); self.profile.match(self.binding)
        self.credential = CredentialFile(Path(inputs['credentialPath']))
        self.transport = PinnedIamOpener(self.profile, clock) if transport is None else transport
        require(type(self.transport) is PinnedIamOpener and self.transport.profile == self.profile
                and self.transport.trust_digest() == inputs['tlsTrustHash'], 'EXACT_CURRENT_POSTBOOT_IAM_TRUST_REQUIRED')
        self.admission = OnlineIamAdmission(self.profile, self.credential, self.transport, clock)
        self.store = AdmissionStore(self.journal, self.profile_hash, self.context, self.generation)
        self.fence = LegacyWriterFence()

    def _verified(self, binding_hash):
        require(binding_hash == self.binding.digest() and authority_guard(self.inputs, self.authority, self.raw,
                self.gate_witness) == self.scope and configuration(self.inputs, self.journal) == self.configuration,
                'POSTBOOT_OWNER_BINDING_CHANGED')
        source_guard(self.inputs); retained_guard(self.inputs); credential_custody(self.inputs)
        self.fence.guard(); invocation_held(self.journal)
        row = self.journal.read(); marker = self.store.read(); scope = self.scope
        require(row.get('contextRef') == self.context and row.get('generationRef') == self.generation
                and row.get('workerSessionHash') == digest(scope) and row.get('policyHash') == digest(scope['policy'])
                and row.get('controlledHistoryProfile') == HISTORY and row.get('renewalProfile') == PROFILE
                and row.get('bootId') == boot_identity() == scope['currentSessionBootId']
                and row.get('retainedFirstGrantBootId') == scope['retainedFirstGrantBootId']
                and row.get('firstGrantReceiptHash') == scope['firstGrantReceiptHash']
                and row.get('legacyHistory') == LEGACY and type(row.get('attempts')) is int
                and 0 <= row['attempts'] <= scope['policy']['max_attempts']
                and row.get('controlledPredecessorGrantAttempts') == scope['predecessorGrantAttempts']
                and row.get('controlledCumulativeGrantAttempts') == scope['predecessorGrantAttempts'] + row['attempts']
                and row['controlledCumulativeGrantAttempts'] <= scope['maximumCumulativeGrantAttempts'],
                'CURRENT_POSTBOOT_SESSION_AND_RETAINED_ACCOUNTING_REQUIRED')
        with protected_directory(self.journal.root) as directory:
            require(json.loads(read_private(directory, 'owner-session.json', 131072), object_pairs_hook=unique) == scope
                    and hashlib.sha256(read_private(directory, 'owner-first-grant.json', 16384)).hexdigest()
                        == scope['firstGrantReceiptHash'], 'POSTBOOT_IMMUTABLE_SESSION_OR_FIRST_GRANT_CHANGED')
            installation = json.loads(read_private(directory, 'installation.json', 16384), object_pairs_hook=unique)
            require(installation.get('contextHash') == scope['contextHash']
                    and installation.get('authorityHash') == hashlib.sha256(self.raw).hexdigest()
                    and installation.get('journalDirectoryIdentity') == list(self.journal.directory_id)
                    and installation.get('initialGateWitnessHash') == row['initialGateWitnessHash'],
                    'POSTBOOT_INSTALLATION_CUSTODY_CHANGED')
        fence = scope['fenceBinding']; named = Path(fence['path'])
        with protected_directory(named.parent) as directory:
            require(json.loads(read_private(directory, named.name, 16384), object_pairs_hook=unique) == fence['value'],
                    'POSTBOOT_GLOBAL_OWNER_FENCE_CHANGED')
        wall, mono = self.clock()
        require(all(type(v) in (int, float) and math.isfinite(v) for v in
                (wall, mono, row['startedWall'], row['startedMonotonic'], row['lastWall'], row['lastMonotonic'])),
                'FINITE_POSTBOOT_OWNER_CLOCKS_REQUIRED')
        if not (row['startedWall'] <= row['lastWall'] <= wall and row['startedMonotonic'] <= row['lastMonotonic'] <= mono):
            raise Permanent('INTEGRITY_UNPROVEN')
        if min(scope['policy']['max_elapsed'] - (wall-row['startedWall']),
               scope['policy']['max_elapsed'] - (mono-row['startedMonotonic'])) <= 0:
            raise Permanent('AUTHORITY_EXPIRED')
        if row['state'] in ('BLOCKED', 'CANCELLED', 'PAUSED_EXHAUSTED', 'RECONCILE_REQUIRED'):
            raise Permanent('AUTHORITY_REVOKED')
        proof = self.gate_witness.observe(stage='ACTIVE')
        require(proof['runtimeGeneration'] == row['gateGeneration'], 'POSTBOOT_GATE_GENERATION_CHANGED')
        return row, marker

    def guard(self, binding_hash):
        row, marker = self._verified(binding_hash)
        if self.observer and (row['state'] != 'ACTIVE' or marker['state'] != 'ACTIVE'):
            raise Permanent('AUTHORITY_REVOKED')

    def prepare(self, binding_hash, deadline):
        require(not self.observer, 'POSTBOOT_OBSERVER_CANNOT_ACQUIRE_TOKEN')
        row, _ = self._verified(binding_hash)
        proof = self.gate_witness.observe(stage='PREGRANT' if row['publicationCount'] == 0 else 'ACTIVE')
        require(proof['runtimeGeneration'] == row['gateGeneration'], 'POSTBOOT_GRANT_GATE_GENERATION_CHANGED')
        self.admission.prepare(deadline); self.guard(binding_hash)

    def admit(self, token, valid_until_monotonic, binding_hash, deadline):
        row, before = self._verified(binding_hash)
        require(row['state'] == ('ACTIVE' if self.observer else 'PUBLISHING'), 'POSTBOOT_PUBLICATION_STATE_REQUIRED')
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        if self.observer:
            require(before['tokenHash'] == token_hash, 'EXACT_CURRENT_POSTBOOT_PUBLISHED_TOKEN_REQUIRED')
        elif row['publicationCount'] == 0:
            require(self.gate_witness.observe(stage='PREGRANT')['runtimeGeneration'] == row['gateGeneration'],
                    'POSTBOOT_FIRST_PUBLICATION_STILL_PAUSED_REQUIRED')
        self.admission.admit(token, valid_until_monotonic, deadline); self.guard(binding_hash)
        if self.observer:
            require(self.store.read() == before, 'POSTBOOT_ADMISSION_CHANGED_DURING_READ')
        elif before['state'] != 'ACTIVE' or before['tokenHash'] != token_hash:
            self.store.save(before, 'ACTIVE', token_hash)
        return True

    def lease(self, minimum_remaining=None):
        require(self.observer, 'POSTBOOT_READ_ONLY_OBSERVER_REQUIRED')
        row, marker = self._verified(self.binding.digest())
        required = self.binding.minimum_remaining if minimum_remaining is None else max(self.binding.minimum_remaining, minimum_remaining)
        wall, mono = self.clock()
        require(type(required) is int and 1 <= required <= 3600 and row['state'] == marker['state'] == 'ACTIVE'
                and all(type(row.get(k)) in (int, float) and math.isfinite(row[k]) for k in ('tokenExpiresWall', 'tokenExpiresMonotonic'))
                and min(row['tokenExpiresWall']-wall, row['tokenExpiresMonotonic']-mono) >= required,
                'CURRENT_POSTBOOT_ACTIVE_TOKEN_WINDOW_REQUIRED')
        self.guard(self.binding.digest())
        require(self.journal.read() == row and self.store.read() == marker, 'POSTBOOT_LEASE_CHANGED')
        return {'schema': 'ouf.semantic-registry-postboot-token-lease.v1', 'currentBootAndTokenWindowObserved': True,
                'minimumRemainingSeconds': required, 'onlineIssuerAdmissionPerformed': False, 'tokenAcquisitionAllowed': False,
                'controlledCumulativeGrantAttempts': row['controlledCumulativeGrantAttempts']}

    def admit_mounted(self, token, minimum_remaining, binding_hash, deadline):
        self.lease(minimum_remaining)
        row, marker = self._verified(binding_hash); wall, mono = self.clock()
        require(type(deadline) in (int, float) and math.isfinite(deadline) and mono < deadline <= mono+30,
                'FINITE_POSTBOOT_MOUNT_ADMISSION_DEADLINE_REQUIRED')
        valid_until = min(row['tokenExpiresMonotonic'], mono+row['tokenExpiresWall']-wall)
        self.admit(token, valid_until, binding_hash, deadline)
        self.lease(minimum_remaining)
        require(self.journal.read() == row and self.store.read() == marker, 'POSTBOOT_MOUNT_ADMISSION_CHANGED')
        return True

    def pause(self):
        if not self.observer:
            row = self.journal.read(); before = self.store.read()
            require(row['contextRef'] == self.context and row['generationRef'] == self.generation,
                    'ONLY_OWN_POSTBOOT_GENERATION_MAY_BE_REVOKED')
            if before['state'] != 'BLOCKED' or before['tokenHash'] is not None or before['blockedAttempt'] != row['attempts']:
                self.store.save(before, 'BLOCKED', blocked_attempt=row['attempts'])


def build_worker(context, authority, raw, gate_witness, *, clock=lambda: (time.time(), time.monotonic()), transport=None):
    from .scheduler import PostbootScheduledRecovery, PostbootRenewalWorker
    owner = PostbootTokenOwner(context, authority, raw, gate_witness, clock=clock, transport=transport)
    value = copy.deepcopy(owner.scope['policy']); value['delays'] = tuple(value['delays']); policy = Policy(**value)
    adapter = TokenRenewalAdapter(owner.binding, owner.credential, owner, HttpsGrant(clock, opener=owner.transport), clock)
    recovery = PostbootScheduledRecovery(owner.journal, adapter, policy, owner.context, owner.generation,
        clock, __import__('random').SystemRandom().random, interval_seconds=owner.scope['intervalSeconds'])
    return PostbootRenewalWorker(recovery)


def build_observer(context, authority, raw, gate_witness, *, clock=lambda: (time.time(), time.monotonic()), transport=None):
    owner = PostbootTokenOwner(context, authority, raw, gate_witness, observer=True, clock=clock, transport=transport)
    owner.lease()
    return owner
