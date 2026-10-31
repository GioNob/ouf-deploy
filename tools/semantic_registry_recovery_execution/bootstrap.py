"""Distinct current-boot gate prefix; no policy token or JVM release authority.

The original twelve-stage journal, native lifecycle and full admission owners
are retained. This adapter can dispatch only stages 0..3. Its typed witness
binds a later postboot token owner to the first durably captured generation.
"""
import copy
import json
import os
from pathlib import Path
import re
import time

from .core import Ports, Runner, Store, digest, encoded, generation, initial, require, validate_current, validate_plan
from .authorization import AuthorityScope
from .lifecycle import Lifecycle, engine_type
from .read_budget import ReadBudget, read_scope

KEY = 'semanticRegistryPostbootBootstrap'
PREFIX = ('VERIFY_CURRENT_GATES', 'START_NEW_WAIT_GATE', 'VERIFY_NEW_WAIT_GENERATION', 'PAUSE_NEW_WAIT_GATE')


def profile_type():
    from file_only_profile import FileOnlyProfile
    return FileOnlyProfile


def gateway_type():
    from .gateway import CurrentGateway
    return CurrentGateway


def current_boot():
    return Path('/proc/sys/kernel/random/boot_id').read_text(encoding='ascii').strip()


def bootstrap_scope(plan, request, profile, boot_id):
    validate_plan(plan)
    require(type(profile) is profile_type(), 'ACTUAL_FILE_ONLY_BOOTSTRAP_PROFILE_REQUIRED')
    require(type(boot_id) is str and re.fullmatch('[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}', boot_id),
            'EXACT_CURRENT_BOOT_FOR_BOOTSTRAP_SCOPE_REQUIRED')
    return {'schema': 'ouf.semantic-registry-postboot-bootstrap-scope.v1',
        'planHash': digest(plan), 'logicalOperationRef': plan['logicalOperationRef'],
        'registryId': plan['stages'][0]['intent']['registryId'], 'bootId': boot_id,
        'creationRequestHash': digest(request), 'executionProfileHash': profile.verify(request),
        'stages': list(PREFIX), 'maximumDockerEffectAttempts': 2,
        'handoffCheckpoint': 4, 'javaReleaseAllowed': False, 'tokenGrantAllowed': False,
        'databaseMutationAllowed': False, 'gatewayWritesAllowed': False,
        'oldClaimsRemainConsumed': True, 'automaticReplayAllowed': False, 'budgetReset': False}


class BootstrapGateWitness:
    """Read-only native generation proof, never a signature or owner admission."""
    def __init__(self, lifecycle, profile):
        require(type(lifecycle) is Lifecycle and type(lifecycle.authority) is AuthorityScope
                and type(profile) is profile_type(), 'ACTUAL_BOOTSTRAP_LIFECYCLE_AND_PROFILE_REQUIRED')
        self.lifecycle, self.profile = lifecycle, profile
        require(profile is lifecycle.authority.authority.execution_profile,
                'SAME_SIGNED_BOOTSTRAP_EXECUTION_PROFILE_REQUIRED')
        self.scope = bootstrap_scope(lifecycle.plan, lifecycle.request, profile, current_boot())
        self.guard()

    def guard(self):
        row = self.lifecycle.journal()
        require(bootstrap_scope(self.lifecycle.plan, self.lifecycle.request, self.profile, current_boot()) == self.scope
                and row['bootId'] == self.scope['bootId']
                and json.loads(self.lifecycle.authority.raw).get(KEY) == self.scope,
                'CURRENT_SIGNED_POSTBOOT_BOOTSTRAP_SCOPE_REQUIRED')
        return row

    def _prefix(self, row):
        require(4 <= row['nextStage'] <= 12, 'DURABLE_POSTBOOT_PAUSE_PREFIX_REQUIRED')
        start, pause = row['effects'][1], row['effects'][3]
        require(start['stage'] == PREFIX[1] and pause['stage'] == PREFIX[3]
                and start['state'] == pause['state'] == 'APPLIED'
                and all(e.get('nativeRequestAttempted') is True and e.get('nativeResponse204') is True
                        for e in (start, pause)), 'DURABLE_SEPARATE_POSTBOOT_START_AND_PAUSE_REQUIRED')
        fresh = generation(row['newGeneration'])
        first, started, paused = start.get('nativeFirstProcess'), start['nativeEvidence'], pause['nativeEvidence']
        require(type(first) is dict and first.get('newGeneration') == fresh
                and first.get('processKind') == 'GATE_WAITING' and first.get('paused') is False
                and started.get('newGeneration') == paused.get('newGeneration') == fresh
                and started.get('durableNativeStartEvidence') is True
                and started.get('processKind') == paused.get('processKind') == 'GATE_WAITING'
                and started.get('paused') is False and paused.get('paused') is True
                and first.get('startedAt') == started.get('startedAt') == paused.get('startedAt'),
                'FIRST_DURABLE_POSTBOOT_GENERATION_AND_PAUSE_REQUIRED')
        return fresh, first['startedAt']

    def observe(self, stage='PREGRANT'):
        require(stage in ('PREGRANT', 'ACTIVE'), 'CLOSED_POSTBOOT_GATE_WITNESS_PURPOSE_REQUIRED')
        row = self.guard(); fresh, started_at = self._prefix(row); cursor = row['nextStage']
        if stage == 'PREGRANT':
            require(cursor == 4, 'POSTBOOT_FIRST_GRANT_REQUIRES_PAUSED_CHECKPOINT_FOUR')
        allowed_paused, allowed_kinds = {True}, {'GATE_WAITING'}
        unpause = row['effects'][7] if len(row['effects']) > 7 else None
        release = row['effects'][9] if len(row['effects']) > 9 else None
        release_attempt = release_evidence = None
        if cursor >= 7:
            if unpause is not None and unpause.get('nativeRequestAttempted') is True:
                require(unpause['stage'] == 'UNPAUSE_ATTESTED_GENERATION', 'EXACT_POSTBOOT_UNPAUSE_CLAIM_REQUIRED')
                allowed_paused = {True, False} if cursor == 7 else {False}
            if cursor >= 8:
                require(unpause is not None and unpause['state'] == 'APPLIED'
                        and unpause.get('nativeRequestAttempted') is True
                        and unpause['nativeEvidence'].get('newGeneration') == fresh
                        and unpause['nativeEvidence'].get('processKind') == 'GATE_WAITING'
                        and unpause['nativeEvidence'].get('paused') is False,
                        'COMPLETED_SAME_POSTBOOT_UNPAUSE_REQUIRED')
                allowed_paused = {False}
        if cursor >= 9 and release is not None and release.get('nativeRequestAttempted') is True:
            require(release['stage'] == 'RELEASE_SAME_GENERATION_SIGUSR1'
                    and unpause is not None and unpause['state'] == 'APPLIED',
                    'DURABLE_POSTBOOT_RELEASE_CLAIM_REQUIRED')
            release_attempt = digest({k: release[k] for k in
                ('stage', 'intentHash', 'authorityHash', 'nativeRequestAttempted')})
            allowed_kinds = {'GATE_WAITING', 'APPLICATION_RUNNING'}
            if release['state'] == 'APPLIED':
                require(release['nativeEvidence'].get('newGeneration') == fresh
                        and release['nativeEvidence'].get('processKind') == 'APPLICATION_RUNNING'
                        and release['nativeEvidence'].get('paused') is False,
                        'SAME_POSTBOOT_APPLICATION_RELEASE_PROOF_REQUIRED')
                release_evidence = release['nativeEvidenceHash']
        if cursor >= 10:
            require(release_evidence is not None, 'COMPLETED_POSTBOOT_RELEASE_REQUIRED')
            allowed_kinds = {'APPLICATION_RUNNING'}
        actual = self.lifecycle.inspect(); proof = self.lifecycle.process_evidence(actual)
        require(proof['newGeneration'] == fresh and proof['startedAt'] == started_at
                and proof['paused'] in allowed_paused and proof['processKind'] in allowed_kinds,
                'SAME_FENCED_POSTBOOT_GENERATION_REQUIRED')
        # Re-observe after the process/namespace probe. Never adopt a new PID,
        # endpoint or application that appeared without our durable release.
        binding = self.lifecycle.runtime_binding(actual)
        again = self.lifecycle.inspect()
        require(self.lifecycle.process_evidence(again) == proof
                and self.lifecycle.runtime_binding(again) == binding and self.guard() == row,
                'POSTBOOT_GATE_CHANGED_DURING_OBSERVATION')
        return {'schema': 'ouf.semantic-registry-postboot-gate-witness.v1',
            'recoveryPlanHash': digest(self.lifecycle.plan),
            'recoveryLogicalOperationRef': self.lifecycle.plan['logicalOperationRef'],
            'runtimeGeneration': copy.deepcopy(fresh), 'processKind': proof['processKind'],
            'paused': proof['paused'], 'checkpoint': cursor,
            'durableStartEvidenceHash': row['effects'][1]['nativeEvidenceHash'],
            'durablePauseEvidenceHash': row['effects'][3]['nativeEvidenceHash'],
            'durableReleaseAttemptHash': release_attempt, 'durableReleaseEvidenceHash': release_evidence,
            'runtimeAuthorityIssued': False, 'applicationReadinessProven': False}


class BootstrapPorts(Ports):
    """Only initial read/start/read/pause. Full native owners resume at stage 4."""
    def __init__(self, lifecycle, profile, gateway):
        require(type(lifecycle) is Lifecycle and type(profile) is profile_type()
                and type(gateway) is gateway_type() and gateway.lifecycle is lifecycle,
                'ACTUAL_SAME_BOOTSTRAP_LIFECYCLE_PROFILE_GATEWAY_REQUIRED')
        self.lifecycle, self.profile, self.gateway = lifecycle, profile, gateway
        self.witness = BootstrapGateWitness(lifecycle, profile)

    def guard(self, plan, row, stage):
        require(plan == self.lifecycle.plan and row == self.witness.guard()
                and 0 <= row['nextStage'] < 4 and stage == plan['stages'][row['nextStage']]
                and stage['name'] == PREFIX[row['nextStage']], 'BOOTSTRAP_PREFIX_ONLY_STOP_BEFORE_ADMISSION')
        self.gateway.guard()
        require(self.witness.guard() == row, 'BOOTSTRAP_CHANGED_DURING_GUARD')

    def gates(self):
        row = self.witness.guard(); cursor = row['nextStage']
        attempted = cursor == 1 and len(row['effects']) > 1 and row['effects'][1].get('nativeRequestAttempted') is True
        if cursor < 2 and not attempted:
            route = self.gateway.verify(endpoint_required=False)
        elif cursor >= 2:
            route = self.gateway.verify(endpoint_required=True)
        else:
            # A missing START ACK must be reconciled by Lifecycle; do not
            # pretend the endpoint is still absent or adopt a newly found PID.
            route = {'startOutcomeRequiresReconciliation': True}
        actual = self.lifecycle.inspect()
        status, image = self.lifecycle.engine.request('GET', '/v1.44/images/' + self.lifecycle.request['Image'] + '/json')
        require(status == 200 and type(image) is dict and image.get('Id') == self.lifecycle.request['Image'],
                'CURRENT_IMMUTABLE_BOOTSTRAP_IMAGE_REQUIRED')
        if cursor == 0:
            require(actual['State'] == self.lifecycle.baseline['State']
                    and actual['NetworkSettings'] == self.lifecycle.baseline['NetworkSettings'],
                    'SAME_STOPPED_BOOTSTRAP_BASELINE_REQUIRED')
        require(self.witness.guard() == row, 'BOOTSTRAP_PREREQUISITES_CHANGED')
        return {'currentRoute': route, 'exactImmutableImageObserved': True,
            'completeOciAdmissionProven': False, 'tokenOwnerAdmissionProven': False, 'javaReleaseAllowed': False}

    def apply(self, plan, row, stage):
        self.guard(plan, row, stage)
        require(stage['name'] in (PREFIX[1], PREFIX[3]), 'ONLY_GATE_START_AND_PAUSE_EFFECTS_ALLOWED')
        self.gates(); require(self.lifecycle.journal() == row, 'BOOTSTRAP_CHANGED_BEFORE_NATIVE_EFFECT')
        self.lifecycle.apply(stage)

    def observe(self, plan, row, stage):
        self.guard(plan, row, stage); prerequisites = self.gates(); name = stage['name']
        if name in (PREFIX[1], PREFIX[3]):
            return self.lifecycle.observe(stage)
        if name == PREFIX[0]:
            return 'APPLIED', {'bootstrapPrerequisites': prerequisites, 'sameReviewedRegistryStopped': True,
                               'runtimeAuthorityIssued': False}
        proof = self.lifecycle.process_evidence(self.lifecycle.inspect())
        require(proof['newGeneration'] == row['newGeneration'] and proof['processKind'] == 'GATE_WAITING'
                and proof['paused'] is False, 'SAME_UNRELEASED_BOOTSTRAP_GATE_REQUIRED')
        return 'APPLIED', proof


def installation_scope(context, request, profile, boot_id):
    from .factory import factory_scope
    factory = factory_scope(context)
    return {'schema': 'ouf.semantic-registry-postboot-bootstrap-installation.v1',
        'factoryScopeHash': digest(factory), 'bootstrapScopeHash': digest(bootstrap_scope(context['plan'], request, profile, boot_id)),
        'executionRoot': factory['executionRoot'], 'logicalOperationRef': context['plan']['logicalOperationRef'],
        'operation': 'CREATE_ONE_CURRENT_BOOT_GATE_RECOVERY', 'maximumDirectoryCreates': 2,
        'maximumRuntimeSeconds': 900, 'existingInstallationAdoptionAllowed': False,
        'ownerAdmissionRequiredBeforeGateStart': False, 'ownerAdmissionRequiredBeforeJavaRelease': True,
        'oldClaimsRemainConsumed': True, 'runtimeEffectsAllowed': False, 'budgetReset': False}


def install(context, authority, raw):
    """Create only new canonical finite ledgers; no owner or runtime dispatch."""
    from .factory import current_scope
    from tools.semantic_policy_token_owner.producer import protected_directory
    require(os.geteuid() == os.getegid() == 0, 'ROOT_POSTBOOT_BOOTSTRAP_INSTALLER_REQUIRED')
    _, retained, scoped = current_scope(context, authority, raw)
    profile, request = authority.execution_profile, retained['registryInputs']['creationRequest']
    boot = current_boot(); expected = installation_scope(context, request, profile, boot); signed = json.loads(raw)
    require(signed.get('semanticRegistryPostbootInstallation') == expected
            and signed.get(KEY) == bootstrap_scope(context['plan'], request, profile, boot)
            and signed.get('semanticRegistryRecoveryReads') == read_scope(context['plan'], context['executionRoot']),
            'CURRENT_SIGNED_POSTBOOT_INSTALLATION_AND_READ_SCOPES_REQUIRED')
    wall, mono = time.time(), time.monotonic(); expires = min(wall + 900, signed['expiresAt'])
    require(signed['issuedAt'] <= wall < expires, 'CURRENT_FINITE_POSTBOOT_INSTALLATION_WINDOW_REQUIRED')
    value = initial(context['plan'], authority_hash=scoped.hash, expires_unix=expires,
        expires_monotonic=mono + expires - wall, boot_id=boot,
        predecessor_history_hash=authority.expected['predecessorHistoryHash'], created_unix=wall, created_monotonic=mono)
    scoped.guard(value); root = Path(context['executionRoot'])
    with protected_directory(root.parent) as parent:
        parent_info = os.fstat(parent)
        pin = lambda s: (s.st_dev, s.st_ino, s.st_uid, s.st_gid, s.st_mode)
        require(current_boot() == boot and authority(raw) is True
                and installation_scope(context, request, profile, boot) == expected,
                'POSTBOOT_INSTALLATION_SCOPE_CHANGED')
        os.mkdir(root.name, 0o700, dir_fd=parent); os.fsync(parent)
        fd = os.open(root.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
        try:
            os.mkdir('node', 0o700, dir_fd=fd); os.fsync(fd)
            store = Store(root, context['plan']['logicalOperationRef']); store.initialize(value)
            ReadBudget.initialize(store, scoped, context['plan'])
            scoped.guard(store.read()); validate_current(context['plan'], store.read(), current_boot(), (time.time(), time.monotonic()))
            _, checked_retained, checked_scope = current_scope(context, authority, raw)
            require(checked_retained == retained and checked_scope.hash == scoped.hash and current_boot() == boot,
                    'POSTBOOT_INSTALLATION_RETAINED_CONTEXT_CHANGED')
            info = os.fstat(fd)
            require(pin(info) == pin(root.lstat()) == pin(os.stat(root.name, dir_fd=parent, follow_symlinks=False))
                    and pin(parent_info) == pin(os.fstat(parent)) == pin(root.parent.lstat())
                    and installation_scope(context, request, profile, boot) == expected,
                    'POSTBOOT_INSTALLATION_DIRECTORY_CHANGED')
            receipt = {'schema': 'ouf.semantic-registry-postboot-bootstrap-installation-receipt.v1',
                'installationScopeHash': digest(expected), 'contextHash': digest(context), 'authorityHash': scoped.hash,
                'directoryIdentity': {'device': info.st_dev, 'inode': info.st_ino}, 'initialJournalHash': digest(value),
                'bootId': boot, 'expiresUnix': expires, 'runtimeEffectsDispatched': 0, 'tokenGrantAttempts': 0,
                'authorityIssuedByInstaller': False, 'automaticReplayAllowed': False, 'budgetReset': False}
            output = os.open('bootstrap-installation.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
            try:
                with os.fdopen(os.dup(output), 'wb') as stream:
                    stream.write(encoded(receipt)); stream.flush(); os.fsync(stream.fileno())
                os.fsync(output); os.fsync(fd)
            finally:
                os.close(output)
            return receipt
        finally:
            os.close(fd)


def build(context, authority, raw):
    """Reconstruct the gate adapter on existing ledgers; never initialize them."""
    from .factory import current_scope
    _, retained, scoped = current_scope(context, authority, raw)
    plan = context['plan']; request = retained['registryInputs']['creationRequest']; profile = authority.execution_profile
    store = Store(context['executionRoot'], plan['logicalOperationRef']); budget = ReadBudget(store, scoped, plan)
    binding = context['engineBinding']
    require(set(binding) == {'socketPath', 'socketBinding'}, 'EXACT_CURRENT_BOOTSTRAP_ENGINE_BINDING_REQUIRED')
    engine = engine_type()(binding['socketPath'], tuple(binding['socketBinding']))
    lifecycle = Lifecycle(engine, scoped, store, plan, request, context['stoppedSnapshot'], retained['proposal'])
    gw = context['gateway']
    require(set(gw) == {'pin', 'profile', 'routes', 'networkId'}, 'EXACT_CURRENT_BOOTSTRAP_GATEWAY_CONTEXT_REQUIRED')
    gateway = gateway_type()(lifecycle, gw['pin'], gw['profile'], gw['routes'], gw['networkId'], budget)
    ports = BootstrapPorts(lifecycle, profile, gateway)
    return Runner(plan, store, ports, boot_id=current_boot())
