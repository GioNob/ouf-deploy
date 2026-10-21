"""Preserve the complete retained host intent while declaring a replacement.

This compiler produces private review evidence. It does not create an OCI bundle,
invoke Docker, acquire the lease lock, read secret files or grant transition authority.
"""
import copy
import hashlib
import json
import os
import re
import sys
import tempfile
import types
from pathlib import Path

CUSTODY_HASH = 'cb9ff64684243d563da79d327eb7d7e325dbea6a3922c91a0b7791a3ceec9baf'
INTAKE = Path('/etc/ouf/deploy-snapshots/semantic-discovery-protected-bindings-qb3381ho/private-protected-bindings.json')
INTAKE_HASH = '6521033c3c9c1c5dd0963d630e3748003b20e9d6a8a0f71fcc23e92471e5b358'
CONTRACT = Path('/etc/ouf/deploy-snapshots/semantic-discovery-application-contract-y4k46mc9/private-application-input-contract.json')
CONTRACT_HASH = '3883a3d2e2a6a4be044b91254092ff77a9b077e0aa0e94f6c1109fb29629b89c'
IMAGE = 'sha256:b1a7956a673f88b5ee65d174c2eda7b9e448153e101348c06fdd53c0640e700b'


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def digest(value):
    return hashlib.sha256(encoded(value)).hexdigest()


def exact_path(value):
    require(type(value) is str and value.startswith('/') and ':' not in value
            and '\n' not in value and '\r' not in value and '\x00' not in value
            and '..' not in Path(value).parts, 'EXACT_MOUNT_PATH_REQUIRED')
    return str(Path(value))


def compile_declaration(intake, contract):
    require(contract.get('schema') == 'ouf.discovery.private-application-input-contract.v1'
            and contract.get('protectedIntakeHash') == INTAKE_HASH
            and contract.get('productionApplyReady') is False
            and contract.get('applicationCutoverAuthorized') is False
            and contract.get('completeReplacementOciProven') is False,
            'EXACT_UNAPPLIED_APPLICATION_CONTRACT_REQUIRED')
    draft = intake['replacementConfigurationDraft']
    require(intake.get('productionApplyReady') is False and draft.get('applyAuthorized') is False,
            'UNAPPLIED_PROTECTED_INTAKE_REQUIRED')
    for key, other in [('candidateConfig', 'candidateConfig'),
                       ('retainedConsultationMounts', 'retainedAuthMounts')]:
        require(contract[key] == draft[other], 'APPLICATION_CONTRACT_DRAFT_DRIFT')
    require(contract['candidateConfig'].get('User') == '10001:10001',
            'EXACT_NON_ROOT_CANDIDATE_USER_REQUIRED')
    require(contract['originalProviderBinding'] == intake['originalProviderBinding']
            and contract['runtimeInputManifest'] == intake['runtimeInputManifest'],
            'APPLICATION_CONTRACT_INTAKE_DRIFT')
    original = copy.deepcopy(draft['retainedContainer'])
    require(original['State']['Running'] is True and original['State']['Pid'] > 0
            and all(key in original for key in ('Id', 'Image', 'Config', 'HostConfig', 'Mounts')),
            'RETAINED_NATIVE_CREATION_FRAME_REQUIRED')
    networks = original['NetworkSettings']['Networks']
    require(type(networks) is dict and bool(networks), 'COMPLETE_RETAINED_NETWORK_INTENT_REQUIRED')
    mounts = contract['roleOwnedReadOnlyMounts']
    require(len(mounts) == 3 and len(draft['newReadOnlyMounts']) == 3,
            'EXACT_THREE_ROLE_MOUNTS_REQUIRED')
    targets = {exact_path(m['Destination']) for m in original['Mounts']}
    require(len(targets) == len(original['Mounts']), 'DISTINCT_RETAINED_MOUNTS_REQUIRED')
    host = copy.deepcopy(original['HostConfig'])
    require(host.get('Privileged') is False and not host.get('ContainerIDFile')
            and host.get('NetworkMode') not in ('host', 'none')
            and not str(host.get('NetworkMode', '')).startswith('container:'),
            'SHARED_BRIDGE_REPLACEMENT_HOST_SCOPE_REQUIRED')
    binds = host.get('Binds')
    require(binds is None or type(binds) is list, 'EXACT_RETAINED_BIND_DECLARATIONS_REQUIRED')
    additions = []
    for mount, reviewed in zip(mounts, draft['newReadOnlyMounts']):
        require(all(mount.get(k) == reviewed.get(k) for k in ('source', 'target', 'uid', 'gid', 'mode', 'readOnly'))
                and mount['readOnly'] is True and mount['uid'] == mount['gid'] == 10001
                and mount['mode'] == 0o400 and re.fullmatch('[a-f0-9]{64}', mount['sha256'])
                and mount['secretBytesFreshlyVerified'] is False,
                'EXACT_UNMOUNTED_ROLE_INPUT_REQUIRED')
        source, target = exact_path(mount['source']), exact_path(mount['target'])
        require(target not in targets, 'REPLACEMENT_MOUNT_TARGET_CONFLICT')
        require(not any(target.startswith(v.rstrip('/') + '/') or v.startswith(target.rstrip('/') + '/')
                        for v in targets), 'REPLACEMENT_MOUNT_SHADOWING_DENIED')
        targets.add(target)
        additions.append(source + ':' + target + ':ro')
    host['Binds'] = list(binds or []) + additions
    # The original frame is retained in full; no defaults or resource limits vanish.
    declaration = {
        'schema': 'ouf.discovery.private-replacement-runtime-declaration.v1',
        'inputBindings': {'protectedIntakeHash': INTAKE_HASH, 'applicationContractHash': CONTRACT_HASH},
        'candidateImageId': IMAGE,
        'candidateConfig': copy.deepcopy(contract['candidateConfig']),
        'proposedHostConfig': host,
        'retainedNativeCreationFrame': original,
        'retainedNetworkObservations': copy.deepcopy(networks),
        'roleOwnedReadOnlyMounts': copy.deepcopy(mounts),
        'hostDelta': {'field': 'Binds', 'appendedReadOnlyBinds': additions},
        'requiredBeforeMutation': [
            'FRESH_NATIVE_HOST_AND_IMAGE_AND_RECIPROCAL_PEER_CLOSURE',
            'EXACT_NEW_SIGNED_TRANSPORT_AND_DRIVER_AND_PROFILE_CLOSURE',
            'EXPLICIT_COORDINATED_TRANSITION_AUTHORITY_NO_R9_REPLAY',
            'DATABASE_FENCE_AND_FRESH_BACKUP_AND_MIGRATION_AWARE_RECOVERY',
            'PRIVATE_SOURCE_BYTES_AND_ROLE_METADATA_REVERIFIED',
            'HOST_READINESS_AND_RETAINED_ORIGINAL_RECOVERY_GENERATION'],
        'requiredBeforeAcceptance': [
            'REALIZED_COMPLETE_OCI_AND_RECIPROCAL_PEER_VERIFIED',
            'IAM_ENFORCED_APPLICATION_AND_PROVIDER_HEALTH',
            'FILE_ONBOARDING_ENRICHMENT_DURABLE_INGESTION_UDP_SEARCH_PROVEN'],
        'observationsAreHistorical': True,
        'secretBytesFreshlyVerified': False,
        'completeReplacementOciProven': False,
        'applicationCutoverAuthorized': False,
        'productionApplyReady': False,
    }
    public = {
        'candidateImageId': IMAGE,
        'retainedCreationFrameHash': digest(original),
        'proposedHostConfigHash': digest(host),
        'retainedNetworkObservationHash': digest(networks),
        'hostFieldsPreservedExceptDeclaredBindAppend': all(host[k] == v for k, v in original['HostConfig'].items() if k != 'Binds'),
        'retainedMountCount': len(original['Mounts']),
        'roleOwnedReadOnlyMountCount': len(mounts),
        'networkCount': len(networks),
        'observationsAreHistorical': True,
        'completeReplacementOciProven': False,
        'productionApplyReady': False,
        'applicationCutoverAuthorized': False,
    }
    return declaration, public


def main():
    report = dict(schema='ouf.discovery.replacement-runtime-declaration.v1',
                  commonLockAcquired=False, r9Touched=False, containerLifecycleOperations=0,
                  credentialFilesOpened=0, privateKeyFilesOpened=0, privateValuesPrinted=False,
                  existingConfigurationWrites=0, databaseWrites=0, firewallWrites=0,
                  dnsQueries=0, iamRequests=0, providerCalls=0, imageImports=0,
                  signaturesIssued=0, mountsInstalled=False, readOnlyRetrySafe=True,
                  notReleaseAcceptance=True)
    try:
        require(os.geteuid() == 0 and sys.flags.isolated and sys.dont_write_bytecode and len(sys.argv) == 1,
                'ISOLATED_ROOT_DECLARATION_COMPILATION_REQUIRED')
        source = globals().get('__custody_source__')
        require(type(source) is bytes and hashlib.sha256(source).hexdigest() == CUSTODY_HASH,
                'SEALED_CUSTODY_SOURCE_REQUIRED')
        custody = types.ModuleType('custody')
        exec(compile(source, 'sealed-custody', 'exec'), custody.__dict__)
        raw_intake = custody.file_bytes(INTAKE, 0, {0o600}, expected=INTAKE_HASH)
        raw_contract = custody.file_bytes(CONTRACT, 0, {0o600}, expected=CONTRACT_HASH)
        private, public = compile_declaration(json.loads(raw_intake), json.loads(raw_contract))
        require(custody.file_bytes(INTAKE, 0, {0o600}, expected=INTAKE_HASH) == raw_intake
                and custody.file_bytes(CONTRACT, 0, {0o600}, expected=CONTRACT_HASH) == raw_contract,
                'DECLARATION_INPUT_CHANGED_DURING_COMPILATION')
        directory = Path(tempfile.mkdtemp(prefix='semantic-discovery-runtime-declaration-', dir=custody.BASE))
        directory.chmod(0o700)
        body = encoded(private)
        custody.create(directory / 'private-runtime-declaration.json', body)
        report.update(status='REPLACEMENT_RUNTIME_DECLARED_NOT_REALIZED', evidenceDirectory=str(directory),
                      privateDeclarationHash=hashlib.sha256(body).hexdigest(), **public)
        custody.create(directory / 'receipt.json', encoded(report))
        code = 0
    except Exception as error:
        reason = str(error)
        report.update(status='RUNTIME_DECLARATION_BLOCKED', errorType=type(error).__name__,
                      reason=reason if re.fullmatch('[A-Z][A-Z0-9_]{0,120}', reason) else 'RUNTIME_DECLARATION_UNPROVEN')
        code = 1
    print('OUF_REPLACEMENT_RUNTIME_DECLARATION=' + json.dumps(report, sort_keys=True))
    return code


if __name__ == '__main__':
    raise SystemExit(main())
