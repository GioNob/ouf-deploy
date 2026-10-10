"""One protected preparation: current R10/peer/custody + file DB secret intent.

Only creates a new private snapshot. No Docker lifecycle, image import, nft
mutation, database query/write, lease lock, signature, grant or credential rotation.
Preparation observations must be reverified by a future governed applicator.
"""
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import types

BASE = Path('/etc/ouf/deploy-snapshots')
DECLARATION = BASE / 'semantic-qualified-package-declaration-v7nhhm3o/private-runtime-declaration.json'
DECLARATION_HASH = '78dc04694daf0dd8685b74eedddd64365c600c2303ac3fbaa47313bdb85b5d59'
CUSTODY_HASH = 'cb9ff64684243d563da79d327eb7d7e325dbea6a3922c91a0b7791a3ceec9baf'
R10 = BASE / 'semantic-finite-lease-recovery-r10-nw9ue4d5'
UNIT = 'ouf-semantic-provider-lease-finite-r10.service'
IMAGE = 'sha256:e826bd9769a72e930e356f72c1c244007f9a34d065db94ca8113b064d10d8b85'
OWNER_HASH = '656c23f18e3f3eb4c1ce630f5056be87f7883eab7b048065092dafbd018284a8'
PROGRAMS = {
    'activate.py': '40822d277af67ec7145fb811cc2076e7845072418f1c25e306e1c0c9e14499e7',
    'activation_core.py': '06d14a340db6d35a795115fd921f901e1cd0de74c06174562107270b08fc7c2a',
    'reader.py': '4ddfda694150771fc8059ce22080a44c1d42db80c4f85b6b42f85c46442536d2',
    'dns.py': 'f1491cca148c488bbee8089dabcada0361781962d7b2858ad2fc4549cea3696f',
    'materialize_southbound_lease_refresh.py': 'c3160940cf79678cb8e44c036cb0d947016f885ab09acfe6cce571833db5b079',
    'nft.py': '04cd115c756158ce2c04f32608380d7a40f4577d85785dfe46571825876545c1',
    'supervisor.py': '08a354cfbea6a31ed1ea21dd80ddab0d0f983e3a0143a6f656124cf843d5635c'}


def require(value, reason):
    if not value:
        raise ValueError(reason)


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def digest(value):
    return hashlib.sha256(encoded(value)).hexdigest()


def environment(config):
    require(type(config.get('Env')) is list and len(config['Env']) <= 256, 'BOUNDED_APPLICATION_ENV_REQUIRED')
    values = {}
    for row in config['Env']:
        require(type(row) is str and '=' in row and len(row) <= 65536, 'EXACT_APPLICATION_ENV_REQUIRED')
        key, value = row.split('=', 1)
        require(re.fullmatch('[A-Za-z_][A-Za-z0-9_]{0,127}', key) and key not in values, 'UNIQUE_APPLICATION_ENV_REQUIRED')
        values[key] = value
    return values


def frame(value):
    return {k: value[k] for k in ('Id', 'Image', 'Config', 'HostConfig', 'Mounts')} | {
        'networks': value['NetworkSettings']['Networks'],
        'generation': {k: value['State'][k] for k in ('Pid', 'StartedAt', 'Running')}}


def check_live(declaration, current):
    require(declaration.get('schema') == 'ouf.discovery.private-qualified-package-runtime-declaration.v1'
            and declaration.get('candidateImageId') == IMAGE
            and all(declaration.get(k) is False for k in ('productionApplyReady', 'applicationCutoverAuthorized', 'completeReplacementOciProven')),
            'EXACT_UNAPPLIED_QUALIFIED_DECLARATION_REQUIRED')
    require(frame(current) == frame(declaration['retainedNativeCreationFrame'])
            and current['State']['Running'] is True and current['State']['Status'] == 'running',
            'RETAINED_LIVE_APPLICATION_FRAME_DRIFT')
    approved, live = environment(declaration['candidateConfig']), environment(current['Config'])
    password = approved.get('OUF_SEM_DB_PASSWORD')
    require(type(password) is str and 0 < len(password.encode()) <= 4096
            and not any(c in password for c in ('\r', '\n', '\x00'))
            and live.get('OUF_SEM_DB_PASSWORD') == password, 'EXACT_EXISTING_DATABASE_CREDENTIAL_REQUIRED')
    require(not any(k in approved for k in ('SPRING_CONFIG_IMPORT', 'SPRING_DATASOURCE_PASSWORD')),
            'EXISTING_PASSWORD_OR_CONFIG_IMPORT_OVERRIDE_REQUIRES_REVIEW')
    return password.encode()


def compile_file_secret(declaration, current, directory):
    """Pure intent compiler; credential data stays out of its returned public view."""
    credential = check_live(declaration, current)
    root = Path(directory)
    require(root.is_absolute() and '..' not in root.parts and ':' not in str(root)
            and re.fullmatch('/[A-Za-z0-9_./-]+', str(root)), 'SAFE_PROTECTED_SNAPSHOT_PATH_REQUIRED')
    source, target = str(root / 'database-secret'), '/run/ouf-semantic-db'
    result = copy.deepcopy(declaration)
    destinations = [m['Destination'] for m in current['Mounts']] + [m['target'] for m in declaration['roleOwnedReadOnlyMounts']]
    require(not any(v == target or v.startswith(target + '/') or target.startswith(v.rstrip('/') + '/') for v in destinations),
            'DATABASE_SECRET_MOUNT_SHADOWING_DENIED')
    env = environment(result['candidateConfig'])
    env.pop('OUF_SEM_DB_PASSWORD')
    env['SPRING_CONFIG_IMPORT'] = 'configtree:' + target + '/'
    result['candidateConfig']['Env'] = [k + '=' + env[k] for k in sorted(env)]
    binding = source + ':' + target + ':ro'
    result['proposedHostConfig']['Binds'].append(binding)
    result['hostDelta']['appendedReadOnlyBinds'].append(binding)
    result['schema'] = 'ouf.discovery.private-file-secret-runtime-declaration.v1'
    result['inputBindings']['qualifiedPackageDeclarationHash'] = DECLARATION_HASH
    result['databaseSecretProjection'] = {
        'sourceDirectory': source, 'targetDirectory': target, 'directoryUid': 10001,
        'directoryGid': 10001, 'directoryMode': 0o500, 'readOnly': True,
        'file': {'name': 'OUF_SEM_DB_PASSWORD', 'uid': 10001, 'gid': 10001, 'mode': 0o400,
                 'sha256': hashlib.sha256(credential).hexdigest()},
        'credentialRotated': False, 'platformSecretManagerIntegrationProven': False}
    result['runtimeInputsFreshlyVerifiedAtPreparation'] = True
    result['freshRuntimeCustodyProven'] = False
    result['observationsAreHistorical'] = True
    result['requiredBeforeMutation'].append('REVERIFY_FILE_SECRET_PROJECTION_AND_ALL_INPUT_BYTES_AT_APPLY')
    public = {'candidateImageId': IMAGE, 'candidateConfigHash': digest(result['candidateConfig']),
              'proposedHostConfigHash': digest(result['proposedHostConfig']),
              'retainedLiveFrameHash': digest(frame(current)), 'databasePasswordInCandidateEnv': False,
              'databaseCredentialRotated': False, 'databaseSecretProjectionReadOnly': True,
              'databaseSecretDirectoryMode': '0500', 'databaseSecretFileMode': '0400',
              'additionalReadOnlyBindCount': 1, 'retainedRoleInputCount': len(declaration['roleOwnedReadOnlyMounts']),
              'platformSecretManagerIntegrationProven': False,
              'productionApplyReady': False, 'completeReplacementOciProven': False,
              'applicationCutoverAuthorized': False, 'freshRuntimeCustodyProven': False}
    return result, public, credential


def native(reader, binding, args, docker=False):
    props = ['LoadState', 'ActiveState', 'SubState', 'MainPID', 'Restart', 'NRestarts', 'ExecStart']
    require((docker and args == ['inspect', '--type', 'container', reader.SEMANTIC_ID])
            or (not docker and args == ['show', UNIT, '--no-pager', '--property=' + ','.join(props)]),
            'EXACT_READ_ONLY_NATIVE_SCOPE_REQUIRED')
    reader.private(binding['path'], binding['sha256'], executable=True)
    argv = [binding['path'], *args]
    if docker:
        # Use the already reviewed empty activation CLI directory.
        config = reader.OUTPUT / 'activation-docker-cli'
        s = config.lstat()
        require(stat.S_ISDIR(s.st_mode) and s.st_uid == s.st_gid == 0 and stat.S_IMODE(s.st_mode) == 0o700
                and not os.path.lexists(config / 'config.json'), 'EMPTY_RETAINED_DOCKER_CLI_REQUIRED')
        argv = [binding['path'], '--config', str(config), *args]
    p = subprocess.run(argv, stdin=subprocess.DEVNULL, capture_output=True, timeout=15,
                       env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C', 'DOCKER_HOST': 'unix:///var/run/docker.sock'})
    require(p.returncode == 0 and len(p.stdout) <= 2000000, 'BOUNDED_READ_ONLY_NATIVE_RESULT_REQUIRED')
    reader.private(binding['path'], binding['sha256'], executable=True)
    return p.stdout


def r10_state(reader, commands):
    auth_raw = reader.private(R10 / 'authorization.json')
    auth = reader.parse(auth_raw)
    require(auth.get('schema') == 'ouf.provider-finite-lease-recovery-authorization.v1'
            and auth.get('ownerConfigurationHash') == OWNER_HASH and auth.get('serviceUnit') == UNIT
            and auth.get('programHashes') == PROGRAMS and auth.get('automaticRestart') is False
            and auth.get('enableAtBoot') is False and auth.get('containerLifecycleAuthorized') is False,
            'EXACT_CONSUMED_R10_AUTHORIZATION_REQUIRED')
    claim = reader.parse(reader.private('/etc/ouf/provider-finite-lease-recovery-r10.claim'))
    require(claim.get('directory') == str(R10) and claim.get('approvalRef') == auth['approvalRef']
            and claim.get('startAuthorized') is False, 'CONSUMED_R10_CLAIM_BINDING_DRIFT')
    for name, expected in PROGRAMS.items():
        reader.private(R10 / name, expected)
    worker = reader.parse(reader.private(R10 / 'worker-status.json'))
    require(worker.get('status') == 'LEASE_ACTIVE' and type(worker.get('refreshCount')) is int
            and worker['refreshCount'] >= 2 and type(worker.get('workerPid')) is int,
            'CURRENT_R10_PRIVATE_WORKER_UNPROVEN')
    props = ['LoadState', 'ActiveState', 'SubState', 'MainPID', 'Restart', 'NRestarts', 'ExecStart']
    raw = native(reader, commands['systemctl'], ['show', UNIT, '--no-pager', '--property=' + ','.join(props)])
    service = dict(v.split('=', 1) for v in raw.decode().splitlines() if '=' in v)
    require(set(service) == set(props) and service['ActiveState'] == 'active' and service['SubState'] == 'running'
            and service['Restart'] == 'no' and service['NRestarts'] == '0'
            and service['MainPID'] == str(worker['workerPid']) and str(R10 / 'activate.py') in service['ExecStart'],
            'CURRENT_EXACT_R10_SERVICE_UNPROVEN')
    require(reader.private(R10 / 'authorization.json') == auth_raw, 'R10_AUTHORIZATION_CHANGED_DURING_READ')
    return {'workerPid': worker['workerPid'], 'refreshCount': worker['refreshCount'],
            'workerGeneration': reader.generation(worker['workerPid']), 'authorizationHash': hashlib.sha256(auth_raw).hexdigest(),
            'serviceUnit': UNIT, 'automaticRestart': False, 'continuousLivenessProven': False}


def main():
    os.umask(0o077)
    report = dict(schema='ouf.discovery.current-cutover-input-preparation.v1', containerLifecycleOperations=0,
                  imageImports=0, databaseWrites=0, databaseQueries=0, firewallWrites=0, commonLockAcquired=False,
                  privateValuesPrinted=False, signaturesIssued=0, providerCalls=0, dnsQueries=0,
                  existingConfigurationWrites=0, r10Touched=False, credentialRotated=False,
                  applicationHealthProven=False, notReleaseAcceptance=True)
    phase = 'VERIFY_SEALED_CUSTODY_AND_QUALIFIED_DECLARATION'
    try:
        require(os.geteuid() == 0 and sys.flags.isolated and sys.dont_write_bytecode and len(sys.argv) == 1,
                'ISOLATED_ROOT_PREPARATION_REQUIRED')
        source = globals().get('__custody_source__')
        require(type(source) is bytes and hashlib.sha256(source).hexdigest() == CUSTODY_HASH, 'SEALED_CUSTODY_SOURCE_REQUIRED')
        custody = types.ModuleType('custody')
        exec(compile(source, 'sealed-custody', 'exec'), custody.__dict__)
        raw = custody.file_bytes(DECLARATION, 0, {0o600}, expected=DECLARATION_HASH)
        declaration = json.loads(raw)
        reader_raw = custody.file_bytes(R10 / 'reader.py', 0, {0o600}, expected=PROGRAMS['reader.py'])
        reader = types.ModuleType('reader')
        reader.__file__ = str(R10 / 'reader.py')
        exec(compile(reader_raw, reader.__file__, 'exec'), reader.__dict__)
        human = reader.parse(reader.private(reader.CONTEXT / 'human-approval-binding.json'))
        cfg = reader.parse(reader.private(reader.CONTEXT / 'execution-configuration.json', human['configurationHash']))
        phase = 'VERIFY_CURRENT_R10_AND_RETAINED_APPLICATION_FRAME'
        r10_before = r10_state(reader, cfg['commandBindings'])
        args = ['inspect', '--type', 'container', reader.SEMANTIC_ID]
        current = reader.parse(native(reader, cfg['commandBindings']['docker'], args, True))[0]
        check_live(declaration, current)
        phase = 'VERIFY_CURRENT_RECIPROCAL_PEER_AND_SOURCE_BOUND_SHARED_GUARDS'
        observations = reader.collect_cutover()
        lease = observations['lease']
        require(lease['journalState'] == 'LEASE_READY' and lease['leaseAuthorized'] is True
                and lease['journalAndMembershipConsistent'] and not lease['providerSetsEmpty']
                and len(lease['flows']) == 2
                and all(f['inetAddressCount'] == f['bridgeAddressCount'] and f['inetAddressCount'] > 0
                        and type(f['minRemainingTtlSeconds']) is int and 0 < f['minRemainingTtlSeconds'] <= f['leaseSeconds']
                        for f in lease['flows']), 'CURRENT_TWO_FLOW_SECONDS_LEASE_UNPROVEN')
        require(observations['currentSemanticPeer']['generation']['pid'] == current['State']['Pid'],
                'LIVE_RECIPROCAL_PEER_GENERATION_DRIFT')
        phase = 'REVERIFY_THREE_EXISTING_ROLE_INPUT_BYTES_AND_METADATA'
        verified = []
        for mount in declaration['roleOwnedReadOnlyMounts']:
            require(mount['uid'] == mount['gid'] == 10001 and mount['mode'] == 0o400 and mount['readOnly'] is True,
                    'EXACT_ROLE_INPUT_METADATA_REQUIRED')
            value = custody.file_bytes(mount['source'], mount['uid'], {mount['mode']}, expected=mount['sha256'])
            require(Path(mount['source']).lstat().st_gid == mount['gid'], 'EXACT_ROLE_INPUT_GROUP_REQUIRED')
            verified.append((mount, hashlib.sha256(value).hexdigest()))
        report.update(existingRoleInputFilesOpened=3, existingCredentialFilesOpened=1,
                      existingPrivateKeyFilesOpened=1, existingPublicTrustFilesOpened=1)
        phase = 'STABLE_RECHECK_BEFORE_PRIVATE_SNAPSHOT_CREATION'
        after = reader.parse(native(reader, cfg['commandBindings']['docker'], args, True))[0]
        require(frame(after) == frame(current), 'LIVE_APPLICATION_CHANGED_DURING_PREPARATION')
        r10_after = r10_state(reader, cfg['commandBindings'])
        require(r10_after['workerGeneration'] == r10_before['workerGeneration']
                and r10_after['authorizationHash'] == r10_before['authorizationHash']
                and r10_after['refreshCount'] >= r10_before['refreshCount'], 'R10_GENERATION_CHANGED_DURING_PREPARATION')
        require(custody.file_bytes(DECLARATION, 0, {0o600}, expected=DECLARATION_HASH) == raw,
                'QUALIFIED_DECLARATION_CHANGED_DURING_PREPARATION')
        for mount, expected in verified:
            custody.file_bytes(mount['source'], mount['uid'], {mount['mode']}, expected=expected)
        require(shutil.disk_usage(BASE).free >= 1073741824, 'PROTECTED_SNAPSHOT_FREE_SPACE_REQUIRED')
        phase = 'CREATE_PRIVATE_FILE_SECRET_PROJECTION_AND_DECLARED_INTENT'
        root = Path(tempfile.mkdtemp(prefix='semantic-current-cutover-inputs-', dir=BASE))
        root.chmod(0o700)
        private, public, credential = compile_file_secret(declaration, current, root)
        secret = root / 'database-secret'
        secret.mkdir(mode=0o700)
        custody.create(secret / 'OUF_SEM_DB_PASSWORD', credential, 10001, 10001, 0o400)
        os.chown(secret, 10001, 10001)
        secret.chmod(0o500)
        require(custody.file_bytes(secret / 'OUF_SEM_DB_PASSWORD', 10001, {0o400}, expected=hashlib.sha256(credential).hexdigest()) == credential,
                'NEW_DATABASE_SECRET_BYTE_CUSTODY_UNPROVEN')
        private['currentNativeObservation'] = observations
        private['r10Observation'] = r10_after
        private['observedAtUnixSeconds'] = int(time.time())
        body = encoded(private)
        custody.create(root / 'private-runtime-declaration.json', body)
        report.update(status='CURRENT_INPUTS_AND_FILE_SECRET_DECLARED_NOT_APPLY_READY', evidenceDirectory=str(root),
                      privateDeclarationHash=hashlib.sha256(body).hexdigest(), **public,
                      currentR10=r10_after, currentLease=lease, currentSemanticPeer=observations['currentSemanticPeer'],
                      existingRoleInputsReverified=True, commonLockAcquired=False)
        custody.create(root / 'receipt.json', encoded(report))
        code = 0
    except Exception as error:
        reason = str(error)
        report.update(status='CURRENT_CUTOVER_INPUT_PREPARATION_BLOCKED', phase=phase, errorType=type(error).__name__,
                      reason=reason if re.fullmatch('[A-Z][A-Z0-9_]{0,120}', reason) else 'CURRENT_INPUT_CUSTODY_UNPROVEN')
        code = 1
    print('OUF_CURRENT_CUTOVER_INPUTS=' + json.dumps(report, sort_keys=True))
    return code


if __name__ == '__main__':
    raise SystemExit(main())
