"""Read engine/service/resource metadata through the already available runner.

Never reads protected snapshots, nft or key files; no image import or lifecycle.
Only public projections are emitted. No observation grants mutation authority.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import time

spec = importlib.util.spec_from_file_location('backup', Path(__file__).with_name('backup-semantic-target.py'))
backup = importlib.util.module_from_spec(spec)
spec.loader.exec_module(backup)
CID = '7ae83be8c1fe9fe25774b7d748e35153652b29b2501886f89daeabb83bd1a147'
UNIT = 'ouf-semantic-provider-lease-resilient-r12.service'
IMAGES = {
    'semantic': 'sha256:e826bd9769a72e930e356f72c1c244007f9a34d065db94ca8113b064d10d8b85',
    'ingestion': 'sha256:98af9d774e446ce621128a52bfa1f9faaa096052cdc185f17dc81f1ea76e9a05',
    'udp': 'sha256:7a97979286113c4e3ef6bae87e1bf2d54d2f7195d447ce43b9329f3b90899d28'}


def require(ok, reason):
    if not ok:
        raise RuntimeError(reason)


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()).hexdigest()


def stable(value):
    return {k: value[k] for k in ('Id', 'Image', 'Config', 'HostConfig', 'Mounts', 'NetworkSettings')} | {
        'generation': {k: value['State'][k] for k in ('Pid', 'StartedAt', 'Running')}}


def project(value):
    require(value['Id'] == CID and value['Image'] == backup.SEMANTIC_IMAGE and
            value['State']['Running'] is True and value['State']['Status'] == 'running' and
            type(value['State']['Pid']) is int and value['State']['Pid'] > 1,
            'EXACT_RUNNING_INSTALLED_SEMANTIC_REQUIRED')
    host = value['HostConfig']
    require(host.get('Privileged') is False and host.get('NetworkMode') not in ('host', 'none') and
            not str(host.get('NetworkMode', '')).startswith('container:'), 'RETAINED_SHARED_BRIDGE_SCOPE_REQUIRED')
    env = {}
    for entry in value['Config']['Env']:
        key, val = entry.split('=', 1)
        require(key not in env, 'DUPLICATE_INSTALLED_ENVIRONMENT')
        env[key] = val
    return {'containerId': value['Id'], 'imageId': value['Image'],
            'installedStableBindingHash': digest(stable(value)),
            'installedConfigHash': digest(value['Config']), 'installedHostConfigHash': digest(host),
            'installedMountsHash': digest(value['Mounts']), 'networkSettingsHash': digest(value['NetworkSettings']),
            'generation': {k: value['State'][k] for k in ('Pid', 'StartedAt', 'Running')},
            'runtime': host['Runtime'], 'restartPolicy': host['RestartPolicy'],
            'memoryLimitBytes': host['Memory'], 'mountCount': len(value['Mounts']),
            'networks': [{'networkNameHash': digest(name), 'networkId': n['NetworkID'],
                          'ipv4': n['IPAddress'], 'mac': n['MacAddress']}
                         for name, n in value['NetworkSettings']['Networks'].items()],
            'legacyDatabasePasswordEnvironmentPresent': bool(env.get('OUF_SEM_DB_PASSWORD')),
            'springConfigImportPresent': bool(env.get('SPRING_CONFIG_IMPORT')),
            'fullRealizedOciProven': False, 'protectedDeclarationCompared': False}


def service():
    props = ['LoadState', 'ActiveState', 'SubState', 'MainPID', 'NRestarts', 'Restart', 'Result', 'ExecStart']
    result = subprocess.run(['/usr/bin/systemctl', 'show', UNIT, '--no-pager',
                             '--property=' + ','.join(props)], stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10,
                            env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'})
    require(result.returncode == 0 and len(result.stdout) <= 32768, 'BOUNDED_SERVICE_METADATA_REQUIRED')
    parsed = dict(row.split('=', 1) for row in result.stdout.decode().splitlines() if '=' in row)
    require(set(parsed) == set(props), 'COMPLETE_SERVICE_METADATA_REQUIRED')
    exact = '/etc/ouf/deploy-snapshots/semantic-resilient-lease-recovery-r12-y048hyms/activate.py' in parsed['ExecStart']
    pid = parsed['MainPID']
    running = parsed['ActiveState'] == 'active' and parsed['SubState'] == 'running' and pid.isdecimal() and int(pid) > 1
    return {k: v for k, v in parsed.items() if k != 'ExecStart'} | {
        'execStartMatchesReportedSnapshot': exact,
        'serviceActiveAtObservation': running and exact and parsed['Restart'] == 'no',
        'nativeLeaseMembershipProven': False, 'workerPrivateStatusRead': False,
        'continuousLivenessProven': False}


def main():
    report = dict(schema='ouf.discovery.r12-cutover-host-metadata.v1',
                  containerLifecycleOperations=0, imageImports=0, databaseWrites=0,
                  protectedSnapshotFilesOpened=0, credentialFilesOpened=0, privateKeyFilesOpened=0,
                  privateValuesPrinted=False, firewallWrites=0, commonLockAcquired=False,
                  applicationHealthProven=False, applicationCutoverAuthorized=False, notReleaseAcceptance=True)
    try:
        before = backup.inspect('ouf-semantic')
        report['semantic'] = project(before)
        postgres = backup.inspect('ouf-postgres')
        backup.binding(before, postgres)
        report['postgres'] = {'containerId': postgres['Id'], 'imageId': postgres['Image'],
                              'stableBindingHash': digest(stable(postgres)),
                              'generation': {k: postgres['State'][k] for k in ('Pid', 'StartedAt', 'Running')}}
        report['r12Service'] = service()
        report['qualifiedImagesPresentInEngine'] = {}
        for name, image in IMAGES.items():
            result = subprocess.run(['docker', 'image', 'inspect', '--format', '{{.Id}}', image],
                                    stdin=subprocess.DEVNULL, capture_output=True, timeout=10)
            require(len(result.stdout) <= 4096 and len(result.stderr) <= 32768, 'BOUNDED_IMAGE_INSPECT_REQUIRED')
            report['qualifiedImagesPresentInEngine'][name] = result.returncode == 0 and result.stdout.decode().strip() == image
        memory = {}
        for line in Path('/proc/meminfo').read_text().splitlines():
            key, _, rest = line.partition(':')
            if key in ('MemTotal', 'MemAvailable'):
                memory[key + 'Bytes'] = int(rest.split()[0]) * 1024
        report['resources'] = {**memory, 'rootFilesystemFreeBytes': shutil.disk_usage('/').free,
                               'runnerFilesystemFreeBytes': shutil.disk_usage(Path.home()).free,
                               'resourceAdmissionProven': False}
        require(stable(before) == stable(backup.inspect('ouf-semantic')) and
                stable(postgres) == stable(backup.inspect('ouf-postgres')), 'INSTALLED_GENERATION_OR_CONFIGURATION_CHANGED')
        after = service()
        require(all(after[k] == report['r12Service'][k] for k in ('MainPID', 'ActiveState', 'SubState', 'Restart', 'execStartMatchesReportedSnapshot')),
                'R12_SERVICE_GENERATION_CHANGED_DURING_READ')
        report.update(status='CURRENT_CUTOVER_HOST_METADATA_CAPTURED', observedAtUnixSeconds=int(time.time()),
                      readConsistencyMode='STABLE_REREADS_NOT_ATOMIC_TRANSITION_AUTHORITY')
        code = 0
    except Exception as error:
        reason = str(error)
        report.update(status='CURRENT_CUTOVER_HOST_READ_BLOCKED', errorType=type(error).__name__,
                      reason=reason if re.fullmatch('[A-Z][A-Z0-9_]{0,120}', reason) else 'HOST_METADATA_UNPROVEN')
        code = 1
    print('OUF_CURRENT_CUTOVER_HOST_METADATA=' + json.dumps(report, sort_keys=True))
    return code


if __name__ == '__main__':
    raise SystemExit(main())
