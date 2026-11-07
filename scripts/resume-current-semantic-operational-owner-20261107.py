#!/usr/bin/env python3
"""Resume the installed continuous owner; never unmask the legacy producer."""
import base64
import datetime
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import signal
import subprocess
import time

SERVICE = 'ouf-registry-token-7cb59501000058b5dc5030ad.service'
LEGACY = ('ouf-policy-token@semantic.service', 'ouf-policy-token@semantic.timer')
PROPERTIES = ('LoadState', 'ActiveState', 'SubState', 'UnitFileState', 'MainPID',
              'NRestarts', 'Result', 'ExecMainStatus', 'Type', 'User', 'Restart',
              'RootDirectory', 'NoNewPrivileges', 'ExecStart', 'ExecStartPre',
              'ExecStartPost', 'ExecCondition', 'FragmentPath')
SUCCESS = 'SEMANTIC_OPERATIONAL_OWNER_ACTIVE_TOKEN_FRESH_POLICY_GET_OK'

def need(ok, code):
    if not ok:
        raise RuntimeError(code)

def command(*args):
    return subprocess.run(('/usr/bin/systemctl', '--no-pager', *args),
                          stdin=subprocess.DEVNULL, capture_output=True, timeout=25)

def unit_read(unit):
    result = command('--all', 'show', unit, '--property=' + ','.join(PROPERTIES))
    need(result.returncode == 0 and len(result.stdout) <= 131072, 'UNIT_METADATA_READ_FAILED')
    pairs = [line.split('=', 1) for line in result.stdout.decode().splitlines() if '=' in line]
    fields = dict(pairs)
    need(len(fields) == len(pairs) and all(k in fields for k in PROPERTIES[:4]), 'UNIT_METADATA_INCOMPLETE')
    return fields

def public_unit(fields):
    return {key: value for key, value in fields.items()
            if key not in ('ExecStart', 'ExecStartPre', 'ExecStartPost', 'ExecCondition',
                           'FragmentPath', 'RootDirectory') and re.fullmatch('[A-Za-z0-9_-]{0,80}', value)}

def legacy_guard(report):
    rows = {unit: unit_read(unit) for unit in LEGACY}
    report['legacyUnits'] = {unit: public_unit(row) for unit, row in rows.items()}
    need(all(row['LoadState'] == 'masked' and row['ActiveState'] == 'inactive'
             for row in rows.values()), 'LEGACY_PRODUCER_MUST_REMAIN_MASKED_INACTIVE')

def service_guard(row, c, unit_raw):
    need(all(k in row for k in PROPERTIES), 'SERVICE_METADATA_INCOMPLETE')
    need(row['LoadState'] == 'loaded' and row['UnitFileState'] in ('disabled', 'enabled')
         and row['Type'] == 'simple' and row['User'] == 'root'
         and row['Restart'] == 'on-failure' and row['NoNewPrivileges'] == 'yes'
         and row['RootDirectory'] == c['destinations']['installationRoot'] + '/sandbox'
         and row['FragmentPath'] == c['serviceUnitPath'], 'INSTALLED_OPERATIONAL_UNIT_REQUIRED')
    need(not any(row[k] for k in ('ExecStartPre', 'ExecStartPost', 'ExecCondition')),
         'UNEXPECTED_OPERATIONAL_START_HOOK')
    starts = [line[len('ExecStart=:'):] for line in unit_raw.decode().splitlines()
              if line.startswith('ExecStart=:')]
    actual = re.search(r'argv\[\]=(.*?);', row['ExecStart'])
    need(len(starts) == 1 and row['ExecStart'].count('argv[]=') == 1 and actual
         and shlex.split(actual.group(1)) == shlex.split(starts[0]), 'LOADED_WORKER_COMMAND_DIFFERS_FROM_REVIEW')

def claims(token):
    part = token.split('.')[1]
    return json.loads(base64.urlsafe_b64decode(part + '=' * (-len(part) % 4)))

def verify_binding(doc, values, c, token, mount):
    target = values['ouf.authorization.registry-token-file']
    mounts = sorted([m for m in doc['Mounts'] if target.startswith(m['Destination'].rstrip('/') + '/')],
                    key=lambda m: len(m['Destination']), reverse=True)
    need(mounts and mounts[0]['Type'] == 'bind' and mounts[0]['RW'] is False,
         'ROTATING_TOKEN_DIRECTORY_MOUNT_REQUIRED')
    m = mounts[0]; binding = c['ownerInputs']['binding']
    source = Path(m['Source'] + target[len(m['Destination']):])
    need(source == Path(binding['output_directory']) / binding['output_member']
         and binding['output_gid'] == mount['gid'] == 10001 and mount['sameFileAsCurrentHostSource'],
         'INSTALLED_OWNER_OUTPUT_NOT_CURRENT_MOUNTED_TOKEN')
    issuer = values['ouf.iam.issuer'].rstrip('/')
    value = claims(token)
    need(c['ownerInputs']['iamProfile']['issuer'].rstrip('/') == issuer
         and binding['endpoint'] == issuer + '/protocol/openid-connect/token'
         and value.get('iss', '').rstrip('/') == issuer
         and binding['client_id'] in (value.get('azp'), value.get('client_id'))
         and set(binding['scope'].split()) <= set(value.get('scope', '').split()),
         'EXISTING_OWNER_IDENTITY_OR_SCOPE_DIFFERS')

def unchanged(doc, runtime):
    current = runtime['inspect'](doc['Id'])[doc['Id']]
    need(all(current[k] == doc[k] for k in ('Id', 'Image', 'Config', 'HostConfig', 'Mounts', 'NetworkSettings'))
         and all(current['State'][k] == doc['State'][k] for k in ('Pid', 'StartedAt', 'Running', 'Restarting')),
         'SEMANTIC_RUNTIME_CHANGED')

def claim_start(doc, raw):
    root = Path('/var/lib/ouf-storage-migration/semantic-operational-owner-starts')
    root.mkdir(mode=0o700, exist_ok=True)
    need(not root.is_symlink() and root.stat().st_uid == 0 and not root.stat().st_mode & 0o077,
         'PRIVATE_ATTEMPT_DIRECTORY_REQUIRED')
    path = root / (hashlib.sha256(doc['Id'].encode() + b'\0' + raw).hexdigest() + '.json')
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as stream:
        json.dump({'service': SERVICE, 'containerId': doc['Id'], 'attemptNotCompletion': True}, stream)
        stream.flush(); os.fsync(stream.fileno())
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    try: os.fsync(fd)
    finally: os.close(fd)
    return str(path)

def execute(report, runtime, reader, owner):
    bound, docs = runtime['retained_semantic']({})
    doc = docs[bound['semantic']]
    need(runtime['semantic_process'](doc)['processKind'] == 'APPLICATION_RUNNING', 'SEMANTIC_JAVA_REQUIRED')
    values, _ = reader['declarations'](doc)
    target = values['ouf.authorization.registry-token-file']
    raw, mount = reader['mounted_read'](doc, target, 65536)
    token, report['tokenBefore'] = reader['token_metadata'](raw, time.time())
    url = reader['endpoint'](values['ouf.authorization.registry-url'])
    delay = int(values.get('ouf.authorization.refresh-seconds') or '30')
    need(1 <= delay <= 60, 'REFRESH_WAIT_OUT_OF_RANGE')
    legacy_guard(report)
    review = owner['object_at'](owner['REVIEW'], owner['REVIEW_SHA'])
    c = review['configuration']
    need(owner['digest'](owner['encoded'](c)) == owner['CONFIG_SHA'], 'REVIEWED_CONFIGURATION_CHANGED')
    need(Path(c['serviceUnitPath']).name == SERVICE, 'REVIEWED_SERVICE_IDENTITY_CHANGED')
    config_path = Path(c['destinations']['installationRoot']) / 'configuration.json'
    need(owner['object_at'](config_path, owner['CONFIG_SHA']) == c, 'INSTALLED_CONFIGURATION_CHANGED')
    need(review['serviceUnit']['path'] == c['serviceUnitPath'], 'REVIEWED_UNIT_PATH_CHANGED')
    unit_raw = owner['read'](c['serviceUnitPath'], 65536, review['serviceUnit']['sha256'])
    before = unit_read(SERVICE); report['serviceBefore'] = public_unit(before)
    service_guard(before, c, unit_raw)
    verify_binding(doc, values, c, token, mount)
    report['installedOwnerMatchesCurrentTokenBinding'] = True
    ledger_path = Path(c['destinations']['ledgerRoot']) / 'state.json'
    def ledger():
        row = owner['object_at'](ledger_path, mutable=True)
        projected = dict(row)
        unknown_reason = row.get('reason') not in owner['REASONS']
        if unknown_reason:
            projected['reason'] = 'UNKNOWN_PREVIOUS_GRANT_OR_PUBLICATION_OUTCOME'
        public = owner['project'](projected, owner['CONFIG_SHA'], time.time())
        if unknown_reason:
            public['reasonCode'] = 'UNCLASSIFIED_OWNER_REASON'
        return row, public
    row, report['ledgerBefore'] = ledger()
    already_active = before['ActiveState'] == 'active' and before['SubState'] == 'running'
    need(row['state'] not in ('BLOCKED', 'REVOKED'), 'OWNER_LEDGER_REQUIRES_RECONCILIATION')
    if not already_active:
        need(before['ActiveState'] in ('inactive', 'failed') and before['MainPID'] == '0',
             'OWNER_SERVICE_TRANSITION_IN_PROGRESS')
        need(row['state'] in ('READY', 'RESERVED', 'ACTIVE', 'RETRY_WAIT'),
             'PREVIOUS_GRANT_OR_PUBLICATION_OUTCOME_UNKNOWN')
        unchanged(doc, runtime)
        report['privateStartAttemptFile'] = claim_start(doc, raw)
        report['serviceStartDispatched'] = True
        result = command('start', SERVICE)
        report['serviceStartExitCode'] = result.returncode
        need(result.returncode == 0, 'EXISTING_OPERATIONAL_OWNER_START_FAILED')
    report['ownerAlreadyRunning'] = already_active
    deadline = time.monotonic() + 90
    while True:
        current = unit_read(SERVICE); report['serviceAfter'] = public_unit(current)
        row, report['ledgerAfter'] = ledger()
        need(report['ledgerAfter']['controlledCumulativeGrantAttempts'] >= report['ledgerBefore']['controlledCumulativeGrantAttempts']
             and report['ledgerAfter']['version'] >= report['ledgerBefore']['version'], 'OPERATIONAL_LEDGER_REGRESSED')
        need(row['state'] not in ('BLOCKED', 'REVOKED'), 'OWNER_LEDGER_REQUIRES_RECONCILIATION')
        need(current['ActiveState'] == 'active' and current['SubState'] == 'running', 'OWNER_NOT_RUNNING')
        fresh, new_mount = reader['mounted_read'](doc, target, 65536)
        new_token, after = reader['token_metadata'](fresh, time.time()); report['tokenAfter'] = after
        if (row['state'] == 'ACTIVE' and after['expiryEpoch'] > time.time() + 60
                and not after['notYetValidAtRead'] and row['tokenHash'] == hashlib.sha256(fresh).hexdigest()):
            break
        need(time.monotonic() < deadline, 'FRESH_PUBLICATION_NOT_OBSERVED_WITHIN_WINDOW')
        time.sleep(2)
    report['mountedTokenChanged'] = fresh != raw
    verify_binding(doc, values, c, new_token, new_mount)
    report['policyGetAttempts'] = 1
    report['policyGet'] = reader['policy_get'](url, new_token)
    need(report['policyGet'].get('httpStatus') == 200 and report['policyGet'].get('activePolicyResponseRead'),
         'FRESH_TOKEN_POLICY_GET_NOT_SUCCESSFUL')
    unchanged(doc, runtime)
    legacy_guard(report)
    service_guard(unit_read(SERVICE), c, unit_raw)
    if unit_read(SERVICE)['UnitFileState'] != 'enabled':
        report['serviceEnableDispatched'] = True
        need(command('enable', SERVICE).returncode == 0, 'OPERATIONAL_OWNER_ENABLE_FAILED')
    time.sleep(delay + 2)
    report['normalPolicyRefreshWaitSeconds'] = delay + 2
    unchanged(doc, runtime)
    current = unit_read(SERVICE); report['serviceAfter'] = public_unit(current)
    need(current['ActiveState'] == 'active' and current['SubState'] == 'running'
         and current['UnitFileState'] == 'enabled', 'OWNER_RUNNING_ENABLED_NOT_PROVEN')
    report.update(status=SUCCESS, semanticRuntimeUnchanged=True, applicationLoadedPolicyProven=False,
                  automaticRenewalCycleProven=False)

def main():
    report = {'schema': 'ouf.semantic-operational-owner-resume.v1', 'status': 'HELD',
              'service': SERVICE, 'serviceStartDispatched': False, 'serviceEnableDispatched': False,
              'credentialValuesEmitted': False, 'applicationConfigurationChanged': False,
              'applicationLoadedPolicyProven': False, 'permissionChanges': 0, 'serviceStops': 0,
              'businessRequestsIssued': 0, 'databaseQueriesIssuedByScript': 0, 's3Requests': 0,
              'policyGetAttempts': 0, 'operationalLedgerWritesByScript': 0,
              'existingOwnerMayRequestTokensAndWriteLedger': True}
    signal.alarm(240)
    try:
        need(os.geteuid() == 0, 'ROOT_REQUIRED')
        with open('/run/lock/ouf-runtime-e2e.lock', 'a') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            execute(report, globals()['RUNTIME_READER'], globals()['POLICY_READER'], globals()['OWNER_READER'])
    except Exception as exc:
        report['reason'] = str(exc) if isinstance(exc, RuntimeError) and re.fullmatch('[A-Z0-9_]{1,120}', str(exc)) else type(exc).__name__
    report['observedAt'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    print(json.dumps(report, sort_keys=True))
    return 0 if report['status'] == SUCCESS else 1

if __name__ == '__main__':
    raise SystemExit(main())
