#!/usr/bin/env python3
"""Prepare a private host-writer containment draft. No apply mode or service mutation.
Unit configuration may contain secrets: retain privately, export only review metadata.
No runtime token bodies, Docker/IAM calls, old-plan rebind or attempt reset.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import subprocess
import sys
import time

DRIVER = Path('/var/lib/ouf-storage-test-cold-stop-20261106.py')
DRIVER_SHA = 'b3b28645ed377459fbe577fe4eb5eb8fb351a0e2c0e3f7067d5745f6f83ad2b5'
UNIT = re.compile(r'ouf-[A-Za-z0-9_.@-]+\.(?:service|timer)')
SAFE = ('Id', 'LoadState', 'ActiveState', 'SubState', 'UnitFileState', 'MainPID', 'Result')
PROPS = SAFE + ('Triggers', 'TriggeredBy', 'FragmentPath', 'DropInPaths',
    'NeedDaemonReload', 'Names', 'Following', 'PartOf', 'ConsistsOf', 'PropagatesStopTo',
    'BoundBy', 'Type', 'Restart', 'KillMode', 'KillSignal', 'SendSIGKILL',
    'TimeoutStopUSec', 'RemainAfterExit', 'ExecStart', 'ExecStop', 'ExecStopPost',
    'ReadWritePaths', 'ReadOnlyPaths', 'StateDirectory', 'RuntimeDirectory',
    'RuntimeDirectoryPreserve', 'WorkingDirectory', 'RootDirectory', 'ControlGroup',
    'Job', 'TimersMonotonic', 'TimersCalendar')
TIMERS = (
    'ouf-gateway-policy-token.timer', 'ouf-ingestion-policy-token.timer',
    'ouf-onboarding-identity-token.timer', 'ouf-policy-token@onboarding.timer',
    'ouf-policy-token@udp.timer')
SERVICES = tuple(n[:-6] + '.service' for n in TIMERS)
REGISTRY = 'ouf-registry-token-7cb59501000058b5dc5030ad.service'
MASKED = ('ouf-policy-token@semantic.service', 'ouf-policy-token@semantic.timer')
EXPECTED = set(TIMERS + SERVICES + (REGISTRY,) + MASKED)
AREA = Path('/var/lib/ouf-storage-host-containment-preparation-20261106-v1')
PRIOR = {
    '/var/lib/ouf-storage-migration/cold-backup-20261106-v3/plan.private.json':
        '1c0bb62ceba85f748e43465d36f016b4c575c586d40390dc92095a1dbc71bd0f',
    '/var/lib/ouf-storage-migration/cold-backup-20261106-v4/plan.private.json':
        '0f71ecd23a6e929045c08144a4ce0b878c7a25c87ecaf4e4e50ccc85ee486ea1',
    '/var/lib/ouf-storage-migration/cold-test-stop-20261106-v1/claim.private.json':
        '786b60aa3d5217b73120a277218d73d3e5edd138bc26b8ed1f66a8d741215ee9',
    '/var/lib/ouf-storage-migration/cold-test-stop-20261106-v1/proposal.private.json':
        '62b2afd01e215f0da5719c3e22cda1d1c19d11747bc80e102d611b8af5ff5df5'}


def need(ok, reason):
    if not ok: raise ValueError(reason)


def command(argv, until):
    need(time.monotonic() < until, 'TOTAL_TIME_LIMIT')
    p = subprocess.Popen(['/usr/bin/systemctl', '--no-pager', *argv],
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C', 'SYSTEMD_PAGER': 'cat'}, start_new_session=True)
    data = bytearray()
    selector = selectors.DefaultSelector()
    selector.register(p.stdout, selectors.EVENT_READ)
    deadline = min(until, time.monotonic() + 10)
    try:
        while selector.get_map():
            need(time.monotonic() < deadline, 'SYSTEMCTL_READ_TIMEOUT')
            for key, _ in selector.select(min(0.2, max(0, deadline - time.monotonic()))):
                chunk = os.read(key.fileobj.fileno(), 65536)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                data.extend(chunk)
                need(len(data) <= 1 << 20, 'SYSTEMCTL_OUTPUT_LIMIT')
        rc = p.wait(timeout=max(0.01, deadline - time.monotonic()))
        need(rc == 0, 'SYSTEMCTL_READ_FAILED')
        return bytes(data).decode('utf-8')
    finally:
        selector.close()
        if p.poll() is None:
            os.killpg(p.pid, signal.SIGKILL)  # Metadata CLI only, never a service.
            p.wait(timeout=5)
        p.stdout.close()


def unit_names(raw):
    result = set()
    for line in raw.splitlines():
        fields = line.split()
        if fields and fields[0] == '\u25cf': fields.pop(0)
        if fields and UNIT.fullmatch(fields[0]): result.add(fields[0])
    need(len(result) <= 32, 'UNIT_COUNT_LIMIT')
    return result


def property_rows(raw):
    rows = []
    for block in raw.strip().split('\n\n'):
        values = {}
        for line in block.splitlines():
            key, separator, value = line.partition('=')
            need(bool(separator) and key in PROPS, 'UNEXPECTED_SYSTEMCTL_PROPERTY')
            values.setdefault(key, []).append(value)
        need(len(values.get('Id', [])) == 1 and UNIT.fullmatch(values['Id'][0]), 'UNIT_ID_CARDINALITY')
        rows.append(values)
    need(len(rows) <= 32 and len({x['Id'][0] for x in rows}) == len(rows), 'UNIT_RECORD_COUNT')
    return rows


def one(row, key):
    values = row.get(key, [])
    need(len(values) == 1, 'PROPERTY_CARDINALITY')
    return values[0]


def words(row, key):
    value = one(row, key)
    # Do not pretend to decode systemd C-escaping with a shell parser.
    need(not any(c in value for c in ('\\', '"', "'")), 'ESCAPED_PROPERTY_REQUIRES_REVIEW')
    return value.split()


def configuration_path_kind(path):
    """Classify manager-reported paths, without resolving or following symlinks.

    systemd linked unit fragments can be outside its search directories and can
    have arbitrary filenames. Location is metadata, not proof of file custody.
    protected() remains the actual descriptor-relative custody/read boundary.
    """
    if not path or not Path(path).is_absolute() or path != str(Path(path)) or path != os.path.normpath(path):
        return 'INVALID_NONCANONICAL_PATH'
    if any(path == root or path.startswith(root + '/') for root in ('/proc', '/sys', '/dev')):
        return 'INVALID_PSEUDO_FILESYSTEM_PATH'
    if path.startswith(('/etc/systemd/', '/run/systemd/', '/usr/lib/systemd/',
                        '/usr/local/lib/systemd/', '/lib/systemd/')):
        return 'SYSTEMD_CONFIGURATION_LOCATION'
    return 'EXTERNAL_MANAGER_REPORTED_LOCATION'


def review(rows, sources, config):
    by_name = {one(row, 'Id'): row for row in rows}
    need(set(by_name) == EXPECTED, 'TOKEN_UNIT_SET_CHANGED')
    result = []
    for name in sorted(by_name):
        row = by_name[name]
        report = {k: one(row, k) for k in SAFE if k in row}
        report['configurationFilesBound'] = sum(name in f['units'] for f in config.values())
        report['externalConfigurationFilesBound'] = sum(name in f['units'] and
            f.get('locationKind') == 'EXTERNAL_MANAGER_REPORTED_LOCATION' for f in config.values())
        report['needDaemonReload'] = one(row, 'NeedDaemonReload')
        report['otherNamesPresent'] = set(words(row, 'Names')) - {name} != set()
        report['stopPropagationPresent'] = any(words(row, k) for k in ('ConsistsOf', 'PropagatesStopTo', 'BoundBy'))
        report['alsoInstallTargetsPresent'] = any(
            name in f['units'] and re.search(r'(?m)^[ \t]*Also[ \t]*=[ \t]*[^\s#;]', f['text'])
            is not None for f in config.values())
        report['associatedUnits'] = sorted(set(words(row, 'Triggers') + words(row, 'TriggeredBy')))
        if name.endswith('.service') and name not in MASKED:
            for key in ('Type', 'Restart', 'KillMode', 'KillSignal', 'SendSIGKILL',
                        'TimeoutStopUSec', 'RemainAfterExit', 'RuntimeDirectoryPreserve'):
                report[key] = one(row, key)
            report['execStopPresent'] = bool(one(row, 'ExecStop'))
            report['execStopPostPresent'] = bool(one(row, 'ExecStopPost'))
            # Advisory route comparison only. Absence does not prove no writer.
            paths = words(row, 'ReadWritePaths')
            report['declaredWritablePathsOverlapSourceCount'] = sum(
                any(p.lstrip('-+') == s or p.lstrip('-+').startswith(s.rstrip('/') + '/')
                    or s.startswith(p.lstrip('-+').rstrip('/') + '/') for p in paths)
                for s in sources)
        result.append(report)
    return result


def bootstrap():
    for path in (Path('/'), Path('/var'), Path('/var/lib')):
        s = path.lstat()
        need(stat.S_ISDIR(s.st_mode) and s.st_uid == 0 and not s.st_mode & 0o022, 'PROGRAM_ANCESTRY')
    fd = os.open(DRIVER, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as f:
        s = os.fstat(f.fileno())
        need(stat.S_ISREG(s.st_mode) and s.st_uid == 0 and s.st_nlink == 1 and
             stat.S_IMODE(s.st_mode) == 0o600 and s.st_size == 15186, 'DRIVER_METADATA')
        raw = f.read(15187)
    need(hashlib.sha256(raw).hexdigest() == DRIVER_SHA, 'DRIVER_DIGEST')
    d = {'__name__': 'definitions_only', '__file__': str(DRIVER)}
    exec(compile(raw, str(DRIVER), 'exec'), d)
    h, _ = d['bootstrap']()
    return h


def prepare(h, run=command):
    need(not os.path.lexists(AREA), 'PREPARATION_ALREADY_EXISTS_NO_OVERWRITE')
    inputs = {path: h['protected'](Path(path), private=True) for path in PRIOR}
    need(all(h['digest'](inputs[p]) == digest for p, digest in PRIOR.items()), 'PRIOR_ATTEMPT_BINDING')
    legacy = h['decode'](inputs[next(iter(PRIOR))])
    need(len(legacy['sources']) == 34 and len(legacy['runtimeSources']) == 5, 'SOURCE_SET_CHANGED')
    until = time.monotonic() + 60
    patterns = ['ouf-*token*.service', 'ouf-*token*.timer']
    installed = unit_names(run(['list-unit-files', '--no-legend', *patterns], until))
    loaded = unit_names(run(['list-units', '--all', '--plain', '--no-legend', *patterns], until))
    names = {n for n in installed | loaded if '@.' not in n}
    need(names == EXPECTED, 'TOKEN_UNIT_SET_CHANGED')
    rows = property_rows(run(['show', *sorted(names), *['--property=' + k for k in PROPS]], until))
    need({one(row, 'Id') for row in rows} == names, 'SHOW_UNIT_SET_CHANGED')
    config, findings, reads_attempted = {}, [], 0
    for row in rows:
        name = one(row, 'Id')
        if name in MASKED:
            need(one(row, 'LoadState') == 'masked' and one(row, 'ActiveState') == 'inactive', 'MASKED_UNIT_CHANGED')
            continue
        need(one(row, 'LoadState') == 'loaded', 'UNIT_NOT_LOADED')
        fragment = one(row, 'FragmentPath')
        paths = [('FragmentPath', fragment)] + [('DropInPaths', path) for path in words(row, 'DropInPaths')]
        for property_name, path in paths:
            need(time.monotonic() < until, 'CONFIGURATION_READ_BUDGET')
            if path in config:
                config[path]['units'].append(name)
                continue
            location = configuration_path_kind(path)
            context = {'unit': name, 'property': property_name,
                       'pathSha256': h['digest'](path.encode()), 'locationKind': location}
            if location.startswith('INVALID_'):
                findings.append(context | {'reason': 'UNIT_CONFIGURATION_PATH_REQUIRES_REVIEW', 'bodyReadAttempted': False})
                continue
            need(reads_attempted < 64, 'CONFIGURATION_READ_BUDGET')
            reads_attempted += 1
            try:
                raw = h['protected'](Path(path), limit=262144)
                config[path] = {'sha256': h['digest'](raw), 'text': raw.decode('utf-8'),
                                'units': [name], 'locationKind': location}
            except (h['Held'], OSError, UnicodeError) as error:
                # Do not export exception text: OSError may contain private paths.
                findings.append(context | {'reason': 'UNIT_CONFIGURATION_CUSTODY_OR_ENCODING_UNPROVEN',
                    'bodyReadAttempted': True, 'errorType': type(error).__name__,
                    'errno': error.errno if isinstance(error, OSError) else None})
        if one(row, 'NeedDaemonReload') != 'no':
            findings.append({'unit': name, 'reason': 'EFFECTIVE_CONFIGURATION_RELOAD_REQUIRED'})
    reports = review(rows, legacy['sources'], config)
    draft = {'schema': 'ouf.storage-host-containment-draft.v1',
        'createdEpoch': int(time.time()), 'legacyValidUntilEpoch': legacy['validUntilEpoch'],
        'priorInputSha256': PRIOR, 'sources': legacy['sources'],
        'unitProperties': rows, 'unitConfiguration': config, 'findings': findings,
        'configurationReadAttempts': reads_attempted,
        'timerUnits': list(TIMERS), 'serviceUnits': list(SERVICES) + [REGISTRY],
        'maskedUnitsRemainUntouched': list(MASKED),
        'registryInclusionReason': 'Conservative containment of additional active OUF token producer; source disjointness unproven',
        'proposedSequence': [
            'Review exact unit configuration and prepare bounded no-force/no-restart containment executor',
            'Acquire decision for exact host containment and linked new Docker stop/capture operation',
            'Prevent automatic activation of five timers and continuous registry service',
            'Stop timers; let paired oneshots finish within finite budget; stop continuous service without forced kill',
            'Verify all six services inactive and host writer containment remains in effect',
            'Bind stable runtime identities to explicitly new operation retaining prior attempts and original plan expiry',
            'Use qualified Docker stop/capture core; verify host containment before and after capture',
            'Keep OUF offline; transfer encrypted archive to PC and verify isolated restore'],
        'executorImplemented': False, 'serviceMutationsAuthorized': False,
        'coherentSystemdSnapshotProven': False,
        'currentTokenAuthenticityProven': False, 'writerCensusComplete': False,
        'automaticReplayAllowed': False, 'automaticRestartAllowed': False,
        'runtimeAuthorityIssued': False, 'acceptanceCreditAdded': 0}
    raw = h['canonical'](draft)
    need(len(raw) <= 16 << 20 and time.monotonic() < until, 'PREPARATION_BUDGET')
    summary = {'schema': 'ouf.storage-host-containment-preparation.v1',
        'status': 'HOST_CONTAINMENT_DRAFT_PREPARED_REVIEW_REQUIRED',
        'candidateFile': str(AREA / 'draft.private.json'), 'candidateSha256': h['digest'](raw),
        'legacyPlanSha256': next(iter(PRIOR.values())), 'legacyValidUntilEpoch': legacy['validUntilEpoch'],
        'legacyPlanUnexpiredAtPreparation': int(time.time()) < legacy['validUntilEpoch'],
        'units': reports, 'unitConfigurationFilesBound': len(config), 'findings': findings,
        'configurationReadAttempts': reads_attempted,
        'proposedTimerUnits': list(TIMERS), 'proposedServiceUnits': list(SERVICES) + [REGISTRY],
        'registryIncludedConservatively': True, 'wholeBackupSourcesConsidered': len(legacy['sources']),
        'oldPlanOrAttemptModified': False, 'runtimeCredentialBodiesRead': 0,
        'unitConfigurationMayContainSecretsRetainedPrivately': True,
        'systemctlReadCommands': 3, 'serviceMutations': 0, 'dockerRequests': 0, 'iamRequests': 0,
        'filesWritten': 2, 'executorImplemented': False, 'targetStopOrCaptureAuthorized': False,
        'coherentSystemdSnapshotProven': False,
        'automaticReplayAllowed': False, 'automaticRestartAllowed': False,
        'runtimeAuthorityIssued': False, 'acceptanceCreditAdded': 0}
    # New, private preparatory files only. Preserve partial writes; no overwrite.
    AREA.mkdir(mode=0o700)
    h['new'](AREA / 'draft.private.json', raw)
    h['new'](AREA / 'result.json', h['canonical'](summary))
    return summary


if __name__ == '__main__':
    try:
        need(os.geteuid() == os.getegid() == 0 and sys.flags.isolated and sys.flags.no_site
             and sys.dont_write_bytecode, 'ROOT_ISOLATED_PYTHON_REQUIRED')
        print(json.dumps(prepare(bootstrap()), sort_keys=True))
    except Exception as error:
        reason = str(error) if type(error).__name__ in ('Held', 'ValueError') else type(error).__name__
        print(json.dumps({'status': 'HELD', 'reason': reason, 'partialPreparationPreserved': True,
            'serviceMutations': 0, 'automaticReplayAllowed': False, 'automaticRestartAllowed': False,
            'runtimeAuthorityIssued': False, 'acceptanceCreditAdded': 0}))
        sys.exit(2)

