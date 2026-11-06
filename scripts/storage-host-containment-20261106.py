#!/usr/bin/env python3
"""One explicit host-only maintenance attempt. Never starts, replays or captures.
All configuration and mutation receipts stay private. Operator decision provenance
is not authenticated HUMAN/THS or a runtime authority grant.
"""
import argparse
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

READER = Path('/var/lib/ouf-storage-host-preparation-reader-20261106.py')
READER_SHA = 'caac2981e43b96150bc0875405facfc4cb34ad8b188adc210e4ed214bb5bf5b1'
DRAFT = Path('/var/lib/ouf-storage-host-containment-preparation-20261106-v1/draft.private.json')
DRAFT_SHA = 'c4d59b3894f59d6679f11d48dbec2a3d7f5cbba6c8aa89bbee78b63e86475d0a'
AREA = Path('/var/lib/ouf-storage-host-containment-20261106-v1')
SYSTEMD_ROOT = Path('/etc/systemd/system')
OVERRIDE_NAME = 'zzzz-ouf-storage-offline-20261106.conf'
OVERRIDE = b'[Service]\nRestart=no\nSendSIGKILL=no\nRuntimeDirectoryPreserve=yes\nTimeoutStopSec=120s\n'
EXTRA = ('RefuseManualStop', 'OnFailure', 'OnSuccess', 'ControlPID')
EMPTY_DEPENDENCIES = ('Following', 'PartOf', 'ConsistsOf', 'PropagatesStopTo', 'BoundBy', 'OnFailure', 'OnSuccess')
STABLE_COMMON = ('FragmentPath', 'DropInPaths', 'Names', 'Following', 'PartOf', 'ConsistsOf', 'PropagatesStopTo', 'BoundBy', 'Triggers', 'TriggeredBy')
STABLE_SERVICE = ('Type', 'Restart', 'KillMode', 'KillSignal', 'SendSIGKILL', 'TimeoutStopUSec', 'RemainAfterExit', 'RuntimeDirectoryPreserve', 'ReadWritePaths', 'ReadOnlyPaths', 'StateDirectory', 'RuntimeDirectory', 'WorkingDirectory', 'RootDirectory')


def need(ok, reason):
    if not ok:
        raise ValueError(reason)


def bootstrap():
    for path in (Path('/'), Path('/var'), Path('/var/lib')):
        s = path.lstat()
        need(stat.S_ISDIR(s.st_mode) and s.st_uid == 0 and not s.st_mode & 0o022, 'PROGRAM_ANCESTRY')
    fd = os.open(READER, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as f:
        s = os.fstat(f.fileno())
        need(stat.S_ISREG(s.st_mode) and s.st_uid == 0 and s.st_nlink == 1 and
             stat.S_IMODE(s.st_mode) == 0o600 and s.st_size == 18228, 'READER_METADATA')
        raw = f.read(18229)
    need(hashlib.sha256(raw).hexdigest() == READER_SHA, 'READER_DIGEST')
    import types
    p = types.ModuleType('pinned_preparation_definitions')
    p.__file__ = str(READER)
    exec(compile(raw, str(READER), 'exec'), p.__dict__)
    return p, p.bootstrap()


class Runner:
    def __init__(self, h, root):
        self.h, self.root = h, root
        self.until = time.monotonic() + 600
        self.calls = self.bytes = self.mutations = 0
        self.cgroups = {}

    def run(self, binary, args, mutation=False):
        need(binary in ('systemctl', 'busctl'), 'CLI_NOT_ALLOWED')
        need(self.calls < 256 and time.monotonic() < self.until and self.bytes < 32 << 20, 'HOST_COMMAND_BUDGET')
        if binary == 'systemctl':
            need(args[0] in (('disable', 'stop', 'daemon-reload') if mutation else ('show', 'list-units', 'list-unit-files')), 'SYSTEMCTL_COMMAND_KIND')
        else:
            need(not mutation and args[0] in ('call', 'get-property'), 'BUSCTL_READ_ONLY')
            if args[0] == 'call':
                need(len(args) == 7 and args[1:4] == ['org.freedesktop.systemd1', '/org/freedesktop/systemd1', 'org.freedesktop.systemd1.Manager']
                     and args[4] in ('GetUnit', 'GetUnitProcesses') and args[5] == 's', 'BUSCTL_METHOD_NOT_ALLOWED')
            else:
                need(args[1] == 'org.freedesktop.systemd1' and
                     (len(args) == 6 and args[3:] == ['org.freedesktop.systemd1.Service', 'ExecStop', 'ExecStopPost'] or
                      len(args) == 5 and args[3:] == ['org.freedesktop.systemd1.Slice', 'ControlGroup']), 'BUSCTL_PROPERTY_NOT_ALLOWED')
        self.calls += 1
        if mutation:
            self.mutations += 1
            self.h['new'](self.root / ('action-%03d.intent.json' % self.mutations), self.h['canonical']({'binary': binary, 'args': args, 'ordinal': self.mutations}))
        flags = ['--no-ask-password'] if binary == 'systemctl' else ['--allow-interactive-authorization=no']
        argv = ['/usr/bin/' + binary, '--no-pager', *flags, *args]
        child = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C', 'SYSTEMD_PAGER': 'cat'}, start_new_session=True)
        selector = selectors.DefaultSelector()
        buffers = {child.stdout: bytearray(), child.stderr: bytearray()}
        for stream in buffers:
            selector.register(stream, selectors.EVENT_READ)
        deadline = min(self.until, time.monotonic() + 15)
        try:
            while selector.get_map():
                need(time.monotonic() < deadline, 'HOST_CLI_TIMEOUT_OUTCOME_REQUIRES_REVIEW')
                for key, _ in selector.select(min(0.2, max(0, deadline - time.monotonic()))):
                    raw = os.read(key.fileobj.fileno(), 65536)
                    if not raw:
                        selector.unregister(key.fileobj)
                        continue
                    buffers[key.fileobj].extend(raw)
                    self.bytes += len(raw)
                    need(sum(map(len, buffers.values())) <= 1 << 20 and self.bytes <= 32 << 20, 'HOST_CLI_OUTPUT_BUDGET')
            rc = child.wait(timeout=max(.01, deadline - time.monotonic()))
            out, err = bytes(buffers[child.stdout]), bytes(buffers[child.stderr])
            self.h['new'](self.root / ('command-%03d.private.json' % self.calls), self.h['canonical']({'binary': binary, 'args': args, 'returncode': rc, 'stdout': out.decode(), 'stderr': err.decode()}))
            if mutation:
                self.h['new'](self.root / ('action-%03d.reply.json' % self.mutations), self.h['canonical']({'returncode': rc, 'command': self.calls}))
            need(rc == 0, 'HOST_CLI_FAILED_NO_RETRY')
            return out.decode()
        finally:
            selector.close()
            if child.poll() is None:
                os.killpg(child.pid, signal.SIGKILL)  # Local CLI only, never a service.
                child.wait(timeout=5)
            for stream in buffers:
                stream.close()


def show(p, run):
    props = tuple(dict.fromkeys(p.PROPS + EXTRA + ('Slice',)))
    old = p.PROPS
    try:
        p.PROPS = props
        rows = p.property_rows(run.run('systemctl', ['show', '--all', *sorted(p.EXPECTED), *['--property=' + k for k in props]]))
    finally:
        p.PROPS = old
    need({p.one(r, 'Id') for r in rows} == p.EXPECTED, 'HOST_UNIT_MEMBERSHIP')
    return {p.one(r, 'Id'): r for r in rows}


def object_path(run, unit):
    raw = run.run('busctl', ['call', 'org.freedesktop.systemd1', '/org/freedesktop/systemd1',
        'org.freedesktop.systemd1.Manager', 'GetUnit', 's', unit]).strip()
    match = re.fullmatch(r'o "(/org/freedesktop/systemd1/unit/[A-Za-z0-9_]+)"', raw)
    need(match is not None, 'TYPED_UNIT_OBJECT_REQUIRED')
    return match.group(1)


def empty_stop_hooks(run, unit):
    path = object_path(run, unit)
    raw = run.run('busctl', ['get-property', 'org.freedesktop.systemd1', path,
        'org.freedesktop.systemd1.Service', 'ExecStop', 'ExecStopPost'])
    need(raw.splitlines() == ['a(sasbttttuii) 0', 'a(sasbttttuii) 0'], 'TYPED_EMPTY_STOP_HOOKS_REQUIRED_' + unit)


def cgroup_root():
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for name in ('sys', 'fs', 'cgroup'):
            nxt = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd); fd = nxt
        marker = os.open('cgroup.controllers', os.O_RDONLY | os.O_NOFOLLOW, dir_fd=fd)
        os.close(marker)
        return fd
    except BaseException:
        os.close(fd)
        raise


def cgroup_empty(path):
    need(path.startswith('/') and path != '/' and str(Path(path)) == path and
         os.path.normpath(path) == path, 'CANONICAL_NONROOT_CGROUP_REQUIRED')
    fd = cgroup_root()
    try:
        for name in Path(path).parts[1:]:
            try:
                nxt = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            except FileNotFoundError:
                return True  # The exact bound cgroup no longer exists.
            os.close(fd); fd = nxt
        event = os.open('cgroup.events', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
        try:
            raw = os.read(event, 4097)
        finally:
            os.close(event)
        need(len(raw) <= 4096, 'CGROUP_EVENTS_SIZE')
        pairs = [line.split() for line in raw.decode('ascii').splitlines()]
        need(all(len(pair) == 2 for pair in pairs) and len({pair[0] for pair in pairs}) == len(pairs), 'CGROUP_EVENTS_SHAPE')
        values = dict(pairs)
        need(values.get('populated') in ('0', '1'), 'CGROUP_POPULATED_REQUIRED')
        return values['populated'] == '0'
    finally:
        os.close(fd)


def valid_slice_name(name):
    # Keep systemd's escaped name verbatim for GetUnit; never unescape into a path.
    return (len(name) <= 255 and
            re.fullmatch(r'(?:[A-Za-z0-9_:.-]|\\x[0-9a-fA-F]{2})+\.slice', name) is not None)


def bind_cgroups(p, run, rows):
    fd = cgroup_root(); os.close(fd)
    for unit in tuple(p.SERVICES) + (p.REGISTRY,):
        path = p.one(rows[unit], 'ControlGroup')
        if not path:
            slice_name = p.one(rows[unit], 'Slice')
            need(valid_slice_name(slice_name), 'SLICE_NAME_REQUIRED')
            raw = run.run('busctl', ['get-property', 'org.freedesktop.systemd1', object_path(run, slice_name),
                'org.freedesktop.systemd1.Slice', 'ControlGroup']).strip()
            need(raw.startswith('s '), 'TYPED_SLICE_CGROUP_REQUIRED')
            parent = json.loads(raw[2:])
            need(isinstance(parent, str) and parent.startswith('/'), 'SLICE_CGROUP_REQUIRED')
            path = parent.rstrip('/') + '/' + unit
        need(path.startswith('/') and path.endswith('/' + unit) and os.path.normpath(path) == path, 'EXACT_UNIT_CGROUP_REQUIRED')
        run.cgroups[unit] = path


def no_processes(run, unit):
    need(cgroup_empty(run.cgroups[unit]), 'UNIT_CGROUP_REMAINS_POPULATED')


def verify_files(h, draft):
    for path, row in draft['unitConfiguration'].items():
        raw = h['protected'](Path(path), limit=262144)
        need(h['digest'](raw) == row['sha256'], 'UNIT_CONFIGURATION_CHANGED')
        need(not re.search(rb'(?m)^[ \t]*(?:Also|Alias)[ \t]*=[ \t]*[^\s#;]', raw), 'INSTALL_ALSO_OR_ALIAS_REQUIRES_REVIEW')


def check_units(p, rows, draft, patched=False):
    prior = {p.one(r, 'Id'): r for r in draft['unitProperties']}
    for unit, row in rows.items():
        if unit in p.MASKED:
            need(p.one(row, 'LoadState') == 'masked' and p.one(row, 'ActiveState') == 'inactive', 'MASKED_PAIR_CHANGED')
            continue
        need(p.one(row, 'LoadState') == 'loaded' and p.one(row, 'NeedDaemonReload') == 'no', 'EFFECTIVE_UNIT_CONFIGURATION_REQUIRED')
        need(p.words(row, 'Names') == [unit] and p.one(row, 'RefuseManualStop') == 'no', 'UNIT_ALIAS_OR_REFUSED_STOP')
        need(all(p.words(row, k) == [] for k in EMPTY_DEPENDENCIES), 'UNIT_STOP_PROPAGATION_OR_TRIGGER')
        common = STABLE_COMMON if not patched else tuple(k for k in STABLE_COMMON if k not in ('DropInPaths', 'Triggers', 'TriggeredBy'))
        for key in common:
            need(row.get(key) == prior[unit].get(key), 'UNIT_CONFIGURATION_PROPERTY_CHANGED_' + key)
        if unit in p.TIMERS:
            need(p.words(row, 'Triggers') == [unit[:-6] + '.service'] and not p.words(row, 'TriggeredBy'), 'TIMER_TRIGGER_SCOPE')
        else:
            allowed_trigger = [] if unit == p.REGISTRY else [unit[:-8] + '.timer']
            need(not p.words(row, 'Triggers') and set(p.words(row, 'TriggeredBy')) <= set(allowed_trigger), 'UNEXPECTED_SERVICE_TRIGGER')
            need(p.one(row, 'Type') == ('simple' if unit == p.REGISTRY else 'oneshot') and
                 p.one(row, 'RemainAfterExit') == 'no' and p.one(row, 'KillMode') == 'control-group' and
                 p.one(row, 'KillSignal') == '15', 'SERVICE_STOP_PROFILE')
            if not patched:
                for key in STABLE_SERVICE:
                    need(row.get(key) == prior[unit].get(key), 'SERVICE_CONFIGURATION_CHANGED_' + key)
            else:
                for key, value in {'Restart': 'no', 'SendSIGKILL': 'no', 'RuntimeDirectoryPreserve': 'yes', 'TimeoutStopUSec': '2min'}.items():
                    need(p.one(row, key) == value, 'OFFLINE_OVERRIDE_NOT_EFFECTIVE_' + key)
                expected = p.words(prior[unit], 'DropInPaths') + [str(SYSTEMD_ROOT / (unit + '.d') / OVERRIDE_NAME)]
                need(set(p.words(row, 'DropInPaths')) == set(expected), 'UNEXPECTED_EFFECTIVE_DROPIN')
    return rows


def wait_inactive(p, run, units, timeout=120):
    until = min(run.until, time.monotonic() + timeout)
    while True:
        rows = show(p, run)
        for unit in units:
            if unit.endswith('.service'):
                current = p.one(rows[unit], 'ControlGroup')
                need(not current or current == run.cgroups[unit], 'UNIT_CGROUP_CHANGED')
        for unit in p.MASKED:
            need(p.one(rows[unit], 'LoadState') == 'masked' and p.one(rows[unit], 'ActiveState') == 'inactive', 'MASKED_PAIR_CHANGED')
        inactive = all(p.one(rows[n], 'ActiveState') == 'inactive' and p.one(rows[n], 'SubState') == 'dead'
                       and (not n.endswith('.service') or p.one(rows[n], 'MainPID') == p.one(rows[n], 'ControlPID') == '0')
                       and p.one(rows[n], 'Job') == '' for n in units)
        if inactive:
            for unit in units:
                if unit.endswith('.service'):
                    no_processes(run, unit)
            return rows
        need(time.monotonic() < until, 'HOST_NATURAL_STOP_TIMEOUT_NO_KILL')
        time.sleep(min(2, max(0, until - time.monotonic())))


def containment(h, p, draft, root, run, decision, runtime_sources):
    services = tuple(p.SERVICES) + (p.REGISTRY,)
    verify_files(h, draft)
    rows = check_units(p, show(p, run), draft)
    need(all(p.one(rows[n], 'UnitFileState') == 'enabled' for n in tuple(p.TIMERS) + (p.REGISTRY,)), 'ENABLEMENT_CHANGED')
    for unit in services:
        empty_stop_hooks(run, unit)  # Typed zero-length arrays, not omitted CLI fields.
    bind_cgroups(p, run, rows)
    verify_files(h, draft)
    # No pre-existing override is adopted, overwritten or removed.
    fd = h['runtime_parent'](SYSTEMD_ROOT / 'custody-check-only')
    os.close(fd)
    for unit in services:
        path = SYSTEMD_ROOT / (unit + '.d') / OVERRIDE_NAME
        need(not os.path.lexists(path), 'HOST_OVERRIDE_ALREADY_EXISTS')
        parent = path.parent
        if os.path.lexists(parent):
            fd = h['runtime_parent'](path)
            os.close(fd)
    h['new'](root / 'preflight.private.json', h['canonical']({'unitRows': rows, 'typedEmptyStopHooks': list(services), 'unitCgroups': run.cgroups}))
    for index, unit in enumerate(services):
        path = SYSTEMD_ROOT / (unit + '.d') / OVERRIDE_NAME
        h['new'](root / ('file-%02d.intent.json' % index), h['canonical']({'path': str(path), 'sha256': h['digest'](OVERRIDE)}))
        try:
            path.parent.mkdir(mode=0o755)
        except FileExistsError:
            pass
        fd = h['runtime_parent'](path)
        os.close(fd)
        h['new'](path, OVERRIDE)
        h['new'](root / ('file-%02d.reply.json' % index), h['canonical']({'written': True}))
    for unit in tuple(p.TIMERS) + (p.REGISTRY,):
        run.run('systemctl', ['disable', '--no-reload', unit], mutation=True)
    run.run('systemctl', ['daemon-reload'], mutation=True)
    rows = check_units(p, show(p, run), draft, patched=True)
    need(all(p.one(rows[n], 'UnitFileState') == 'disabled' for n in tuple(p.TIMERS) + (p.REGISTRY,)), 'DISABLE_POSTCONDITION')
    for unit in p.TIMERS:
        run.run('systemctl', ['stop', '--no-block', unit], mutation=True)
    wait_inactive(p, run, tuple(p.TIMERS) + tuple(p.SERVICES))
    # Oneshots have finished naturally. Only the continuous registry receives stop.
    run.run('systemctl', ['stop', '--no-block', p.REGISTRY], mutation=True)
    rows = wait_inactive(p, run, tuple(p.TIMERS) + services)
    check_units(p, rows, draft, patched=True)
    verify_files(h, draft)
    first = {path: h['runtime_source_identity'](path) for path in runtime_sources}
    need(time.monotonic() < run.until, 'HOST_TOTAL_BUDGET')
    second = {path: h['runtime_source_identity'](path) for path in runtime_sources}
    need(first == second, 'RUNTIME_WRITER_STILL_CHANGING_SOURCE')
    rows = wait_inactive(p, run, tuple(p.TIMERS) + services, timeout=0)
    check_units(p, rows, draft, patched=True)
    need(all(p.one(rows[n], 'UnitFileState') == 'disabled' for n in tuple(p.TIMERS) + (p.REGISTRY,)), 'FINAL_DISABLE_POSTCONDITION')
    need(time.monotonic() < run.until, 'HOST_TOTAL_BUDGET')
    h['new'](root / 'runtime-snapshot.private.json', h['canonical'](second))
    h['new'](root / 'final-units.private.json', h['canonical'](rows))
    result = {'schema': 'ouf.storage-host-containment-result.v1', 'status': 'HOST_WRITERS_CONTAINED_NEW_STOP_PLAN_REQUIRED',
        'decisionReference': decision, 'draftSha256': h['digest'](h['canonical'](draft)),
        'overrideFilesWritten': len(services), 'timersDisabledAndStopped': len(p.TIMERS),
        'registryDisabledAndStopped': True, 'oneshotsInactiveWithoutStopCommand': len(p.SERVICES),
        'typedEmptyStopHooksVerified': len(services) * 2, 'runtimeSourcesStableAtObservation': len(second),
        'runtimeSnapshotSha256': h['digest'](h['canonical'](second)), 'legacyValidUntilEpoch': draft['legacyValidUntilEpoch'],
        'commandCalls': run.calls, 'mutationCommands': run.mutations, 'cliOutputBytes': run.bytes,
        'forcedServiceKills': 0, 'automaticReplayAllowed': False, 'automaticRestartAllowed': False,
        'runtimeAuthorityIssued': False, 'writerCensusComplete': False, 'applicationDrainProven': False,
        'dockerRequests': 0, 'iamRequests': 0, 'targetCapturePerformed': False, 'acceptanceCreditAdded': 0}
    h['new'](root / 'result.json', h['canonical'](result))
    return result


def apply(h, p, decision):
    raw = h['protected'](DRAFT, private=True)
    need(h['digest'](raw) == DRAFT_SHA, 'EXACT_REVIEWED_DRAFT_REQUIRED')
    draft = h['decode'](raw)
    need(draft['timerUnits'] == list(p.TIMERS) and draft['serviceUnits'] == list(p.SERVICES) + [p.REGISTRY], 'EXACT_HOST_SCOPE')
    need(int(time.time()) + 5400 < draft['legacyValidUntilEpoch'], 'ORIGINAL_PLAN_WINDOW_INSUFFICIENT')
    need(all(f.get('reason') == 'PROPERTY_CARDINALITY' and f.get('property') in ('ExecStop', 'ExecStopPost') and f.get('occurrences') == 0 for f in draft['findings']), 'OTHER_DRAFT_FINDINGS_REQUIRE_REVIEW')
    for path, sha in draft['priorInputSha256'].items():
        need(h['digest'](h['protected'](Path(path), private=True)) == sha, 'PRIOR_ATTEMPT_CHANGED')
    old = h['decode'](h['protected'](Path(next(iter(p.PRIOR))), private=True))
    sources = sorted(old['runtimeSources'])
    need(len(sources) == 5, 'EXACT_RUNTIME_SOURCES')
    AREA.mkdir(mode=0o700)  # Permanent one-shot claim before any provider query.
    h['new'](AREA / 'claim.private.json', h['canonical']({'draftSha256': DRAFT_SHA, 'decisionReference': decision,
        'attempts': 1, 'maximumSeconds': 600, 'maximumCliCalls': 256, 'maximumCliBytes': 32 << 20,
        'priorInputSha256': draft['priorInputSha256'], 'legacyValidUntilEpoch': draft['legacyValidUntilEpoch'],
        'automaticReplayAllowed': False, 'runtimeAuthorityIssued': False}))
    h['new'](AREA / 'reviewed-draft.private.json', raw)
    return containment(h, p, draft, AREA, Runner(h, AREA), decision, sources)


if __name__ == '__main__':
    try:
        need(os.geteuid() == os.getegid() == 0 and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode, 'ROOT_ISOLATED_PYTHON_REQUIRED')
        parser = argparse.ArgumentParser()
        parser.add_argument('--decision-reference', required=True)
        parser.add_argument('--exclusive-operator-maintenance', action='store_true', required=True)
        parser.add_argument('--nonproduction-test-state', action='store_true', required=True)
        args = parser.parse_args()
        need(re.fullmatch(r'[A-Z0-9-]{8,100}', args.decision_reference) is not None, 'DECISION_REFERENCE_FORMAT')
        p, h = bootstrap()
        print(json.dumps(apply(h, p, args.decision_reference), sort_keys=True))
    except Exception as error:
        reason = str(error) if type(error).__name__ in ('Held', 'ValueError', 'PropertyIssue') else type(error).__name__
        print(json.dumps({'status': 'HELD', 'reason': reason, 'partialOperationPreserved': True,
            **({'propertyIssue': error.details} if hasattr(error, 'details') else {}),
            'automaticReplayAllowed': False, 'automaticRestartAllowed': False,
            'runtimeAuthorityIssued': False, 'acceptanceCreditAdded': 0}))
        sys.exit(2)
