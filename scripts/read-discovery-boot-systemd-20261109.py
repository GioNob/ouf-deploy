#!/usr/bin/env python3
"""Report the failed loaded-unit predicate; four bounded reads, no activation."""
import json
import subprocess
import tempfile
from datetime import datetime, timezone

PROPERTIES = ('LoadState','ActiveState','SubState','MainPID','ControlPID','NeedDaemonReload','FragmentPath',
              'DropInPaths','ExecStart','ExecStartPre','User','Group','RootDirectory','RootImage','ProtectSystem',
              'ReadWritePaths','ReadOnlyPaths','InaccessiblePaths','PrivateNetwork','PrivateUsers')
UNITS = ('ouf-semantic-boot-guard.service', 'docker.service')
VISIBLE = ('LoadState','ActiveState','SubState','MainPID','ControlPID','NeedDaemonReload')
ENV = {'PATH':'/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL':'C'}


def inspect(unit, include_empty):
    args = ['/usr/bin/systemctl','show',unit,'--property='+','.join(PROPERTIES),'--no-pager']
    if include_empty:
        args.append('--all')
    with tempfile.TemporaryFile() as output:
        result = subprocess.run(args, stdin=subprocess.DEVNULL, stdout=output,
                                stderr=subprocess.DEVNULL, timeout=15, env=ENV)
        output.seek(0)
        raw = output.read(65537)
    if result.returncode != 0 or len(raw) > 65536:
        raise RuntimeError('SYSTEMD_READ_FAILED')
    rows = {}
    for line in raw.decode('utf-8').splitlines():
        key, sep, value = line.partition('=')
        if not sep or key in rows:
            raise RuntimeError('TYPED_SYSTEMD_METADATA_REQUIRED')
        rows[key] = value
    return {
        'withAll': include_empty,
        'missingProperties': sorted(set(PROPERTIES)-set(rows)),
        'unexpectedPropertyCount': len(set(rows)-set(PROPERTIES)),
        'emptyProperties': sorted(k for k in PROPERTIES if rows.get(k) == ''),
        'state': {k:rows.get(k) for k in VISIBLE},
        'failedPredicates': [name for name, ok in (
            ('completePropertySet',set(rows)==set(PROPERTIES)),
            ('loaded',rows.get('LoadState')=='loaded'),
            ('noPendingReload',rows.get('NeedDaemonReload')=='no'),
            ('noControlProcess',rows.get('ControlPID')=='0')) if not ok]
    }


def main():
    report = {'schema':'ouf.discovery-boot-systemd-read.v1',
              'observedAt':datetime.now(timezone.utc).isoformat(), 'status':'HELD',
              'unitReads':[], 'serviceChanges':0, 'daemonReloads':0,
              'activationAttempted':False, 'automaticReplayAllowed':False,
              'credentialFileContentsRead':0, 'snapshotAtomic':False}
    try:
        for unit in UNITS:
            for include_empty in (False, True):
                report['unitReads'].append({'unit':unit, **inspect(unit, include_empty)})
        report['status'] = 'SYSTEMD_BOOT_PREDICATES_READ'
    except Exception as exc:
        report['reason'] = str(exc) if type(exc) is RuntimeError else type(exc).__name__
    print(json.dumps(report, sort_keys=True))
    return 0 if report['status'] == 'SYSTEMD_BOOT_PREDICATES_READ' else 1


if __name__ == '__main__':
    raise SystemExit(main())
