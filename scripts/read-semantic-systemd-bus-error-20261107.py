#!/usr/bin/env python3
"""Read the exact failed D-Bus stage; never start/load/change a service."""
import datetime
import json
import re
import subprocess

SERVICE = 'ouf-registry-token-7cb59501000058b5dc5030ad.service'
HOOKS = ('ExecStartPre', 'ExecStartPost', 'ExecCondition')

def main():
    report = {'schema': 'ouf.semantic-systemd-bus-diagnostic.v1', 'status': 'READ_INCOMPLETE',
              'service': SERVICE, 'calls': [], 'serviceConfigurationChanged': False,
              'serviceStartDispatched': False, 'credentialFilesRead': 0,
              'credentialValuesEmitted': False, 'successfulHookValuesEmitted': False}
    def call(phase, args):
        row = {'phase': phase}
        report['calls'].append(row)
        try:
            result = subprocess.run(('/usr/bin/busctl', '--system', '--no-pager', *args),
                stdin=subprocess.DEVNULL, capture_output=True, timeout=15,
                env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'})
            row.update(exitCode=result.returncode, stdoutBytes=len(result.stdout), stderrBytes=len(result.stderr))
            if result.returncode:
                # Only errors from these fixed metadata reads; never journal or hook output.
                row['errorMessage'] = result.stderr[:2048].decode('utf-8', errors='replace').strip()
                row['errorTruncated'] = len(result.stderr) > 2048
                return None
            return result.stdout.decode('utf-8', errors='replace').strip()
        except (OSError, subprocess.TimeoutExpired) as exc:
            row['errorClass'] = type(exc).__name__
            return None
    raw = call('GET_UNIT', ('call', 'org.freedesktop.systemd1', '/org/freedesktop/systemd1',
                           'org.freedesktop.systemd1.Manager', 'GetUnit', 's', SERVICE))
    if raw is not None:
        match = re.fullmatch(r'o "(/org/freedesktop/systemd1/unit/[A-Za-z0-9_]+)"', raw)
        report['unitObjectPathValid'] = bool(match)
        if match:
            for name in HOOKS:
                value = call(name, ('get-property', 'org.freedesktop.systemd1', match.group(1),
                                   'org.freedesktop.systemd1.Service', name))
                if value is not None:
                    report['calls'][-1]['typedEmptyArray'] = value == 'a(sasbttttuii) 0'
                    shape = re.match(r'^([a-z(){}]+) ([0-9]+)(?: |$)', value)
                    if shape:
                        report['calls'][-1].update(typeSignature=shape.group(1), elementCount=int(shape.group(2)))
            report['status'] = 'BUS_METADATA_RESULTS_RECORDED'
    report['observedAt'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    print(json.dumps(report, sort_keys=True))

if __name__ == '__main__':
    main()
