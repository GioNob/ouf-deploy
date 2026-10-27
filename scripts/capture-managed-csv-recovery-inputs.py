#!/usr/bin/env python3
"""Sealed read-only operator entry; not an installation or domain approval."""
import importlib.util
import json
import os
from pathlib import Path
import pwd
import re
import signal
import sys


def main():
    folder = Path(__file__).resolve().parent
    spec = importlib.util.spec_from_file_location('retained_csv_inputs', folder/'retained_inputs.py')
    core = importlib.util.module_from_spec(spec); spec.loader.exec_module(core)
    capture = None
    try:
        core.require(len(sys.argv) == 1 and os.geteuid() == os.getegid() == 0
                     and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode
                     and os.environ.get('SUDO_UID') == str(pwd.getpwnam('oufadmin').pw_uid),
                     'ISOLATED_OUFADMIN_ROOT_CAPTURE_REQUIRED')
        case = core.decode((folder/'case.json').read_bytes())
        core.require(case['schema'] == 'ouf.managed-csv-recovery-capture-case.v1'
                     and case['targetApplyAuthorized'] is False, 'READ_ONLY_CAPTURE_CASE_REQUIRED')
        signal.signal(signal.SIGALRM, lambda *_: core.require(False, 'FINITE_CAPTURE_WINDOW_EXPIRED'))
        signal.alarm(core.MAXIMUMS['seconds'])
        capture = core.Capture(case['outputRoot'], case['cohortSize'])
        result = core.prepare(capture, case)
    except BaseException as error:
        reason = str(error) if isinstance(error, core.Stop) and re.fullmatch('[A-Z0-9_]{1,120}', str(error)) else 'PRIVATE_CAPTURE_FAILURE_RECONCILE'
        result = {'schema': 'ouf.managed-csv-recovery-input-capture-result.v1', 'status': 'STOP_RECONCILE',
                  'complete': False, 'reasonCode': reason, 'counts': dict(capture.counts) if capture else {},
                  'runtimeAuthorityIssued': False, 'containerWrites': 0, 'automaticReplayAllowed': False,
                  'budgetReset': False, 'applicationE2EProven': False, 'releaseAcceptance': False}
        if capture is not None and not (capture.root/'result.json').exists():
            capture.put('result.json', result)
    finally:
        signal.alarm(0)
    print(json.dumps(result, sort_keys=True, separators=(',', ':')), flush=True)
    return 0 if result['complete'] else 2


if __name__ == '__main__':
    raise SystemExit(main())
