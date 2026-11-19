#!/usr/bin/env python3
"""Closed operator entry for exact archives and a conditional two-owner plan."""
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
    spec = importlib.util.spec_from_file_location('managed_csv_image_plan', folder/'image_plan.py')
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    scope = None
    try:
        module.require(len(sys.argv) == 3 and os.geteuid() == os.getegid() == 0
                       and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode
                       and os.environ.get('SUDO_UID') == str(pwd.getpwnam('oufadmin').pw_uid),
                       'ISOLATED_OUFADMIN_ROOT_IMAGE_PLAN_REQUIRED')
        module.require(Path(sys.argv[1]) == folder/'onboarding.zip' and Path(sys.argv[2]) == folder/'mcp.zip',
                       'TWO_EXACT_SEALED_ZIP_PATHS_REQUIRED')
        signal.signal(signal.SIGALRM, lambda *_: module.require(False, 'FINITE_IMAGE_PLAN_WINDOW_EXPIRED')); signal.alarm(300)
        case = module.decode((folder/'case.json').read_bytes())
        module.require(case['schema'] == 'ouf.managed-csv-control-image-plan-case.v1' and case['targetApplyAuthorized'] is False,
                       'EXACT_CLOSED_METADATA_IMAGE_CASE_REQUIRED')
        scope = module.Scope(case['outputRoot'])
        helpers = {name: module.load_module(folder, name+'.py', checksum) for name, checksum in case['helperHashes'].items()}
        receipts = {role: module.decode((folder/(role+'-custody.json')).read_bytes()) for role in ('onboarding', 'mcp')}
        result = module.prepare(scope, case, receipts, {'onboarding': Path(sys.argv[1]), 'mcp': Path(sys.argv[2])},
                                helpers['plan_helper'], helpers['retained_mac'], helpers['image_custody'], helpers['stage_image'].unpack)
    except BaseException as error:
        reason = str(error) if isinstance(error, module.Stop) and re.fullmatch('[A-Z0-9_]{1,120}', str(error)) else 'PRIVATE_IMAGE_PLAN_UNPROVEN_RECONCILE'
        result = {'schema': 'ouf.managed-csv-control-image-plan-result.v1', 'status': 'STOP_RECONCILE', 'reasonCode': reason,
                  'complete': False, 'counts': dict(scope.counts) if scope else {}, 'runtimeAuthorityIssued': False,
                  'automaticReplayAllowed': False, 'budgetReset': False, 'applicationE2EProven': False, 'releaseAcceptance': False}
        if scope is not None and not (scope.root/'result.json').exists():
            module.put(scope.root/'result.json', result)
    finally:
        signal.alarm(0)
    print(json.dumps(result, sort_keys=True, separators=(',', ':')), flush=True)
    return 0 if result['complete'] else 2


if __name__ == '__main__':
    raise SystemExit(main())
