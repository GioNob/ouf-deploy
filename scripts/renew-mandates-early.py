#!/usr/bin/env python3
"""Task-33: one governed early renewal with the INSTALLED renewal job (D-028, D-030).

Loads the installed renewal.py from its verified bytes (configuration hash
pinned in the installed unit), validates the configuration with the original
T-30 threshold, then lowers the threshold to window - 1 day for this single
run. Everything else is production code: coherence, D-018 preconditions,
generations, versioned base, status and incident. Plan is read only.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import types

CONFIGURATION = '/etc/ouf/authority-mandate-renewal/configuration.json'
EARLY_MARGIN_SECONDS = 86400
PLAN_SCHEMA = 'ouf.semantic-mandate-renewal-early-plan.v1'


class Held(Exception):
    pass


def need(ok, code):
    if not ok:
        raise Held(code)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def installed_job(configuration_path, configuration_sha256, clock=None):
    """The installed Job, compiled from bytes verified against the pinned configuration."""
    raw = Path(configuration_path).read_bytes()
    need(hashlib.sha256(raw).hexdigest() == configuration_sha256, 'RENEWAL_CONFIGURATION_DRIFT')
    source_binding = json.loads(raw)['renewalSource']
    source = Path(source_binding['path']).read_bytes()
    need(hashlib.sha256(source).hexdigest() == source_binding['sha256'], 'RENEWAL_SOURCE_DRIFT')
    module = types.ModuleType('ouf_installed_mandate_renewal')
    module.__file__ = source_binding['path']
    exec(compile(source, source_binding['path'], 'exec'), module.__dict__)
    # The Job re-reads and re-verifies configuration, source and mandates module itself.
    job = module.Job(configuration_path, configuration_sha256, **({'clock': clock} if clock else {}))
    # Only now, after validation with the original T-30, lower the threshold for this run.
    module.RENEW_BEFORE_SECONDS = module.WINDOW_SECONDS - EARLY_MARGIN_SECONDS
    return module, job


def plan(module, job, now):
    need(job.incident() is None, 'OPEN_INCIDENT_PRESENT')
    info = {}
    try:
        context = job.evaluate(now, info)
    except module.Blocked as error:
        raise Held(str(error)) from None
    renew = sorted(name for name, value in context['plans'].items() if value is not None)
    need(bool(renew), 'NOTHING_TO_RENEW_EARLY')
    # Stable facts only: windows depend on `now` and are recomputed by the job at apply.
    return {'schema': PLAN_SCHEMA, 'configurationSha256': hashlib.sha256(job.raw).hexdigest(),
            'renewalSourceSha256': job.cfg['renewalSource']['sha256'],
            'ledgers': {name: {'generations': ledger.snapshot()['generations'], 'headSha256': ledger.snapshot()['headSha256']}
                        for name, ledger in context['ledgers'].items()},
            'keys': {name: job.cfg[name]['keyRefs'] for name in ('b1b2', 'base')},
            'renew': renew, 'thresholdSeconds': module.RENEW_BEFORE_SECONDS,
            'windowSeconds': module.WINDOW_SECONDS}


def apply(module, job, approved, now):
    fresh = plan(module, job, now)
    need(digest(fresh) == approved, 'FRESH_EARLY_RENEWAL_PLAN_HASH_MISMATCH')
    outcome, reason, _ = job.run()
    need((outcome, reason) == ('RENEWED', None), 'EARLY_RENEWAL_NOT_RENEWED_' + str(reason))
    status = json.loads((job.state_root / 'status.json').read_bytes())
    for name in fresh['renew']:
        need(status['ledgers'][name]['generation'] == fresh['ledgers'][name]['generations'] + 1,
             'EARLY_RENEWAL_GENERATION_NOT_WRITTEN')
    need(status['versionedBase'] is not None, 'VERSIONED_BASE_NOT_WRITTEN')
    return {'schema': 'ouf.semantic-mandate-renewal-early-result.v1', 'status': 'EARLY_RENEWAL_APPLIED',
            'planSha256': approved, 'outcome': outcome, 'ledgers': status['ledgers'],
            'versionedBase': status['versionedBase'], 'openIncident': status['openIncident']}


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    mode = p.add_mutually_exclusive_group(required=True)
    mode.add_argument('--plan', action='store_true')
    mode.add_argument('--apply', action='store_true')
    p.add_argument('--plan-sha256')
    p.add_argument('--configuration-sha256', required=True)
    args = p.parse_args(argv)
    report = {'schema': 'ouf.semantic-mandate-renewal-early-result.v1', 'status': 'HELD'}
    try:
        need(os.geteuid() == os.getegid() == 0 and sys.flags.isolated, 'ISOLATED_ROOT_REQUIRED')
        need(re.fullmatch('[0-9a-f]{64}', args.configuration_sha256) is not None, 'EXACT_CONFIGURATION_HASH_REQUIRED')
        need(bool(args.plan_sha256) == args.apply and (not args.apply or re.fullmatch('[0-9a-f]{64}', args.plan_sha256)),
             'HUMAN_APPROVED_PLAN_HASH_REQUIRED')
        import time
        module, job = installed_job(CONFIGURATION, args.configuration_sha256)
        now = int(time.time())
        if args.apply:
            report = apply(module, job, args.plan_sha256, now)
        else:
            value = plan(module, job, now)
            report = dict(value, status='EARLY_RENEWAL_PLANNED', planSha256=digest(value))
    except Held as error:
        report['reason'] = str(error)
    except Exception as error:
        reason = str(error)
        report['reason'] = reason if re.fullmatch('[A-Z][A-Z0-9_]{0,100}', reason) else type(error).__name__
    print(json.dumps(report, sort_keys=True))
    return 0 if report['status'] != 'HELD' else 1


if __name__ == '__main__':
    raise SystemExit(main())
