"""Human-invoked D-050 entrypoint. No service starts or R3 authorization writes."""
import argparse
import os
from pathlib import Path
import sys

from tools.semantic_provider_r3 import install_common as I
from . import boot_dispatcher as B
from . import migration as M
from .native import Native, native_template


def arguments(argv):
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    for name in ('plan', 'apply', 'restore', 'finalize'):
        mode.add_argument('--' + name, action='store_true')
    parser.add_argument('--operation', choices=('migrate', 'finalize'), default='migrate')
    parser.add_argument('--plan-sha256')
    parser.add_argument('--migration-plan-sha256')
    parser.add_argument('--migration-directory')
    parser.add_argument('--to-generation', type=int, default=2)
    for name in ('inputs', 'inputs-sha256', 'install-root', 'wrapper', 'wrapper-sha256', 'lock',
                 'docker', 'docker-sha256', 'docker-socket', 'systemctl', 'systemctl-sha256',
                 'nft', 'nft-sha256', 'generation-directory', 'output-directory'):
        parser.add_argument('--' + name, required=True)
    args = parser.parse_args(argv)
    args.timeout_seconds = 30
    B.need(args.plan == (args.plan_sha256 is None), 'PLAN_DIGEST_ARGUMENT_REQUIRED')
    B.need(not (args.restore or args.finalize or args.operation == 'finalize') or args.migration_directory is not None,
           'MIGRATION_DIRECTORY_REQUIRED')
    B.need(args.operation == 'migrate' or args.plan or args.finalize, 'INVALID_OPERATION')
    for name, value in vars(args).items():
        if name.endswith('sha256') and value is not None:
            B.need(I.V.hashed(value), 'INVALID_DIGEST_ARGUMENT')
    return args


def main(argv=None):
    report = {'schema': M.SCHEMA, 'status': 'HELD', 'doNotRerunApply': False,
              'startAuthorized': False, 'leaseAuthorized': False, 'containerLifecycleOperations': 0}
    io = None
    try:
        B.need(sys.platform == 'linux' and os.geteuid() == os.getegid() == 0
               and sys.flags.isolated and sys.dont_write_bytecode, 'ROOT_ISOLATED_REQUIRED')
        os.umask(0o077)
        if argv == ['--native-template']:
            native_template()
            return 0
        args = arguments(argv)
        report['doNotRerunApply'] = args.restore or args.finalize or (args.apply and Path(args.output_directory).exists())
        with I.module_scope():
            io = Native(args)
            if args.restore or args.finalize or args.operation == 'finalize':
                migration = io.load('plan.json')
                M.validate_plan(migration)
                actual_paths, expected_paths = io.paths(), migration['paths']
                if not args.restore:
                    # Task-66 changes only this invocation binding during the
                    # required R3 upgrade. Finalize's OWN plan seals its value.
                    import copy
                    expected_paths = copy.deepcopy(expected_paths)
                    expected_paths['r3']['wrapper_sha256'] = actual_paths['r3']['wrapper_sha256']
                B.need(expected_paths == actual_paths, 'LEASE_KERNEL_INVOCATION_BINDING_CHANGED')
                expected = args.plan_sha256 if args.restore else args.migration_plan_sha256
                B.need(expected == migration['planSha256'], 'LEASE_KERNEL_MIGRATION_DIGEST_REQUIRED')
                if args.restore:
                    report.update(M.restore(io, migration, expected))
                else:
                    if args.finalize and io.exists('finalize-intent.json'):
                        planned = io.load('finalize-intent.json')
                    else:
                        with io.locks():
                            planned = M.finalize_plan(io, migration)
                    if args.plan:
                        report.update(planned, status='PLAN_READY')
                    else:
                        report.update(M.finalize(io, migration, planned, args.plan_sha256))
            else:
                with io.locks():
                    planned = M.plan(io, args.to_generation)
                if args.plan:
                    report.update(planned, status='PLAN_READY')
                else:
                    report.update(M.apply(io, planned, args.plan_sha256))
    except Exception as error:
        reason = str(error)
        report['reason'] = reason if OPAQUE_CODE(reason) else 'LEASE_KERNEL_OPERATION_UNPROVEN'
        report['errorClass'] = type(error).__name__
        if io is not None and io.work.exists():
            report['doNotRerunApply'] = True
            try:
                io.record({'phase': 'held', 'side': 'after', 'evidence': report.copy(),
                           'leaseAuthorized': False, 'startAuthorized': False})
            except Exception:
                report['diagnosisSaved'] = False
    print(B.canonical(report).decode('ascii'), flush=True)
    return int(report['status'] == 'HELD')


def OPAQUE_CODE(value):
    import re
    return re.fullmatch('[A-Z][A-Z0-9_]{0,95}', value) is not None
