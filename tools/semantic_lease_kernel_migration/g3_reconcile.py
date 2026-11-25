"""Reconcile an authenticated G3 selection. plan is read-only; apply takes its digest."""
import argparse
from contextlib import ExitStack
import os

from . import boot_dispatcher as boot
from . import g3_journal as journal


def _inspect(state, observe):
    api = state.api
    api.need(state.journal['bootId'] == state.boot_id, 'G3_BINDING')
    journal.g.verify_renewal_margin(state.owner['renewalMarginSeconds'], state.owner['tickSeconds'])
    expected = {'head': state.head, 'owner': state.owner_hash, 'generation': 3,
                'decision': 'OPERATE', 'projection': journal.g.PROJECTION, 'footprint': state.footprint,
                'bootId': state.boot_id, 'cohortStopped': True, 'epochsTerminal': True,
                'supervisor': 'WAITING'}
    # observe() authenticates the current head and independently observes both
    # roles under the operation, issuer and common locks. Never read a cached flag.
    live = (observe(state) if observe is not None else
            api.document(api.command(state.owner['reconcileObserver'], ['observe', state.head])))
    api.need(api.canonical(live) == api.canonical(expected), 'G3_RECONCILE_OBSERVATION')
    tables = state.tables()
    guard = state.guard(tables)
    blocked = {**state.journal, 'state': 'BLOCKED'}
    closed = {**state.journal, 'state': 'QUIESCED'}
    api.need(api.canonical(state.journal) == state.raw, 'G3_BINDING')
    plan = {'schema': 'ouf.lease-kernel.reconcile-plan.g3.v1', 'observation': live,
            'guardSha256': api.digest(guard), 'beforeSha256': api.digest(blocked),
            'afterSha256': api.digest(closed), 'sealSha256': api.digest(guard['instance'])}
    directory = state.directory / 'reconcile'
    seal = journal.optional(api, state.seal_path)
    intent = state.intent(plan)
    done = state.completion(plan)
    if os.path.lexists(directory):
        journal.private_directory(api, directory)
        api.need(api.private(directory / 'plan.json') == api.canonical(plan), 'G3_PLAN_DRIFT')
        reserved = journal.optional(api, directory / 'seal-intent.json')
        final = journal.optional(api, directory / 'receipt.json')
        if reserved is not None:
            api.need(reserved == api.canonical(intent) and seal == api.canonical(guard['instance']),
                     'G3_SEAL_DRIFT')
        else:
            api.need(seal is None, 'G3_SEAL_DRIFT')
        if state.journal['state'] == 'QUIESCED':
            api.need(reserved is not None, 'G3_BINDING')
        if final is not None:
            api.need(state.journal['state'] == 'QUIESCED' and final == api.canonical(done), 'G3_BINDING')
    else:
        api.need(state.journal['state'] == 'BLOCKED' and seal is None, 'G3_BINDING')
    return plan, guard['instance']


def _execute(pointer, observe, requested, api):
    selection = api.sealed_receipt(pointer)
    receipt = selection[1]
    ref = receipt['bootProfile']
    profile = api.document(api.private(ref['path'], ref['sha256']))
    owner = api.document(api.private(profile['coordinatedConfiguration'], profile['coordinatedConfigurationHash']))
    with ExitStack() as locks:
        # Same lock order as D-050: operations, issuer, common guard.
        paths = owner['operationLockFiles']
        api.need(isinstance(paths, list) and len(paths) == 2 and len(set(paths)) == 2, 'G3_BINDING')
        for path in sorted(paths):
            locks.enter_context(api.lock(path))
        locks.enter_context(api.directory_lock(owner['authorizationDirectory']))
        locks.enter_context(api.lock(owner['commonLockFile']))
        api.need(selection == journal.confirmed_selection(api, pointer), 'BOOT_POINTER_CHANGED')
        state = journal.BootState(receipt, api)
        plan, seal = _inspect(state, observe)
        digest = api.digest(plan)
        if requested is None:
            return {'plan': plan, 'planSha256': digest}
        api.need(digest == requested, 'G3_PLAN_DRIFT')
        state.confirm_journal()
        directory = state.directory / 'reconcile'
        if journal.make_directory(api, directory):
            api.write_once(directory / 'plan.json', api.canonical(plan))
        else:
            journal.sync_verified(api, directory / 'plan.json', api.canonical(plan), 'G3_PLAN_DRIFT')
        if journal.optional(api, directory / 'seal-intent.json') is None:
            api.write_once(directory / 'seal-intent.json', api.canonical(state.intent(plan)))
            api.write_once(state.seal_path, api.canonical(seal))
        if state.journal['state'] == 'BLOCKED':
            journal.sync_verified(api, state.seal_path, api.canonical(seal), 'G3_SEAL_DRIFT')
            state.transition('QUIESCED')
        api.private(owner['journalFile'], plan['afterSha256'])
        done = state.completion(plan)
        path = directory / 'receipt.json'
        if journal.optional(api, path) is None:
            api.write_once(path, api.canonical(done))
            api.need(api.private(path) == api.canonical(done), 'G3_BINDING')
        else:
            journal.sync_verified(api, path, api.canonical(done), 'G3_BINDING')
        return done


def plan(pointer, observe=None, api=boot):
    return _execute(pointer, observe, None, api)


def apply(pointer, plan_sha256, observe=None, api=boot):
    api.need(isinstance(plan_sha256, str), 'G3_PLAN_DRIFT')
    return _execute(pointer, observe, plan_sha256, api)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pointer', required=True)
    sub = parser.add_subparsers(dest='action', required=True)
    sub.add_parser('plan')
    sub.add_parser('apply').add_argument('planSha256')
    args = parser.parse_args(argv)
    try:
        result = plan(args.pointer) if args.action == 'plan' else apply(args.pointer, args.planSha256)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        # Private file names and external command data stay off stdout.
        code = str(exc) if isinstance(exc, ValueError) and str(exc).isidentifier() else 'G3_EVIDENCE'
        print('HELD', code)
        return 1
    print(boot.canonical(result).decode('ascii'))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
