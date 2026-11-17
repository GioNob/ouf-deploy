"""Portable D-050 state machine. Every effect is supplied by a native boundary.

There is deliberately no automatic rollback or replay of a consumed apply.
Restore reconciles only the two planned file values and the owned table pair.
"""
import copy

from . import boot_dispatcher as B

SCHEMA = 'ouf.semantic-lease-kernel-migration.v1'
POLICIES = {(1, 2): {'fields': ('generation', 'providerFlowMatch', 'tableName'),
                     'providerFlowMatch': 'ORIGINAL_TUPLE',
                     'r3BeforeMaxVersion': 11, 'r3AfterMinVersion': 12}}


def destination(old, number):
    previous = old.get('generation', 1)
    policy = POLICIES.get((previous, number))
    B.need(policy is not None and number == previous + 1, 'LEASE_KERNEL_GENERATION_NOT_SUPPORTED')
    result = copy.deepcopy(old)
    # Suffixes accumulate, so a future g3 never aliases a retained g1/g2 name.
    result.update(generation=number, providerFlowMatch=policy['providerFlowMatch'],
                  tableName=old['tableName'] + '_g' + str(number))
    B.need(len(result['tableName']) <= 32, 'LEASE_KERNEL_TABLE_NAME_TOO_LONG')
    return result


def difference(old, new):
    B.need((old.get('generation', 1), new.get('generation')) in POLICIES, 'LEASE_KERNEL_DIFF_NOT_ALLOWED')
    expected = destination(old, new.get('generation'))
    B.need(new == expected, 'LEASE_KERNEL_DIFF_NOT_ALLOWED')
    changed = [k for k in sorted(set(old) | set(new)) if old.get(k) != new.get(k)]
    B.need(set(changed) <= set(POLICIES[(old.get('generation', 1), new['generation'])]['fields']),
           'LEASE_KERNEL_DIFF_NOT_ALLOWED')
    return [{'field': k, 'beforePresent': k in old, 'before': old.get(k), 'after': new[k]} for k in changed]


def idle(observation):
    B.need(set(observation['candidates']) == {'adapter', 'southbound'}, 'LEASE_KERNEL_TWO_ROLES_REQUIRED')
    for row in observation['candidates'].values():
        docker, epoch = row['docker'], row['epoch']
        B.need(docker['Status'] in ('created', 'exited') and docker['Running'] is False and docker['Pid'] == 0
               and docker['RestartPolicy'] == 'no', 'LEASE_KERNEL_PROVIDER_NOT_STOPPED')
        B.need(epoch is not None and epoch['state'] in ('DELETED', 'FAILED', 'ABANDONED')
               and epoch['live'] is False, 'LEASE_KERNEL_EPOCH_NOT_TERMINAL')
    sup = observation['supervisor']
    B.need(sup['state'] == 'WAITING' and sup['authorizationSequence'] == observation['authorization']['sequence']
           and sup['unit']['ActiveState'] == 'active' and sup['unit']['SubState'] == 'running',
           'LEASE_KERNEL_SUPERVISOR_NOT_WAITING')
    B.need(observation['lease'] == {'state': 'QUIESCED', 'leaseAuthorized': False},
           'LEASE_KERNEL_NOT_QUIESCED')
    B.need(all(not row[f] for row in observation['tables'].values() for f in ('inet', 'bridge')),
           'LEASE_KERNEL_EPOCH_TABLES_PRESENT')


def quiesced(owner, journal):
    B.need(journal.get('state') == 'QUIESCED' and journal.get('leaseAuthorized') is False
           and journal.get('startAuthorized') is False
           and all(journal.get(k) == v for k, v in owner['binding'].items())
           and journal.get('leaseAddresses') == [[] for _ in owner['kernel']['providerFlows']],
           'LEASE_KERNEL_JOURNAL_DRIFT')


def seals(kernel, tables):
    B.empty(tables)
    return {'kernel': B.digest(kernel), 'structure': B.digest(B.structure(tables)),
            'boot': B.digest(B.stable(tables))}


def verify_tables(tables, expected):
    B.empty(tables)
    B.need(B.digest(B.structure(tables)) == expected, 'LEASE_KERNEL_STRUCTURE_DRIFT')


def digest_plan(value):
    return {**value, 'planSha256': B.digest(value)}


def validate_plan(plan):
    B.need(plan['planSha256'] == B.digest({k: v for k, v in plan.items() if k != 'planSha256'}),
           'LEASE_KERNEL_PLAN_DIGEST_CHANGED')


def plan(io, number=2, proposed=None):
    observation = io.observe()
    idle(observation)
    context = io.context()
    owner = context['owner']
    quiesced(owner, context['journal'])
    io.authorization(owner, 'migrate', observation)
    old = io.tables(owner['kernel'])
    verify_tables(old, owner['expectedStructureHash'])
    target = destination(owner['kernel'], number) if proposed is None else proposed
    delta = difference(owner['kernel'], target)
    B.need(target['tableName'] not in {row.get('tableName') for row in observation['tables'].values()},
           'LEASE_KERNEL_TARGET_CANDIDATE_TABLE_COLLISION')
    B.need(io.tables(target) is None, 'LEASE_KERNEL_TARGET_TABLES_ALREADY_EXIST')
    template = io.template(target)
    B.empty(template)
    return digest_plan({'schema': SCHEMA, 'operation': 'migrate', 'observation': observation,
        'context': context, 'destination': target, 'difference': delta,
        'before': seals(owner['kernel'], old), 'expectedBootFootprint': B.digest(B.stable(template)),
        'templateStructure': B.structure(template),
        'nativeSealAssignment': 'READBACK_BEFORE_PUBLICATION_HANDLES_ARE_NOT_PREDICTED',
        'paths': io.paths(), 'sourceHashes': io.source_hashes(),
        'startAuthorized': False, 'leaseAuthorized': False, 'pointOfNoReturn': False})


def event(io, phase, side, value):
    io.record({'phase': phase, 'side': side, 'evidence': value,
               'leaseAuthorized': False, 'startAuthorized': False})


def target_readback(io, plan):
    value = io.tables(plan['destination'])
    B.empty(value)
    B.need(B.digest(B.stable(value)) == plan['expectedBootFootprint'], 'LEASE_KERNEL_TARGET_FOOTPRINT_DRIFT')
    return value


def apply(io, planned, expected):
    validate_plan(planned)
    B.need(planned['planSha256'] == expected and planned['operation'] == 'migrate', 'LEASE_KERNEL_PLAN_DIGEST_CHANGED')
    with io.locks():
        # Recompute EVERYTHING under all locks, before the exclusive claim.
        B.need(plan(io, planned['destination']['generation']) == planned, 'LEASE_KERNEL_PLAN_DIGEST_CHANGED')
        io.claim(planned)
        event(io, 'generation', 'before', planned['paths'])
        io.prepare(planned)
        event(io, 'generation', 'after', io.source_hashes())
        event(io, 'nft-create', 'before', {'source': planned['before'], 'targetAbsent': True})
        # One batch creates BOTH new tables, never deletes/recreates N.
        io.batch(io.compile(planned['destination']))
        target = target_readback(io, planned)
        verify_tables(io.tables(planned['context']['owner']['kernel']), planned['before']['structure'])
        after = seals(planned['destination'], target)
        io.save('native-after.json', {'seals': after, 'tables': B.structure(target)})
        event(io, 'nft-create', 'after', after)
        publication = io.stage(planned, target)
        io.save('publication.json', publication)
        event(io, 'publication', 'before', io.publication_state(publication))
        io.publish(publication, restore=False)
        event(io, 'publication', 'after', io.publication_state(publication))
        io.check_journals(planned)
        verify_tables(io.tables(planned['destination']), after['structure'])
        verify_tables(io.tables(planned['context']['owner']['kernel']), planned['before']['structure'])
        result = {'schema': SCHEMA, 'status': 'LEASE_KERNEL_MIGRATED', 'planSha256': expected,
                  'before': planned['before'], 'after': after, 'doNotRerunApply': True,
                  'startAuthorized': False, 'leaseAuthorized': False, 'journal': 'QUIESCED'}
        io.save('receipt.json', result)
        return result


def restore(io, planned, expected):
    validate_plan(planned)
    B.need(planned['planSha256'] == expected, 'LEASE_KERNEL_PLAN_DIGEST_CHANGED')
    with io.locks():
        B.need(not io.exists('finalize-intent.json'), 'LEASE_KERNEL_FINALIZE_IRREVERSIBLE')
        observation = io.observe()
        idle(observation)
        io.authorization(planned['context']['owner'], 'restore', observation)
        # A new R3 authorization, even one for N, closes this rollback window.
        B.need(observation['authorization'] == planned['observation']['authorization'],
               'LEASE_KERNEL_R3_HEAD_CHANGED_RESTORE_DENIED')
        old = planned['context']['owner']
        io.check_journals(planned)
        verify_tables(io.tables(old['kernel']), planned['before']['structure'])
        target = io.tables(planned['destination'])
        if target is not None:
            target_readback(io, planned)
            if io.exists('native-after.json'):
                verify_tables(target, io.load('native-after.json')['seals']['structure'])
            else:
                # Timeout/crash after nft commit but before readback evidence.
                # Exclusive intent proves absence before this one atomic batch;
                # accept only its exact empty compiler footprint, seal it ONCE.
                B.need(io.event_exists('nft-create', 'before'), 'LEASE_KERNEL_CREATION_INTENT_MISSING')
                io.save('native-after.json', {'seals': seals(planned['destination'], target),
                                            'tables': B.structure(target), 'reconciledAfterCommit': True})
        publication = io.load('publication.json') if io.exists('publication.json') else []
        io.publication_state(publication)  # validate ALL files before any effect
        event(io, 'restore-publication', 'before', io.publication_state(publication))
        io.publish(publication, restore=True)
        event(io, 'restore-publication', 'after', io.publication_state(publication))
        event(io, 'restore-nft', 'before', None if target is None else seals(planned['destination'], target))
        if target is not None:
            verify_tables(io.tables(planned['destination']), io.load('native-after.json')['seals']['structure'])
            io.batch(io.delete(planned['destination']))
        B.need(io.tables(planned['destination']) is None, 'LEASE_KERNEL_TARGET_STILL_PRESENT')
        verify_tables(io.tables(old['kernel']), planned['before']['structure'])
        io.check_journals(planned)
        event(io, 'restore-nft', 'after', planned['before'])
        result = {'schema': SCHEMA, 'status': 'LEASE_KERNEL_RESTORED', 'planSha256': expected,
                  'before': planned['before'], 'after': planned['before'],
                  'doNotRerunApply': True, 'leaseAuthorized': False, 'startAuthorized': False}
        if io.exists('restore-receipt.json'):
            B.need(io.load('restore-receipt.json') == result, 'LEASE_KERNEL_RESTORE_RECEIPT_DRIFT')
        else:
            io.save('restore-receipt.json', result)
        return result


def finalize_plan(io, migration):
    validate_plan(migration)
    B.need(io.exists('receipt.json') and not io.exists('restore-receipt.json')
           and not io.exists('finalize-intent.json'), 'LEASE_KERNEL_MIGRATION_NOT_FINALIZABLE')
    observation = io.observe()
    idle(observation)
    owner = io.new_owner()
    io.check_journals(migration)
    io.authorization(owner, 'finalize', observation)
    publication = io.load('publication.json')
    B.need(all(row['state'] == 'new' for row in io.publication_state(publication)), 'LEASE_KERNEL_NOT_PUBLISHED')
    target = io.tables(migration['destination'])
    verify_tables(target, io.load('native-after.json')['seals']['structure'])
    verify_tables(io.tables(migration['context']['owner']['kernel']), migration['before']['structure'])
    return digest_plan({'schema': SCHEMA, 'operation': 'finalize', 'migrationPlanSha256': migration['planSha256'],
        'observation': observation, 'before': migration['before'], 'after': seals(migration['destination'], target),
        'paths': io.paths(), 'pointOfNoReturn': True,
        'consequence': 'RESTORE_DENIED_NEW_GENERATION_REQUIRED', 'leaseAuthorized': False, 'startAuthorized': False})


def finalize(io, migration, planned, expected):
    validate_plan(planned)
    B.need(expected == planned['planSha256'], 'LEASE_KERNEL_PLAN_DIGEST_CHANGED')
    with io.locks():
        if io.exists('finalize-intent.json'):
            B.need(io.load('finalize-intent.json') == planned
                   and planned['migrationPlanSha256'] == migration['planSha256'], 'LEASE_KERNEL_FINALIZE_INTENT_DRIFT')
            observation = io.observe()
            idle(observation)
            io.authorization(io.new_owner(), 'finalize', observation)
            B.need(observation == planned['observation'], 'LEASE_KERNEL_PLAN_DIGEST_CHANGED')
            B.need(all(row['state'] == 'new' for row in io.publication_state(io.load('publication.json'))),
                   'LEASE_KERNEL_NOT_PUBLISHED')
            io.check_journals(migration)
        else:
            B.need(finalize_plan(io, migration) == planned, 'LEASE_KERNEL_PLAN_DIGEST_CHANGED')
            io.finalize_claim(planned)
            event(io, 'finalize-nft', 'before', planned)
            io.save('finalize-intent.json', planned)
        verify_tables(io.tables(migration['destination']), planned['after']['structure'])
        old = io.tables(migration['context']['owner']['kernel'])
        if old is not None:
            verify_tables(old, planned['before']['structure'])
            io.batch(io.delete(migration['context']['owner']['kernel']))
        B.need(io.tables(migration['context']['owner']['kernel']) is None, 'LEASE_KERNEL_PREDECESSOR_STILL_PRESENT')
        verify_tables(io.tables(migration['destination']), planned['after']['structure'])
        io.check_journals(migration)
        event(io, 'finalize-nft', 'after', {'predecessorAbsent': True, 'successor': planned['after']})
        result = {'schema': SCHEMA, 'status': 'LEASE_KERNEL_FINALIZED', 'planSha256': expected,
                  'migrationPlanSha256': migration['planSha256'], 'before': planned['before'], 'after': planned['after'],
                  'restoreAllowed': False, 'doNotRerunApply': True, 'leaseAuthorized': False, 'startAuthorized': False}
        if io.exists('finalize-receipt.json'):
            B.need(io.load('finalize-receipt.json') == result, 'LEASE_KERNEL_FINALIZE_RECEIPT_DRIFT')
        else:
            io.save('finalize-receipt.json', result)
        return result
