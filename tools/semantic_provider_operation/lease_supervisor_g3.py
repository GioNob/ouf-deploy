"""One opt-in G3 renewal. The supervisor supplies its authenticated head,
fresh resolution reader and sealed readback-margin compiler (step 3 wiring).
"""
import math
import time

from tools.semantic_lease_kernel_migration import boot_dispatcher as boot
from tools.semantic_lease_kernel_migration import g3_contract as g
from tools.semantic_lease_kernel_migration import g3_journal as journal
from tools.semantic_provider_r3.lease_kernel_g3 import locked
from . import nft_batch_g3


def _verify(state, authenticate, admission, clock):
    policy = state.authenticate(authenticate())
    seal = state.local_reference()
    began = clock()
    pair = state.read_pair()
    g.verify_tick(policy, seal, pair, state.membership(admission), int(clock()))
    # Use the beginning of the read for a conservative lower bound on expiry.
    expiry = min((began + entry['elem']['expires'] for doc in pair.values()
                  for row in doc['nftables'] for entry in row.get('set', {}).get('elem', [])),
                 default=math.inf)
    return expiry


def _block(state, before, reason):
    api = state.api
    path = state.denial_path
    journal_path = state.owner['journalFile']
    api.need(api.private(journal_path) == before, 'FOREIGN_PUBLICATION_PRESERVED')
    denial = {'schema': 'ouf.lease-kernel.tick-denied.g3.v1', 'head': state.head,
              'owner': state.owner_hash, 'bootId': state.boot_id,
              'journalSha256': api.sha(before), 'reason': reason}
    # A partial diagnostic must never prevent revocation of journal authority.
    write_error = None
    try:
        existing = journal.optional(api, path)
        if existing is None:
            api.write_once(path, api.canonical(denial))
        else:
            journal.sync_verified(api, path, existing, 'G3_DENIAL_EVIDENCE')
    except (OSError, ValueError) as exc:
        write_error = exc
    journal.transition_locked(api, journal_path, before, state.head, state.owner_hash, 'BLOCKED')
    if write_error is not None:
        raise ValueError('G3_DENIAL_EVIDENCE') from write_error


def tick(coordinator, authenticate, resolve, compile_refresh, *, api=boot, clock=time.monotonic):
    """Renew under the common lock or raise a public HELD code. Never reopen.

    resolve(owner) reads current DNS evidence in the authenticated epoch scope.
    compile_refresh is the verified compiler for this owner's kernel.
    """
    with locked(coordinator, api) as state:
        state.confirm_journal()
        before = state.raw
        api.need(state.journal['state'] in ('LEASE_READY', 'LEASE_UPDATING'), 'G3_JOURNAL_DENIED')
        try:
            api.need(journal.optional(api, state.denial_path) is None, 'G3_PRIOR_DENIAL')
            api.need(state.journal['state'] == 'LEASE_READY', 'G3_INTERRUPTED_RENEWAL')
            owner = state.owner
            period, margin = owner['tickSeconds'], owner['renewalMarginSeconds']
            g.verify_renewal_margin(margin, period)
            previous = state.confirmed_admission()
            admitted = api.document(previous)
            _verify(state, authenticate, admitted, clock)
            resolutions = resolve(owner)
            now = clock()
            plan = compile_refresh(owner['kernel'], resolutions, now,
                                   apply_budget_seconds=owner['applyBudgetSeconds'])
            api.need(plan['denyOnly'] is False and plan['tableName'] == state.name
                     and plan['tableFamilies'] == ['inet', 'bridge']
                     and plan['atomicBatchRequired'] is True, 'G3_ADMISSION_DENIED')
            fresh = state.admission({f'provider_{i}': dict.fromkeys(r['addresses'], math.floor(r['expiresMonotonic']))
                                     for i, r in enumerate(resolutions)})
            state.membership(fresh)
            state.transition('LEASE_UPDATING')
            before = api.canonical({**state.journal, 'state': 'LEASE_UPDATING'})
            with nft_batch_g3.guarded_batch() as submit:
                expires = _verify(state, authenticate, admitted, clock)
                api.need(clock() < min(plan['mustApplyByMonotonic'], expires), g.TTL)
                if plan['nftTransaction']:
                    try:
                        submit(state.name, plan['nftTransaction'])
                    except ValueError as exc:
                        if str(exc) == nft_batch_g3.CONFLICT:
                            # Diagnose a replaced instance without resending the batch.
                            _verify(state, authenticate, admitted, clock)
                        raise
            api.need(clock() < plan['mustApplyByMonotonic'], g.TTL)
            _verify(state, authenticate, fresh, clock)
            encoded = api.canonical(fresh)
            api.cas(state.admission_path, previous, encoded)
            stored = api.private(state.admission_path)
            api.need(stored == encoded, g.BINDING)
            # Disk synchronization can consume the remaining admission window.
            # Verify the committed receipt against a new read immediately before READY.
            expires = _verify(state, authenticate, api.document(stored), clock)
            now = clock()
            next_tick = min(now + period, expires - margin)
            api.need(now < next_tick, g.TTL)
            journal.transition_locked(api, owner['journalFile'], before, state.head, state.owner_hash, 'LEASE_READY')
            before = api.canonical(state.journal)
            api.need(clock() < next_tick, g.TTL)
            return {'state': 'LEASE_READY', 'nextTickMonotonic': next_tick}
        except Exception as exc:
            # Keep the original CAS expectation even if a publication failed
            # after rename. A subsequent invocation classifies its actual residue.
            reason = 'G3_RENEWAL_HELD'
            if isinstance(exc, ValueError) and str(exc) in {
                g.BINDING, g.SEAL_DRIFT, g.POLICY_DRIFT, g.MEMBERS, g.TTL, g.NFT_FORMAT,
                g.NFT_VERSION_DENIED, 'R3_LEASE_KERNEL_NOT_FINALIZED', 'PARTIAL_TABLE_PAIR_PRESERVED',
                'G3_PRIOR_DENIAL', 'G3_INTERRUPTED_RENEWAL', 'G3_ADMISSION_DENIED',
                nft_batch_g3.CONFLICT,
            }:
                reason = str(exc)
            _block(state, before, reason)
            raise ValueError(reason) from exc
