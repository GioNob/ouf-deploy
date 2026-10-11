"""Continuous scoped lease supervision with a durable finite recovery budget.

No authorization creation or journal initialization. The new sealed entrypoint
must own an exclusive lifetime worker lock and supply current finite authority,
custody and process-generation guards. Never attach to the consumed R10 worker.
"""
from bounded_recovery import Permanent, Temporary, fingerprint
from adaptive_supervisor import window
from resilient_lease_adapter import LeaseAdapter
import re


def ttl_zero(error):
    facts = getattr(error, 'nft_readback', {})
    return (str(error) == 'NFT_SET_TTL_UNPROVEN'
            and facts.get('expiresType') == 'int' and facts.get('expiresValue') == 0
            and facts.get('duplicateAddress') is False)


class RenewingLeaseAdapter(LeaseAdapter):
    def pause(self):
        backend = self.c.owner.backend
        previous = backend.active_deadline
        backend.active_deadline = None
        try:
            return super().pause()
        finally:
            backend.active_deadline = previous

    def prepare(self, deadline):
        with self.c.owner.backend.within(deadline):
            return super().prepare(deadline)

    def publish(self, evidence, deadline):
        try:
            with self.c.owner.backend.within(deadline):
                return super().publish(evidence, deadline)
        except Exception:
            self.pause()
            raise

    def prepare_renewal(self, deadline):
        # Keep the preceding finite lease while collecting NEW evidence.
        # DNS and all waits are outside the shared lease lock.
        with self.c.owner.backend.within(deadline):
            self.guard()
            return self.fresh_evidence(deadline)

    def publish_renewal(self, evidence, deadline):
        try:
            with self.c.owner.backend.within(deadline):
                return self._publish_renewal(evidence, deadline)
        except Temporary:
            self.pause()
            raise Temporary('DNS_WINDOW_TOO_SHORT', no_effect=True) from None
        except RuntimeError as error:
            if ttl_zero(error):
                self.pause()
                raise Temporary('DNS_WINDOW_TOO_SHORT', no_effect=True) from None
            self.pause()
            raise Permanent('INTEGRITY_UNPROVEN') from None
        except Exception:
            self.pause()
            raise

    def _publish_renewal(self, evidence, deadline):
        self.guard()
        values = evidence['values']
        if self.clock() >= deadline:
            raise Temporary('DNS_WINDOW_TOO_SHORT', no_effect=True)
        try:
            with self.c.hold_lock():
                self.guard()
                previous = self.c.journal()
                if previous['state'] != 'LEASE_READY' or previous['leaseAuthorized'] is not True:
                    raise Permanent('INTEGRITY_UNPROVEN')
                backend, cfg = self.c.owner.backend, self.c.configuration
                actual = self.c.sets()
                if any(not set(row).issubset(set(approved))
                       for row, approved in zip(actual, previous['leaseAddresses'])):
                    raise Permanent('INTEGRITY_UNPROVEN')
                plan = self.compiler.compile_refresh(cfg, values, self.clock(),
                    apply_budget_seconds=self.c.owner.profile['applyBudgetSeconds'])
                if plan['denyOnly']: raise Temporary('DNS_WINDOW_TOO_SHORT')
                deadline = min(deadline, plan['mustApplyByMonotonic'])
                pending = {**previous, 'state': 'LEASE_UPDATING', 'leaseAuthorized': False}
                self.c.publish(previous, pending)
                backend.verify_ownership(cfg)
                if self.clock() >= deadline: raise Temporary('DNS_WINDOW_TOO_SHORT')
                backend.apply(plan['nftTransaction'], deadline)
                sets = backend.read_sets(cfg)
                now = self.clock()
                if now >= deadline: raise Temporary('DNS_WINDOW_TOO_SHORT')
                expected = {(family, i) for family in ('inet', 'bridge') for i in range(len(values))}
                if set(sets) != expected: raise Permanent('INTEGRITY_UNPROVEN')
                for (family, index), members in sets.items():
                    if set(members) != set(values[index]['addresses']):
                        raise Permanent('INTEGRITY_UNPROVEN')
                    for ttl in members.values():
                        if type(ttl) is not int or not 0 < ttl <= cfg['providerFlows'][index]['leaseSeconds']:
                            raise Permanent('INTEGRITY_UNPROVEN')
                        if now + ttl > values[index]['expiresMonotonic']:
                            raise Permanent('INTEGRITY_UNPROVEN')
                backend.verify_ownership(cfg)
                self.guard()
                if self.clock() >= deadline: raise Temporary('DNS_WINDOW_TOO_SHORT')
                ready = {**pending, 'state': 'LEASE_READY', 'leaseAuthorized': True,
                         'leaseAddresses': [sorted(sets['inet', i]) for i in range(len(values))]}
                self.c.publish(pending, ready)
                return fingerprint(ready)
        except Exception:
            raise


class Supervisor:
    def __init__(self, recovery, coordinator, poll_seconds, *, heartbeat=5):
        if type(heartbeat) is not int or not 1 <= heartbeat <= 30:
            raise ValueError('BOUNDED_LOCAL_HEARTBEAT_REQUIRED')
        self.r, self.c = recovery, coordinator
        self.poll, self.heartbeat = poll_seconds, heartbeat
        self.active_here = False
        self.renewals = 0

    def local_guard(self):
        # Parked journals do not probe dependencies. Local revocation must
        # nevertheless remain observable even after retry-budget exhaustion.
        self.r.adapter.guard()

    def tick(self):
        row = self.r.journal.read()
        if row['state'] == 'ACTIVE':
            row = self.r.step()
        if row['state'] != 'ACTIVE':
            try:
                self.local_guard()
            except Permanent as error:
                return self.r.pause(row, 'BLOCKED', error.code)
            except Exception:
                return self.r.pause(row, 'BLOCKED', 'LOCAL_AUTHORITY_UNPROVEN')
            row = self.r.step()
            if row['state'] == 'ACTIVE':
                self.active_here = True
                return self.tick()
            return row
        if not self.active_here:
            # A recovered ACTIVE checkpoint from another invocation is not
            # permission to attach/restart or renew the preceding live lease.
            return self.r.pause(row, 'RECONCILE_REQUIRED', 'WORKER_INVOCATION_RECONCILIATION_REQUIRED')
        try:
            self.local_guard()
            if self.r.remaining(row) <= 0:
                return self.r.pause(row, 'PAUSED_EXHAUSTED', 'RECOVERY_SCOPE_TIME_EXHAUSTED')
            schedule = window(self.c, self.poll, clock=lambda: self.r.now()[1])
            return {**row, 'waitSeconds': min(self.heartbeat, schedule['waitSeconds']),
                    'leaseDeadlineMonotonic': schedule['deadlineMonotonic']}
        except Permanent as error:
            return self.r.pause(row, 'BLOCKED', error.code)
        except RuntimeError as error:
            if ttl_zero(error) or str(error) in {
                    'LEASE_READ_WINDOW_EXHAUSTED', 'CURRENT_APPROVED_TWO_FAMILY_MEMBERSHIP_REQUIRED'}:
                # Empty/unequal membership is not classified by this generic
                # code: it may be tampering, so remains BLOCKED below.
                if str(error) == 'CURRENT_APPROVED_TWO_FAMILY_MEMBERSHIP_REQUIRED':
                    return self.r.pause(row, 'BLOCKED', 'INTEGRITY_UNPROVEN')
                self.active_here = False
                return self.r.retry(row, Temporary('DNS_WINDOW_TOO_SHORT', no_effect=True))
            return self.r.pause(row, 'BLOCKED', 'INTEGRITY_UNPROVEN')
        except Exception:
            return self.r.pause(row, 'BLOCKED', 'LOCAL_STATE_UNPROVEN')

    def renew(self, scheduled):
        row = self.r.journal.read()
        if row['state'] != 'ACTIVE' or not self.active_here:
            raise RuntimeError('CURRENT_INVOCATION_ACTIVE_REQUIRED')
        publishing = False
        try:
            self.local_guard()
            if self.r.now()[1] >= scheduled['leaseDeadlineMonotonic']:
                raise Temporary('DNS_WINDOW_TOO_SHORT')
            remaining = self.r.remaining(row)
            if remaining <= 0:
                return self.r.pause(row, 'PAUSED_EXHAUSTED', 'RECOVERY_SCOPE_TIME_EXHAUSTED')
            deadline = self.r.now()[1] + min(self.r.policy.attempt_timeout, remaining)
            evidence = self.r.adapter.prepare_renewal(deadline)
            self.local_guard()
            if self.r.now()[1] >= deadline: raise Temporary('DEPENDENCY_TIMEOUT')
            publishing = True
            result = self.r.adapter.publish_renewal(evidence, deadline)
            if self.r.now()[1] >= deadline or self.r.remaining(row) <= 0:
                return self.r.pause(row, 'RECONCILE_REQUIRED', 'PUBLICATION_DEADLINE_UNPROVEN')
            if type(result) is not str or not re.fullmatch('[0-9a-f]{64}', result):
                return self.r.pause(row, 'RECONCILE_REQUIRED', 'DURABLE_RESULT_UNPROVEN')
            row = self.r.save(row, 'ACTIVE', 'RENEWED', resultRef=result)
            self.renewals += 1
            return row
        except Temporary as error:
            self.active_here = False
            if publishing and not error.no_effect:
                return self.r.pause(row, 'RECONCILE_REQUIRED', 'PUBLICATION_OUTCOME_AMBIGUOUS')
            return self.r.retry(row, error)
        except Permanent as error:
            return self.r.pause(row, 'BLOCKED', error.code)
        except Exception:
            return self.r.pause(row, 'RECONCILE_REQUIRED' if publishing else 'BLOCKED',
                                'UNCLASSIFIED_FAILURE')

    def serve(self, stop, observe):
        with self.r.journal.invocation():
            return self._serve(stop, observe)

    def _serve(self, stop, observe):
        try:
            while not stop.is_set():
                row = self.tick()
                # Owner projection contains only safe codes and counts, not
                # source addresses, exception strings or proof/credential bytes.
                def projection(value):
                    return {'state': value['state'], 'reason': value['reason'],
                            'attempts': value['attempts'], 'renewals': self.renewals,
                            'incidentRef': self.r.context, 'ready': value['state'] == 'ACTIVE',
                            'live': True}
                try:
                    observe(projection(row))
                except (RuntimeError, Temporary) as error:
                    transient_read = (isinstance(error, Temporary)
                                      and error.code == 'DNS_WINDOW_TOO_SHORT' and error.no_effect)
                    if row['state'] != 'ACTIVE' or not (ttl_zero(error) or transient_read):
                        raise
                    self.active_here = False
                    row = self.r.retry(self.r.journal.read(),
                                       Temporary('DNS_WINDOW_TOO_SHORT', no_effect=True))
                    observe(projection(row))
                if stop.wait(row.get('waitSeconds', self.r.wait_seconds(row, self.heartbeat))):
                    break
                if row['state'] == 'ACTIVE': self.renew(row)
            return self.r.step(cancelled=True)
        finally:
            # If observation or storage fails, revoke before allowing exit.
            # No implicit journal recreation, retry or automatic process restart.
            self.r.adapter.pause()
