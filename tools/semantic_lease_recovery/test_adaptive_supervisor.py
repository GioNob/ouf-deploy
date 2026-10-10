import copy
from contextlib import nullcontext
import unittest
from adaptive_supervisor import window, supervise


class Fixture:
    def __init__(self):
        self.now = 100.; self.latency = .2; self.ttl = 6.
        self.configuration = {'providerFlows': [{'source': '10.77.0.2', 'leaseSeconds': 30,
                                                  'allowedPrivateAddresses': ['10.78.0.2']}]}
        self.record = {'state': 'LEASE_READY', 'leaseAuthorized': True, 'startAuthorized': False,
                       'leaseAddresses': [['10.78.0.2']]}
        self.owner = type('Owner', (), {'backend': self})()
        self.cycles = 0; self.quiesced = False; self.fail_refresh = False
    def hold_lock(self): return nullcontext()
    def journal(self): return copy.deepcopy(self.record)
    def verify_ownership(self, cfg): pass
    def read_sets(self, cfg):
        self.now += self.latency
        return {('inet', 0): {'10.78.0.2': self.ttl}, ('bridge', 0): {'10.78.0.2': self.ttl}}
    def clock(self): return self.now
    def fresh_start(self): self.cycles += 1
    def refresh(self):
        if self.fail_refresh: raise RuntimeError('FRESH_DNS_FAILED')
        self.cycles += 1
    def quiesce(self):
        self.quiesced = True; self.record.update(state='QUIESCED', leaseAuthorized=False)


class Tests(unittest.TestCase):
    def test_actual_short_ttl_overrides_configured_ceiling_poll(self):
        f = Fixture(); r = window(f, 15, clock=f.clock)
        self.assertAlmostEqual(r['waitSeconds'], 2.9)
        self.assertAlmostEqual(r['deadlineMonotonic'], 106.)
    def test_read_latency_never_extends_expiry(self):
        f = Fixture(); f.latency = 5.
        self.assertEqual(window(f, 15, clock=f.clock)['waitSeconds'], .5)
        f = Fixture(); f.latency = 6.
        with self.assertRaisesRegex(RuntimeError, 'LEASE_READ_WINDOW_EXHAUSTED'): window(f, 15, clock=f.clock)
    def test_zero_negative_bool_string_infinite_ttl_are_never_accepted(self):
        for ttl in (0, -1, True, '6000', float('inf'), float('nan'), 31):
            f = Fixture(); f.ttl = ttl
            with self.assertRaisesRegex(RuntimeError, 'POSITIVE_FINITE_KERNEL_TTL_REQUIRED'): window(f, 15, clock=f.clock)
    def test_consumed_or_start_authority_never_rearmed(self):
        for patch in ({'state': 'QUIESCED'}, {'leaseAuthorized': False}, {'startAuthorized': True}):
            f = Fixture(); f.record.update(patch)
            with self.assertRaisesRegex(RuntimeError, 'CURRENT_LEASE_AUTHORITY_REQUIRED'): window(f, 15, clock=f.clock)
    def test_short_lease_multiple_fresh_cycles_then_stop_revoke(self):
        f = Fixture()
        class Stop:
            def is_set(self): return False
            def wait(self, seconds):
                self_test.assertLess(seconds, 3.)
                f.now += seconds
                return f.cycles == 5
        self_test = self
        supervise(f, lambda: None, 15, Stop(), log=lambda *a, **kw: None, clock=f.clock)
        self.assertEqual(f.cycles, 5); self.assertTrue(f.quiesced)
    def test_late_wakeup_never_attempts_refresh_and_quiesces(self):
        f = Fixture()
        class Stop:
            def is_set(self): return False
            def wait(self, seconds): f.now += 7; return False
        with self.assertRaisesRegex(RuntimeError, 'LEASE_SCHEDULER_WAKE_DEADLINE_MISSED'):
            supervise(f, lambda: None, 15, Stop(), log=lambda *a, **kw: None, clock=f.clock)
        self.assertEqual(f.cycles, 1); self.assertTrue(f.quiesced)
    def test_new_dns_failure_propagates_and_revokes(self):
        f = Fixture(); f.fail_refresh = True
        class Stop:
            def is_set(self): return False
            def wait(self, seconds): f.now += seconds; return False
        with self.assertRaisesRegex(RuntimeError, 'FRESH_DNS_FAILED'):
            supervise(f, lambda: None, 15, Stop(), log=lambda *a, **kw: None, clock=f.clock)
        self.assertTrue(f.quiesced)


if __name__ == '__main__': unittest.main()
