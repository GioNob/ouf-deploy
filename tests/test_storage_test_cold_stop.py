import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


fixture = load('stop_proposal_fixture', 'tests/test_storage_cold_stop_proposal.py')
d = load('test_cold_stop_driver', 'scripts/storage-test-cold-stop.py')
b, p = fixture.b, fixture.p


class FakeRunner:
    def __init__(self, host):
        self.host, self.calls, self.total = copy.deepcopy(host), 0, 0
        self.mutations, self.events = [], []
        self.lose_update_reply = self.never_exit = self.bad_exit = False
        self.clock = 50

    def inventory(self, ids):
        self.calls += 3
        return copy.deepcopy(self.host)

    def docker(self, *args, **kwargs):
        self.calls += 1
        if args[0] == 'inspect':
            return b.canonical([self.host[cid] for cid in args[1:]])
        if args[0] == 'events':
            return b''.join(b.canonical(e) for e in self.events)
        self.mutations.append(args)
        cid = args[-1]
        if args[0] == 'update':
            self.host[cid]['HostConfig']['RestartPolicy'] = {'Name': 'no', 'MaximumRetryCount': 0}
            self.events.append({'Actor': {'ID': cid}, 'Action': 'update'})
            if self.lose_update_reply: raise b.Held('SIMULATED_REPLY_LOST_AFTER_EFFECT')
        elif args[0] == 'kill':
            assert args[1] in ('--signal=SIGTERM', '--signal=SIGINT', '--signal=INT', '--signal=2')
            self.events.append({'Actor': {'ID': cid}, 'Action': 'kill'})
            if not self.never_exit:
                self.host[cid]['State'].update(Running=False, Pid=0, Status='exited', ExitCode=137 if self.bad_exit else 0)
                self.events.append({'Actor': {'ID': cid}, 'Action': 'die'})
        else: raise AssertionError(args)
        return (cid + '\n').encode()

    def sleep(self, seconds): self.clock += seconds


class StopTests(unittest.TestCase):
    def setUp(self):
        f = fixture.ProposalTests()
        f.setUp()
        self.host, self.plan = f.host, f.plan
        self.plan['validUntilEpoch'] = 20000
        self.plan['runtimeSources'] = {}
        for cid, row in self.host.items():
            if row['State']['Running']:
                row['State'].update(Paused=False, Restarting=False, OOMKilled=False, Error='')
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.run = FakeRunner(self.host)
        self.addCleanup(self.tmp.cleanup)

    def execute(self):
        return d.stop_once(vars(b), vars(p), self.plan, self.host, self.root, self.run, 'test-decision',
            wall=lambda: self.run.clock, monotonic=lambda: self.run.clock, sleep=self.run.sleep)

    def test_35_policy_14_signal_and_no_restart(self):
        result = self.execute()
        self.assertEqual((result['policyChanges'], result['selectedRolesStopped'], result['mutationCalls']), (35, 14, 49))
        self.assertFalse(result['applicationDrainProven'])
        self.assertFalse(result['runtimeAuthorityIssued'])
        self.assertTrue((self.root / 'result.json').is_file())
        self.assertEqual(len(list(self.root.glob('*.intent.private.json'))), 49)
        self.assertFalse(any(cmd[0] in ('start', 'restart', 'rm') for cmd in self.run.mutations))

    def test_consumed_claim_blocks_replay_without_new_provider_calls(self):
        self.execute()
        before = self.run.calls
        with self.assertRaises(FileExistsError): self.execute()
        self.assertEqual(self.run.calls, before)

    def test_lost_reply_preserves_intent_and_does_not_replay(self):
        self.run.lose_update_reply = True
        with self.assertRaisesRegex(b.Held, 'SIMULATED_REPLY_LOST_AFTER_EFFECT'): self.execute()
        self.assertEqual(len(self.run.mutations), 1)
        self.assertTrue((self.root / 'action-001.intent.private.json').is_file())
        self.assertFalse((self.root / 'action-001.reply.private.json').exists())
        with self.assertRaises(FileExistsError): self.execute()
        self.assertEqual(len(self.run.mutations), 1)

    def test_timeout_never_sends_sigkill_or_another_group(self):
        self.run.never_exit = True
        with self.assertRaisesRegex(b.Held, 'GROUP_STOP_TIMEOUT_NO_FORCE'): self.execute()
        self.assertEqual(sum(x[0] == 'kill' for x in self.run.mutations), 4)
        self.assertNotIn('SIGKILL', str(self.run.mutations))
        self.assertFalse((self.root / 'result.json').exists())

    def test_bad_exit_blocks_next_group(self):
        self.run.bad_exit = True
        with self.assertRaisesRegex(b.Held, 'UNCLEAN_STOP'): self.execute()
        self.assertEqual(sum(x[0] == 'kill' for x in self.run.mutations), 4)

    def test_fresh_generation_drift_before_mutation(self):
        cid = self.plan['roles']['onboarding']['containerId']
        self.run.host[cid]['State']['StartedAt'] = 'new'
        with self.assertRaisesRegex(b.Held, 'ROLE_GENERATION_CHANGED'): self.execute()
        self.assertFalse(self.run.mutations)

    def test_outside_active_and_membership_drift(self):
        self.run.host['%064x' % 1130]['State']['Running'] = True
        with self.assertRaisesRegex(b.Held, 'UNBOUND_ACTIVE_PROCESS'): self.execute()
        self.assertFalse(self.run.mutations)

    def test_insufficient_plan_window_before_claim(self):
        self.plan['validUntilEpoch'] = 4000
        with self.assertRaisesRegex(b.Held, 'PLAN_WINDOW_TOO_SHORT'): self.execute()
        self.assertEqual(self.run.calls, 0)
        self.assertFalse((self.root / 'claim.private.json').exists())

    def test_budget_never_resets(self):
        self.run.calls = d.MAX_COMMANDS
        with self.assertRaisesRegex(b.Held, 'STOP_COMMAND_OR_BYTE_BUDGET'): self.execute()
        self.assertEqual(self.run.calls, d.MAX_COMMANDS)
        self.assertFalse(self.run.mutations)

    def test_nonproduction_profile_does_not_claim_business_drain(self):
        proposal = p.compile_proposal(self.plan, self.host, vars(b), b.digest(b.canonical(self.plan)), 50, True)
        self.assertEqual(proposal['profile'], 'NONPRODUCTION_TEST_STATE_PRESERVATION')
        self.assertTrue(proposal['unresolvedApplicationWorkMustBePreserved'])
        self.assertFalse(proposal['applicationDrainProven'])


if __name__ == '__main__': unittest.main()
