"""Prove explicit source deltas and numeric-only diagnostics; no target actions."""
import hashlib
import importlib.util
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parent
ORIGINAL = ROOT.parents[0] / 'semantic_cohort_admission/cohort-draft/tools/semantic_provider_dns.py'
if not ORIGINAL.exists(): ORIGINAL = ROOT / 'semantic_provider_dns_original.py'
CANDIDATE = ROOT / 'dns_recovery_dns.py'
if not CANDIDATE.exists(): CANDIDATE = ROOT / 'semantic_provider_dns_candidate.py'
spec = importlib.util.spec_from_file_location('fixture_dns_recovery_core', ROOT / 'dns_recovery_core.py')
core = importlib.util.module_from_spec(spec)
spec.loader.exec_module(core)


class RecoveryCoreTest(unittest.TestCase):
    def setUp(self):
        self.modules = {k: v for k, v in sys.modules.items() if k == 'tools' or k.startswith('tools.')}
        names = ('materialize_southbound_kernel', 'semantic_provider_dns', 'materialize_southbound_lease_refresh',
            'semantic_provider_lease_nft', 'semantic_provider_lease_owner',
            'semantic_provider_lease_coordination', 'semantic_provider_coordinated_supervisor')
        self.original = ORIGINAL.read_bytes()
        self.new = CANDIDATE.read_bytes()
        self.sources = {'tools/' + name + '.py': b'FIXTURE_ONLY = True\n' for name in names}
        self.sources['tools/semantic_provider_dns.py'] = self.original
        self.sources['scripts/run_semantic_coordinated_lease_owner.py'] = b'# fixture\n'
        self.owner = {'sourceHashes': {name: core.digest(raw) for name, raw in self.sources.items()}}
        self.reads = []
        self.binding = {'path': '/fixture/new_dns.py', 'sha256': core.digest(self.new),
            'originalSha256': core.digest(self.original)}

    def tearDown(self):
        for name in list(sys.modules):
            if name == 'tools' or name.startswith('tools.'): del sys.modules[name]
        sys.modules.update(self.modules)

    def read(self, path, expected):
        self.reads.append(str(path))
        raw = self.new if str(path) == self.binding['path'] else self.sources[str(path.relative_to('/fixture/source'))]
        self.assertEqual(core.digest(raw), expected)
        return raw

    def test_verified_new_module_executes_but_retained_original_bytes_are_preserved(self):
        modules, saved = core.load_installed(self.owner, Path('/fixture/source'), self.read, dns_override=self.binding)
        self.assertEqual(saved['tools/semantic_provider_dns.py'], self.original)
        self.assertEqual(saved, self.sources)
        dns = modules['semantic_provider_dns']
        def query(resolver, port, host, kind, deadline):
            return {'transport': 'UDP', 'responseHash': 'a' * 64, 'authenticatedDataFlag': False,
                'records': [{'owner': host, 'type': kind, 'class': 1, 'ttl': 30, 'section': 'answer',
                    'value': '93.184.216.34' if kind == 1 else '2001:4860:4860::8888'}]}
        result = dns.observe('https://provider.fixture.example/sparql', ['127.0.0.1'], 53, 4, [], 2, 30, query)
        self.assertEqual(result['freshObservationAttempts'], 1)
        self.assertEqual(result['usableAddresses'], ['93.184.216.34'])

    def test_wrong_original_hash_or_unknown_delta_fields_refused_before_new_bytes(self):
        for delta in ({**self.binding, 'originalSha256': '0' * 64}, {**self.binding, 'unreviewed': True}):
            with self.assertRaisesRegex(ValueError, 'EXPLICIT_REVIEWED_DNS_DELTA_REQUIRED'):
                core.load_installed(self.owner, Path('/fixture/source'), self.read, dns_override=delta)
            self.assertNotIn('/fixture/new_dns.py', self.reads)

    def test_numeric_window_and_attempt_count_recorded_without_raw_private_values(self):
        error = RuntimeError('DNS_OBSERVATION_EXPIRED_OR_NONCACHEABLE')
        error.observation_window = {'minimumObservedTtlSeconds': 0, 'elapsedSeconds': .02, 'ttlNoncacheable': True}
        error.fresh_observation_attempts = 3
        error.endpoint = 'https://private.example/?token=secret'
        result = core.diagnosis(error)
        window = result['exceptionChain'][0]['dnsObservationWindow']
        self.assertEqual(window['freshObservationAttempts'], 3)
        self.assertTrue(window['ttlNoncacheable'])
        self.assertNotIn('private.example', str(result)); self.assertNotIn('secret', str(result))

    def test_nonfinite_or_extra_private_window_fields_are_not_projected(self):
        for window in ({'minimumObservedTtlSeconds': 0, 'elapsedSeconds': float('nan'), 'ttlNoncacheable': True},
                       {'minimumObservedTtlSeconds': True, 'elapsedSeconds': .1, 'ttlNoncacheable': False},
                       {'minimumObservedTtlSeconds': 0, 'elapsedSeconds': .1, 'ttlNoncacheable': True, 'secret': 'private'}):
            error = RuntimeError('DNS_OBSERVATION_EXPIRED_OR_NONCACHEABLE')
            error.observation_window = window; error.fresh_observation_attempts = 3
            self.assertNotIn('dnsObservationWindow', core.diagnosis(error)['exceptionChain'][0])


if __name__ == '__main__': unittest.main()
