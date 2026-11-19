"""D-050/task-64 portable compiler contract; no network or installation."""
import copy
import hashlib
import importlib
import importlib.util
import json
from pathlib import Path
import sys
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
COMPILERS = ROOT / 'tools/semantic_cohort_admission/cohort-draft/tools'
package = types.ModuleType('task64_compilers')
package.__path__ = [str(COMPILERS)]
sys.modules.setdefault(package.__name__, package)
old = importlib.import_module('task64_compilers.materialize_southbound_kernel')
m = importlib.import_module('task64_compilers.materialize_southbound_kernel_v2')
with patch.dict(sys.modules, {'tools.materialize_southbound_kernel_v2': m}):
    spec = importlib.util.spec_from_file_location('task64_refresh', ROOT /
        'tools/semantic_lease_recovery/materialize_southbound_lease_refresh_v2.py')
    refresh = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(refresh)
with patch.dict(sys.modules, {'tools.materialize_southbound_kernel': old}):
    spec = importlib.util.spec_from_file_location('task64_old_refresh', ROOT /
        'tools/semantic_lease_recovery/readback_margin_compiler.py')
    old_refresh = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(old_refresh)


def kernel(version=1, ipv6=False):
    source, address, resolver = (('fd64::2', '2001:db8::10', 'fd64::53') if ipv6 else
                                 ('10.64.0.2', '198.51.100.10', '10.64.0.53'))
    result = {'tableName': 'ouf_task64', 'guardedInterfaces': ['egress'],
        'existingInterfaces': ['shared'],
        'staticFlows': [{'purpose': 'DNS', 'source': source, 'destination': resolver,
                         'protocol': p, 'port': 53} for p in ('tcp', 'udp')] +
                       [{'purpose': 'GATEWAY_ADAPTER', 'source': source,
                         'destination': resolver, 'protocol': 'tcp', 'port': 8080}],
        'providerFlows': [{'endpointRef': 'provider', 'endpoint': 'https://provider.invalid:444/path',
            'source': source, 'addresses': [address], 'leaseSeconds': 30,
            'resolutionEvidenceRef': 'fresh', 'allowedPrivateAddresses': [address]}]}
    if version == 2:
        result.update(generation=2, providerFlowMatch='ORIGINAL_TUPLE')
    return result


def observations(cfg, *, now=100, lifetime=30):
    return [{**{k: f[k] for k in ('endpointRef', 'endpoint', 'resolutionEvidenceRef', 'addresses')},
             'observedMonotonic': now, 'expiresMonotonic': now + lifetime,
             'historicalEvidenceOnly': False} for f in cfg['providerFlows']]


class CompilerTests(unittest.TestCase):
    def test_frozen_historical_source_hashes(self):
        # Git delivery bytes are LF; core.autocrlf checkouts are normalized ONLY
        # for this source-file pin, never for compiled nft output equivalence.
        pins = {
            'tools/semantic_cohort_admission/cohort-draft/tools/materialize_southbound_kernel.py':
                '98e3004300226fecd509a46c009585df14021927f20d4e5c82d8ff7a8a8180de',
            'tools/semantic_cohort_admission/cohort-draft/tools/materialize_southbound_lease_refresh.py':
                '1c0d7f1243752fe216ef62eefbc2e3253b8f2503b518fafe11277e4d7721a084',
            'tools/semantic_lease_recovery/materialize_southbound_lease_refresh.py':
                'c3160940cf79678cb8e44c036cb0d947016f885ab09acfe6cce571833db5b079',
            'tools/semantic_lease_activation/materialize_southbound_lease_refresh.py':
                'c3160940cf79678cb8e44c036cb0d947016f885ab09acfe6cce571833db5b079',
            'tools/semantic_lease_recovery/readback_margin_compiler.py':
                '814b5321a5fe5772562f50aa17c34c99c2be741b6e2a9d26110a6b8991bdbf1d',
            'tools/semantic_guard_extension/extend_empty_lease_guard.py':
                'a2da96318982f48d7230c958841c83994bcfca172aeb8612343a3df57049855d',
        }
        for path, digest in pins.items():
            with self.subTest(path=path):
                self.assertEqual(hashlib.sha256((ROOT / path).read_bytes().replace(b'\r\n', b'\n')).hexdigest(), digest)

    def test_generation_one_entire_plan_and_nft_bytes_identical(self):
        configs = [kernel(), kernel(ipv6=True)]
        combined = kernel(); combined['providerFlows'] += kernel(ipv6=True)['providerFlows']
        configs.append(combined)
        none = kernel(); none['providerFlows'] = []; none['staticFlows'] = []
        configs.append(none)
        bounded = kernel(); bounded['guardedInterfaces'] = ['br' + str(i) for i in range(8)]
        bounded['staticFlows'] *= 21
        bounded['providerFlows'] *= 16
        configs.append(bounded)
        for cfg in configs:
            for empty in (False, True):
                with self.subTest(cfg=cfg, empty=empty):
                    before = copy.deepcopy(cfg)
                    expected = old.materialize(cfg, empty_provider_sets=empty)
                    for explicit in (False, True):
                        selected = copy.deepcopy(cfg)
                        if explicit:
                            selected.update(generation=1, providerFlowMatch='CURRENT_TUPLE')
                        actual = m.materialize(config=selected, empty_provider_sets=empty)
                        self.assertEqual(json.dumps(actual).encode(), json.dumps(expected).encode())
                        self.assertEqual(actual['nftRules'].encode(), expected['nftRules'].encode())
                    self.assertEqual(cfg, before)

    def test_original_tuple_both_directions_families_and_ipv6(self):
        for ipv6 in (False, True):
            cfg = kernel(2, ipv6); before = copy.deepcopy(cfg)
            plan = m.materialize(cfg); rules = plan['nftRules']
            family = 'ip6' if ipv6 else 'ip'; source = cfg['providerFlows'][0]['source']
            original = (f'ct original {family} saddr {source} ct original {family} daddr @provider_0 '
                        'ct original protocol tcp ct original proto-dst 444')
            for direction, state in (('original', '{ new, established }'), ('reply', 'established')):
                self.assertEqual(2, rules.count(f'ct direction {direction} {original} ct state {state} counter accept'))
            self.assertNotIn('tcp sport 444', rules)
            self.assertNotIn('tcp dport 444', rules)
            self.assertEqual(plan['tableFamilies'], ['inet', 'bridge'])
            self.assertIn('type ipv6_addr' if ipv6 else 'type ipv4_addr', rules)
            self.assertEqual(cfg, before)
            self.assertEqual(plan['generation'], 2)
            # Reverse ONLY the provider replacements: every other byte, including
            # DNS/relay, sets, hooks, ARP/ND and final drops must be historical.
            restored = rules
            for direction, state, legacy in (
                ('original', '{ new, established }', f'{family} saddr {source} {family} daddr @provider_0 tcp dport 444'),
                ('reply', 'established', f'{family} saddr @provider_0 {family} daddr {source} tcp sport 444')):
                restored = restored.replace(f'ct direction {direction} {original} ct state {state}',
                                            f'{legacy} ct state {state}')
            self.assertEqual(old.materialize(kernel(ipv6=ipv6))['nftRules'].encode(), restored.encode())

    def test_generation_is_part_of_existing_kernel_guard_digest(self):
        # Use the actual existing digest, without changing compose.py.
        sys.path.insert(0, str(ROOT))
        from tools.semantic_provider_r3.compose import lease_guard_hash
        v1, v2 = kernel(), kernel(2)
        self.assertNotEqual(lease_guard_hash(v1), lease_guard_hash(v2))
        for cfg in (v1, v2):
            self.assertEqual(lease_guard_hash(cfg), hashlib.sha256(
                json.dumps(cfg, sort_keys=True, separators=(',', ':')).encode()).hexdigest())

    def test_version_profile_rejects_partial_unknown_and_mismatched_fields(self):
        profiles = [dict(generation=2), dict(providerFlowMatch='ORIGINAL_TUPLE'),
                    dict(generation=3, providerFlowMatch='ORIGINAL_TUPLE'),
                    dict(generation=True, providerFlowMatch='CURRENT_TUPLE'),
                    dict(generation=2., providerFlowMatch='ORIGINAL_TUPLE'),
                    dict(generation=2, providerFlowMatch='CURRENT_TUPLE'),
                    dict(generation=1, providerFlowMatch='ORIGINAL_TUPLE')]
        for profile in profiles:
            with self.subTest(profile=profile), self.assertRaises(ValueError):
                m.materialize({**kernel(), **profile})

    def test_historical_denials_are_preserved_in_both_generations(self):
        cases = []
        def case(mutate):
            cfg = kernel(); mutate(cfg); cases.append(cfg)
        case(lambda c: c.update(extra=True))
        case(lambda c: c.pop('existingInterfaces'))
        case(lambda c: c.update(tableName='bad; drop'))
        case(lambda c: c.update(guardedInterfaces=['shared']))
        case(lambda c: c.update(guardedInterfaces=['egress'] * 2))
        case(lambda c: c.update(guardedInterfaces=['br' + str(i) for i in range(9)]))
        case(lambda c: c.update(staticFlows=c['staticFlows'] * 22))
        case(lambda c: c.update(providerFlows=c['providerFlows'] * 17))
        for field, value in [('source', '127.0.0.1'), ('source', '0.0.0.0'),
                             ('source', 'fe80::1'), ('source', '224.0.0.1'),
                             ('addresses', []), ('addresses', ['198.51.100.10'] * 2),
                             ('addresses', ['198.51.100.' + str(i) for i in range(1, 34)]),
                             ('addresses', ['2001:db8::10']), ('allowedPrivateAddresses', []),
                             ('allowedPrivateAddresses', ['10.0.0.10']),
                             ('leaseSeconds', 0), ('leaseSeconds', 3601), ('leaseSeconds', True),
                             ('endpoint', 'http://provider.invalid'), ('endpoint', 'https://u:p@provider.invalid'),
                             ('endpoint', 'https://provider.invalid:65536'), ('endpointRef', 'bad ref')]:
            case(lambda c, k=field, v=value: c['providerFlows'][0].update({k: v}))
        for field, value in [('purpose', 'OTHER'), ('protocol', 'udp'), ('port', 0)]:
            case(lambda c, k=field, v=value: c['staticFlows'][-1].update({k: v}))
        for cfg in cases:
            with self.subTest(cfg=cfg):
                with self.assertRaises((ValueError, TypeError)) as expected:
                    old.materialize(cfg)
                for version in (1, 2):
                    selected = copy.deepcopy(cfg)
                    if version == 2: selected.update(generation=2, providerFlowMatch='ORIGINAL_TUPLE')
                    with self.assertRaises(type(expected.exception)) as actual:
                        m.materialize(selected)
                    self.assertEqual(str(actual.exception), str(expected.exception))

    def test_empty_sets_only_with_explicit_empty_mode(self):
        cfg = kernel(2); cfg['providerFlows'][0]['addresses'] = []
        with self.assertRaises(ValueError): m.materialize(cfg)
        rules = m.materialize(cfg, empty_provider_sets=True)['nftRules']
        self.assertEqual(2, rules.count('set provider_0 { type ipv4_addr; flags timeout; }'))
        self.assertNotIn('elements =', rules)


class RefreshTests(unittest.TestCase):
    def test_refresh_transaction_equivalence_with_historical_readback_margin(self):
        for ipv6 in (False, True):
            cfg = kernel(ipv6=ipv6)
            for remaining in (0, 2.9, 3., 30.):
                rows = observations(cfg, lifetime=remaining)
                expected = old_refresh.compile_refresh(cfg, rows, 100., apply_budget_seconds=1)
                for versioned in (cfg, {**cfg, 'generation': 2, 'providerFlowMatch': 'ORIGINAL_TUPLE'}):
                    actual = refresh.compile_refresh(versioned, rows, 100., apply_budget_seconds=1)
                    self.assertEqual(json.dumps(actual).encode(), json.dumps(expected).encode())

    def test_refresh_changes_only_sets_and_validates_original_tuple_kernel(self):
        for ipv6 in (False, True):
            cfg = kernel(2, ipv6); before = copy.deepcopy(cfg)
            plan = refresh.compile_refresh(cfg, observations(cfg), 101., apply_budget_seconds=2)
            self.assertFalse(plan['denyOnly'])
            address = cfg['providerFlows'][0]['addresses'][0]
            expected = ''.join(f'flush set {f} ouf_task64 provider_0\n' for f in ('inet', 'bridge'))
            expected += ''.join(f'add element {f} ouf_task64 provider_0 {{ {address} timeout 27s }}\n'
                                for f in ('inet', 'bridge'))
            self.assertEqual(plan['nftTransaction'], expected)
            self.assertEqual(cfg, before)

    def test_bad_resolution_clears_every_set_and_never_changes_rules(self):
        cfg = kernel(2); cfg['providerFlows'] += kernel(2, True)['providerFlows']
        for change in ('missing', 'historical', 'private', 'family', 'expired', 'margin', 'binding'):
            rows = observations(cfg)
            if change == 'missing': rows.pop()
            if change == 'historical': rows[-1]['historicalEvidenceOnly'] = True
            if change == 'private': rows[-1]['addresses'] = ['fd64::99']
            if change == 'family': rows[-1]['addresses'] = ['1.1.1.1']
            if change == 'expired': rows[-1]['expiresMonotonic'] = 101
            if change == 'margin': rows[-1]['expiresMonotonic'] = 103.9
            if change == 'binding': rows[-1]['endpoint'] = 'https://other.invalid'
            with self.subTest(change=change):
                result = refresh.compile_refresh(cfg, rows, 101., apply_budget_seconds=1)
                self.assertTrue(result['denyOnly'])
                self.assertEqual(result['nftTransaction'], ''.join(
                    f'flush set {f} ouf_task64 provider_{i}\n' for f in ('inet', 'bridge') for i in range(2)))
        cfg['generation'] = 99
        with self.assertRaises(ValueError):
            refresh.compile_refresh(cfg, [], 101., apply_budget_seconds=1)


if __name__ == '__main__': unittest.main()
