"""Compare the complete candidate closure with independently relocated historical bindings."""
from types import ModuleType
import unittest

import test_semantic_provider_r3_v27 as v27
from r3_sealed_inputs import sealed_blob

C = v27.C


def with_ceiling(inputs, ceiling):
    files = inputs['files']
    settings = dict(C.document(files['settings']), compositionCeiling=ceiling)
    return dict(inputs, files=dict(files, settings=C.canonical(settings)))


def relocated_hashes(result, number):
    """Relocate historical paths and rehash the exact documents referenced by them."""
    previous = C.document(result['authorization'])['sequence']
    root = result['layout']['installRoot'] + '/'
    prefix = f'versions/{previous}/'
    destination = f'versions/{number}/'
    original = {p.removeprefix(prefix): raw for p, raw in result['documents'].items()}
    hashes = {}

    def relocate(value):
        if isinstance(value, str) and value.startswith(root + prefix):
            return root + destination + value.removeprefix(root + prefix)
        if isinstance(value, list):
            return [relocate(item) for item in value]
        if isinstance(value, dict):
            relocated = {k: relocate(v) for k, v in value.items()}
            path = value.get('path', '')
            if path.startswith(root + prefix) and 'sha256' in value:
                target = path.removeprefix(root + prefix)
                if value['sha256'] != C.sha(original[target]):
                    raise AssertionError('invalid historical binding ' + target)
                relocated['sha256'] = digest(target)
            return relocated
        return value

    def digest(path):
        if path not in hashes:
            raw = original[path]
            if not path.startswith('source/'):
                raw = C.canonical(relocate(C.document(raw)))
            hashes[path] = C.sha(raw)
        return hashes[path]

    return {destination + path: digest(path) for path in original}


class Ceiling(unittest.TestCase):
    def test_complete_historical_closures(self):
        number = 28
        for ceiling in (24, 25, 26, 27):
            with self.subTest(ceiling=ceiling):
                if ceiling == 24:
                    inputs, _, historical = v27.v25.v24.fixture()
                else:
                    inputs, historical = v27.fixture(ceiling)
                previous = C.sha(historical['authorization'])
                capped = with_ceiling(inputs, ceiling)
                candidate = C.compose(capped, number, sequence=number, supersedes=previous)
                expected = relocated_hashes(historical, number)
                self.assertEqual({path: C.sha(raw) for path, raw in candidate['documents'].items()}, expected)
                payload = C.document(candidate['authorization'])
                self.assertEqual((payload['sequence'], payload['supersedes'], payload['compositionCeiling']),
                                 (number, previous, ceiling))
                prefix = f'versions/{number}/'
                expected_payload = C.document(historical['authorization'])
                expected_payload.update(sequence=number, supersedes=previous, compositionCeiling=ceiling,
                                        runtimeConfigurationSha256=expected[prefix + 'runtime-configuration.json'])
                for role, fields in expected_payload['roles'].items():
                    fields['admissionConfigurationSha256'] = expected[prefix + f'broker/{role}.json']
                self.assertEqual(payload, expected_payload)
                self.assertEqual(candidate['inputHashes']['settings'], C.sha(capped['files']['settings']))
                auth_hash = C.sha(candidate['authorization'])
                self.assertEqual(candidate['hashes'], expected | {f'authorization/{number}.json': auth_hash})
                installed_auth = C.contract_module(candidate['documents'][prefix + 'source/' + v27.overlay.AUTH],
                                                   'historical_auth')
                self.assertEqual(installed_auth.validate(candidate['authorization']), payload)

    def test_same_renewal_cannot_distinguish_25_from_26_by_output_hash(self):
        inputs, _ = v27.fixture(25)
        candidates = [C.compose(with_ceiling(inputs, cap), 28, sequence=28, supersedes='a' * 64)
                      for cap in (25, 26)]
        first, second = candidates
        self.assertEqual(first['documents'], second['documents'])
        self.assertNotEqual(first['inputHashes']['settings'], second['inputHashes']['settings'])
        self.assertNotEqual(first['authorization'], second['authorization'])

    def test_uncapped_releases_against_the_pre_extension_composer(self):
        import test_semantic_provider_r3_v12 as v12
        import test_semantic_provider_r3_v13 as v13
        import test_semantic_provider_r3_v15 as v15
        import test_semantic_provider_r3_v18 as v18
        import test_semantic_provider_r3_v22 as v22

        auth_path = v27.overlay.AUTH
        old_auth = sealed_blob(auth_path)
        old = ModuleType('tools.semantic_provider_r3.historical_compose')
        old.__package__ = C.__package__
        exec(compile(sealed_blob('tools/semantic_provider_r3/compose.py'), '<685b6252:compose>', 'exec'), old.__dict__)
        old.A = C.contract_module(old_auth, 'old_authorization')

        fixtures = {v: v12.F.fixture(v) for v in range(1, 12)}
        fixtures[12] = v12.fixture()[0]
        fixtures[13] = fixtures[14] = v13.fixture()[0]
        fixtures[15] = v15.fixture()[0]
        fixtures[16] = v27.v16.v16_fixture()[0]
        fixtures[17] = dict(fixtures[16], files=dict(fixtures[16]['files'],
                            driverBudget=v12.blob('ops/vps/r3-driver-budget.json')))
        for version in range(18, 22):
            fixtures[version] = v18.fixture()[0]
        for version in range(22, 25):
            fixtures[version] = v22.fixture()[0]
        for version in range(25, 28):
            fixtures[version] = v27.fixture(version)[0]

        stale = dict(fixtures[24], sources=fixtures[24]['sources'] | {auth_path: old_auth})
        with self.assertRaisesRegex(C.A.OperationDenied, '^R3_COMPOSED_AUTHORIZATION_REJECTED$'):
            C.compose(with_ceiling(stale, 24), 28, sequence=28, supersedes='a' * 64)

        for version, inputs in fixtures.items():
            with self.subTest(version=version):
                chain = {} if version == 1 else dict(sequence=version, supersedes='a' * 64)
                historical = old.compose(dict(inputs, sources=inputs['sources'] | {auth_path: old_auth}),
                                         version, **chain)
                current = C.compose(inputs, version, **chain)
                prefix = '' if version == 1 else f'versions/{version}/'
                docs = current['documents']
                prior = historical['documents']
                self.assertEqual(docs.keys(), prior.keys())
                # Only these five documents can differ. Reverse each dependency
                # hash substitution and compare every restored byte before hashing.
                changed = [prefix + name for name in ('source/' + auth_path, 'broker/adapter.json',
                           'broker/southbound.json', 'supervisor/configuration.json', 'runtime-configuration.json')]
                self.assertCountEqual([p for p in docs if docs[p] != prior[p]], changed)
                substitutions = {}
                for path in changed:
                    raw = docs[path]
                    if path != changed[0]:
                        for new_hash, old_hash in substitutions.items():
                            raw = raw.replace(new_hash, old_hash)
                        self.assertEqual(raw, prior[path], path)
                    substitutions[C.sha(docs[path]).encode()] = C.sha(prior[path]).encode()
                payload = current['authorization']
                for new_hash, old_hash in substitutions.items():
                    payload = payload.replace(new_hash, old_hash)
                self.assertEqual(payload, historical['authorization'])
                for field in ('layout', 'audit'):
                    self.assertEqual(current[field], historical[field])
                self.assertEqual(current['inputHashes'], historical['inputHashes'] | {
                    'repository/' + auth_path: C.sha(inputs['sources'][auth_path])})

    def test_closed_signed_schema(self):
        payload = C.A.validate(v27.fixture(27)[1]['authorization'])
        for sequence, ceiling in ((28, 23), (28, 28), (24, 25), (23, 24), (28, None),
                                  (28, True), (28, '24'), (28, 24.0)):
            with self.subTest(sequence=sequence, ceiling=ceiling), self.assertRaisesRegex(
                    C.A.OperationDenied, '^R3_COMPOSITION_CEILING_INVALID$'):
                C.A.validate(C.canonical(dict(payload, sequence=sequence, compositionCeiling=ceiling)))
        for changes in ({'unknown': 24}, {'compositionCeiling': 24, 'unknown': 0}):
            with self.assertRaisesRegex(C.A.OperationDenied, '^EXACT_OPERATION_AUTHORIZATION_REQUIRED$'):
                C.A.validate(C.canonical(payload | changes))
        for ceiling in (24, 27):
            value = dict(payload, compositionCeiling=ceiling)
            self.assertEqual(C.A.validate(C.canonical(value)), value)

    def test_invalid_ceiling(self):
        inputs, _ = v27.fixture(27)
        for ceiling in (23, 28, 99, 24.0, '24', True, None):
            with self.subTest(ceiling=ceiling), self.assertRaisesRegex(
                    C.A.OperationDenied, '^R3_COMPOSITION_CEILING_INVALID$'):
                C.compose(with_ceiling(inputs, ceiling), 28, sequence=28, supersedes='a' * 64)

    def test_ceiling_24_requires_its_exact_inputs_and_renewal(self):
        v24, _, _ = v27.v25.v24.fixture()
        v25, _ = v27.fixture(25)
        for inputs, code in ((v25, 'EXACT_R3_INPUT_SET_REQUIRED'),
                             (dict(v24, files=dict(v24['files'], leaseRenewal=v25['files']['leaseRenewal'])),
                              'R3_LEASE_RENEWAL_INVALID')):
            with self.subTest(code=code), self.assertRaisesRegex(C.A.OperationDenied, code):
                C.compose(with_ceiling(inputs, 24), 28, sequence=28, supersedes='a' * 64)
