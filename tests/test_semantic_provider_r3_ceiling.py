"""Compare the complete candidate closure with independently relocated historical bindings."""
import unittest

import test_semantic_provider_r3_v27 as v27

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
                candidate = C._compose_candidate(capped, number, sequence=number, supersedes=previous)
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
                with self.assertRaisesRegex(installed_auth.OperationDenied, 'EXACT_OPERATION_AUTHORIZATION_REQUIRED'):
                    installed_auth.validate(candidate['authorization'])

    def test_same_renewal_cannot_distinguish_25_from_26_by_output_hash(self):
        inputs, _ = v27.fixture(25)
        candidates = [C._compose_candidate(with_ceiling(inputs, cap), 28, sequence=28, supersedes='a' * 64)
                      for cap in (25, 26)]
        first, second = candidates
        self.assertEqual(first['documents'], second['documents'])
        self.assertNotEqual(first['inputHashes']['settings'], second['inputHashes']['settings'])
        self.assertNotEqual(first['authorization'], second['authorization'])

    def test_public_composition_requires_an_accepted_signing_contract(self):
        inputs, _, previous = v27.v25.v24.fixture()
        with self.assertRaisesRegex(C.A.OperationDenied, '^EXACT_OPERATION_AUTHORIZATION_REQUIRED$'):
            C.compose(with_ceiling(inputs, 24), 28, sequence=28, supersedes=C.sha(previous['authorization']))

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
