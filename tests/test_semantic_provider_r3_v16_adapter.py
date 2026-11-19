"""Portable proofs for the D-053 adapter and driver budget changes in R3."""
import copy
from contextlib import nullcontext
from dataclasses import replace
import json
from pathlib import Path, PurePosixPath
import re
import runpy
import stat
import sys
import tempfile
from types import ModuleType, SimpleNamespace
import unittest
from unittest.mock import patch

import test_semantic_provider_r3_v15 as V15
from tools.semantic_provider_config import acceptance_g7 as G, b1_v4 as B, contract as D
from tools.semantic_provider_config import observation as O, publication as P
from tools.semantic_provider_r3 import adapter_v16 as A, compose as C, driver_budget_v17 as BUDGET
from tools.semantic_provider_r3 import read_adapter_v16 as R, upgrade
from tools.semantic_provider_routes.routes import Held


V13, V12 = V15.V13, V15.V13.V12
SOURCE = '/fixture/adapter.json'
OLD = ['https://fixture.invalid/old/']
NEW = ['http://fixture.invalid/new#', 'https://fixture.invalid/vocabulary/']


def raw(document):
    return D.canonical(document) + b'\n'


def config(prefixes=OLD, endpoint='https://fixture1.invalid/sparql'):
    return {'listenAddress': '0.0.0.0', 'listenPort': 9443, 'maxWorkers': 4, 'requestTimeoutSeconds': 8,
            'searchPath': '/search', 'fetchPath': '/fetch', 'receiptKeyFile': '/private/receipt.key',
            'tlsCertificateFile': '/private/server.crt', 'tlsPrivateKeyFile': '/private/server.key',
            'admission': {'installation': 'synthetic-installation', 'issuer': 'https://issuer.invalid',
                          'audience': 'gateway', 'workload': 'registry', 'scope': 'query', 'tenants': ['fixture']},
            'provider': {'endpoint': endpoint, 'allowed_cidrs': [], 'namespace_prefixes': prefixes,
                         'max_request_bytes': 100, 'max_response_bytes': 1000, 'max_intent_chars': 256,
                         'timeout_seconds': 5, 'ca_file': '/private/ca.crt'}}


def profile(ref='schema-gov', **scope):
    return {'schema': 'ouf.semantic-provider-installation.v1',
            D.DECLARATION: [{'endpointRef': ref, 'namespacePrefixes': NEW}], **scope}


def v16_fixture():
    kernel = V12.kernel_configuration()
    kernel['providerFlows'][1]['endpoint'] = 'https://fixture1.invalid/sparql'
    with patch.object(V12, 'kernel_configuration', return_value=kernel):
        inputs, old = V15.fixture()
    files = inputs['files']
    kernel = C.document(files['coordinator'])['kernel']
    flow = next(row for row in kernel['providerFlows'] if row['source'] == '172.22.0.3')
    original = raw(config(OLD, flow['endpoint']))
    published = raw(config(NEW, flow['endpoint']))
    entry = {'source': SOURCE, 'target': D.TARGET, 'sha256': D.sha(original), 'readOnly': True,
             **dict(zip(('uid', 'gid', 'mode'), D.METADATA)), 'maxBytes': 1048576}
    template, launch, context = (C.document(files['adapter/' + p]) for p in ('template', 'launch', 'context'))
    template['expectedOci']['mounts'].append(dict(type='bind', source=SOURCE, destination=D.TARGET, options=['ro']))
    launch['manifest']['mounts'].append({key: entry[key] for key in ('source', 'target', 'readOnly')})
    launch['sources'].append(entry)
    policy = C.compile_policy(template, launch, context)
    accepted = C.ACCEPT.decode_manifest(files['acceptance'])
    for part, doc in (('template', template), ('launch', launch), ('policy', policy)):
        files['adapter/' + part] = raw(doc)
        accepted['roles']['adapter']['recipe'][part]['sha256'] = C.sha(files['adapter/' + part])
    files['acceptance'] = C.ACCEPT.build_acceptance(**accepted)
    before = C.compose(inputs, 15, sequence=15, supersedes=C.sha(old['authorization']))
    recipes = {part: files['adapter/' + part] for part in B.B.PARTS}
    publication = {'source': SOURCE, 'oldSha256': D.sha(original), 'newSha256': D.sha(published)}
    for part, content in B.revise('adapter', recipes, publication, C).items():
        files['adapter/' + part] = content
        accepted['roles']['adapter']['recipe'][part]['sha256'] = C.sha(content)
    files[A.PROFILE] = raw(profile(flow['endpointRef'], installationRef=accepted['installationRef'],
                                   entityRef=accepted['entityRef']))
    accepted['profile'] = {'path': D.PROFILE_PATH, 'sha256': C.sha(files[A.PROFILE])}
    files['acceptance'] = C.ACCEPT.build_acceptance(**(accepted | {'generation': 7}))
    files[A.INPUT] = raw(D.project(SOURCE, published))
    inputs['sources'].update({p: V12.blob(p) for p in C.SOURCE_INPUTS_V16 - C.SOURCE_INPUTS_V15})
    return inputs, before


class Configuration(unittest.TestCase):
    def test_projection_is_closed_and_reader_checks_custody_and_bytes(self):
        original = raw(config())
        projected = D.project(SOURCE, original)
        self.assertEqual(projected, {'source': SOURCE, 'sha256': D.sha(original), 'bytes': len(original),
                                    'provider': {'endpoint': {'host': 'fixture1.invalid', 'port': 443, 'path': '/sparql'},
                                                 'allowed_cidrs': [], 'namespace_prefixes': OLD}})
        entry = dict(source=SOURCE, sha256=D.sha(original), target=D.TARGET, readOnly=True,
                     uid=10006, gid=10006, mode=0o600, maxBytes=1048576)
        recipe = raw({'sources': [entry]})
        pins = SimpleNamespace(adapter_launch='/launch.json', adapter_policy='/policy.json',
                               adapter_launch_sha256=D.sha(recipe), adapter_policy_sha256=D.sha(recipe))
        disk = {'/launch.json': recipe, '/policy.json': recipe, SOURCE: original}
        calls = []

        def read(path, digest, **kwargs):
            self.assertEqual(D.sha(disk[path]), digest)
            calls.append((path, kwargs))
            return disk[path]

        self.assertEqual(R.observe(pins, read=read), projected)
        self.assertEqual(calls[:3], calls[3:])
        self.assertEqual(calls[2], (SOURCE, {'metadata': D.METADATA, 'limit': 1048576}))
        self.assertNotIn(b'/private/', raw(projected))

    def test_canonical_identity_closed_shape_and_prefix_syntax(self):
        original = raw(config())
        for payload in (original.rstrip(), original + b'\n', b' ' + original,
                        original.replace(b'"listenPort":9443', b'"listenPort":9443,"listenPort":9443'),
                        raw(config() | {'privateValue': 'synthetic'})):
            with self.subTest(payload=payload), self.assertRaises(Held):
                D.project(SOURCE, payload)
        for prefix in ('ftp://fixture.invalid/ns/', 'https://user@fixture.invalid/', 'https://fixture.invalid/?#',
                       'https://fixture.invalid/ns', 'https://fixture.invalid/ns#value/', 'https:///path/'):
            with self.subTest(prefix=prefix), self.assertRaisesRegex(Held, D.NAMESPACES):
                D.prefixes([prefix], declaration=True)
        for endpoint in ('https://fixture1.invalid/sparql?', 'https://fixture1.invalid/sparql#',
                         'http://fixture1.invalid/sparql', 'https://user@fixture1.invalid/sparql'):
            with self.subTest(endpoint=endpoint), self.assertRaisesRegex(Held, D.ENDPOINT):
                D.project(SOURCE, raw(config(endpoint=endpoint)))
        after, changes, before, projection = D.regenerate(SOURCE, original, profile())
        self.assertEqual(changes, [{'path': '/provider/namespace_prefixes', 'before': OLD, 'after': NEW}])
        self.assertEqual((before['sha256'], projection['sha256']), (D.sha(original), D.sha(after)))
        revised = D.config(after)
        revised['provider']['namespace_prefixes'] = OLD
        self.assertEqual(raw(revised), original)
        with self.assertRaisesRegex(Held, 'ADAPTER_NAMESPACE_DELTA_REQUIRED'):
            D.regenerate(SOURCE, after, profile())

    def test_additive_profile_and_reverse_delta(self):
        path = Path(__file__).resolve().parents[1] / 'scripts/revise-semantic-provider-namespaces.py'
        # The profile planner uses no system users or groups in the pure fixture.
        with patch.dict(sys.modules, {name: ModuleType(name) for name in ('grp', 'pwd')}):
            script = runpy.run_path(str(path))
        revise = script['namespace_revision']
        destination = PurePosixPath(D.PROFILE_PATH)
        original = {'schema': 'ouf.semantic-provider-installation.v1', 'installationRef': destination.parent.name,
                    'externalEndpoints': {'provider': {'sourceRole': 'adapter'}}, 'retained': {'number': 1}}
        old_pin = D.sha(raw(original))
        args = SimpleNamespace(restore=False, revise_from_sha256=old_pin,
                               namespace_endpoint_ref='schema-gov', namespace_prefix=NEW)
        backup = destination.with_name(destination.name + '.superseded-' + old_pin)
        stored = {destination: original}

        def read(path, expected):
            self.assertEqual(D.sha(raw(stored[path])), expected)
            return stored[path], {'previousProfileSha256': expected, 'previousProfileIdentity': {}}

        with patch.dict(revise.__globals__, {'absolute': PurePosixPath, 'revision_base': read}):
            proposal, updated = revise(args)
            self.assertEqual(proposal['profileDiff'], [{'path': '/providerNamespaces', 'change': 'added'}])
            self.assertEqual(D.decode(updated), original | {D.DECLARATION: profile()[D.DECLARATION]})
            stored[backup] = original
            stored[destination] = D.decode(updated)
            args.restore, args.original_profile_sha256 = True, old_pin
            args.revise_from_sha256 = proposal['profileSha256']
            self.assertEqual(revise(args)[1], raw(original))
            stored[destination]['retained']['number'] = True
            args.revise_from_sha256 = D.sha(raw(stored[destination]))
            with self.assertRaisesRegex(RuntimeError, 'NAMESPACE_RESTORE_DELTA_UNPROVEN'):
                revise(args)

    def test_publication_plan_apply_restore_and_conflicts(self):
        original = raw(config())
        approved = raw(profile())
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, declaration = root / 'adapter.json', root / 'profile.json'
            source.write_bytes(original)
            declaration.write_bytes(approved)
            entry = replace(P.FILES['adapter.json'], source=source, claim=root / 'claim', declaration=declaration,
                            project=lambda _, value: D.project(SOURCE, value),
                            regenerate=lambda _, value, profile: D.regenerate(SOURCE, value, profile))
            pins = SimpleNamespace(profile_sha256=D.sha(approved), old_sha256=D.sha(original), plan_sha256='0' * 64)

            def read(path, expected=None, **kwargs):
                value = Path(path).read_bytes()
                if expected is not None:
                    D.require(D.sha(value) == expected, 'INPUT_SHA256_MISMATCH')
                return value

            def write(path, value, *args):
                with path.open('xb') as stream:
                    stream.write(value)

            with patch.dict(P.execute.__globals__, {'FILES': {'adapter.json': entry}}), \
                    patch.object(O, 'fenced', nullcontext), patch.object(O, 'safety', return_value=({'ok': True}, {})), \
                    patch.multiple(P.C, directory=lambda *a, **k: None, sync_dir=lambda p: None,
                                   read=read, write_once=write):
                with self.assertRaisesRegex(Held, 'CONFIGURATION_FILE_NOT_ALLOWED'):
                    P.execute('plan', 'apisix.yaml', pins, docker=object())
                plan = P.execute('plan', 'adapter.json', pins, docker=object())
                self.assertEqual(source.read_bytes(), original)
                with self.assertRaisesRegex(Held, 'PLAN_DIGEST_MISMATCH'):
                    P.execute('apply', 'adapter.json', pins, docker=object())
                self.assertFalse(entry.claim.exists())
                pins.plan_sha256 = plan['planSha256']
                result = P.execute('apply', 'adapter.json', pins, docker=object())
                updated = source.read_bytes()
                self.assertEqual(result['newSha256'], D.sha(updated))
                self.assertEqual(P.published(entry, D.sha((entry.claim / 'result.json').read_bytes()), pins.profile_sha256),
                                 result)
                source.write_bytes(updated + b'\n')
                with self.assertRaisesRegex(Held, 'INPUT_SHA256_MISMATCH'):
                    P.execute('restore', 'adapter.json', pins, docker=object())
                source.write_bytes(updated)
                self.assertEqual(P.execute('restore', 'adapter.json', pins, docker=object())['restoredSha256'],
                                 D.sha(original))
                self.assertEqual(source.read_bytes(), original)
                with self.assertRaisesRegex(Held, 'CONFIGURATION_ALREADY_RESTORED'):
                    P.execute('restore', 'adapter.json', pins, docker=object())

    def test_observation_authenticates_selected_version_and_quiescence(self):
        policy = dict.fromkeys(('anchorBinding', 'mandateRoot', 'installationRef', 'issuerRef', 'entityRef'), 'fixture')
        install = O.P.INSTALL
        op = policy | {'authorizationRoot': str(O.P.AUTHORIZATION)}
        cfg = dict(operation=op, opensslBinding='fixture ssl', pythonPath='/usr/bin/python3',
                   registryRoot=str(install / 'registry'),
                   candidates={cid: {'role': role} for role, cid in O.P.CIDS.items()},
                   leaseQuiesce={'configuration': 'supervisor'})
        binding = dict.fromkeys(('transactionId', 'configurationHash', 'leaseStructureHash'), 'fixture')
        owner = {'journalFile': '/fixture/coordination.json', 'commonLockFile': str(O.P.GUARD), 'binding': binding}
        lease = {'ownerConfiguration': 'owner', 'journalPath': owner['journalFile'],
                 'commonLockPath': owner['commonLockFile']}
        journal = binding | {'state': 'QUIESCED', 'leaseAuthorized': False, 'startAuthorized': False}
        cfg_raw = raw(cfg)
        executable = b'# synthetic runtime fixture\n'
        for version in (15, 16):
            with self.subTest(version=version):
                root = install / 'versions' / str(version)
                runtime_path = root / 'source' / O.P.RUNTIME
                config_path = root / 'runtime-configuration.json'
                wrapper = (f'#!/bin/sh\nexec /usr/bin/python3 -I -B {runtime_path} '
                           f'--configuration {config_path} "$@"\n').encode('ascii')
                head = {'decision': 'OPERATE', 'sequence': version, 'sha256': 'a' * 64}
                pins = SimpleNamespace(r3_version=version, r3_configuration_sha256=D.sha(cfg_raw),
                                       r3_wrapper_sha256=D.sha(wrapper), r3_runtime_sha256=D.sha(executable),
                                       r3_head_sha256=head['sha256'])
                by_path = {str(config_path): cfg_raw, str(O.P.WRAPPER): wrapper, str(runtime_path): executable,
                           str(O.P.ROOT / 'ops/vps/r3-settings.json'): raw(policy | {'opensslBinding': 'fixture ssl'})}
                epochs = SimpleNamespace(current=lambda *args: None, TERMINAL={'DELETED'})
                runtime = SimpleNamespace(load_configuration=lambda path: (cfg, cfg_raw), verify_files=lambda cfg: None,
                                          operation_modules=lambda cfg: ('auth', epochs),
                                          authorization_head=lambda *args: head,
                                          bound_bytes={'supervisor': raw({'coordinator': lease}),
                                                       'owner': raw(owner)}.__getitem__)

                def read(path, digest=None, **kwargs):
                    if path == owner['journalFile']:
                        return raw(journal)
                    result = by_path[str(path)]
                    if digest != O.P.SETTINGS_SHA:
                        D.require(D.sha(result) == digest, 'INPUT_SHA256_MISMATCH')
                    return result

                with patch.object(O.types, 'ModuleType', return_value=runtime), \
                        patch.multiple(O.C, read=read, directory=lambda *a, **k: None):
                    observed = O.observe_r3(pins)
                    self.assertEqual(observed['authorization'], head)
                    self.assertEqual(observed['lease']['sha256'], D.sha(raw(journal)))
                    pins.r3_head_sha256 = 'b' * 64
                    with self.assertRaisesRegex(Held, 'R3_OPERATE_HEAD_UNPROVEN'):
                        O.observe_r3(pins)
                    pins.r3_head_sha256 = head['sha256']
                    journal['startAuthorized'] = True
                    try:
                        with self.assertRaisesRegex(Held, 'R3_LEASE_NOT_QUIESCED'):
                            O.observe_r3(pins)
                    finally:
                        journal['startAuthorized'] = False


class RecipesAndAcceptance(unittest.TestCase):
    def test_b1_v4_recompiles_only_adapter_sources_with_real_compiler(self):
        inputs, _ = v16_fixture()
        files = inputs['files']
        published = D.sha(b'new material')
        adapter = {part: files['adapter/' + part] for part in B.B.PARTS}
        previous = D.source_entry(D.decode(adapter['launch']))
        receipt = {'source': SOURCE, 'oldSha256': previous['sha256'], 'newSha256': published}
        updated = B.revise('adapter', adapter, receipt, C)
        self.assertEqual({p for p in adapter if adapter[p] != updated[p]}, {'launch', 'policy'})
        for p in ('launch', 'policy'):
            restored = D.decode(updated[p])
            D.source_entry(restored)['sha256'] = previous['sha256']
            self.assertEqual(raw(restored), adapter[p])
        southbound = {part: files['southbound/' + part] for part in B.B.PARTS}
        self.assertEqual(B.revise('southbound', southbound, receipt, C), southbound)
        with self.assertRaisesRegex(Held, 'ADAPTER_CONFIG_PREVIOUS_SOURCE_UNPROVEN'):
            B.revise('adapter', adapter, receipt | {'oldSha256': '1' * 64}, C)

    def test_g7_requires_b1_v4_and_the_same_profile_and_d042(self):
        pin = D.sha(raw(profile()))
        rootfs = {'path': '/fixture/d042.json', 'sha256': 'f' * 64}
        b1 = {'schema': B.B.SCHEMA, 'status': 'SEMANTIC_PROVIDER_B1_RECIPES_PREPARED', 'recipeRevision': 4,
              'rootfs': rootfs, 'installationProfile': {'path': D.PROFILE_PATH, 'sha256': pin}}
        G.validate(b1, profile(), pin, rootfs)
        for field, invalid, code in (('recipeRevision', 3, 'ACCEPTANCE_G7_B1_V4_REQUIRED'),
                                     ('installationProfile', {}, 'ACCEPTANCE_G7_PROFILE_MISMATCH'),
                                     ('rootfs', {}, 'ACCEPTANCE_G7_D042_REQUIRED')):
            with self.subTest(field=field), self.assertRaisesRegex(Held, code):
                G.validate(b1 | {field: invalid}, profile(), pin, rootfs)

    def test_runbook_source_pins_match_lf_delivery(self):
        root = Path(__file__).resolve().parents[1]
        for name in ('config-publish', 'b1-recipes-v4', 'acceptance-v51-g7'):
            with self.subTest(name=name):
                text = (root / 'ops/vps' / (name + '.sh')).read_text()
                self.assertRegex(text, r'(?m)^C=[0-9a-f]{40}$')
                shell = re.findall(r'^fetch (\S+) ([0-9a-f]{64})$', text, re.MULTILINE)
                acceptance = re.findall(r'^    "([0-9a-f]{64})" "\$1/([^"]+)"', text, re.MULTILINE)
                pins = dict(shell + [(p, digest) for digest, p in acceptance])
                self.assertIn('tools/semantic_provider_config/contract.py', pins)
                for path, digest in pins.items():
                    self.assertEqual(D.sha((root / path).read_bytes().replace(b'\r\n', b'\n')), digest, path)
        self.assertIn('--generation 7', text)
        self.assertIn('--installation-profile-sha256 "$profile_sha"', text)


class Composition(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.inputs, cls.previous = v16_fixture()

    def compose(self, inputs):
        return C.compose(inputs, 16, sequence=16, supersedes=C.sha(self.previous['authorization']))

    def test_v16_inputs_authorization_and_determinism(self):
        files, sources = self.inputs['files'], self.inputs['sources']
        self.assertEqual(C.DATA_INPUTS_V16 - C.DATA_INPUTS_V15, {A.INPUT, A.PROFILE})
        self.assertTrue(C.input_set(files, sources))
        result = self.compose(self.inputs)
        self.assertEqual(result, self.compose(self.inputs))
        for name in (A.INPUT, A.PROFILE):
            self.assertEqual(result['inputHashes'][name], C.sha(files[name]))
            with self.assertRaisesRegex(RuntimeError, 'EXACT_R3_INPUT_SET_REQUIRED'):
                self.compose({'files': {k: v for k, v in files.items() if k != name}, 'sources': sources})
        authorization = C.document(result['authorization'])
        self.assertEqual(authorization['acceptanceSha256'], C.sha(files['acceptance']))
        previous = C.document(self.previous['authorization'])
        head = {'sequence': 15, 'decision': 'OPERATE', 'sha256': C.sha(self.previous['authorization']),
                'authorization': previous}
        issuer = V12.F.load('scripts/issue-semantic-provider-operation-authorization.py', 'v16_adapter_issuer')
        self.assertEqual(issuer.compose_next(self.inputs, head, authorization['issuedAt']), result)
        def pair(path):
            return tuple(C.document(closure['documents'][f'versions/{version}/' + path])
                         for closure, version in ((self.previous, 15), (result, 16)))

        upgrade.shared_state(16, *pair('supervisor/configuration.json'), files, previous)
        self.assertEqual(authorization['lease'], previous['lease'])
        for role, auth in authorization['roles'].items():
            for key, path in (('framePolicySha256', f'documents/{role}/frame-policy.json'),
                              ('admissionConfigurationSha256', f'broker/{role}.json')):
                self.assertEqual(auth[key], C.sha(result['documents']['versions/16/' + path]))
            old_frame, new_frame = pair(f'documents/{role}/frame-policy.json')
            self.assertEqual(old_frame['expectedOci'], new_frame['expectedOci'])
            self.assertEqual(old_frame != new_frame, role == 'adapter')

    def test_v16_denials(self):
        cases = (
            (A.INPUT, lambda p: p['provider']['endpoint'].update(path='/different'), A.ENDPOINT),
            (A.INPUT, lambda p: p['provider'].update(allowed_cidrs=['192.0.2.1/32']), A.CIDRS),
            (A.INPUT, lambda p: p['provider'].update(namespace_prefixes=OLD), A.NAMESPACES),
            (A.INPUT, lambda p: p.update(sha256='0' * 64), A.SOURCE),
            ('adapter/policy', lambda p: D.source_entry(p).update(sha256='0' * 64), A.SOURCE),
            (A.PROFILE, lambda p: p.update(other=True), A.PROFILE_PIN),
            ('coordinator', lambda p: p['kernel']['providerFlows'].append(
                next(row for row in p['kernel']['providerFlows'] if row['source'] == '172.22.0.3')
                | {'endpointRef': 'also-on-egress'}), A.AMBIGUOUS),
            ('coordinator', lambda p: next(row for row in p['kernel']['providerFlows']
                                           if row['source'] == '172.22.0.3').update(allowedPrivateAddresses=['192.0.2.1']),
             A.CIDRS),
        )
        for key, change, code in cases:
            inputs = copy.deepcopy(self.inputs)
            files = inputs['files']
            value = C.document(files[key])
            change(value)
            files[key] = raw(value)
            if key == 'coordinator':
                settings = C.document(files['settings'])
                settings['coordinatorBinding']['sha256'] = C.sha(files[key])
                files['settings'] = raw(settings)
            with self.subTest(key=key, code=code), self.assertRaisesRegex(C.A.OperationDenied, '^' + code + '$'):
                self.compose(inputs)

    def test_frozen_v1_to_v16(self):
        golden = json.loads(V12.blob('tests/fixtures/r3-v1-v15-pre-v16-hashes.json'))
        # Captured at 701a4cc9, before the v17 composer changes.
        golden['16'] = {
            'audit': '302d3b526d20af5f200c95a7258d9351254ce50220df3425aa7a3749db8e8aab',
            'authorization': '8cec50357885e7f0644df4342782c6addb3416ea0466d288391ef144ebf798d1',
            'hashes': '0c253fd9152056bd715538de907b9fc63dc2aec24871e66fe084fa6b863f86de',
            'inputHashes': 'f8603f74a8e182402f046bea74fadc48c9831ece8aae7488a448a4867c9c0270',
            'layout': 'b7406a4f31f4b8fd639205ccb230685aca2087f8c9d80b624deccd699dc14580',
        }
        for version in range(1, 17):
            with self.subTest(version=version):
                if version <= 11:
                    data = V12.F.fixture(version)
                    kwargs = {} if version == 1 else dict(sequence=version, supersedes='a' * 64)
                else:
                    if version == 12:
                        data, previous, _, _ = V12.fixture()
                    elif version < 16:
                        data, previous = (V13 if version < 15 else V15).fixture()
                    else:
                        data, previous = self.inputs, self.previous
                    kwargs = dict(sequence=version, supersedes=C.sha(previous['authorization']))
                output = C.compose(data, version, **kwargs)
                actual = {key: C.sha(C.canonical(output[key])) for key in ('hashes', 'inputHashes', 'audit', 'layout')}
                self.assertEqual(actual | {'authorization': C.sha(output['authorization'])}, golden[str(version)])


class DriverBudget(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        inputs, previous = v16_fixture()
        cls.v16 = C.compose(inputs, 16, sequence=16, supersedes=C.sha(previous['authorization']))
        cls.inputs = inputs | {'files': inputs['files'] | {
            'driverBudget': V12.blob('ops/vps/r3-driver-budget.json')}}

    def compose(self, inputs):
        return C.compose(inputs, 17, sequence=17, supersedes=C.sha(self.v16['authorization']))

    def test_v17_successor_and_sealed_budget(self):
        files, sources = self.inputs['files'], self.inputs['sources']
        self.assertEqual(C.DATA_INPUTS_V17 - C.DATA_INPUTS_V16, {'driverBudget'})
        self.assertEqual(C.SOURCE_INPUTS_V17, C.SOURCE_INPUTS_V16)
        self.assertTrue(C.input_set(files, sources))
        result = self.compose(self.inputs)
        self.assertEqual(result['inputHashes']['driverBudget'], C.sha(files['driverBudget']))
        old_auth, auth = (C.document(r['authorization']) for r in (self.v16, result))
        head = {'sequence': 16, 'decision': 'OPERATE', 'sha256': C.sha(self.v16['authorization']),
                'authorization': old_auth}
        issuer = V12.F.load('scripts/issue-semantic-provider-operation-authorization.py', 'v17_budget_issuer')
        self.assertEqual(issuer.compose_next(self.inputs, head, auth['issuedAt']), result)
        self.assertEqual(auth['supersedes'], head['sha256'])
        self.assertEqual(auth['acceptanceSha256'], old_auth['acceptanceSha256'])
        self.assertEqual(C.ACCEPT.decode_manifest(files['acceptance'])['generation'], 7)
        self.assertEqual(auth['lease'], old_auth['lease'])
        old, new = (r['documents'] for r in (self.v16, result))
        old_cfg, cfg = (C.document(d[f'versions/{v}/runtime-configuration.json'])
                        for d, v in ((old, 16), (new, 17)))
        self.assertEqual(cfg['candidates'], old_cfg['candidates'])
        upgrade.shared_state(17, C.document(old['versions/16/supervisor/configuration.json']),
                             C.document(new['versions/17/supervisor/configuration.json']), files, old_auth)
        self.assertEqual({p.removeprefix('versions/17/source/') for p in new if '/source/' in p
                          and new[p] != old[p.replace('versions/17/', 'versions/16/', 1)]}, {
            'tools/semantic_provider_admission_v2/preparer_v2.py',
            'tools/semantic_provider_admission_v2/driver_v7.py',
            'tools/semantic_provider_preexec_native.py',
            C.SOURCE_MAP_V17['tools/semantic_provider_preexec_native.py'],
        })
        for role in C.ROLES:
            with self.subTest(role=role):
                path = f'documents/{role}/preparer-template.json'
                template_raw = new['versions/17/' + path]
                template = C.document(template_raw)
                self.assertEqual(template['budgetSeconds'], 12)
                self.assertEqual(template['kernel'], C.document(files['coordinator'])['kernel'])
                self.assertEqual(C.document(old['versions/16/' + path])['budgetSeconds'], 5)
                broker_raw = new[f'versions/17/broker/{role}.json']
                broker = C.B.validate(broker_raw)
                self.assertEqual(broker['preparerTemplate']['sha256'], C.sha(template_raw))
                self.assertEqual(auth['roles'][role], old_auth['roles'][role] | {
                    'admissionConfigurationSha256': C.sha(broker_raw)})
                for name, digest in broker['sourceHashes'].items():
                    self.assertEqual(C.sha(new['versions/17/source/' + name]), digest)

    def test_budget_denials_and_boundaries(self):
        for value in (4, 16, True, 12.0, '12', None):
            files = self.inputs['files'] | {'driverBudget': raw({'driverBudgetSeconds': value})}
            with self.subTest(value=value), self.assertRaisesRegex(C.A.OperationDenied, '^' + BUDGET.INVALID + '$'):
                self.compose(self.inputs | {'files': files})
        with self.assertRaisesRegex(C.A.OperationDenied, '^' + BUDGET.INVALID + '$'):
            self.compose(self.inputs | {'files': self.inputs['files'] | {'driverBudget': b'{}'}})
        for value in (5, 15):
            with self.subTest(value=value):
                result = self.compose(self.inputs | {'files': self.inputs['files'] | {
                    'driverBudget': raw({'driverBudgetSeconds': value})}})
                for role in C.ROLES:
                    path = f'versions/17/documents/{role}/preparer-template.json'
                    self.assertEqual(C.document(result['documents'][path])['budgetSeconds'], value)
        old_inputs = self.inputs | {'files': {k: v for k, v in self.inputs['files'].items() if k != 'driverBudget'}}
        with self.assertRaisesRegex(C.A.OperationDenied, '^EXACT_R3_INPUT_SET_REQUIRED$'):
            self.compose(old_inputs)
        with self.assertRaisesRegex(C.A.OperationDenied, '^EXACT_R3_INPUT_SET_REQUIRED$'):
            C.compose(self.inputs, 16, sequence=16, supersedes='f' * 64)
        files = old_inputs['files']
        bad_template = C.document(files['adapter/historicalTemplate']) | {'budgetSeconds': 6}
        with self.assertRaisesRegex(C.A.OperationDenied, '^EXACT_NATIVE_PREPARER_TEMPLATE_REQUIRED$'):
            C.compose(old_inputs | {'files': files | {'adapter/historicalTemplate': raw(bad_template)}},
                      16, sequence=16, supersedes='f' * 64)

    def test_emitted_worker_driver_and_native_backend_accept_budget(self):
        result = self.compose(self.inputs)
        docs = result['documents']
        source = 'versions/17/source/tools/'

        def admission_module(name):
            module = ModuleType('tools.semantic_provider_admission_v2.' + name)
            module.__package__ = 'tools.semantic_provider_admission_v2'
            path = source + 'semantic_provider_admission_v2/' + name + '.py'
            exec(compile(docs[path], path, 'exec'), module.__dict__)
            module.Path = PurePosixPath
            return module

        preparer = admission_module('preparer_v2')
        driver = admission_module('driver_v7')
        fixtures = V12.F.grant_fixture
        with fixtures.part_a.libraries():
            from tools import semantic_provider_deployment_producer as producer, semantic_provider_lease_coordination as lease

            path = source + 'semantic_provider_preexec_native.py'
            native = C.contract_module(docs[path], 'native_budget')
            for role in C.ROLES:
                with self.subTest(role=role):
                    cfg_raw = docs[f'versions/17/broker/{role}.json']
                    cfg = C.B.validate(cfg_raw)
                    template_raw = docs[f'versions/17/documents/{role}/preparer-template.json']
                    root = f"{cfg['registryRoot']}/{cfg['containerId']}/epochs/1"
                    binding = {'containerId': cfg['containerId'], 'epoch': 1, 'configurationHash': C.sha(cfg_raw),
                               'authorizationSha256': C.sha(result['authorization'])}
                    request = {'epoch': 1, 'epochRoot': root, 'bundle': root + '/bundle',
                               'runtimeRoot': cfg['runtimeRootParent'] + '/fixture',
                               'binding': binding | {k: cfg['authorities'][k] for k in ('installationRef', 'entityRef')},
                               'template': C.document(template_raw),
                               'evidenceBinding': {'path': root + '/evidence.json', 'sha256': 'b' * 64},
                               'configurationBinding': {'path': f'/broker/{role}.json', 'sha256': C.sha(cfg_raw)}}
                    with patch.object(C.B, 'private', return_value=C.canonical(request)), \
                            patch.object(C.B, 'load', return_value=(cfg, cfg_raw)), \
                            patch.object(C.B, 'read_binding', return_value=template_raw), \
                            patch.object(C.B, 'epoch_module') as epochs, patch.object(lease, 'PrivateJournal'), \
                            patch.object(producer, 'program'):
                        worker = preparer.Worker(root + '/preparer.json')
                        epochs.return_value.directory.assert_called_once()
                    grant = fixtures.grant()
                    grant.update(sourceRoot=cfg['sourceRoot'], sourceHashes=cfg['sourceHashes'],
                                 operation=cfg['operation'] | cfg['authorities'],
                                 creationFrameObserverBinding=cfg['creationFrameObserverBinding'],
                                 operationBinding=binding, evidenceBinding=request['evidenceBinding'],
                                 consumptionJournal=root + '/deployment.json', preexecJournal=root + '/preexec.json',
                                 commands={k: worker.template['commands'][k] for k in ('nft', 'ip', 'nsenter')},
                                 **{k: worker.template[k] for k in ('budgetSeconds', 'coordinationBinding', 'lockFile',
                                                                  'coordinationJournal', 'kernel', 'dns')})
                    grant['profile'].update(containerId=cfg['containerId'], bundlePath=root + '/bundle',
                                            transactionId=driver.correlation(binding), policy={'tableName': 'fixture'})
                    value = driver.validate(C.canonical(grant))
                    self.assertEqual(value['budgetSeconds'], 12)
                    command_info = SimpleNamespace(st_mode=stat.S_IFREG | 0o755, st_uid=0)
                    with patch.object(native, 'Path') as command_path, patch.object(native, '_ancestors'), \
                            patch.object(native, 'rules', return_value=''):
                        command_path.return_value.lstat.return_value = command_info
                        backend = native.NativeBackend(value['profile'], value['commands'], value['budgetSeconds'])
                    self.assertEqual(backend.budget, 12)
