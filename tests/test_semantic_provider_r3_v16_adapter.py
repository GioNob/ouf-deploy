"""Portable proofs for the D-053 adapter change and the historical R3 closure."""
import copy
from contextlib import nullcontext
from dataclasses import replace
import json
from pathlib import Path, PurePosixPath
import re
import runpy
import sys
import tempfile
from types import ModuleType, SimpleNamespace
import unittest
from unittest.mock import patch

import test_semantic_provider_r3_v15 as V15
from tools.semantic_provider_config import acceptance_g7 as G, b1_v4 as B, contract as D
from tools.semantic_provider_config import observation as O, publication as P
from tools.semantic_provider_r3 import adapter_v16 as A, compose as C, read_adapter_v16 as R
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
        path = Path(__file__).resolve().parents[1] / 'scripts/prepare-semantic-provider-installation.py'
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
                self.assertIn('C=' + '0' * 40 + '\n', text)
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
        from tools.semantic_provider_r3 import upgrade

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

    def test_frozen_v1_to_v15(self):
        golden = json.loads(V12.blob('tests/fixtures/r3-v1-v15-pre-v16-hashes.json'))
        for version in range(1, 16):
            with self.subTest(version=version):
                if version <= 11:
                    data = V12.F.fixture(version)
                    kwargs = {} if version == 1 else dict(sequence=version, supersedes='a' * 64)
                else:
                    if version == 12:
                        data, previous, _, _ = V12.fixture()
                    else:
                        data, previous = (V13 if version < 15 else V15).fixture()
                    kwargs = dict(sequence=version, supersedes=C.sha(previous['authorization']))
                output = C.compose(data, version, **kwargs)
                actual = {key: C.sha(C.canonical(output[key])) for key in ('hashes', 'inputHashes', 'audit', 'layout')}
                self.assertEqual(actual | {'authorization': C.sha(output['authorization'])}, golden[str(version)])
