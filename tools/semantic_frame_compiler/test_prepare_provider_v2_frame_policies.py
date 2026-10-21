import copy
import hashlib
import json
from pathlib import Path
import unittest
from unittest import mock

import prepare_provider_v2_frame_policies as prep
from compile_creation_frame_policy import Denied, canonical
from review_semantic_oci_policy import configured_profile, schema_from_source_closure


class DraftPolicyTests(unittest.TestCase):
    def setUp(self):
        self.info = {'serverVersion': '29.8.1', 'storageDriver': 'overlayfs',
                     'cgroupDriver': 'systemd', 'dataRoot': '/var/lib/docker'}
        self.baselines = {r: json.loads(Path(__file__).with_name('containerd-overlayfs-' + r + '.json').read_bytes())
                          for r in prep.CIDS}

    def test_both_role_drafts_conform_to_full_owner_review_without_approving_target(self):
        schema = schema_from_source_closure(Path(__file__).with_name('semantic_oci_shape_schema.json').read_bytes())
        for role, baseline in self.baselines.items():
            with self.subTest(role=role):
                launch = copy.deepcopy(baseline['launch'])
                launch['startup'].update(args=['/approved/role', '--configuration', '/run/provider.json'], cwd='/app')
                launch['manifest']['memoryBytes'] = 268435456 if role == 'adapter' else 536870912
                draft = prep.compile_role(role, baseline, launch, self.info)
                p = draft['policy']
                result = configured_profile(p['expectedOci'], p['expectedOci'], p['manifest'], p['startup'], p['approvedHooks'], schema)
                self.assertTrue(result['configuredPolicyConforms'])
                self.assertFalse(result['acceptanceGranted'])
                self.assertFalse(result['startAuthorized'])
                self.assertEqual(p['expectedOci']['root']['path'], '/var/lib/docker/rootfs/overlayfs/' + prep.CIDS[role])

    def test_other_engine_storage_cgroup_or_role_cannot_use_baseline(self):
        b = self.baselines['adapter']
        for field, value in [('serverVersion', '28.0.4'), ('storageDriver', 'vfs'), ('cgroupDriver', 'cgroupfs'),
                             ('dataRoot', '/foreign/docker')]:
            info = {**self.info, field: value}
            with self.subTest(field=field), self.assertRaises(Denied): prep.compile_role('adapter', b, b['launch'], info)
        with self.assertRaises(Denied): prep.compile_role('southbound', b, b['launch'], self.info)

    def test_baseline_cannot_be_promoted_to_target_acceptance_by_boolean(self):
        for key in ('targetTemplateApproved', 'acceptanceGranted', 'startAuthorized'):
            b = copy.deepcopy(self.baselines['adapter']); b[key] = True
            with self.subTest(key=key), self.assertRaises(Denied): prep.compile_role('adapter', b, b['launch'], self.info)

    def test_duplicate_private_json_keys_rejected(self):
        with self.assertRaises(Denied): prep.parse(b'{"env":1,"env":2}')

    def test_main_only_queries_info_and_inspect_and_publishes_private_drafts(self):
        source = Path(prep.__file__).resolve().parent
        files = {prep.REG: canonical({'candidates': {}, 'runtimeStateRoot': '/run/docker'})}
        launches = {}
        for role, b in self.baselines.items():
            launches[role] = canonical(b['launch'])
            files[prep.LAUNCH_ROOT / (role + '.launch.json')] = launches[role]
            files[source / ('containerd-overlayfs-' + role + '.json')] = canonical(b)
            for item in b['launch']['sources']:
                files[Path(item['source'])] = b'CI_PRIVATE_SOURCE'
        queries = []; published = {}; stdout = []
        def query(config, *args):
            queries.append(args)
            if args[0] == 'info': return self.info
            self.assertEqual(args[0], 'inspect')
            role = next(r for r, cid in prep.CIDS.items() if cid == args[-1])
            return {'id': prep.CIDS[role], 'image': prep.IMAGES[role], 'runtime': 'ouf-semantic-admitted-v2',
                    'state': {'Status': 'created', 'Running': False, 'Restarting': False, 'Pid': 0,
                              'StartedAt': '0001-01-01T00:00:00Z'}}
        with mock.patch.object(prep, 'sealed_read', side_effect=lambda p, *a, **kw: files[Path(p)]), \
             mock.patch.object(prep, 'query', side_effect=query), \
             mock.patch.object(prep, 'LAUNCH_HASHES', {r: prep.hashed(raw) for r, raw in launches.items()}), \
             mock.patch.object(prep, 'REG_HASH', prep.hashed(files[prep.REG])), \
             mock.patch.object(prep.tempfile, 'mkdtemp', return_value='/approved/test-drafts'), \
             mock.patch.object(prep, 'publish', side_effect=lambda p, raw: published.setdefault(Path(p).name, raw)), \
             mock.patch.object(prep.os, 'geteuid', return_value=0), \
             mock.patch('builtins.print', side_effect=stdout.append):
            prep.main()
        self.assertEqual([q[0] for q in queries], ['info', 'inspect', 'inspect', 'info'])
        self.assertEqual(len(published), 7)
        receipt = json.loads(published['frame-policy-receipt.json'])
        for key in ('targetTemplateApproved', 'contextAuthenticated', 'signedTransactionConfigured', 'runtimeAllowlistChanged',
                    'acceptanceGranted', 'startAuthorized', 'rulesChanged'):
            self.assertFalse(receipt[key])
        self.assertEqual(receipt['containerLifecycleOperations'], 0)
        self.assertNotIn('CI_PRIVATE_SOURCE', stdout[0])
        self.assertNotIn('HOSTNAME=', stdout[0])


if __name__ == '__main__': unittest.main()
