"""Real target-sized executable IO, immutable reuse and retained attempt proof."""
import json
from pathlib import Path
import unittest
from unittest.mock import patch
import test_postboot_prepare as fixture
from tools.semantic_registry_recovery_execution import postboot_prepare as p, file_budget_reconciliation as r

ROOT = Path(__file__).resolve().parents[3]


class FileBudget(unittest.TestCase):
    setUp = fixture.Preparation.setUp

    def sized(self, name, size):
        path = self.root / name
        with path.open('wb') as stream: stream.truncate(size)
        path.chmod(0o500)
        return str(path)

    def test_observed_executable_sizes_with_metadata_exceed_legacy_and_fit_without_duplicate_read(self):
        paths = {name: self.sized(name, size) for name, size in {'docker': 47253935, 'python': 6832784, 'openssl': 1103304}.items()}
        meta = self.sized('synthetic-retained-metadata', 7 * 1048576)
        # Two representative bounded metadata files, same total and final recheck
        # as the real graph. Executable bytes are actually read, not simulated.
        legacy = p.Files()
        legacy.seal(meta, 8388608)
        legacy.seal(paths['docker'], 67108864)
        for name in ('python', 'docker', 'openssl'): legacy.seal(paths[name], 67108864)
        with self.assertRaisesRegex(Exception, 'PREPARATION_FILE_BYTE_BUDGET'): legacy.verify()
        fixed = p.Files()
        fixed.seal(meta, 8388608)
        profiles = {name: fixed.seal(path, 67108864)[0] for name, path in paths.items()}
        before_bytes, before_reads = fixed.bytes, fixed.reads
        for name, path in paths.items(): self.assertEqual(fixed.executable_profile(path, 67108864, profiles[name]['sha256']), profiles[name])
        self.assertEqual((fixed.bytes, fixed.reads), (before_bytes, before_reads))
        fixed.verify()
        self.assertLess(fixed.bytes, p.MAX_BYTES)
        self.assertEqual(p.MAX_BYTES, 167772160)

    def test_reuse_is_defensive_and_rejects_changed_metadata_hash_or_bounds(self):
        path = self.sized('binary', 64); files = p.Files(); profile, _ = files.seal(path, 67108864)
        returned = files.executable_profile(path, 67108864, profile['sha256']); returned['metadata'][0] = -1
        self.assertEqual(files.observed[path][0], profile)
        for maximum, sha in [(64, profile['sha256']), (67108864, '0' * 64)]:
            with self.assertRaisesRegex(Exception, 'SAME_SEALED_EXECUTABLE'): files.executable_profile(path, maximum, sha)
        Path(path).chmod(0o700)
        with self.assertRaisesRegex(Exception, 'SEALED_EXECUTABLE_CUSTODY_CHANGED'): files.executable_profile(path, 67108864, profile['sha256'])

    def test_uncached_executable_is_hashed_and_final_verify_rejects_tamper(self):
        path = self.sized('binary', 64); files = p.Files()
        profile = files.executable_profile(path, 67108864, p.hashlib.sha256(bytes(64)).hexdigest())
        self.assertEqual(files.bytes, 64)
        Path(path).chmod(0o700); Path(path).write_bytes(b'tamper')
        with self.assertRaises(Exception): files.verify()
        self.assertIn(path, files.observed)

    def test_new_case_root_and_read_limit_do_not_reset_when_sources_change(self):
        case = json.loads((ROOT / 'releases/semantic-registry-postboot-byte-case-20261023.json').read_bytes())['preparation']
        boot = '00000000-1111-2222-3333-444444444444'; p.validate_case(case)
        original = {k: v for k, v in case.items() if k != 'fileBudgetRecovery'}
        self.assertNotEqual(p.prepared_root(case, {}, boot), p.prepared_root(original, {}, boot))
        self.assertEqual(p.prepared_root(case, {'source': 'a'}, boot), p.prepared_root(case, {'source': 'b'}, boot))
        files = p.Files(maximum_reads=320); path = self.sized('metadata', 1)
        for _ in range(320): files.seal(path, 16, retain=False)
        with self.assertRaisesRegex(Exception, 'BOUNDED_PREPARATION_FILE'): files.seal(path, 16, retain=False)
        self.assertEqual(p.Files().maximum_reads, 128)

    def test_fifth_consumed_preparation_reconciled_without_old_changes(self):
        case = json.loads((ROOT / 'releases/semantic-registry-postboot-byte-case-20261023.json').read_bytes())['preparation']
        case['frozenReference'] = self.reference
        original = {k: v for k, v in case.items() if k != 'fileBudgetRecovery'}
        boot = '00000000-1111-2222-3333-444444444444'; root = self.root / 'old'; root.mkdir(mode=0o700)
        claim = {'schema': p.SCHEMA, 'caseHash': p.digest(original), 'sourceClosureHash': case['fileBudgetRecovery']['wireSourceClosureHash'],
            'bootId': boot, 'maximumEngineGets': 12, 'maximumAdminGets': 1, 'maximumFrozenGets': 1,
            'maximumTlsHandshakes': 1, 'maximumMetadataReads': 256, 'automaticReplayAllowed': False, 'runtimeAuthorityIssued': False}
        p.publish(root, 'claim.json', claim)
        for n in range(1, 13): p.publish(root, 'engine-get-'+str(n)+'.json', {'attempt': n, 'requestPathHash': 'a' * 64})
        p.publish(root, 'admin-get.json', {'method': 'GET', 'operation': '/apisix/admin/routes', 'maximumAttempts': 1})
        p.publish(root, 'tls-handshake.json', {'originHash': 'a' * 64, 'caProfileHash': 'b' * 64, 'maximumAttempts': 1, 'httpRequests': 0, 'bearersSent': 0})
        p.publish(root, 'frozen-get.json', {'method': 'GET', 'path': p.FROZEN_PATH, 'referenceHash': p.digest(self.reference), 'maximumAttempts': 1})
        p.publish(root, 'frozen-response.json', self.frozen); (root / 'source').mkdir(mode=0o500)
        prior = {'priorAttemptCounts': {'engineGets': 30, 'adminGets': 4, 'frozenConfigurationGets': 2, 'resolverCalls': 6, 'tlsAttemptMarkers': 4}}
        before = {f: (f.read_bytes(), f.stat()) for f in root.glob('*.json')}
        # Earlier chain/root locator are explicit substitutes; new layer uses
        # real protected files and never calls an engine or application entry.
        with patch.object(p, 'reconcile_prior_preparation', return_value=prior), patch.object(p, 'prepared_root', return_value=root):
            result = r.reconcile(case, p.Files(maximum_reads=320), boot)
            self.assertEqual(result['priorAttemptCounts']['engineGets'], 42)
            self.assertEqual(result['cumulativeAttemptCeilings']['engineGets'], 54)
            self.assertEqual(before, {f: (f.read_bytes(), f.stat()) for f in before})
            p.publish(root, 'prepared.json', {'unexpected': True})
            with self.assertRaisesRegex(Exception, 'WIRE_PREPARATION_ADVANCED'): r.reconcile(case, p.Files(), boot)


if __name__ == '__main__': unittest.main()
