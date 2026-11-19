import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import MagicMock, patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('master_crash33', ROOT / 'scripts/run-storage-generation33-lateral-isolation.py')
lab = importlib.util.module_from_spec(spec); spec.loader.exec_module(lab)


class MasterCrashTests(unittest.TestCase):
    def metadata(self):
        return {'metadata': {'FullPath': '/buckets/ouf-identity-fixture/' + lab.VOLUME_KEY,
            'FileSize': lab.VOLUME_BYTES, 'Mime': lab.keys.MIME, 'Content': None,
            'chunks': [{'file_id': '7,12345678', 'size': lab.VOLUME_BYTES}]}}

    def reply(self, path):
        body = None
        if path == '/dir/status': body = {'TopologyId': 'stable-id', 'Topology': {'DataCenters': []}}
        if path.startswith('/dir/lookup?'):
            body = {'volumeOrFileId': '7', 'locations': [{'url': lab.IPS['volume'] + ':18080', 'grpcPort': 28080}]}
        return {'path': path, 'status': 200, 'body': body, 'retryAfterSeconds': 0}

    def test_only_master_replaced_and_mutually_exclusive_crash_modes(self):
        before = {r: {'Id': r, 'RestartCount': 0, 'State': {'Running': True, 'StartedAt': 'old', 'OOMKilled': False}} for r in lab.ROLES}
        after = copy.deepcopy(before); after['master']['Id'] = 'new'
        lab.validate_retained_roles(before, after, 'master')
        for role in ('volume', 'filer', 's3', 'client'):
            bad = copy.deepcopy(after); bad[role]['RestartCount'] = 1
            with self.assertRaises(ValueError): lab.validate_retained_roles(before, bad, 'master')
        for other in ('crash_filer', 'crash_volume'):
            with self.assertRaisesRegex(ValueError, 'ONE_CRASH_ROLE'):
                lab.run(None, None, None, None, crash_master=True, **{other: True})

    def test_topology_queries_exact_chunk_volume_ids_without_assign(self):
        request = MagicMock(side_effect=self.reply)
        result = lab.master_topology(self.metadata(), request)
        self.assertEqual('MASTER_TOPOLOGY_READY', result['status'])
        self.assertEqual(['/readyz', '/dir/status', '/dir/lookup?volumeId=7'], [c.args[0] for c in request.call_args_list])
        self.assertEqual(0, result['mutatingRequests'])

    def test_invalid_volume_ids_cannot_change_lookup_path(self):
        for vid in ('7&fileId=1,x', '../bad', '0', '4294967296', '١'):
            value = self.metadata(); value['metadata']['chunks'][0]['file_id'] = vid + ',x'
            with self.subTest(vid=vid), self.assertRaises(ValueError): lab.master_lookup_ids(value)

    def test_ready_503_is_explicit_pending_with_retry_after(self):
        request = MagicMock(return_value={'path': '/readyz', 'status': 503, 'retryAfterSeconds': 17, 'body': None})
        result = lab.master_topology(self.metadata(), request)
        self.assertEqual('MASTER_REGISTRATION_PENDING', result['status'])
        self.assertEqual(17, result['retryAfterSeconds']); self.assertEqual(1, request.call_count)

    def test_known_volume_404_or_503_is_registration_pending_only(self):
        for status in (404, 503):
            def request(path):
                value = self.reply(path)
                if path.startswith('/dir/lookup?'): value.update(status=status, body={'error': 'not yet registered'})
                return value
            self.assertEqual('MASTER_REGISTRATION_PENDING', lab.master_topology(self.metadata(), request)['status'])
        for status in (401, 403, 423, 500, 302):
            with self.subTest(status=status), self.assertRaises(ValueError):
                lab.master_topology(self.metadata(), lambda p: {**self.reply(p), 'status': status})

    def test_wrong_remote_readonly_or_ambiguous_location_fails(self):
        for field, value in [('url', 'wrong:18080'), ('grpcPort', 28081), ('dataInRemote', True), ('readOnly', True)]:
            def request(path):
                response = self.reply(path)
                if path.startswith('/dir/lookup?'): response['body']['locations'][0][field] = value
                return response
            with self.subTest(field=field), self.assertRaises(ValueError): lab.master_topology(self.metadata(), request)
        def duplicate(path):
            response = self.reply(path)
            if path.startswith('/dir/lookup?'): response['body']['locations'] *= 2
            return response
        with self.assertRaises(ValueError): lab.master_topology(self.metadata(), duplicate)

    def test_topology_identity_and_original_locations_must_survive(self):
        before = lab.master_topology(self.metadata(), self.reply)
        lab.validate_master_recovery(before, copy.deepcopy(before))
        for field, value in [('topologyId', 'different'), ('locations', {}), ('status', 'MASTER_REGISTRATION_PENDING')]:
            after = copy.deepcopy(before); after[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError): lab.validate_master_recovery(before, after)

    def test_missing_topology_identity_blocks_even_with_live_listener(self):
        def request(path):
            value = self.reply(path)
            if path == '/dir/status': value['body']['TopologyId'] = ''
            return value
        with self.assertRaises(ValueError): lab.master_topology(self.metadata(), request)

    def test_retry_after_jitter_and_budget_are_enforced(self):
        with patch.object(lab.os, 'urandom', return_value=b'\xff\xff'):
            self.assertAlmostEqual(1.2, lab.master_retry_delay(1, 0, 0, 120))
            self.assertEqual(40, lab.master_retry_delay(1, 40, 0, 120))
            with self.assertRaises(ValueError): lab.master_retry_delay(1, 121, 0, 120)
            with self.assertRaises(ValueError): lab.master_retry_delay(10, 0, 0, 120)
            with self.assertRaises(ValueError): lab.master_retry_delay(1, 0, 119, 120)

    def test_replacement_log_requires_both_peer_registrations(self):
        filer = '+ client .filer@' + lab.IPS['filer'] + ':18888.28888'
        s3 = '+ client .s3@' + lab.IPS['s3'] + ':28333'
        self.assertTrue(lab.master_registration_log(filer + '\n' + s3))
        self.assertFalse(lab.master_registration_log(filer)); self.assertFalse(lab.master_registration_log(s3))
        self.assertFalse(lab.master_registration_log((filer + s3).replace('+ client', '- client')))

    def test_inventory_preserves_bytes_and_rejects_empty_symlink_and_budget(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            with self.assertRaises(ValueError): lab.master_inventory(root)
            file = root / 'raft.log'; file.write_bytes(b'persistent state')
            before = lab.master_inventory(root); self.assertEqual(before, lab.master_inventory(root))
            file.write_bytes(b'changed state'); self.assertNotEqual(before, lab.master_inventory(root))
            (root / 'link').symlink_to(file)
            with self.assertRaises(ValueError): lab.master_inventory(root)
            (root / 'link').unlink()
            with file.open('wb') as out: out.truncate(32 * 1024 * 1024 + 1)
            with self.assertRaises(ValueError): lab.master_inventory(root)

    def test_http_probe_is_bounded_loopback_get_and_denies_mutating_paths(self):
        conn = MagicMock(); response = conn.getresponse.return_value
        response.status = 200; response.getheader.return_value = None; response.read.return_value = b'{}'
        with patch.object(lab.http.client, 'HTTPConnection', return_value=conn) as factory:
            lab.master_http('/dir/lookup?volumeId=7')
            factory.assert_called_once_with('127.0.0.1', 19333, timeout=5)
            conn.request.assert_called_once_with('GET', '/dir/lookup?volumeId=7', headers={'Accept': 'application/json'})
            response.read.assert_called_once_with(256 * 1024 + 1)
            for path in ('/dir/assign', '/vol/grow', '/dir/lookup?volumeId=7&fileId=x'):
                with self.assertRaises(ValueError): lab.master_http(path)
            response.getheader.return_value = 'invalid'
            with self.assertRaises(ValueError): lab.master_http('/readyz')
        conn.close.assert_called()


if __name__ == '__main__': unittest.main()
