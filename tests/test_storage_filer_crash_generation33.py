import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import MagicMock, patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('filer_crash33', ROOT / 'scripts/run-storage-generation33-lateral-isolation.py')
lab = importlib.util.module_from_spec(spec); spec.loader.exec_module(lab)


class FilerCrashTests(unittest.TestCase):
    def metadata(self):
        return {'FullPath': '/buckets/ouf-identity-fixture/' + lab.VOLUME_KEY,
                'FileSize': lab.VOLUME_BYTES, 'Mime': lab.keys.MIME, 'Content': None,
                'chunks': [{'file_id': '1,12345678', 'size': lab.VOLUME_BYTES}]}

    def store(self, root):
        shard = root / '00'; shard.mkdir()
        for name, body in [('CURRENT', b'MANIFEST-000001\n'), ('MANIFEST-000001', b'manifest'),
                           ('000001.log', b'persisted metadata log')]: (shard / name).write_bytes(body)
        return shard

    def test_only_filer_is_replaced_and_all_other_roles_retained(self):
        before = {r: {'Id': r, 'RestartCount': 0, 'State': {'Running': True, 'StartedAt': 'initial',
                   'OOMKilled': False, 'Error': '', 'ExitCode': 0}} for r in lab.ROLES}
        after = copy.deepcopy(before); after['filer']['Id'] = 'new-filer'
        lab.validate_retained_roles(before, after, 'filer')
        for role in lab.ROLES:
            bad = copy.deepcopy(after)
            if role == 'filer': bad[role]['Id'] = before[role]['Id']
            else: bad[role]['State']['StartedAt'] = 'restart'
            with self.subTest(role=role), self.assertRaises(ValueError): lab.validate_retained_roles(before, bad, 'filer')
        killed = copy.deepcopy(before['filer']); killed['State'].update(Running=False, ExitCode=137)
        lab.validate_killed_role(before['filer'], killed)
        killed['State']['OOMKilled'] = True
        with self.assertRaises(ValueError): lab.validate_killed_role(before['filer'], killed)

    def test_crash_role_is_bounded_and_simultaneous_crashes_rejected(self):
        with self.assertRaises(ValueError): lab.validate_retained_roles({}, {}, 'master')
        with self.assertRaisesRegex(ValueError, 'ONE_CRASH_ROLE'):
            lab.run(None, None, None, None, crash_volume=True, crash_filer=True)

    def test_filer_reuses_data_but_changes_gate(self):
        args = lab.container_argv('image', 'new', 'net', Path('/data'), Path('/config'),
                                  Path('/binary'), 'filer', Path('/data/new-gate'))
        self.assertIn('type=bind,src=/data/filer,dst=/data', args)
        self.assertIn('type=bind,src=/data/new-gate,dst=/gate,readonly', args)
        self.assertIn('-defaultStoreDir=/data', args)
        self.assertEqual(args[args.index('--ip') + 1], lab.IPS['filer'])
        self.assertNotIn('--privileged', args)

    def test_stopped_leveldb_inventory_detects_byte_changes(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); shard = self.store(root); before = lab.filer_inventory(root)
            self.assertEqual(before, lab.filer_inventory(root))
            (shard / '000001.log').write_bytes(b'changed metadata log!!')
            self.assertNotEqual(before, lab.filer_inventory(root))
            self.assertEqual(3, len(before))

    def test_incomplete_leveldb_metadata_is_rejected(self):
        for name in ('CURRENT', 'MANIFEST-000001', '000001.log'):
            with tempfile.TemporaryDirectory() as temp:
                root = Path(temp); shard = self.store(root); (shard / name).unlink()
                with self.subTest(name=name), self.assertRaises(ValueError): lab.filer_inventory(root)

    def test_symlinks_and_oversized_metadata_fail_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); shard = self.store(root)
            (root / 'escape').symlink_to(shard, target_is_directory=True)
            with self.assertRaises(ValueError): lab.filer_inventory(root)
            (root / 'escape').unlink()
            with (shard / 'large.log').open('wb') as stream: stream.truncate(32 * 1024 * 1024 + 1)
            with self.assertRaises(ValueError): lab.filer_inventory(root)

    def test_metadata_requires_exact_path_length_mime_and_external_chunks(self):
        value = self.metadata(); lab.validate_filer_metadata(value, 'ouf-identity-fixture')
        for field, invalid in [('FullPath', '/wrong'), ('FileSize', 1), ('Mime', 'wrong'),
                               ('Content', 'inline'), ('chunks', [])]:
            bad = copy.deepcopy(value); bad[field] = invalid
            with self.subTest(field=field), self.assertRaises(ValueError): lab.validate_filer_metadata(bad, 'ouf-identity-fixture')

    def test_chunk_references_and_aggregate_length_are_required(self):
        for invalid in ([{'size': lab.VOLUME_BYTES}], [{'file_id': '1,x', 'size': 1}],
                        [{'file_id': '1,x', 'size': -1}], [{'file_id': '1,x', 'size': '8'}]):
            bad = self.metadata(); bad['chunks'] = invalid
            with self.subTest(chunks=invalid), self.assertRaises(ValueError): lab.validate_filer_metadata(bad, 'ouf-identity-fixture')

    def test_metadata_probe_is_direct_read_only_and_has_bounded_response(self):
        conn = MagicMock(); response = conn.getresponse.return_value
        response.status = 200; response.read.return_value = json.dumps(self.metadata()).encode()
        with patch.object(lab.http.client, 'HTTPConnection', return_value=conn) as factory:
            result = lab.filer_metadata()
        factory.assert_called_once_with(lab.IPS['filer'], 18888, timeout=10)
        conn.request.assert_called_once_with('GET', '/buckets/ouf-identity-fixture/' + lab.VOLUME_KEY + '?metadata=true',
                                             headers={'Accept': 'application/json'})
        response.read.assert_called_once_with(256 * 1024 + 1)
        self.assertEqual(0, result['mutatingRequests']); self.assertEqual(0, result['bodyReads'])
        conn.close.assert_called_once()
        for status, body in [(404, b'{}'), (200, b'x' * (256 * 1024 + 1))]:
            response.status = status; response.read.return_value = body
            with patch.object(lab.http.client, 'HTTPConnection', return_value=conn), self.assertRaises(ValueError): lab.filer_metadata()

    def test_filer_response_counter_covers_established_http_to_s3_only(self):
        rules = lab.nft_rules('filer')
        position = rules.index('ip daddr ' + lab.IPS['s3'] + ' tcp sport 18888 counter name filer_http_response_bytes')
        self.assertLess(position, rules.index('ct state established,related accept'))
        self.assertNotIn('filer_http_response_bytes', lab.nft_rules('client'))


if __name__ == '__main__': unittest.main()
