import copy
import importlib.util
import pathlib
import tempfile
import unittest
import zipfile

SPEC = importlib.util.spec_from_file_location('stage', pathlib.Path(__file__).parents[1]/'scripts/stage_managed_profile_control_image.py')
m = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(m)


class CustodyTests(unittest.TestCase):
    def test_wrong_artifact_creates_no_delivery(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory); source = root/'bad'; source.write_bytes(b'bad')
            case = {'role': 'mcp', 'artifactZipBytes': 3, 'artifactZipSha256': '0'*64, 'targetApplyAuthorized': False}
            with self.assertRaisesRegex(m.Stop, 'EXACT_QUALIFIED_ZIP'):
                m.prepare(source, root/'out', root, case)
            self.assertFalse((root/'out').exists())

    def test_consumed_delivery_is_not_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory); source = root/'data'; source.write_bytes(b'data'); (root/'out').mkdir()
            marker = root/'out'/'retained'; marker.write_text('keep')
            case = {'role': 'mcp', 'artifactZipBytes': 4, 'artifactZipSha256': m.file_hash(source), 'targetApplyAuthorized': False}
            with self.assertRaisesRegex(m.Stop, 'DELIVERY_DIRECTORY_CONSUMED'):
                m.prepare(source, root/'out', root, case)
            self.assertEqual(marker.read_text(), 'keep')

    def test_parts_reassemble_exact_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory); source = root/'source'; raw = bytes(range(256))*31
            source.write_bytes(raw); (root/'parts').mkdir(); rows = m.split(source, root/'parts', 1000)
            self.assertEqual(b''.join((root/'parts'/row['name']).read_bytes() for row in rows), raw)
            self.assertTrue(all(m.file_hash(root/'parts'/row['name']) == row['sha256'] for row in rows))

    def test_duplicate_metadata_rejected(self):
        with self.assertRaisesRegex(m.Stop, 'UNIQUE_JSON_KEYS'):
            m.parsed(b'{"imageId":"one","imageId":"two"}')

    def test_zip_path_and_duplicate_members_rejected_before_extract(self):
        for names in (['../image.tar.gz', 'manifest.json', 'SHA256SUMS'], ['image.tar.gz', 'image.tar.gz', 'SHA256SUMS']):
            with tempfile.TemporaryDirectory() as directory:
                root = pathlib.Path(directory); (root/'out').mkdir()
                with zipfile.ZipFile(root/'test.zip', 'w') as zipped:
                    for name in names:
                        zipped.writestr(name, b'x')
                with self.assertRaisesRegex(m.Stop, 'EXACT_CI_MEMBER_SET'):
                    m.unpack(root/'test.zip', root/'out', {'role': 'onboarding', 'maximumCompressedBytes': 50})
                self.assertEqual(list((root/'out').iterdir()), [])

    def test_all_36_existing_migrations_and_new_role(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory)/'application.jar'; facts = []
            with zipfile.ZipFile(path, 'w') as jar:
                for version in range(1, 37):
                    name = 'V%d__retained.sql' % version; raw = ('select %d;' % version).encode()
                    jar.writestr('BOOT-INF/classes/db/migration/'+name, raw)
                    facts.append({'version': str(version), 'script': name, 'sha256': m.hashlib.sha256(raw).hexdigest(), 'flywayChecksum': m.checksum(raw)})
                jar.writestr('BOOT-INF/classes/application.yml', 'retained: true')
                jar.writestr('BOOT-INF/classes/authorization/managed-profile-recovery-role-v1.json', '{"roles":[]}')
            self.assertFalse(m.jar_facts(path, facts)['databaseMigrationRequired'])
            drift = copy.deepcopy(facts); drift[35]['sha256'] = '0'*64
            with self.assertRaisesRegex(m.Stop, 'ALL_36_INSTALLED_MIGRATIONS'):
                m.jar_facts(path, drift)

    def test_missing_migration_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory)/'application.jar'
            with zipfile.ZipFile(path, 'w') as jar:
                jar.writestr('BOOT-INF/classes/db/migration/V36__only.sql', 'select 1;')
            with self.assertRaisesRegex(m.Stop, 'EXACT_36_MIGRATION_RESOURCES'):
                m.jar_facts(path, [])

    def test_flyway_line_endings_preserved(self):
        self.assertEqual(m.checksum(b'one\ntwo\n'), m.checksum(b'\xef\xbb\xbfone\r\ntwo\r\n'))


if __name__ == '__main__':
    unittest.main()
