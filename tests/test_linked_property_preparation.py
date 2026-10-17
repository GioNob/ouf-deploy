"""Integrity boundaries for private release preparation; no host access needed."""
import importlib.util
import io
from pathlib import Path
import tempfile
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('prep', ROOT / 'tools/linked_property_rollout/preparation.py')
p = importlib.util.module_from_spec(spec)
spec.loader.exec_module(p)


class PreparationTest(unittest.TestCase):
    def test_installed_prefix_drift_is_rejected(self):
        expected = [{'version':'1','script':'V1__one.sql','checksum':123,'success':True}]
        observed = [{'installed_rank':0,'version':None,'script':'"ouf_udp"','checksum':None,'success':True},
                    {'installed_rank':1,**expected[0]}]
        p.verify_history(observed, expected, 'ouf_udp')
        for key, bad in [('checksum',124),('success',False),('installed_rank',2),('script','V1__other.sql')]:
            mutated = [observed[0],{**observed[1],key:bad}]
            with self.assertRaises(ValueError): p.verify_history(mutated, expected, 'ouf_udp')
        with self.assertRaises(ValueError): p.verify_history(observed+observed[1:],expected,'ouf_udp')
        p.verify_history(observed[1:],expected,'ouf_udp',allow_existing_schema=True)

    def test_jar_flyway_checksum_ignores_bom_and_line_endings(self):
        with tempfile.TemporaryDirectory() as d:
            result=[]
            for i, raw in enumerate((b'hello\nworld\n',b'\xef\xbb\xbfhello\r\nworld\r\n')):
                jar=Path(d)/str(i)
                with zipfile.ZipFile(jar,'w') as z:z.writestr('BOOT-INF/classes/db/migration/V1__one.sql',raw)
                result.append(p.migration_rows(jar))
            self.assertEqual(result[0][0]['checksum'],result[1][0]['checksum'])
            self.assertNotEqual(result[0][0]['sha256'],result[1][0]['sha256'])

    def test_duplicate_migration_version_is_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            jar=Path(d)/'a.jar'
            with zipfile.ZipFile(jar,'w') as z:
                z.writestr('BOOT-INF/classes/db/migration/V1__one.sql','select 1;')
                z.writestr('BOOT-INF/classes/db/migration/V1__two.sql','select 2;')
            with self.assertRaisesRegex(ValueError,'DUPLICATE_MIGRATION_VERSION'):p.migration_rows(jar)

    def test_package_traversal_and_symlink_are_rejected(self):
        for name, mode in [('../outside',0o100600),('/outside',0o100600),('inside',0o120777)]:
            raw=io.BytesIO()
            with zipfile.ZipFile(raw,'w') as z:
                info=zipfile.ZipInfo(name);info.external_attr=mode<<16;z.writestr(info,b'data')
            raw.seek(0)
            with zipfile.ZipFile(raw) as z:
                with self.assertRaises(ValueError):p.zip_index(z)

    def test_complete_manifest_and_hashes_are_required(self):
        for sums, valid in [('0'*64+'  a\n',False),
                            (p.hashlib.sha256(b'data').hexdigest()+'  a\n',True),('',False)]:
            raw=io.BytesIO()
            with zipfile.ZipFile(raw,'w') as z:
                z.writestr('a',b'data');z.writestr('SHA256SUMS',sums);z.writestr('SHA256SUMS.sigstore.json','{}')
            raw.seek(0)
            with zipfile.ZipFile(raw) as z:
                if valid:self.assertEqual(set(p.verify_package(z,p.zip_index(z))),{'a'})
                else:
                    with self.assertRaises(ValueError):p.verify_package(z,p.zip_index(z))

    def test_copy_checks_content_before_review_and_preserves_source(self):
        with tempfile.TemporaryDirectory() as d:
            source=Path(d)/'source';source.write_bytes(b'qualified')
            with self.assertRaisesRegex(ValueError,'QUALIFIED_PACKAGE_DIGEST_CHANGED'):
                p.copy_package(source,Path(d)/'bad','0'*64)
            p.copy_package(source,Path(d)/'good',p.hashlib.sha256(b'qualified').hexdigest())
            self.assertEqual(source.read_bytes(),b'qualified')
            with self.assertRaises(FileExistsError):
                p.copy_package(source,Path(d)/'good',p.hashlib.sha256(b'qualified').hexdigest())

    def test_documents_have_bounded_unique_names_and_no_overwrite(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            with self.assertRaises(ValueError):p.document(root,'authority.json',{})
            p.write_new(root/'review.json',b'one')
            with self.assertRaises(FileExistsError):p.write_new(root/'review.json',b'two')
            self.assertEqual((root/'review.json').read_bytes(),b'one')

    def test_duplicate_json_is_rejected(self):
        with self.assertRaises(ValueError):p.parsed('{"complete":true,"complete":false}')

if __name__ == '__main__':unittest.main()
