"""Keep a narrowly scoped OS repair from changing other application inputs."""
import copy, importlib.util, io, json, sys, tarfile, unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('repair', ROOT/'scripts/prepare-m2-runtime-os-repair.py')
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
sys.path.insert(0,str(ROOT/'tests'))
import test_image_custody as archive_fixture


class RuntimeRepair(unittest.TestCase):
    def test_scanner_envelope_preserves_configuration_and_each_expanded_layer_byte(self):
        source=archive_fixture.fixture(compressed=True); audit=archive_fixture.audit(source); output=io.BytesIO()
        scanner=m.classic_scan_archive(io.BytesIO(source[0]),output,audit)
        self.assertEqual(scanner['imageConfig'],audit['imageConfig'])
        self.assertEqual(scanner['configSha256'],audit['configSha256'])
        self.assertEqual([v['diffId'] for v in scanner['layers']],[v['diffId'] for v in audit['layers']])
        self.assertNotEqual(scanner['layers'][0]['blobSha256'],audit['layers'][0]['blobSha256'])
        self.assertEqual('sha256:'+scanner['layers'][0]['blobSha256'],scanner['layers'][0]['diffId'])
        wrong=copy.deepcopy(audit);wrong['layers'][0]['diffId']='sha256:'+'0'*64
        with self.assertRaisesRegex(ValueError,'EXPANDED_LAYER_BYTES_FOR_SCAN'):
            m.classic_scan_archive(io.BytesIO(source[0]),io.BytesIO(),wrong)

    def test_only_the_three_vendor_fixed_package_versions_may_change(self):
        case = json.loads(m.CASE.read_bytes()); before = dict(case['originalPackageVersions'], **{'openjdk': 'preserved'})
        after = dict(before, **{v['package']: v['version'] for v in case['fixedPackages']})
        self.assertEqual(m.changed_packages(before, after, case), set(case['allowedPackageVersionChanges']))
        for mutated in [dict(after, openjdk='changed'), {k:v for k,v in after.items() if k != 'openjdk'},
            dict(after, added='unreviewed'), dict(after, musl='unreviewed'), before]:
            with self.assertRaisesRegex(ValueError, 'ONLY_THREE_PINNED'): m.changed_packages(before, mutated, case)

    def test_package_database_duplicate_or_incomplete_entries_are_denied(self):
        self.assertEqual(m.packages(b'P:one\nV:1\n\nP:two\nV:2\n'), {'one':'1','two':'2'})
        for raw in (b'P:one\nV:1\nP:duplicate\n', b'P:one\nV:1\n\nP:one\nV:2\n', b'P:one\n'):
            with self.assertRaises(ValueError): m.packages(raw)

    def layers(self, rows):
        outer = io.BytesIO(); names = []
        with tarfile.open(fileobj=outer, mode='w') as tar:
            for i, contents in enumerate(rows):
                layer = io.BytesIO()
                with tarfile.open(fileobj=layer, mode='w') as target:
                    for name, kind, body in contents:
                        entry = tarfile.TarInfo(name); entry.type = kind; entry.size = len(body)
                        if kind == tarfile.SYMTYPE: entry.linkname = '/not-followed'; entry.size = 0
                        target.addfile(entry, io.BytesIO(body))
                name = str(i)+'.tar'; raw = layer.getvalue(); entry = tarfile.TarInfo(name); entry.size = len(raw)
                tar.addfile(entry, io.BytesIO(raw)); names.append(name)
        outer.seek(0); return outer, {'layerMembers': names}

    def test_final_package_database_obeys_layer_whiteouts_and_denies_links(self):
        target = 'lib/apk/db/installed'; first = [(target, tarfile.REGTYPE, b'P:original\nV:1\n')]
        stream, audit = self.layers([first, [(target, tarfile.REGTYPE, b'P:fixed\nV:2\n')]])
        self.assertEqual(m.effective_file(stream, audit, target, 100), b'P:fixed\nV:2\n')
        for name in ('.wh.lib', 'lib/.wh.apk', 'lib/apk/.wh.db', 'lib/apk/db/.wh.installed',
            'lib/apk/db/.wh..wh..opq'):
            stream, audit = self.layers([first, [(name, tarfile.REGTYPE, b'')]])
            with self.assertRaisesRegex(ValueError, 'FINAL_IMAGE_MEMBER_REQUIRED'):
                m.effective_file(stream, audit, target, 100)
        for name in ('lib', 'lib/apk', 'lib/apk/db', target):
            stream, audit = self.layers([first, [(name, tarfile.SYMTYPE, b'')]])
            with self.assertRaises(ValueError): m.effective_file(stream, audit, target, 100)


if __name__ == '__main__': unittest.main()
