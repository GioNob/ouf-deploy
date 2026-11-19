import hashlib
import importlib.util
import io
import json
from pathlib import Path
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('lifecycle', ROOT/'scripts/assess-storage-sdk-lifecycle.py')
lifecycle = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(lifecycle)


class StorageSdkLifecycleTest(unittest.TestCase):
    def fixture(self, graph_extra=(), scanned_extra=(), spdx_extra=()):
        v2 = lifecycle.SDK_V1 + '-v2/service/s3'
        packages = [lifecycle.WEED, lifecycle.WEED + '/s3api', v2, *graph_extra]
        graph = json.dumps({'packages': packages}).encode()
        binary = '1' * 64
        source = '2' * 40
        config = 'sha256:' + '3' * 64
        modules = [('stdlib', '1.27.3'), (v2, 'v1.2.3'), *scanned_extra]
        rows = [
            {'binarySha256': binary, 'declaredSource': source,
             'compiledPackagesSha256': hashlib.sha256(graph).hexdigest()},
            None,
            {'binarySha256': binary, 'sourceCommit': source, 'configDigest': config},
            {'SchemaVersion': 2, 'Metadata': {
                'ImageID': config, 'ImageConfig': {'config': {
                    'Entrypoint': ['/usr/local/bin/weed'],
                    'Labels': {'org.ouf.binary.sha256': binary, 'org.opencontainers.image.revision': source},
                }},
             }, 'Results': [{'Target': 'usr/local/bin/weed', 'Class': 'lang-pkgs', 'Type': 'gobinary',
                             'Packages': [{'Name': name, 'Version': version} for name, version in modules]}]},
            {'spdxVersion': 'SPDX-2.3', 'documentNamespace': 'https://example.invalid/sbom',
             'packages': [{'name': name, 'versionInfo': version} for name, version in [*modules, *spdx_extra]]},
        ]
        evidence = {name: json.dumps(row).encode() for name, row in zip(lifecycle.INPUTS, rows)}
        evidence['original-compiled-packages.json'] = graph
        return evidence

    def test_v2_only_passes_lifecycle_without_admission(self):
        result = lifecycle.assess(self.fixture())
        self.assertEqual(result['status'], 'AWS_SDK_V1_ABSENT')
        self.assertFalse(result['releaseAdmitted'])

    def test_vendored_v1_holds_even_if_absent_from_scan_and_spdx(self):
        path = 'example.invalid/vendor/' + lifecycle.SDK_V1 + '/service/s3'
        result = lifecycle.assess(self.fixture(graph_extra=[path]))
        self.assertEqual(result['status'], 'HELD_AWS_SDK_V1_PRESENT')
        self.assertEqual(result['compiledSdkV1Packages'], [path])

    def test_v1_in_either_module_inventory_holds(self):
        module = (lifecycle.SDK_V1, 'v1.55.8')
        for field in ('scanned_extra', 'spdx_extra'):
            with self.subTest(field=field):
                result = lifecycle.assess(self.fixture(**{field: [module]}))
                self.assertEqual(result['status'], 'HELD_AWS_SDK_V1_PRESENT')

    def test_spdx_missing_scanned_v1_is_invalid_evidence(self):
        evidence = self.fixture(scanned_extra=[(lifecycle.SDK_V1, 'v1.55.8')])
        clean = self.fixture()
        evidence['image.spdx.json'] = clean['image.spdx.json']
        with self.assertRaisesRegex(ValueError, 'SBOM_MUST_INCLUDE_ALL_SCANNED_PACKAGES'):
            lifecycle.assess(evidence)

    def test_same_source_different_image_is_invalid_evidence(self):
        evidence = self.fixture()
        scan = json.loads(evidence['fresh-image-scan.json'])
        scan['Metadata']['ImageID'] = 'sha256:' + '4' * 64
        evidence['fresh-image-scan.json'] = json.dumps(scan).encode()
        with self.assertRaisesRegex(ValueError, 'EXACT_IMAGE_SCAN_REQUIRED'):
            lifecycle.assess(evidence)

    def test_changed_graph_is_invalid_even_with_v2_only(self):
        evidence = self.fixture()
        evidence['original-compiled-packages.json'] += b' '
        with self.assertRaisesRegex(ValueError, 'COMPILED_GRAPH_CHANGED'):
            lifecycle.assess(evidence)

    def test_archive_with_altered_member_is_invalid(self):
        evidence = self.fixture()
        manifest = ''.join(f'{hashlib.sha256(raw).hexdigest()}  {name}\n' for name, raw in evidence.items())
        evidence['image.spdx.json'] += b' '
        memory = io.BytesIO()
        with zipfile.ZipFile(memory, 'w') as archive:
            archive.writestr('SHA256SUMS', manifest)
            for name, raw in evidence.items():
                archive.writestr(name, raw)
        with zipfile.ZipFile(memory) as archive:
            with self.assertRaisesRegex(ValueError, 'MEMBER_CHECKSUM_MISMATCH'):
                lifecycle.read_evidence(archive)

    def test_exact_4_51_archive_holds(self):
        path = ROOT/'evidence/artifacts/storage-runtime-image-readback-41527990598.zip'
        with zipfile.ZipFile(path) as archive:
            result = lifecycle.assess(lifecycle.read_evidence(archive))
        self.assertEqual(result['status'], 'HELD_AWS_SDK_V1_PRESENT')
        self.assertEqual(len(result['compiledSdkV1Packages']), 55)
        expected = ['github.com/aws/aws-sdk-go@v1.55.8']
        self.assertEqual(result['scannedSdkV1Modules'], expected)
        self.assertEqual(result['sbomSdkV1Modules'], expected)
