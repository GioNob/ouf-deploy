import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('image', ROOT/'tools/storage_security/runtime_image.py')
image = importlib.util.module_from_spec(spec)
spec.loader.exec_module(image)


class RuntimeImageTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.out = Path(self.tmp.name)/'image'
        self.binary = b'synthetic static executable; never executed'
        self.licence = b'Apache License\nVersion 2.0\nsynthetic fixture'
        self.pin = patch.object(image, 'BINARY_SHA', image.sha(self.binary))
        self.pin.start()
        self.addCleanup(self.pin.stop)

    def build(self):
        return image.write_image(self.binary, self.licence, self.out)

    def test_reproducible_oci_and_docker_have_same_exact_layer_and_config(self):
        record = self.build()
        other = self.out.parent/'other'
        self.assertEqual(record, image.write_image(self.binary, self.licence, other))
        for p in self.out.rglob('*'):
            if p.is_file():
                self.assertEqual(p.read_bytes(), (other/p.relative_to(self.out)).read_bytes())
        with tarfile.open(self.out/'runtime.docker.tar') as tar:
            m = json.load(tar.extractfile('manifest.json'))[0]
            self.assertEqual(image.sha(tar.extractfile(m['Layers'][0]).read()), record['layerDigest'][7:])
            self.assertEqual(image.sha(tar.extractfile(m['Config']).read()), record['configDigest'][7:])

    def test_changed_binary_denied_before_output(self):
        with self.assertRaisesRegex(ValueError, 'EXACT_OWNER_REVIEWED'):
            image.write_image(self.binary+b'changed', self.licence, self.out)
        self.assertFalse(self.out.exists())

    def test_existing_output_is_never_reinitialized(self):
        self.build()
        before = (self.out/'image-record.json').read_bytes()
        with self.assertRaisesRegex(ValueError, 'NEW_OUTPUT'):
            self.build()
        self.assertEqual(before, (self.out/'image-record.json').read_bytes())

    def test_changed_blob_is_rejected(self):
        r = self.build()
        (self.out/'blobs/sha256'/r['layerDigest'][7:]).write_bytes(b'tampered')
        with self.assertRaisesRegex(ValueError, 'BLOB_IDENTITY'):
            image.verify_layout(self.out)

    def test_extra_docker_content_is_rejected(self):
        self.build()
        with (self.out/'runtime.docker.tar').open('ab') as f:
            f.write(b'unexplained')
        with self.assertRaisesRegex(ValueError, 'RECONSTRUCTED_IMAGE_CHANGED'):
            image.verify_layout(self.out)

    def test_receipt_cannot_claim_admission(self):
        self.build()
        p = self.out/'image-record.json'
        r = json.loads(p.read_bytes()); r['releaseAdmitted'] = True
        p.write_bytes(image.canonical(r))
        with self.assertRaisesRegex(ValueError, 'RECONSTRUCTED_IMAGE_CHANGED'):
            image.verify_layout(self.out)

    def test_descriptor_traversal_and_symlink_are_rejected(self):
        r = self.build()
        p = self.out/'blobs/sha256'/r['layerDigest'][7:]
        content = p.read_bytes(); p.unlink()
        external = self.out.parent/'external'; external.write_bytes(content)
        p.symlink_to(external)
        with self.assertRaisesRegex(ValueError, 'REGULAR_BLOB'):
            image.verify_layout(self.out)
        index = json.loads((self.out/'index.json').read_bytes())
        index['manifests'][0]['digest'] = 'sha256:../../external'
        (self.out/'index.json').write_bytes(image.canonical(index))
        with self.assertRaisesRegex(ValueError, 'SAFE_SHA256'):
            image.verify_layout(self.out)

    def test_exact_least_privilege_filesystem_and_no_embedded_bindings(self):
        r = self.build()
        c = json.loads((self.out/'blobs/sha256'/r['configDigest'][7:]).read_bytes())
        self.assertEqual(c['config']['User'], '10001:10001')
        self.assertFalse(set(c['config']) & {'Env', 'ExposedPorts', 'Volumes', 'Cmd'})
        with tarfile.open(fileobj=io.BytesIO((self.out/'blobs/sha256'/r['layerDigest'][7:]).read_bytes())) as tar:
            self.assertTrue(all(m.uid == m.gid == m.mtime == 0 for m in tar))
            self.assertEqual(tar.getmember('usr/local/bin/weed').mode, 0o555)
        self.assertFalse(r['releaseAdmitted'])
        self.assertFalse(r['thirdPartyLicencesAccepted'])

    def assessment_fixture(self):
        record = self.build()
        spec = importlib.util.spec_from_file_location('assess_image', ROOT/'scripts/assess-storage-runtime-image-20261102.py')
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        readback = self.out.parent/'readback'; readback.mkdir()
        evidence = self.out.parent/'evidence'; evidence.mkdir()
        for name in ['candidate.json', 'compiled-packages.json']:
            (readback/name).write_text('{}')
        for name in ['seaweedfs-g1-applicability-owner-decision-20261102.json', 'seaweedfs-g1-openvex-20261102.json']:
            (evidence/name).write_text('{}')
        (self.out/'current-advisory.json').write_text('{}')
        scan = {'Trivy': {'Version': '0.70.0'}, 'Metadata': {'ImageID': record['configDigest']},
                'Results': [{'Target': 'usr/local/bin/weed', 'Class': 'lang-pkgs', 'Type': 'gobinary',
                             'Packages': [{'Name': 'example.test/dependency', 'Version': 'v1.2.3'}]}]}
        sbom = {'spdxVersion': 'SPDX-2.3', 'documentNamespace': 'urn:fixture:sbom',
                'packages': [{'name': 'example.test/dependency', 'versionInfo': 'v1.2.3'}]}
        (self.out/'fresh-image-scan.json').write_text(json.dumps(scan))
        (self.out/'image.spdx.json').write_text(json.dumps(sbom))
        # Applicability policy has its separate nine-test qualification. These
        # tests isolate scan identity/inventory boundaries before/after that call.
        policy = SimpleNamespace(assess=lambda *args: {'vulnerabilitySubgate': 'PASS_WITH_EXACT_DISPOSITION'})
        mocked = patch.object(module, 'load_module', side_effect=lambda name, path: image if name == 'runtime_image' else policy)
        mocked.start(); self.addCleanup(mocked.stop)
        return module, readback, evidence, scan, sbom

    def test_scan_of_another_image_is_rejected(self):
        m, r, e, scan, _ = self.assessment_fixture()
        scan['Metadata']['ImageID'] = 'sha256:'+'0'*64
        (self.out/'fresh-image-scan.json').write_text(json.dumps(scan))
        with self.assertRaisesRegex(ValueError, 'EXACT_IMAGE_SCAN'):
            m.assess(self.out, r, e)

    def test_empty_or_extra_scan_target_never_counts_as_clean(self):
        m, r, e, scan, _ = self.assessment_fixture()
        for results in [[], scan['Results'] + [{'Class': 'os-pkgs'}]]:
            scan['Results'] = results
            (self.out/'fresh-image-scan.json').write_text(json.dumps(scan))
            with self.assertRaisesRegex(ValueError, 'ONE_COMPLETE_RUNTIME_BINARY_SCAN'):
                m.assess(self.out, r, e)

    def test_sbom_missing_dependency_is_rejected(self):
        m, r, e, _, sbom = self.assessment_fixture()
        sbom['packages'][0]['versionInfo'] = 'v9.9.9'
        (self.out/'image.spdx.json').write_text(json.dumps(sbom))
        with self.assertRaisesRegex(ValueError, 'SBOM_MUST_INCLUDE_ALL'):
            m.assess(self.out, r, e)

    def test_valid_sbom_does_not_accept_licences_or_release(self):
        m, r, e, _, _ = self.assessment_fixture()
        result = m.assess(self.out, r, e)
        self.assertEqual(result['scannedPackages'], 1)
        self.assertEqual(result['licenceReview'], 'OPEN')
        self.assertFalse(result['releaseAdmitted'])
        self.assertFalse(result['thirdPartyLicencesAccepted'])


if __name__ == '__main__':
    unittest.main()
