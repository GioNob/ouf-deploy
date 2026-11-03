import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('candidate', ROOT / 'scripts/qualify-seaweedfs-452-image.py')
candidate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(candidate)
image = candidate.image


class CandidateImageTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.out = Path(tmp.name) / 'image'
        self.binary = b'synthetic patched candidate'
        self.licence = b'Apache License synthetic fixture'
        self.profile = candidate.PROFILE._replace(binary_sha=image.sha(self.binary),
                                                   licence_sha=image.sha(self.licence))
        profile = patch.object(candidate, 'PROFILE', self.profile)
        profile.start()
        self.addCleanup(profile.stop)

    def prepare(self, findings):
        record = image.write_image(self.binary, self.licence, self.out, profile=self.profile)
        graph = image.canonical({'packages': [
            candidate.lifecycle.WEED, candidate.lifecycle.WEED + '/s3api',
        ]})
        (self.out / 'original-compiled-packages.json').write_bytes(graph)
        (self.out / 'original-candidate.json').write_bytes(image.canonical({
            'binarySha256': self.profile.binary_sha,
            'declaredSource': self.profile.source_commit,
            'compiledPackagesSha256': image.sha(graph),
        }))
        config = json.loads((self.out / 'blobs/sha256' / record['configDigest'][7:]).read_bytes())
        self.scan = {
            'SchemaVersion': 2, 'Trivy': {'Version': '0.70.0'},
            'Metadata': {'ImageID': record['configDigest'], 'ImageConfig': config},
            'Results': [{'Target': 'usr/local/bin/weed', 'Class': 'lang-pkgs', 'Type': 'gobinary',
                         'Packages': [{'Name': 'stdlib', 'Version': 'v1.27.3'},
                                      {'Name': 'example.test/dep', 'Version': 'v1.0.0'}],
                         'Vulnerabilities': findings}],
        }
        self.write_scan()
        (self.out / 'image.spdx.json').write_bytes(image.canonical({
            'spdxVersion': 'SPDX-2.3', 'documentNamespace': 'urn:fixture:spdx',
            'packages': [{'name': 'stdlib', 'versionInfo': 'v1.27.3'},
                         {'name': 'example.test/dep', 'versionInfo': 'v1.0.0'}],
        }))
        return record['configDigest']

    def write_scan(self):
        (self.out / 'fresh-image-scan.json').write_bytes(image.canonical(self.scan))

    def test_old_profile_cannot_verify_candidate_and_changed_licence_is_denied(self):
        with self.assertRaisesRegex(ValueError, 'EXACT_UPSTREAM_LICENCE'):
            image.write_image(self.binary, self.licence + b'changed', self.out, profile=self.profile)
        self.assertFalse(self.out.exists())
        self.prepare([])
        with self.assertRaisesRegex(ValueError, 'EXACT_OWNER_REVIEWED'):
            image.verify_layout(self.out)

    def test_clean_raw_scan_does_not_issue_admission(self):
        result = candidate.assess(self.out, self.prepare([]), 'a' * 40, 1)
        self.assertEqual(result['vulnerabilitySubgate'], 'PASS_RAW')
        self.assertEqual(result['sdkLifecycle']['status'], 'AWS_SDK_V1_ABSENT')
        self.assertEqual(result['overallSwG1'], 'OPEN')
        self.assertFalse(result['releaseAdmitted'])
        self.assertEqual(result['targetOperations'], 0)

    def test_raw_unknown_and_high_are_held_without_legacy_disposition(self):
        image_id = self.prepare([
            {'Severity': 'UNKNOWN', 'VulnerabilityID': 'GO-2026-5932'},
            {'Severity': 'HIGH', 'VulnerabilityID': 'GO-FIXTURE-HIGH'},
        ])
        result = candidate.assess(self.out, image_id, 'a' * 40, 1)
        self.assertEqual(result['vulnerabilitySubgate'], 'HELD_RAW_FINDINGS')
        self.assertEqual(result['unresolvedHighCriticalUnknown'], ['GO-2026-5932', 'GO-FIXTURE-HIGH'])
        self.assertEqual(result['appliedApplicabilityDispositions'], [])

    def test_wrong_daemon_image_and_malformed_severity_are_denied(self):
        image_id = self.prepare([{'Severity': 'UNRECOGNIZED', 'VulnerabilityID': 'GO-FIXTURE'}])
        with self.assertRaisesRegex(ValueError, 'DAEMON_IMAGE_ID'):
            candidate.assess(self.out, 'sha256:' + '0' * 64, 'a' * 40, 1)
        with self.assertRaisesRegex(ValueError, 'COMPLETE_SEVERITY'):
            candidate.assess(self.out, image_id, 'a' * 40, 1)
