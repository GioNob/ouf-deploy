"""Actual target public roster versus selected original producer contracts."""
import importlib.util, io, json, stat, tempfile, unittest, zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('core_origins', ROOT/'scripts/stage-m2-current-core-origin.py')
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
from tools.m2_discovery_installation_profile.retained_mount_role_correction import ROSTER


class CurrentOrigins(unittest.TestCase):
    def test_four_actual_current_roles_and_separate_semantic_candidate_match_the_public_receipts(self):
        cases = json.loads(m.ORIGINS.read_bytes())['roles']
        rows = json.loads((ROOT/'evidence/m2-discovery-current-bindings-target-20261029.json').read_bytes())['receipt']['bindings']
        by_id = {row['containerId']: row for row in rows}
        for role in ('mcp', 'onboarding', 'ingestion', 'udp'):
            self.assertTrue(cases[role]['currentRoleFromOperatorPublicReceipt'])
            self.assertEqual(cases[role]['nativeImageId'], by_id[ROSTER[role]['containerId']]['imageId'])
        self.assertFalse(cases['semantic']['currentRoleFromOperatorPublicReceipt'])
        self.assertTrue(cases['semantic']['qualifiedReplacementCandidateNotYetSelected'])
        self.assertNotEqual(cases['semantic']['nativeImageId'], by_id[ROSTER['semantic']['containerId']]['imageId'])
        self.assertNotEqual(cases['mcp']['sourceCommit'], 'f249b3dcc58c2a96742092d90fa09fd90b705bd0')
        self.assertNotEqual(cases['udp']['sourceCommit'], 'b49c0d6f50c574c11684361ce4e8040e9cbddee2')

    def test_new_source_lock_preserves_distinct_original_formats_and_requires_the_m2_profile(self):
        cases = json.loads(m.ORIGINS.read_bytes())['roles']; lock = json.loads(m.LOCK.read_bytes())
        modules = {row['module']: row for row in lock['modules']}
        self.assertEqual(set(modules), set(cases)|{'gateway'})
        for role, case in cases.items(): self.assertEqual(modules[role]['commit'], case['sourceCommit'])
        self.assertEqual(cases['onboarding']['originalFormat'], 'ONBOARDING_TESTED_IMAGE')
        self.assertEqual(cases['mcp']['originalFormat'], 'MCP_QUALIFIED_CI_IMAGE')
        self.assertEqual(cases['mcp']['ciSourceBinding']['sourceCommit'], cases['mcp']['sourceCommit'])
        self.assertEqual(lock['registryRuntimeRequirements']['effectiveMountPurposes'], 7)
        self.assertFalse(lock['registryRuntimeRequirements']['fileFirstProfileUsed'])
        for key in ('candidateSelectionChanged','runtimeAuthorityIssued','targetApplyAuthorized','releaseAcceptance'):
            self.assertFalse(lock[key])

    def test_wrong_archive_and_unknown_role_cannot_create_an_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); source = root/'wrong.zip'; source.write_bytes(b'wrong original archive')
            output = root/'not-created'
            with self.assertRaisesRegex(ValueError, 'ORIGINAL_CI_ZIP_BYTES'): m.stage('mcp', source, output)
            self.assertFalse(output.exists())
            with self.assertRaisesRegex(ValueError, 'KNOWN_ORIGIN'): m.stage('invented-role', source, output)
            self.assertFalse(output.exists())

    def test_origin_archive_paths_and_file_types_are_checked_before_any_extraction(self):
        for name, mode in [('../escape', stat.S_IFREG), ('/absolute', stat.S_IFREG),
            ('a//b', stat.S_IFREG), ('link', stat.S_IFLNK), ('device', stat.S_IFCHR)]:
            with self.subTest(name=name):
                raw = io.BytesIO()
                with zipfile.ZipFile(raw, 'w') as zipped:
                    entry = zipfile.ZipInfo(name); entry.external_attr = (mode|0o600)<<16
                    zipped.writestr(entry, b'disposable')
                raw.seek(0)
                with zipfile.ZipFile(raw) as zipped, self.assertRaisesRegex(ValueError, 'REGULAR_ORIGIN_MEMBERS'):
                    m.entries(zipped)


if __name__ == '__main__': unittest.main()
