"""Real bounded package tree/archives; native runtime/publisher leaves modeled."""
import hashlib, os, sys, unittest
from pathlib import Path
from unittest.mock import Mock
ROOT = Path(__file__).resolve().parents[1]; sys.path[:0] = [str(ROOT), str(ROOT/'tests')]
import test_m2_discovery_artifact_membership as named_fixture
import test_image_custody as image_fixture
from tools.m2_discovery_installation_profile import package_membership as m


class PackageMembership(unittest.TestCase):
    def prepared(self):
        case = named_fixture.Membership(); self.addCleanup(case.doCleanups)
        named, root, package, records, _, original_seal = case.prepared()
        runtime = named.databases.runtime; runtime.guard = Mock(); runtime.inputs['peers'] = {}
        named.publisher.inputs['artifacts'][0]['bundle'] = {'path': str(root/'bundle.json')}
        for name, record in records.items():
            record['artifactKind'] = 'SOURCE_AND_ROUTE_PACKAGE' if name == 'gateway' else 'DOCKER_SAVE'
            if name in ('onboarding', 'ingestion', 'udp'):
                def change(config, manifest):
                    config['config']['Env'].append('PACKAGE_MODULE='+name); manifest['RepoTags'] = [name+':fixture']
                source = image_fixture.fixture(change)
                path = package/name/'image.docker.tar'; path.write_bytes(source[0]); path.chmod(0o600)
                record['files']['image.docker.tar'] = source[1]; record['imageId'] = source[2]
                runtime.inputs['peers'][name] = {'runtimeBinding': {'imageId': source[2]}}
            if name == 'gateway':
                raw = b'{"fixtureRoutes":true}'
                path = package/name/'routes.file-loop.json'; path.write_bytes(raw); path.chmod(0o600)
                record['files'][path.name] = hashlib.sha256(raw).hexdigest()
        def seal():
            original_seal()
            sums = named_fixture.m.checksum_map((package/'COHORT_SHA256SUMS').read_bytes())
            for name, record in records.items():
                raw = ''.join(sha+'  '+member+'\n' for member, sha in sorted(record['files'].items())).encode()
                path = package/name/'SHA256SUMS'; path.write_bytes(raw); path.chmod(0o600)
                sums[name+'/SHA256SUMS'] = hashlib.sha256(raw).hexdigest()
            subject = package/'COHORT_SHA256SUMS'
            subject.write_bytes(''.join(sha+'  '+name+'\n' for name, sha in sorted(sums.items())).encode())
            named.publisher.inputs['artifacts'][0]['subject']['sha256'] = hashlib.sha256(subject.read_bytes()).hexdigest()
            runtime.input_hash = m.digest(runtime.inputs)
        seal()
        return m.CurrentPackageMembership(named), root, package, records, seal

    def test_all_six_deliveries_five_images_and_exact_tree_without_extraction_or_runtime_promotion(self):
        reader, root, _, _, _ = self.prepared(); before = {str(p.relative_to(root)) for p in root.rglob('*')}
        proof = reader.observe()
        self.assertTrue(proof['sixModulePackageBytesProven']); self.assertTrue(proof['fiveReviewedModuleImageIdentitiesProven'])
        self.assertEqual((proof['moduleCount'], proof['originalImageCount']), (6, 5))
        self.assertEqual(before, {str(p.relative_to(root)) for p in root.rglob('*')})
        for key in ('allRuntimeArtifactMembershipProven', 'completePrivateCustodyProven',
            'actualWorkloadBearerAdmissionProven', 'fullCohortProven', 'nativeMutationDispatched',
            'runtimeAuthorityIssued', 'targetApplyAuthorized', 'releaseAcceptance'):
            self.assertIs(proof[key], False)

    def test_changed_gateway_payload_not_used_by_selected_image_owner_is_now_denied(self):
        reader, _, package, _, _ = self.prepared(); path = package/'gateway/routes.file-loop.json'
        path.write_bytes(b'{"unreviewed":true}')
        with self.assertRaisesRegex(ValueError, 'COMPLETE_PACKAGE_MEMBER_BYTES'): reader.observe()

    def test_undeclared_file_and_empty_directory_are_not_ignored(self):
        for directory in (False, True):
            with self.subTest(directory=directory):
                reader, _, package, _, _ = self.prepared(); path = package/'extra'
                path.mkdir(mode=0o700) if directory else path.write_bytes(b'extra')
                with self.assertRaisesRegex(ValueError, 'UNDECLARED_PACKAGE_DIRECTORY|REGULAR_PACKAGE_FILE_SET'): reader.observe()

    def test_missing_module_checksum_and_outer_extra_member_are_not_accepted(self):
        reader, _, package, _, _ = self.prepared(); path = package/'gateway/SHA256SUMS'; path.unlink()
        with self.assertRaisesRegex(ValueError, 'COMPLETE_SIGNED_PACKAGE_FILE_SET'): reader.observe()
        reader, _, package, _, _ = self.prepared(); path = package/'COHORT_SHA256SUMS'
        path.write_bytes(path.read_bytes()+b'0'*64+b'  extra\n')
        reader.membership.publisher.inputs['artifacts'][0]['subject']['sha256'] = hashlib.sha256(path.read_bytes()).hexdigest()
        with self.assertRaisesRegex(ValueError, 'SIX_MODULE_SIGNED_CHECKSUM_CLOSURE'): reader.observe()

    def test_inner_checksum_must_agree_even_if_altered_outer_checksum_is_authenticated(self):
        reader, _, package, _, _ = self.prepared(); path = package/'gateway/SHA256SUMS'
        path.write_bytes(b'0'*64+b'  other.json\n')
        subject = package/'COHORT_SHA256SUMS'; sums = named_fixture.m.checksum_map(subject.read_bytes())
        sums['gateway/SHA256SUMS'] = hashlib.sha256(path.read_bytes()).hexdigest()
        subject.write_bytes(''.join(sha+'  '+name+'\n' for name, sha in sorted(sums.items())).encode())
        reader.membership.publisher.inputs['artifacts'][0]['subject']['sha256'] = hashlib.sha256(subject.read_bytes()).hexdigest()
        with self.assertRaisesRegex(ValueError, 'MODULE_CHECKSUM_CLOSURE'): reader.observe()

    def test_other_retained_image_identity_cannot_be_selected_by_matching_signed_bytes(self):
        reader, _, _, _, _ = self.prepared()
        reader.runtime.inputs['peers']['onboarding']['runtimeBinding']['imageId'] = 'sha256:'+'e'*64
        with self.assertRaisesRegex(ValueError, 'IMAGE_MUST_MATCH_SAME_REVIEWED'): reader.observe()

    def test_linked_world_writable_and_replaced_members_are_rejected(self):
        for change in ('symlink', 'hardlink', 'permissions'):
            with self.subTest(change=change):
                reader, root, package, _, _ = self.prepared(); path = package/'gateway/routes.file-loop.json'
                if change == 'symlink':
                    target = root/'outside'; path.rename(target); path.symlink_to(target)
                elif change == 'hardlink': os.link(path, root/'alias')
                else: path.chmod(0o666)
                with self.assertRaisesRegex(ValueError, 'REGULAR_PACKAGE_FILE_SET'): reader.observe()

    def test_tree_change_during_hashing_never_returns_a_successful_interval(self):
        reader, _, package, _, _ = self.prepared(); original = reader.inventory; calls = [0]
        def changed(*args):
            calls[0] += 1
            if calls[0] == 2: (package/'gateway/routes.file-loop.json').write_bytes(b'{"changed":true}')
            return original(*args)
        reader.inventory = changed
        with self.assertRaisesRegex(ValueError, 'PACKAGE_OR_PARENT_CHANGED'): reader.observe()

    def test_foreign_owner_and_revocation_deny_before_any_package_read(self):
        reader, _, _, _, _ = self.prepared(); reader.runtime = object()
        with self.assertRaisesRegex(ValueError, 'SAME_EXACT_CURRENT_PACKAGE'): reader.observe()
        reader, _, _, _, _ = self.prepared()
        reader.runtime.guard.side_effect = ValueError('CURRENT_PARENT_REVOKED')
        with self.assertRaisesRegex(ValueError, 'CURRENT_PARENT_REVOKED'): reader.observe()


if __name__ == '__main__': unittest.main()
