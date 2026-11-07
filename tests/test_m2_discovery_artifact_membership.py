"""Actual protected JAR/SQL, Docker tar and signed-subject digest composition.

Parent/publisher cryptography is modeled here and independently qualified by
the existing native publisher suite. No source package is executed/extracted.
"""
import copy, hashlib, io, shutil, sys, tarfile, tempfile, unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock
ROOT = Path(__file__).resolve().parents[1]; sys.path[:0] = [str(ROOT), str(ROOT/'tests')]
import test_m2_discovery_current_databases as database_fixture
import test_image_custody as image_fixture
from fixtures.offline_image_producer import produce
from test_chatbot_cohort_plan import fixture as old_container
from tools.m2_discovery_installation_profile import artifact_membership as m
from tools.m2_discovery_installation_profile.current_cohort import CurrentCohortRuntime
from tools.m2_discovery_installation_profile.custody_capture import encoded
from tools.semantic_registry_operational_owner.core import Denied


class Membership(unittest.TestCase):
    def prepared(self):
        tmp = tempfile.TemporaryDirectory(dir=ROOT); self.addCleanup(tmp.cleanup)
        root = Path(tmp.name); root.chmod(0o700); package = root/'package'; package.mkdir(mode=0o700)
        modules = database_fixture.artifacts(root); by_module = {row['module']: row for row in modules}
        files = {name: {} for name in m.MODULES}; selected = []
        lock = root/'producer-source-lock.json'
        lock.write_bytes(encoded({'modules': [{'module': name, 'commit': image_fixture.SOURCE} for name in sorted(m.MODULES)]}))
        for name in sorted(m.MODULES):
            (package/name).mkdir(mode=0o700)
            raw = encoded({'module': name, 'disposableFixture': True})
            path = package/name/'package-record.json'; path.write_bytes(raw); path.chmod(0o600)
            files[name]['package-record.json'] = hashlib.sha256(raw).hexdigest()
        for name, row in by_module.items():
            if name != 'mcp':
                raw = Path(row['artifact']['root']).read_bytes(); (package/name/'application.jar').write_bytes(raw)
                files[name]['application.jar'] = hashlib.sha256(raw).hexdigest()
        deliveries = {}
        for name in ('semantic', 'mcp'):
            def change(config, manifest):
                config['config']['Env'].append('FIXTURE_MODULE='+name); manifest['RepoTags'] = [name+':fixture']
                if name == 'mcp':
                    config['config']['User'] = '10005:10005'
                    config['config']['Entrypoint'] = ['/usr/local/bin/ouf-mcp']
            source = image_fixture.fixture(change); (package/name/'image.docker.tar').write_bytes(source[0])
            derived = io.BytesIO(); original = image_fixture.audit(source)
            payload = b'disposable Semantic jar; never run' if name == 'semantic' else b'disposable MCP executable; never run'
            deliveries[name] = produce(root/(name+'-producer-checkout'), package/name, name, original, source[0], payload, lock)
            files[name].update({p.relative_to(package/name).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
                for p in (package/name).rglob('*') if p.is_file() and p.name != 'SHA256SUMS'})
            plan = image_fixture.c.tagless_archive(io.BytesIO(source[0]), derived, original)
            path = root/(name+'.tagless.tar'); path.write_bytes(derived.getvalue()); path.chmod(0o600)
            audit = image_fixture.c.archive(derived, plan['derivedArchiveSha256'], source[2], image_fixture.SOURCE)
            selected.append({'module': name, 'archivePath': str(path), 'audit': audit,
                'originalArchiveSha256': source[1]})
        records = {name: {'module': name, 'sourceCommit': image_fixture.SOURCE,
            'scanGate': 'PASS_HIGH_CRITICAL_UNKNOWN_INCLUDING_UNFIXED', 'files': files[name]} for name in m.MODULES}
        for name, delivery in deliveries.items(): records[name] = dict(delivery, files=files[name])
        for image in selected: records[image['module']]['imageId'] = image['audit']['imageId']
        for path in package.rglob('*'):
            if path.is_file(): path.chmod(0o600)
        parent = object(); images = object.__new__(m.DiscoveryImages); images.parent = parent; images.guard = Mock()
        images.plan = {'images': selected}; selected_runtime = SimpleNamespace(images=images)
        held = {'state': 'READY', 'nextPhase': 12, 'version': 42}
        def snapshot(expected=None):
            if expected is not None and expected != held: raise ValueError('HELD_HISTORY_CHANGED')
            return copy.deepcopy(held)
        selected_runtime.held = snapshot
        runtime = object.__new__(CurrentCohortRuntime); runtime.selected = selected_runtime; runtime.parent = parent
        runtime.inputs = {}; db = object.__new__(m.CurrentCohortDatabases); db.runtime = runtime
        db.inputs = {'modules': modules}; db.guard = Mock()
        publisher = object.__new__(m.CurrentPublisherCustody); publisher.parent = parent
        publisher.runtime_inputs = runtime.inputs; publisher.guard = Mock()
        publisher.observe = Mock(return_value={'modeledRealPublisherVerification': True})
        subject = package/'COHORT_SHA256SUMS'
        publisher.inputs = {'artifacts': [{'role': m.ROLE, 'subject': {'path': str(subject), 'maximumBytes': 131072},
            'sourceCommit': 'f'*40}]}
        def source_tar(change=None):
            buffer = io.BytesIO()
            with tarfile.open(fileobj=buffer, mode='w') as tar:
                for ref in by_module['mcp']['artifact']['files']:
                    name = str(Path(ref['path']).relative_to(by_module['mcp']['artifact']['root']))
                    data = Path(ref['path']).read_bytes(); entry = tarfile.TarInfo(name); entry.size = len(data)
                    if change and change(tar, entry, data): continue
                    tar.addfile(entry, io.BytesIO(data))
            path = package/'mcp'/'source.tar'; path.write_bytes(buffer.getvalue()); path.chmod(0o600)
            files['mcp']['source.tar'] = hashlib.sha256(buffer.getvalue()).hexdigest()
        def seal():
            lock = {'modules': [{'module': name, 'commit': record['sourceCommit']} for name, record in sorted(records.items())]}
            raw_lock = encoded(lock); lock_hash = hashlib.sha256(raw_lock).hexdigest()
            for record in records.values(): record['cohortSourceLockSha256'] = lock_hash
            manifest = {'schema': 'ouf.chatbot-file-cohort-package.v1', 'sourceLockSha256': lock_hash,
                'producer': {'sourceCommit': 'f'*40}, 'modules': [records[name] for name in sorted(records)],
                'runtimeAuthorityIssued': False, 'targetApplyAuthorized': False}
            raw_manifest = encoded(manifest)
            for name, raw in (('cohort-manifest.json', raw_manifest), ('source-lock.json', raw_lock)):
                path = package/name; path.write_bytes(raw); path.chmod(0o600)
            hashes = {'cohort-manifest.json': hashlib.sha256(raw_manifest).hexdigest(), 'source-lock.json': lock_hash}
            for name, record in records.items():
                hashes.update({name+'/'+member: sha for member, sha in record['files'].items()})
            subject.write_bytes(''.join(sha+'  '+name+'\n' for name, sha in sorted(hashes.items())).encode()); subject.chmod(0o600)
            publisher.inputs['artifacts'][0]['subject']['sha256'] = hashlib.sha256(subject.read_bytes()).hexdigest()
            runtime.inputs['cohortManifestHash'] = images.plan['cohortManifestHash'] = m.digest(manifest)
            publisher.runtime_hash = m.digest(runtime.inputs)
            for image in selected:
                image['modulePackageHash'] = m.digest(m.decode((package/image['module']/'package-record.json').read_bytes()))
        source_tar(); seal()
        return m.CurrentArtifactMembership(publisher, db, images), root, package, records, source_tar, seal

    def test_real_archive_and_migration_membership_is_bound_without_execution_or_extraction(self):
        reader, root, _, _, _, _ = self.prepared(); before = {p.relative_to(root) for p in root.rglob('*')}
        result = reader.observe()
        self.assertTrue(result['selectedImageAndMigrationMembershipProven'])
        self.assertEqual((result['migrationModuleCount'], result['selectedImageCount']), (4, 2))
        for key in ('allRuntimeArtifactMembershipProven', 'completePrivateCustodyProven', 'actualWorkloadBearerAdmissionProven',
            'fullCohortProven', 'runtimeAuthorityIssued', 'targetApplyAuthorized', 'nativeMutationDispatched', 'releaseAcceptance'):
            self.assertIs(result[key], False)
        self.assertEqual(before, {p.relative_to(root) for p in root.rglob('*')})

    def test_missing_publisher_role_and_foreign_owner_are_denied_before_provenance(self):
        reader, _, _, _, _, _ = self.prepared()
        reader.publisher.inputs['artifacts'][0]['role'] = 'unrelatedArtifact'
        with self.assertRaisesRegex(ValueError, 'EXPLICIT_PARENT_REVIEWED'): reader.observe()
        reader.publisher.observe.assert_not_called()
        reader.publisher.parent = object()
        with self.assertRaisesRegex(ValueError, 'SAME_PARENT_REVIEW'): reader.observe()

    def test_changed_signed_subject_or_manifest_bytes_are_not_repaired(self):
        reader, _, package, _, _, _ = self.prepared(); path = package/'cohort-manifest.json'
        path.write_bytes(b'{}')
        with self.assertRaises((ValueError, Denied)): reader.observe()
        self.assertEqual(path.read_bytes(), b'{}')

    def test_independently_reviewed_jar_with_other_bytes_is_not_a_member(self):
        reader, _, _, _, _, _ = self.prepared(); db = next(v for v in reader.databases.inputs['modules'] if v['module'] == 'onboarding')
        path = Path(db['artifact']['root']); path.write_bytes(path.read_bytes()+b'unrelated reviewed bytes')
        db['artifact']['files'][0]['sha256'] = hashlib.sha256(path.read_bytes()).hexdigest()
        with self.assertRaisesRegex(ValueError, 'JAR_IS_NOT_A_SIGNED_PACKAGE_MEMBER'): reader.observe()

    def test_missing_mcp_migration_in_authenticated_source_tar_denies(self):
        reader, _, _, _, source_tar, seal = self.prepared(); source_tar(lambda *args: True); seal()
        with self.assertRaisesRegex(ValueError, 'MIGRATIONS_DIFFER_FROM_SIGNED_SOURCE'): reader.observe()

    def test_duplicate_and_symlink_entries_are_denied_even_with_matching_signed_archive_digest(self):
        reader, _, _, _, source_tar, seal = self.prepared()
        def duplicate(tar, entry, raw): tar.addfile(entry, io.BytesIO(raw)); return False
        source_tar(duplicate); seal()
        with self.assertRaisesRegex(ValueError, 'UNIQUE_REGULAR'): reader.observe()
        def symlink(tar, entry, raw):
            entry.type = tarfile.SYMTYPE; entry.linkname = '/not-read'; entry.size = 0; tar.addfile(entry); return True
        source_tar(symlink); seal()
        with self.assertRaisesRegex(ValueError, 'UNIQUE_REGULAR'): reader.observe()

    def test_changed_original_or_derived_image_archive_cannot_use_a_previous_loaded_image_proof(self):
        reader, _, package, _, _, _ = self.prepared(); original = package/'semantic'/'image.docker.tar'
        raw = original.read_bytes(); original.write_bytes(b'tampered')
        with self.assertRaises(ValueError): reader.observe()
        original.write_bytes(raw); derived = Path(reader.images.plan['images'][0]['archivePath']); derived.write_bytes(b'tampered')
        with self.assertRaises(ValueError): reader.observe()
        self.assertEqual(derived.read_bytes(), b'tampered')

    def test_source_commit_drift_in_reviewed_image_plan_is_denied(self):
        reader, _, _, _, _, _ = self.prepared(); reader.images.plan['images'][0]['audit']['sourceCommit'] = 'e'*40
        with self.assertRaisesRegex(ValueError, 'SIGNED_IMAGE_PRODUCER_PACKAGE_RECORD'): reader.observe()

    def test_actual_image_and_delivery_producers_compose_with_the_mcp_planner(self):
        from tools.m2_discovery_installation_profile.mcp_runtime import compile_plan
        reader, _, package, records, _, _ = self.prepared()
        selected = reader.images.plan['images'][1]
        raw = m.decode((package/'mcp/package-record.json').read_bytes())
        delivery = {k: v for k, v in records['mcp'].items() if k != 'files'}
        self.assertNotEqual(m.digest(raw), m.digest(delivery))
        self.assertNotEqual(m.digest(raw), records['mcp']['files']['package-record.json'])
        old, _, _ = old_container('mcp')
        plan = compile_plan(old=old, selected_image=selected, package=raw, cohort_id='disposable-m2',
            environment_delta={}, registry_request_hash='1'*64, cohort_manifest_hash=reader.images.plan['cohortManifestHash'])
        self.assertEqual(plan['replacement']['modulePackageHash'], selected['modulePackageHash'])
        self.assertTrue(reader.observe()['selectedImageAndMigrationMembershipProven'])
        selected['modulePackageHash'] = m.digest(delivery)
        with self.assertRaisesRegex(ValueError, 'SAME_SELECTED_MCP_PACKAGE'): compile_plan(old=old,
            selected_image=selected, package=raw, cohort_id='disposable-m2', environment_delta={},
            registry_request_hash='1'*64, cohort_manifest_hash=reader.images.plan['cohortManifestHash'])
        with self.assertRaisesRegex(ValueError, 'SIGNED_SELECTED_IMAGE_PACKAGE_AND_SOURCE'): reader.observe()

    def test_signed_member_bytes_cannot_be_replaced_by_an_equal_delivery_manifest_hash(self):
        reader, _, package, records, _, seal = self.prepared()
        path = package/'semantic/package-record.json'; original = path.read_bytes()
        path.write_bytes(b'{}')
        with self.assertRaises((ValueError, Denied)): reader.observe()
        self.assertEqual(path.read_bytes(), b'{}')
        path.write_bytes(original); records['semantic']['files'].pop('package-record.json'); seal()
        with self.assertRaisesRegex(ValueError, 'SIGNED_IMAGE_PACKAGE_RECORD_MEMBER_REQUIRED'): reader.observe()

    def test_resealed_producer_record_must_match_image_identity_user_scan_and_authority(self):
        for field, value in (('schema', 'ouf.chatbot-file-module-package.v1'), ('module', 'onboarding'),
            ('sourceCommit', 'b'*40), ('imageId', 'sha256:'+'b'*64), ('runtimeUser', '0:0'),
            ('artifactFormat', 'host declaration'), ('imageScanGate', 'UNSCANNED'),
            ('notReleaseAcceptance', False), ('signatureIssued', True), ('targetApplyAuthorized', True),
            ('vpsOperations', False)):
            with self.subTest(field=field):
                reader, _, package, records, _, seal = self.prepared(); path = package/'mcp/package-record.json'
                raw = m.decode(path.read_bytes()); raw[field] = value; path.write_bytes(encoded(raw))
                records['mcp']['files']['package-record.json'] = hashlib.sha256(path.read_bytes()).hexdigest(); seal()
                with self.assertRaisesRegex(ValueError, 'SIGNED_IMAGE_PRODUCER_PACKAGE_RECORD'): reader.observe()

    def test_publisher_revocation_stops_before_membership_reads(self):
        reader, _, _, _, _, _ = self.prepared(); reader.publisher.observe.side_effect = ValueError('PUBLISHER_REVOKED')
        reader.databases.sources = Mock(side_effect=AssertionError('NO_MEMBERSHIP_AFTER_REVOCATION'))
        with self.assertRaisesRegex(ValueError, 'PUBLISHER_REVOKED'): reader.observe()
        reader.databases.sources.assert_not_called()

    def test_identical_archive_replacement_while_the_original_descriptor_is_open_is_denied(self):
        reader, _, package, _, _, _ = self.prepared(); path = package/'semantic'/'image.docker.tar'
        with self.assertRaisesRegex(ValueError, 'SOURCE_FILE_CHANGED_DURING_READ'):
            with m.stable_source(path, 2147483648, m.ObservationBudget(30)) as stream:
                raw = stream.read(); path.rename(path.with_suffix('.retained'))
                path.write_bytes(raw); path.chmod(0o600)
        self.assertEqual(path.read_bytes(), raw)

    def test_checksum_duplicates_traversal_and_absolute_names_deny(self):
        for names in (['a', 'a'], ['../not-read'], ['/not-read']):
            raw = ''.join('a'*64+'  '+name+'\n' for name in names).encode()
            with self.subTest(names=names), self.assertRaises(ValueError): m.checksum_map(raw)


if __name__ == '__main__': unittest.main()
