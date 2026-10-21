"""Real ZIP/TAR and root-private filesystem, explicitly synthetic package data.

The layout mirrors scripts/assemble-file-cohort.py and the final upload-artifact
step: six module directories, module checksums, aggregate checksums and a retained
Sigstore bundle. PASS strings below are parser fixtures, never scanner results or
publisher signature proof. No Docker, executable, target or provider is invoked.
"""
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import sys
import tarfile
import tempfile
import unittest
import warnings
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT/'tools/semantic_policy_token_owner')]
from tools.chatbot_file_cohort import package_custody as c
from tools.chatbot_file_cohort.plan import PlanDenied, digest
from tools.semantic_lease_recovery.bounded_recovery import Permanent

PRODUCER = 'c'*40
RUN_ID = 20261014
SCAN_FIXTURE = 'PASS_HIGH_CRITICAL_UNKNOWN_INCLUDING_UNFIXED'
REPOSITORIES = {'semantic':'ouf-semantic-registry', 'onboarding':'ouf-source-onboarding',
    'ingestion':'ouf-ingestion-runtime', 'udp':'ouf-udp-object-resolution',
    'mcp':'ouf-mcp-server', 'gateway':'ouf-api-gateway'}


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    # The actual producer writes sorted, indented JSON with a final newline.
    return (json.dumps(value, sort_keys=True, indent=2)+'\n').encode()


def source_tar(entries=None):
    """Uncompressed git-archive layout, including explicit directory entries."""
    entries = entries or [('README.md', b'explicit synthetic source\n', tarfile.REGTYPE),
        ('src/', b'', tarfile.DIRTYPE), ('src/nested/', b'', tarfile.DIRTYPE),
        ('src/nested/module.py', b'raise RuntimeError("MUST_NEVER_EXECUTE")\n', tarfile.REGTYPE)]
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode='w', format=tarfile.PAX_FORMAT) as archive:
        for name, raw, kind in entries:
            row = tarfile.TarInfo(name); row.type = kind; row.mode = 0o755 if kind == tarfile.DIRTYPE else 0o644
            if kind in (tarfile.SYMTYPE, tarfile.LNKTYPE): row.linkname = '../outside'
            row.size = len(raw) if kind == tarfile.REGTYPE else 0
            archive.addfile(row, io.BytesIO(raw) if row.isfile() else None)
    return output.getvalue()


def synthetic_parts():
    """Accurate producer inputs; every qualification value is a test fixture."""
    lock = {'schema':'ouf.chatbot-file-cohort-source-lock.v1', 'cohortId':'SYNTHETIC-NOT-RELEASE',
        'modules':[{'module':name, 'repository':repo, 'commit':sha(name.encode())[:40],
            'kind':'SOURCE_AND_ROUTE_PACKAGE' if name == 'gateway' else 'DOCKER_SAVE'}
            for name, repo in REPOSITORIES.items()],
        'semanticRuntimeProfile':{'springProfilesActive':'file-first', 'providerInputsRequired':False},
        'composedQualification':{'environment':'SYNTHETIC_PARSER_FIXTURE', 'targetVpsAcceptance':False},
        'targetApplyAuthorized':False, 'runtimeAuthorityIssued':False, 'notReleaseAcceptance':True}
    lock_raw = encoded(lock)
    parts = {}
    for selected in lock['modules']:
        name = selected['module']
        record = {'schema':'ouf.chatbot-file-module-package.v1', 'module':name,
            'repository':'GioNob/'+selected['repository'], 'sourceCommit':selected['commit'],
            'artifactKind':selected['kind'], 'cohortSourceLockSha256':sha(lock_raw),
            'scanGate':SCAN_FIXTURE, 'imageId':None if name == 'gateway' else 'sha256:'+sha(name.encode()),
            'targetApplyAuthorized':False, 'runtimeAuthorityIssued':False, 'notReleaseAcceptance':True,
            'signatureIssued':False, 'vpsOperations':0, 'r12Touched':False, 'budgetReset':False}
        members = {'candidate-manifest.json':encoded(record), 'source.tar':source_tar(),
            'source-inventory.json':encoded({'truncated':False, 'tree':[]}),
            'trivy-image.json':encoded({'explicitSyntheticFixture':True, 'actualScanExecuted':False})}
        if name == 'gateway':
            members.update({'routes.file-loop.json':b'[]\n', 'compiled-route-declarations.json':b'{}\n',
                'gateway-scan/requirements.txt':b'# synthetic package parser fixture\n'})
        else:
            members.update({'image.docker.tar':b'SYNTHETIC IMAGE BYTES; NOT LOADED',
                'package-record.json':encoded({'explicitSyntheticFixture':True}),
                'ouf-mcp' if name == 'mcp' else 'application.jar':b'SYNTHETIC; NOT EXECUTED'})
        if name == 'semantic':
            members['package-record.pre-export.json'] = encoded({'explicitSyntheticFixture':True})
            members['independent-rootfs-seal.json'] = encoded({'imageId':record['imageId'],
                'sourceCommit':selected['commit'], 'javaStarted':False, 'targetAcceptance':False,
                'packageRecordHash':sha(members['package-record.pre-export.json'])})
            members['file-first-four-mount-boot.json'] = encoded({'imageId':record['imageId'],
                'status':'DISPOSABLE_BOOT_PASSED', 'mountCount':4, 'providerEnabled':False,
                'discoveryWorkerEnabled':False, 'explicitSyntheticFixture':True})
        files = {path:sha(raw) for path, raw in sorted(members.items())}
        members['SHA256SUMS'] = ''.join(hashed+'  '+path+'\n' for path, hashed in files.items()).encode()
        parts[name] = (members, {**record, 'files':files})
    return lock, lock_raw, parts


def cohort_members():
    lock, lock_raw, parts = synthetic_parts()
    manifest = {'schema':'ouf.chatbot-file-cohort-package.v1', 'cohortId':lock['cohortId'],
        'sourceLockSha256':sha(lock_raw), 'modules':[record for _, record in parts.values()],
        'producer':{'repository':'GioNob/ouf-deploy', 'workflow':'semantic-proposal-candidate-package.yml',
            'sourceCommit':PRODUCER, 'runId':str(RUN_ID), 'runAttempt':'1'},
        'semanticRuntimeProfile':lock['semanticRuntimeProfile'], 'composedQualification':lock['composedQualification'],
        'targetApplyAuthorized':False, 'runtimeAuthorityIssued':False, 'notReleaseAcceptance':True,
        'fullChatbotProductionAcceptanceProven':False, 'vpsOperations':0, 'r12Touched':False, 'budgetReset':False}
    members = {name+'/'+path:raw for name, (files, _) in parts.items() for path, raw in files.items()}
    members.update({'cohort-manifest.json':encoded(manifest), 'source-lock.json':lock_raw})
    return members, manifest


class PackageCustodyTest(unittest.TestCase):
    def setUp(self):
        self.assertEqual(os.geteuid(), 0, 'native root-custody fixture required')
        self.tmp = tempfile.TemporaryDirectory(dir=ROOT, prefix='package-custody-fixture-')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name); self.root.chmod(0o700)
        self.members, self.manifest = cohort_members()
        self.serial = 0

    def directory(self):
        self.serial += 1
        path = self.root/('private-'+str(self.serial)); path.mkdir(mode=0o700)
        return path

    def archive(self, members=None, extras=(), checksums=None):
        members = copy.deepcopy(self.members if members is None else members)
        sums = ''.join(sha(raw)+'  '+name+'\n' for name, raw in sorted(members.items())).encode()
        members['COHORT_SHA256SUMS'] = sums if checksums is None else checksums
        members['COHORT_SHA256SUMS.sigstore.json'] = encoded({'explicitSyntheticFixture':True,
            'signatureVerified':False, 'actualPublisherAttestation':False})
        self.serial += 1; path = self.root/('delivered-'+str(self.serial)+'.zip')
        with warnings.catch_warnings():
            warnings.simplefilter('ignore', UserWarning)  # Deliberate duplicate ZIP members below.
            with zipfile.ZipFile(path, 'w', compression=zipfile.ZIP_STORED) as archive:
                for name, raw in members.items(): archive.writestr(name, raw)
                for name, raw in extras: archive.writestr(name, raw)
        return path, sha(path.read_bytes())

    def extract(self, archive=None, destination=None, producer=PRODUCER, run=RUN_ID):
        path, hashed = archive or self.archive()
        return c.extract_cohort(path, hashed, producer, run, destination or self.directory())

    def test_real_six_module_zip_and_nested_tar_preserve_bytes_private_custody_and_non_acceptance(self):
        path, hashed = self.archive(); destination = self.directory()
        package, manifest, receipt = self.extract((path, hashed), destination)
        self.assertEqual(manifest, self.manifest)
        self.assertEqual(sha((destination/'cohort.zip').read_bytes()), hashed)
        self.assertEqual(receipt['cohortManifestHash'], digest(manifest))
        self.assertTrue(receipt['publisherSignatureRetained'])
        self.assertFalse(receipt['publisherSignatureLocallyVerified'])
        self.assertFalse(receipt['targetApplyAuthorized'])
        for name, raw in self.members.items(): self.assertEqual((package/name).read_bytes(), raw)
        for record in manifest['modules']:
            source = self.directory(); self.assertEqual(c.extract_source(package, record, source), str(source))
            self.assertEqual((source/'src/nested/module.py').read_bytes(), b'raise RuntimeError("MUST_NEVER_EXECUTE")\n')
        for root in (destination, *(p for p in self.root.iterdir() if p.is_dir())):
            for member in (root, *root.rglob('*')):
                info = member.lstat()
                self.assertEqual((info.st_uid, info.st_gid), (0, 0))
                self.assertEqual(stat.S_IMODE(info.st_mode), 0o700 if member.is_dir() else 0o600)
                self.assertFalse(member.is_symlink())

    def test_wrong_outer_hash_denies_before_zip_parsing(self):
        path, _ = self.archive(); target = self.directory()
        with self.assertRaisesRegex(PlanDenied, 'PRIVATE_PACKAGE_MEMBER_HASH_MISMATCH'):
            self.extract((path, '0'*64), target)
        self.assertFalse((target/'package').exists())

    def test_member_tampering_is_denied_even_when_outer_archive_hash_is_current(self):
        sums = ''.join(sha(raw)+'  '+name+'\n' for name, raw in sorted(self.members.items())).encode()
        self.members['mcp/ouf-mcp'] += b'TAMPERED'
        with self.assertRaisesRegex(PlanDenied, 'PRIVATE_PACKAGE_MEMBER_HASH_MISMATCH'):
            self.extract(self.archive(checksums=sums))

    def test_producer_run_source_lock_and_module_qualification_remain_exact(self):
        for field in ('producer', 'run', 'source-lock', 'source-pin', 'scan', 'duplicate-module'):
            with self.subTest(field=field):
                members = copy.deepcopy(self.members); manifest = copy.deepcopy(self.manifest)
                if field == 'source-lock': members['source-lock.json'] += b'\n'
                if field == 'source-pin': manifest['modules'][0]['sourceCommit'] = 'f'*40
                if field == 'scan': manifest['modules'][0]['scanGate'] = 'NOT_SCANNED'
                if field == 'duplicate-module': manifest['modules'][-1] = copy.deepcopy(manifest['modules'][0])
                members['cohort-manifest.json'] = encoded(manifest)
                with self.assertRaises(PlanDenied):
                    self.extract(self.archive(members), producer='d'*40 if field == 'producer' else PRODUCER,
                                 run=RUN_ID+1 if field == 'run' else RUN_ID)

    def test_duplicate_checksums_and_unlisted_members_are_denied(self):
        sums = ''.join(sha(raw)+'  '+name+'\n' for name, raw in sorted(self.members.items())).encode()
        with self.assertRaisesRegex(PlanDenied, 'DUPLICATE_COHORT_CHECKSUM'):
            self.extract(self.archive(checksums=sums+sums.splitlines(keepends=True)[0]))
        with self.assertRaisesRegex(PlanDenied, 'COMPLETE_COHORT_CHECKSUM_CLOSURE_REQUIRED'):
            self.extract(self.archive(extras=[('unlisted.txt', b'not covered')]))

    def test_zip_traversal_noncanonical_duplicate_and_symlink_entries_are_denied(self):
        for name in ('../outside', '/outside', 'gateway/../outside', 'gateway//extra', './extra'):
            with self.subTest(name=name):
                with self.assertRaisesRegex(PlanDenied, 'EXACT_RELATIVE_PACKAGE_MEMBER_REQUIRED'):
                    self.extract(self.archive(extras=[(name, b'not extracted')]))
        with self.assertRaisesRegex(PlanDenied, 'EXACT_BOUNDED_COHORT_MEMBER_SET_REQUIRED'):
            self.extract(self.archive(extras=[('mcp/source.tar', b'duplicate')]))
        link = zipfile.ZipInfo('link'); link.create_system = 3
        link.external_attr = (stat.S_IFLNK | 0o777) << 16
        with self.assertRaisesRegex(PlanDenied, 'EXACT_BOUNDED_COHORT_MEMBER_SET_REQUIRED'):
            self.extract(self.archive(extras=[(link, b'../outside')]))
        self.assertFalse((self.root/'outside').exists())

    def test_source_archive_changed_after_private_extraction_is_denied(self):
        package, manifest, _ = self.extract(); record = manifest['modules'][0]
        source = package/record['module']/'source.tar'; source.write_bytes(source.read_bytes()+b'drift')
        destination = self.directory()
        with self.assertRaisesRegex(PlanDenied, 'AUTHENTICATED_MODULE_SOURCE_REQUIRED'):
            c.extract_source(package, record, destination)
        self.assertEqual(list(destination.iterdir()), [])

    def test_exact_gateway_systemd_template_names_are_regular_source_files_only(self):
        # These two names occur in the immutable packaged Gateway Git tree
        # bf179e96200deb84942ad32507edef52a4284cd0. Contents are parser fixtures.
        package, manifest, _ = self.extract()
        record = next(row for row in manifest['modules'] if row['module'] == 'gateway')
        names = ['ops/policy_token/ouf-policy-token@.service', 'ops/policy_token/ouf-policy-token@.timer']
        raw = source_tar([('ops/', b'', tarfile.DIRTYPE), ('ops/policy_token/', b'', tarfile.DIRTYPE)]
            + [(name, b'SYNTHETIC SOURCE; NEVER INSTALLED\n', tarfile.REGTYPE) for name in names])
        (package/'gateway/source.tar').write_bytes(raw); record['files']['source.tar'] = sha(raw)
        destination = self.directory(); c.extract_source(package, record, destination)
        for name in names:
            self.assertEqual((destination/name).read_bytes(), b'SYNTHETIC SOURCE; NEVER INSTALLED\n')
            self.assertEqual(stat.S_IMODE((destination/name).stat().st_mode), 0o600)
        # The artifact/checksum namespace and directory grammar do not widen.
        with self.assertRaisesRegex(PlanDenied, 'EXACT_RELATIVE_PACKAGE_MEMBER_REQUIRED'):
            self.extract(self.archive(extras=[('gateway/extra@.service', b'not a source member')]))
        for name in ('ops/template@', '../escape@.service', 'ops//extra@.service', '/extra@.service'):
            with self.subTest(name=name):
                kind = tarfile.DIRTYPE if name == 'ops/template@' else tarfile.REGTYPE
                raw = source_tar([(name, b'not extracted', kind)])
                (package/'gateway/source.tar').write_bytes(raw); record['files']['source.tar'] = sha(raw)
                with self.assertRaisesRegex(PlanDenied, 'EXACT_RELATIVE_PACKAGE_MEMBER_REQUIRED'):
                    c.extract_source(package, record, self.directory())

    def test_hash_valid_tar_traversal_links_and_duplicate_members_are_denied(self):
        entries = [[('../outside', b'no', tarfile.REGTYPE)], [('/outside', b'no', tarfile.REGTYPE)],
            [('link', b'', tarfile.SYMTYPE)], [('link', b'', tarfile.LNKTYPE)],
            [('pipe', b'', tarfile.FIFOTYPE)], [('same', b'a', tarfile.REGTYPE), ('same', b'b', tarfile.REGTYPE)]]
        for rows in entries:
            with self.subTest(rows=[(r[0], r[2]) for r in rows]):
                package, manifest, _ = self.extract(); record = manifest['modules'][0]
                raw = source_tar(rows); (package/record['module']/'source.tar').write_bytes(raw)
                record['files']['source.tar'] = sha(raw)  # Authenticated malformed source fixture.
                with self.assertRaises(PlanDenied): c.extract_source(package, record, self.directory())
        self.assertFalse((self.root/'outside').exists())

    def test_unsafe_destination_or_archive_symlink_denies_without_following(self):
        path, hashed = self.archive(); target = self.directory(); target.chmod(0o770)
        with self.assertRaises(Permanent): self.extract((path, hashed), target)
        target.chmod(0o700)
        link = self.root/'archive-link.zip'; link.symlink_to(path)
        with self.assertRaises(OSError): self.extract((link, hashed), self.directory())
        self.assertFalse((target/'cohort.zip').exists())

    def test_second_extraction_cannot_replace_existing_private_files(self):
        archive = self.archive(); target = self.directory(); self.extract(archive, target)
        before = (target/'cohort.zip').read_bytes()
        with self.assertRaises(FileExistsError): self.extract(archive, target)
        self.assertEqual((target/'cohort.zip').read_bytes(), before)
        package, manifest, _ = self.extract(); source = self.directory()
        prior = source/'README.md'; prior.write_bytes(b'protected prior bytes'); prior.chmod(0o600)
        with self.assertRaises(FileExistsError): c.extract_source(package, manifest['modules'][0], source)
        self.assertEqual(prior.read_bytes(), b'protected prior bytes')


if __name__ == '__main__':
    unittest.main()
