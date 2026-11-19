"""Link reviewed migration sources and selected image archives to signed bytes.

The parent must already select a publisher subject with role cohortChecksums.
The authenticated checksum subject selects the manifest/source lock and members;
there is no caller-selected package path, extraction or new review authority.
This proves the named two images/four migration sources, not every runtime file.
"""
import hashlib, os, re, tarfile
from contextlib import contextmanager
from pathlib import Path
from .custody_capture import decode, digest, require
from .current_publisher import CurrentPublisherCustody
from .current_databases import CurrentCohortDatabases
from .cohort_images import DiscoveryImages
from .node_owner import ObservationBudget
from tools.chatbot_file_cohort.images import private_open
from tools.semantic_registry_operational_owner.guard import protected_file
from tools.semantic_provider_deployment_authentication import attributes
from image_custody import archive, unbound_audit

ROLE = 'cohortChecksums'
MODULES = {'semantic', 'onboarding', 'ingestion', 'udp', 'gateway', 'mcp'}
PREFIX = 'internal/adapter/postgres/migrations/'


def relative(name):
    require(type(name) is str and re.fullmatch(r'[A-Za-z0-9_.@/-]+', name)
        and not name.startswith('/') and str(Path(name)) == name and '..' not in Path(name).parts
        and len(Path(name).parts) <= 32, 'EXACT_AUTHENTICATED_MEMBERSHIP_NAME_REQUIRED')
    return name


def checksum_map(raw):
    require(type(raw) is bytes and 0 < len(raw) <= 131072, 'BOUNDED_SIGNED_MEMBERSHIP_CHECKSUMS_REQUIRED')
    result = {}
    for line in raw.decode('ascii').splitlines():
        match = re.fullmatch(r'([a-f0-9]{64})  (.+)', line)
        require(match is not None, 'EXACT_MEMBERSHIP_CHECKSUM_LINE_REQUIRED')
        name = relative(match[2]); require(name not in result, 'DUPLICATE_MEMBERSHIP_CHECKSUM_DENIED')
        result[name] = match[1]
    require(1 <= len(result) <= 256, 'BOUNDED_UNIQUE_MEMBERSHIP_CHECKSUM_SET_REQUIRED')
    return result


class BudgetStream:
    def __init__(self, stream, budget): self.stream, self.budget = stream, budget
    def read(self, size=-1):
        self.budget.check(); result = self.stream.read(size); self.budget.check(); return result
    def __getattr__(self, name): return getattr(self.stream, name)


@contextmanager
def stable_source(path, maximum, budget):
    with private_open(path, maximum) as stream:
        before = attributes(os.fstat(stream.fileno()))
        require(attributes(Path(path).lstat()) == before, 'MEMBERSHIP_SOURCE_FILE_REPLACED')
        yield BudgetStream(stream, budget)
        require(attributes(os.fstat(stream.fileno())) == before == attributes(Path(path).lstat()),
            'MEMBERSHIP_SOURCE_FILE_CHANGED_DURING_READ')


class CurrentArtifactMembership:
    def __init__(self, publisher, databases, images):
        require(type(publisher) is CurrentPublisherCustody and type(databases) is CurrentCohortDatabases
            and type(images) is DiscoveryImages, 'ACTUAL_PUBLISHER_DATABASE_AND_IMAGE_OWNERS_FOR_MEMBERSHIP_REQUIRED')
        self.publisher, self.databases, self.images = publisher, databases, images
        self.ids = tuple(map(id, (publisher, databases, images)))
        self.guard()

    def guard(self):
        p, d, i = self.publisher, self.databases, self.images
        require(self.ids == tuple(map(id, (p, d, i))) and d.runtime.selected.images is i
            and p.parent is d.runtime.parent is i.parent and p.runtime_inputs == d.runtime.inputs
            and p.runtime_inputs['cohortManifestHash'] == i.plan['cohortManifestHash'],
            'SAME_PARENT_REVIEW_AND_NATIVE_MEMBERSHIP_OWNERS_REQUIRED')
        p.guard(); d.guard(); i.guard()
        rows = [row for row in p.inputs['artifacts'] if row['role'] == ROLE]
        require(len(rows) == 1 and Path(rows[0]['subject']['path']).name == 'COHORT_SHA256SUMS',
            'ONE_EXPLICIT_PARENT_REVIEWED_COHORT_CHECKSUM_PUBLISHER_REQUIRED')
        return rows[0]

    def manifest(self, row, budget):
        ref = row['subject']; root = Path(ref['path']).parent
        sums = protected_file(ref['path'], min(131072, ref['maximumBytes']), expected=ref['sha256'],
            modes=(0o400, 0o440, 0o600, 0o644)); declared = checksum_map(sums)
        def metadata(name):
            require(name in declared, 'SIGNED_COHORT_METADATA_MEMBERSHIP_REQUIRED')
            budget.check(); raw = protected_file(root/name, 8388608, expected=declared[name],
                modes=(0o400, 0o440, 0o600, 0o644)); budget.check(); return decode(raw)
        manifest = metadata('cohort-manifest.json'); lock = metadata('source-lock.json')
        require(manifest.get('schema') == 'ouf.chatbot-file-cohort-package.v1'
            and digest(manifest) == self.publisher.runtime_inputs['cohortManifestHash']
            and manifest.get('sourceLockSha256') == declared['source-lock.json']
            and manifest.get('producer', {}).get('sourceCommit') == row['sourceCommit']
            and manifest.get('runtimeAuthorityIssued') is manifest.get('targetApplyAuthorized') is False,
            'EXACT_PARENT_BOUND_SIGNED_COHORT_MANIFEST_AND_PRODUCER_REQUIRED')
        records = {v['module']: v for v in manifest['modules']}
        require(len(manifest['modules']) == len(lock['modules']) == 6 and set(records) == MODULES
            and {v['module']: v['commit'] for v in lock['modules']} ==
                {name: record['sourceCommit'] for name, record in records.items()},
            'EXACT_SIX_MODULE_SOURCE_LOCKED_MEMBERSHIP_REQUIRED')
        for module, record in records.items():
            require(record.get('cohortSourceLockSha256') == manifest['sourceLockSha256']
                and record.get('scanGate') == 'PASS_HIGH_CRITICAL_UNKNOWN_INCLUDING_UNFIXED'
                and type(record.get('files')) is dict and 1 <= len(record['files']) <= 128
                and all(declared.get(module+'/'+relative(name)) == sha for name, sha in record['files'].items()),
                'SIGNED_MODULE_MEMBER_CHECKSUM_OR_SCAN_BINDING_DIFFERS')
        return root, records, digest({'manifest': manifest, 'sourceLock': lock, 'checksums': declared})

    def mcp_sources(self, root, record, db, budget):
        expected = {str(Path(ref['path']).relative_to(db['artifact']['root'])): ref['sha256']
            for ref in db['artifact']['files']}
        require('source.tar' in record['files'], 'SIGNED_MCP_SOURCE_ARCHIVE_REQUIRED')
        path = root/'mcp'/'source.tar'; expected_archive = record['files']['source.tar']
        found = {}; seen = set(); total = 0
        with stable_source(path, 268435456, budget) as stream:
            h = hashlib.sha256()
            while block := stream.read(1048576): h.update(block)
            require(h.hexdigest() == expected_archive, 'SIGNED_MCP_SOURCE_ARCHIVE_BYTES_DIFFER')
            stream.seek(0)
            with tarfile.open(fileobj=stream, mode='r:') as tar:
                for member in tar:
                    name = relative(member.name.rstrip('/')); budget.check()
                    require(name not in seen and len(seen) < 20000 and (member.isdir() or member.isfile()),
                        'UNIQUE_REGULAR_MCP_SOURCE_MEMBERS_REQUIRED'); seen.add(name)
                    total += member.size
                    require(0 <= member.size <= 33554432 and total <= 268435456, 'BOUNDED_MCP_SOURCE_CONTENT_REQUIRED')
                    if member.isfile() and name.startswith(PREFIX):
                        require(name in expected and 0 < member.size <= 1048576,
                            'EXACT_MCP_MIGRATION_MEMBER_SET_REQUIRED')
                        with tar.extractfile(member) as content:
                            found[name] = hashlib.sha256(content.read(1048577)).hexdigest()
            require(found == expected, 'MCP_MIGRATIONS_DIFFER_FROM_SIGNED_SOURCE_MEMBERS')
        return digest(found)

    def image_package(self, root, record, audit, budget):
        # Delivery manifests and the image producer's package-record.json are
        # distinct documents. The MCP planner binds the latter's canonical
        # digest; authenticate those actual signed member bytes here too.
        expected = record['files'].get('package-record.json')
        require(expected is not None, 'SIGNED_IMAGE_PACKAGE_RECORD_MEMBER_REQUIRED')
        budget.check()
        package = decode(protected_file(root/record['module']/'package-record.json', 1048576,
            expected=expected, modes=(0o400, 0o440, 0o600, 0o644)))
        budget.check()
        require(type(package) is dict and package.get('schema') == 'ouf.unsigned-offline-candidate-package.v1'
            and package.get('module') == record['module']
            and package.get('sourceCommit') == record['sourceCommit'] == audit['sourceCommit']
            and package.get('imageId') == record['imageId'] == audit['imageId']
            and package.get('runtimeUser') == audit['imageConfig'].get('User')
            and package.get('artifactFormat') == 'DOCKER_SAVE_OFFLINE_ARCHIVE_NOT_HOST_OCI_DECLARATION'
            and package.get('imageScanGate') == record['scanGate']
            and package.get('notReleaseAcceptance') is True
            and package.get('signatureIssued') is package.get('targetApplyAuthorized') is False
            and type(package.get('vpsOperations')) is int and package['vpsOperations'] == 0,
            'EXACT_SIGNED_IMAGE_PRODUCER_PACKAGE_RECORD_REQUIRED')
        return digest(package)

    def observe(self):
        budget = ObservationBudget(180); row = self.guard(); held = self.databases.runtime.selected.held()
        publisher = self.publisher.observe(); root, records, manifest_hash = self.manifest(row, budget)
        sources = self.databases.sources(budget); membership = {}
        for db in self.databases.inputs['modules']:
            name = db['module']; record = records[name]
            if name == 'mcp': membership[name] = self.mcp_sources(root, record, db, budget)
            else:
                require(record['files'].get('application.jar') == db['artifact']['files'][0]['sha256'],
                    'REVIEWED_MIGRATION_JAR_IS_NOT_A_SIGNED_PACKAGE_MEMBER')
                membership[name] = db['artifact']['files'][0]['sha256']
        images = {}; packages = {}
        for selected in self.images.plan['images']:
            name = selected['module']; record = records[name]; audit = selected['audit']
            packages[name] = self.image_package(root, record, audit, budget)
            require(selected['modulePackageHash'] == packages[name]
                and selected['originalArchiveSha256'] == record['files'].get('image.docker.tar')
                and record['sourceCommit'] == audit['sourceCommit'] and record['imageId'] == audit['imageId'],
                'EXACT_SIGNED_SELECTED_IMAGE_PACKAGE_AND_SOURCE_REQUIRED')
            with stable_source(root/name/'image.docker.tar', 2147483648, budget) as original:
                archive(original, selected['originalArchiveSha256'], record['imageId'], record['sourceCommit'])
            with stable_source(selected['archivePath'], 2147483648, budget) as derived:
                observed = archive(derived, audit['archiveSha256'], audit['imageId'], audit['sourceCommit'])
                require(observed == unbound_audit(audit), 'CURRENT_DERIVED_IMAGE_ARCHIVE_MEMBERSHIP_CHANGED')
            images[name] = digest(audit)
        require(self.guard() == row and self.manifest(row, budget)[2] == manifest_hash
            and {v['module']: self.image_package(root, records[v['module']], v['audit'], budget)
                for v in self.images.plan['images']} == packages
            and self.databases.sources(budget) == sources and self.publisher.observe() == publisher,
            'SIGNED_ARTIFACT_MEMBERSHIP_CHANGED_DURING_NATIVE_READ')
        self.databases.runtime.selected.held(held); budget.check()
        return {'schema': 'ouf.discovery-current-artifact-membership-witness.v1',
            'heldHistoryHash': digest(held), 'nativeRuntimeInputsHash': self.publisher.runtime_hash,
            'publisherEvidenceHash': digest(publisher), 'signedManifestEvidenceHash': manifest_hash,
            'migrationMembershipHash': digest(membership), 'imageMembershipHash': digest(images),
            'migrationModuleCount': 4, 'selectedImageCount': 2,
            'selectedImageAndMigrationMembershipProven': True, 'allRuntimeArtifactMembershipProven': False,
            'completePrivateCustodyProven': False, 'actualWorkloadBearerAdmissionProven': False,
            'fullCohortProven': False, 'runtimeAuthorityIssued': False, 'targetApplyAuthorized': False,
            'nativeMutationDispatched': False, 'releaseAcceptance': False}
