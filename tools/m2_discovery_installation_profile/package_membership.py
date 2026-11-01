"""All six signed module deliveries and five original image archives.

Reuse the already reviewed cohort checksum subject and its concrete membership
owner. No new input, inferred publisher, extraction, import or authority. This
closes package bytes/selected image identity, not every live private mount,
third-party image, Gateway executable or workload bearer admission.
"""
import hashlib, os, stat
from pathlib import Path
from .artifact_membership import CurrentArtifactMembership, MODULES, checksum_map, relative, stable_source
from .custody_capture import digest, require
from .current_cohort import CurrentCohortRuntime
from .node_owner import ObservationBudget
from tools.semantic_registry_operational_owner.guard import protected_file
from tools.semantic_provider_deployment_authentication import attributes
from image_custody import archive

IMAGES = MODULES - {'gateway'}
MAXIMUM_BYTES = 6 * 1024 ** 3


class CurrentPackageMembership:
    def __init__(self, membership):
        require(type(membership) is CurrentArtifactMembership
            and type(membership.databases.runtime) is CurrentCohortRuntime,
            'ACTUAL_NAMED_MEMBERSHIP_AND_CURRENT_RUNTIME_FOR_COMPLETE_PACKAGE_REQUIRED')
        self.membership = membership
        self.runtime = membership.databases.runtime
        self.ids = (id(membership), id(self.runtime))
        self.guard()

    def guard(self):
        m, r = self.membership, self.runtime
        require(self.ids == (id(m), id(r)) and type(m) is CurrentArtifactMembership
            and type(r) is CurrentCohortRuntime and m.databases.runtime is r,
            'SAME_EXACT_CURRENT_PACKAGE_MEMBERSHIP_OWNERS_REQUIRED')
        r.guard()
        return m.guard()

    def inventory(self, root, allowed, budget):
        """Bounded exact tree; no link, device, extra directory or mutable file."""
        directories = {Path('.')}
        for name in allowed:
            path = Path(relative(name))
            directories.update(path.parents)
        seen, pins = set(), {}
        pending = [root]
        while pending:
            folder = pending.pop(); budget.check()
            info = folder.lstat(); name = folder.relative_to(root)
            require(name in directories and stat.S_ISDIR(info.st_mode) and info.st_uid == 0
                and stat.S_IMODE(info.st_mode) in (0o700, 0o750, 0o755),
                'EXACT_PROTECTED_PACKAGE_DIRECTORY_REQUIRED')
            pins[str(name)] = attributes(info)
            with os.scandir(folder) as entries:
                for entry in entries:
                    budget.check(); path = Path(entry.path); name = path.relative_to(root).as_posix()
                    relative(name); info = entry.stat(follow_symlinks=False)
                    require(len(seen) < 512 and name not in seen, 'BOUNDED_UNIQUE_PACKAGE_TREE_REQUIRED')
                    seen.add(name)
                    if stat.S_ISDIR(info.st_mode):
                        require(Path(name) in directories, 'UNDECLARED_PACKAGE_DIRECTORY_DENIED')
                        pending.append(path)
                    else:
                        require(name in allowed and stat.S_ISREG(info.st_mode) and info.st_uid == 0
                            and info.st_nlink == 1 and 0 < info.st_size <= 2147483648
                            and stat.S_IMODE(info.st_mode) in (0o400, 0o440, 0o600, 0o644),
                            'EXACT_SIGNED_REGULAR_PACKAGE_FILE_SET_REQUIRED')
                        pins[name] = attributes(info)
        require({name for name in seen if Path(name) not in directories} == allowed,
            'COMPLETE_SIGNED_PACKAGE_FILE_SET_REQUIRED')
        return pins

    def observe(self):
        budget = ObservationBudget(180); row = self.guard(); m = self.membership
        held = self.runtime.selected.held(); publisher = m.publisher.observe()
        named = m.observe(); root, records, manifest_hash = m.manifest(row, budget)
        ref = row['subject']
        declared = checksum_map(protected_file(ref['path'], min(131072, ref['maximumBytes']),
            expected=ref['sha256'], modes=(0o400, 0o440, 0o600, 0o644)))
        expected = {'cohort-manifest.json', 'source-lock.json'}
        for name, record in records.items():
            expected.update(name+'/'+relative(member) for member in record['files'])
            expected.add(name+'/SHA256SUMS')
            require(record.get('artifactKind') == ('SOURCE_AND_ROUTE_PACKAGE' if name == 'gateway' else 'DOCKER_SAVE'),
                'EXACT_FIVE_IMAGE_AND_ONE_GATEWAY_PACKAGE_KINDS_REQUIRED')
        require(set(declared) == expected, 'EXACT_SIX_MODULE_SIGNED_CHECKSUM_CLOSURE_REQUIRED')
        allowed = set(declared) | {Path(ref['path']).name}
        bundle = Path(row['bundle']['path'])
        if bundle.is_relative_to(root): allowed.add(relative(bundle.relative_to(root).as_posix()))
        before = self.inventory(root, allowed, budget); total = 0
        hashes = {}
        for name, expected_sha in sorted(declared.items()):
            with stable_source(root/name, 2147483648, budget) as stream:
                h = hashlib.sha256()
                while chunk := stream.read(1048576):
                    total += len(chunk); require(total <= MAXIMUM_BYTES, 'BOUNDED_COMPLETE_PACKAGE_BYTES_REQUIRED')
                    h.update(chunk)
                require(h.hexdigest() == expected_sha, 'SIGNED_COMPLETE_PACKAGE_MEMBER_BYTES_DIFFER')
                hashes[name] = expected_sha
        # Each module checksum file must close exactly its declared payloads;
        # the outer signature alone must not conceal a mixed module inventory.
        for name, record in records.items():
            raw = protected_file(root/name/'SHA256SUMS', 131072,
                expected=declared[name+'/SHA256SUMS'], modes=(0o400, 0o440, 0o600, 0o644))
            require(checksum_map(raw) == record['files'], 'EXACT_SIGNED_MODULE_CHECKSUM_CLOSURE_REQUIRED')
        selected = {v['module']: v['audit']['imageId'] for v in m.images.plan['images']}
        identities = {name: (selected[name] if name in selected else
            self.runtime.inputs['peers'][name]['runtimeBinding']['imageId']) for name in IMAGES}
        images = {}
        for name in sorted(IMAGES):
            record = records[name]
            require(record.get('imageId') == identities[name] and 'image.docker.tar' in record['files'],
                'SIGNED_PACKAGE_IMAGE_MUST_MATCH_SAME_REVIEWED_CURRENT_COHORT_ROLE')
            with stable_source(root/name/'image.docker.tar', 2147483648, budget) as stream:
                proof = archive(stream, record['files']['image.docker.tar'], identities[name], record['sourceCommit'])
            images[name] = digest(proof)
        require(self.inventory(root, allowed, budget) == before and self.guard() == row
            and m.manifest(row, budget)[2] == manifest_hash and m.publisher.observe() == publisher,
            'COMPLETE_SIGNED_PACKAGE_OR_PARENT_CHANGED_DURING_READ')
        self.runtime.selected.held(held); budget.check()
        return {'schema': 'ouf.discovery-current-six-module-package-membership.v1',
            'heldHistoryHash': digest(held), 'nativeRuntimeInputsHash': self.runtime.input_hash,
            'publisherEvidenceHash': digest(publisher), 'namedMembershipEvidenceHash': digest(named),
            'signedManifestEvidenceHash': manifest_hash, 'packageMembersHash': digest(hashes),
            'packageFilePinsHash': digest(before), 'imageMembershipHash': digest(images),
            'moduleCount': 6, 'originalImageCount': 5, 'signedMemberCount': len(declared),
            'sixModulePackageBytesProven': True, 'fiveReviewedModuleImageIdentitiesProven': True,
            'allRuntimeArtifactMembershipProven': False, 'completePrivateCustodyProven': False,
            'actualWorkloadBearerAdmissionProven': False, 'fullCohortProven': False,
            'nativeMutationDispatched': False, 'runtimeAuthorityIssued': False,
            'targetApplyAuthorized': False, 'releaseAcceptance': False}
