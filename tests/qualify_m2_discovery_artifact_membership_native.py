"""Real offline Sigstore + parent Ed25519 + archive/migration membership.

Only disposable CI package bytes are attested. Engine/other admission guards
remain modeled; this does not admit any target/runtime cohort or execute it.
"""
import copy, hashlib, json, os, shutil, sys, unittest
from pathlib import Path
from unittest.mock import Mock
ROOT = Path(__file__).resolve().parents[1]; sys.path[:0] = [str(ROOT), str(ROOT/'tests')]
import test_m2_discovery_artifact_membership as membership_fixture
import test_m2_discovery_current_publisher as publisher_fixture
from tools.m2_discovery_installation_profile import artifact_membership as m
from tools.m2_discovery_installation_profile import current_publisher as publisher_module


def prepare(output, source_commit):
    require = m.require
    require(len(source_commit) == 40 and all(c in '0123456789abcdef' for c in source_commit),
        'EXACT_DISPOSABLE_CI_PRODUCER_COMMIT_REQUIRED')
    output = Path(output); output.mkdir(mode=0o700)
    case = membership_fixture.Membership()
    try:
        reader, root, package, records, _, seal = case.prepared()
        # The subject's producer must equal the workflow certificate source.
        reader.publisher.inputs['artifacts'][0]['sourceCommit'] = source_commit
        original_manifest = m.decode((package/'cohort-manifest.json').read_bytes())
        original_manifest['producer']['sourceCommit'] = source_commit
        raw_manifest = membership_fixture.encoded(original_manifest)
        (package/'cohort-manifest.json').write_bytes(raw_manifest)
        sums = m.checksum_map((package/'COHORT_SHA256SUMS').read_bytes())
        sums['cohort-manifest.json'] = hashlib.sha256(raw_manifest).hexdigest()
        (package/'COHORT_SHA256SUMS').write_bytes(''.join(sha+'  '+name+'\n' for name, sha in sorted(sums.items())).encode())
        reader.images.plan['cohortManifestHash'] = m.digest(original_manifest)
        state = {'originalRoot': str(root), 'cohortManifestHash': m.digest(original_manifest),
            'databaseInputs': reader.databases.inputs, 'imagePlan': reader.images.plan}
        shutil.copytree(root, output/'material')
        (output/'state.json').write_bytes(membership_fixture.encoded(state))
    finally: case.doCleanups()


def relocate(value, previous, current):
    if type(value) is dict: return {k: relocate(v, previous, current) for k, v in value.items()}
    if type(value) is list: return [relocate(v, previous, current) for v in value]
    if type(value) is str and (value == previous or value.startswith(previous+'/')):
        return current+value[len(previous):]
    return value


class NativeMembership(unittest.TestCase):
    def prepared(self, wrong_id=False):
        if os.geteuid() != 0 or os.environ.get('GITHUB_ACTIONS') != 'true':
            raise AssertionError('DISPOSABLE_HOSTED_MEMBERSHIP_CI_ONLY')
        case = publisher_fixture.Publisher(); case.setUp(); self.addCleanup(case.doCleanups)
        old, _, _ = case.prepared(); fixture = Path(os.environ['OUF_MEMBERSHIP_FIXTURE_ROOT'])
        original_state = m.decode((fixture/'state.json').read_bytes())
        state = relocate(original_state, original_state['originalRoot'], str(fixture/'material'))
        inputs = copy.deepcopy(old.inputs); row = inputs['artifacts'][0]
        inputs['cohortManifestHash'] = state['cohortManifestHash']; row['role'] = m.ROLE
        row['subject'] = publisher_fixture.ref(fixture/'material/package/COHORT_SHA256SUMS', 131072)
        row['bundle'] = publisher_fixture.ref(fixture/'bundle.json', 8388608)
        inputs['trustedRoot'] = publisher_fixture.ref(fixture.parent/'trusted-root.jsonl', 1048576)
        inputs['ghExecutable'] = publisher_fixture.ref(Path(os.environ['OUF_GH_PUBLISHER_BINARY']), 134217728)
        row.update(repository=os.environ['OUF_GITHUB_REPOSITORY'], repositoryId=os.environ['OUF_GITHUB_REPOSITORY_ID'],
            ownerId=os.environ['OUF_GITHUB_OWNER_ID'], sourceRef=os.environ['OUF_GITHUB_SOURCE_REF'],
            sourceCommit=os.environ['OUF_GITHUB_SOURCE_SHA'], signerCommit=os.environ['OUF_GITHUB_SIGNER_SHA'],
            workflowPath=os.environ['OUF_GITHUB_PUBLISHER_WORKFLOW_PATH'])
        if wrong_id: row['repositoryId'] = '1'
        runtime = copy.deepcopy(old.runtime_inputs); runtime.pop('additionalInputsHashes')
        runtime['schema'] = publisher_fixture.cohort.m.INPUT_SCHEMA; runtime['cohortManifestHash'] = state['cohortManifestHash']
        runtime = publisher_module.bind_publisher_inputs(runtime, inputs); review = copy.deepcopy(case.review)
        component = review['components']['cohortInstallation']
        component['currentAdmission'] = copy.deepcopy(component['currentAdmission']['requirements'])
        component['currentAdmission']['cohortManifestHash'] = state['cohortManifestHash']
        case.review = publisher_fixture.cohort.m.bind_runtime_review(review, runtime); parent = case.authority(seconds=300)
        publisher = publisher_module.CurrentPublisherCustody(parent, runtime, inputs)
        images = object.__new__(m.DiscoveryImages); images.parent = parent; images.plan = state['imagePlan']
        images.guard = lambda: parent.guard('cohortInstallation', parent.review['components']['cohortInstallation'])
        current = publisher_fixture.cohort.m.CurrentCohortRuntime.__new__(publisher_fixture.cohort.m.CurrentCohortRuntime)
        current.parent = parent; current.inputs = runtime
        selected = membership_fixture.SimpleNamespace(images=images)
        held = {'state': 'READY', 'nextPhase': 12, 'version': 42}
        def snapshot(expected=None):
            if expected is not None and expected != held: raise ValueError('HELD_HISTORY_CHANGED')
            return copy.deepcopy(held)
        selected.held = snapshot; current.selected = selected
        databases = object.__new__(m.CurrentCohortDatabases); databases.runtime = current
        databases.inputs = state['databaseInputs']; databases.guard = images.guard
        return m.CurrentArtifactMembership(publisher, databases, images)

    def test_real_signed_subject_parent_and_named_image_migration_membership_join_offline(self):
        reader = self.prepared(); result = reader.observe()
        self.assertTrue(result['selectedImageAndMigrationMembershipProven'])
        self.assertTrue(reader.publisher.observe()['selectedArtifactPublisherCryptographyVerified'])
        self.assertFalse(result['allRuntimeArtifactMembershipProven']); self.assertFalse(result['fullCohortProven'])
        self.assertFalse(result['runtimeAuthorityIssued']); self.assertFalse(result['targetApplyAuthorized'])

    def test_actual_signature_cannot_override_wrong_repository_identity_before_membership(self):
        reader = self.prepared(wrong_id=True)
        reader.databases.sources = Mock(side_effect=AssertionError('NO_MEMBERSHIP_ON_WRONG_PUBLISHER'))
        with self.assertRaisesRegex(ValueError, 'CERTIFICATE_IDENTITY'): reader.observe()
        reader.databases.sources.assert_not_called()

    def test_current_dual_role_parent_revocation_blocks_valid_publisher_and_membership(self):
        reader = self.prepared(); parent = reader.publisher.parent
        (parent.verifier.signature_directory/(parent.sha+'.FINAL_DEPLOYMENT_APPROVAL.json')).unlink()
        with self.assertRaises((OSError, ValueError)): reader.observe()


if __name__ == '__main__':
    if len(sys.argv) == 4 and sys.argv[1] == '--prepare': prepare(sys.argv[2], sys.argv[3])
    else: unittest.main()
