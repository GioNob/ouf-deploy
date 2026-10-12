"""Real crypto/root custody/atomic publication; synthetic HUMAN decisions only."""
import json,os,sys,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'tests'),str(ROOT/'tools/semantic_application_cutover'),str(ROOT/'tools/semantic_cohort_admission/cohort-draft')]
import tools
tools.__path__.append(str(ROOT/'tools'))
from test_cutover_authority_native import SignedCutover,encoded,sha
from tools.semantic_policy_token_owner.source_stage import declaration,ProtectedTokenSourceStage
from tools.semantic_lease_recovery.bounded_recovery import fingerprint

class SourceStage(unittest.TestCase):
    def fixture(self):
        f=SignedCutover();f.setUp();self.addCleanup(f.doCleanups)
        destination=f.root/'protected-code';destination.mkdir(mode=0o700)
        marker=f.root/'MUST_NOT_EXIST'
        files={'producer.py':('from pathlib import Path\nPath('+repr(str(marker))+').write_text("EXECUTED")\n').encode()}
        info=destination.stat();directory_identity={'device':info.st_dev,'inode':info.st_ino}
        manifest=declaration(str(destination),'a'*40,files,directory_identity=directory_identity)
        f.expected['sourceClosureHash']=fingerprint(manifest)
        value=json.loads(f.authority);value['sourceClosureHash']=f.expected['sourceClosureHash'];f.authority=encoded(value)
        f.approval.update(sourceClosureHash=f.expected['sourceClosureHash'],executionAuthorityHash=sha(f.authority))
        f.write(f.mandate,encoded(f.approval));f.approved=sha(f.mandate.read_bytes())
        for role in f.grant['roles']:f.sign(role)
        stage=ProtectedTokenSourceStage(manifest,files,f.gate(),f.authority)
        return f,destination,marker,files,manifest,stage
    def test_real_signed_stage_is_atomic_private_and_does_not_execute_sources(self):
        f,d,marker,files,m,stage=self.fixture();result=stage.stage()
        self.assertFalse(marker.exists());self.assertTrue(result['publicationIsAtomic'])
        final=Path(result['directory']);self.assertEqual(final.stat().st_mode&0o777,0o700)
        self.assertEqual((final/'producer.py').stat().st_mode&0o777,0o600)
        self.assertEqual((final/'producer.py').read_bytes(),files['producer.py'])
        second=ProtectedTokenSourceStage(m,files,f.gate(),f.authority).stage()
        self.assertEqual(second['protectedFileWrites'],0);self.assertFalse(second['newPublication'])
        self.assertFalse(result['runtimeRegistered']);self.assertFalse(result['productionApplyReady'])
    def test_missing_final_signature_denies_before_protected_writes(self):
        f,d,marker,files,m,stage=self.fixture()
        (f.signatures/(sha(f.authority)+'.FINAL_DEPLOYMENT_APPROVAL.json')).unlink()
        with self.assertRaises(Exception):stage.stage()
        self.assertEqual(list(d.iterdir()),[]);self.assertFalse(marker.exists())
    def test_source_bytes_destination_and_unsigned_manifest_changes_are_denied(self):
        f,d,marker,files,m,stage=self.fixture();stage.files['producer.py']=b'print("unapproved")'
        with self.assertRaisesRegex(ValueError,'SOURCE_STAGE_BYTES'):stage.stage()
        self.assertEqual(list(d.iterdir()),[])
        other=declaration(str(f.root),'a'*40,files,directory_identity=m['directoryIdentity'])
        with self.assertRaisesRegex(ValueError,'SOURCE_AND_DESTINATION_CLOSURE'):
            ProtectedTokenSourceStage(other,files,f.gate(),f.authority)
    def test_revocation_before_atomic_publication_leaves_only_private_incomplete_stage(self):
        f,d,marker,files,m,stage=self.fixture()
        def revoke(point):
            if point=='BEFORE_ATOMIC_PUBLICATION':
                f.approval['state']='REVOKED';f.write(f.mandate,encoded(f.approval))
        with self.assertRaises(Exception):stage.stage(revoke)
        children=list(d.iterdir());self.assertEqual(len(children),2)
        staged=[p for p in children if p.is_dir()][0]
        self.assertTrue(staged.name.startswith('.semantic-native-v11-intake-staging-'))
        self.assertEqual(staged.stat().st_mode&0o777,0o700)
    def test_publication_checkpoint_gap_reconciles_exact_existing_bytes_without_rewrite(self):
        f,d,marker,files,m,stage=self.fixture()
        def gap(point):
            if point=='AFTER_ATOMIC_PUBLICATION':raise RuntimeError('FIXTURE_INTERRUPTION')
        with self.assertRaises(RuntimeError):stage.stage(gap)
        result=ProtectedTokenSourceStage(m,files,f.gate(),f.authority).stage()
        self.assertFalse(result['newPublication']);self.assertEqual(result['protectedFileWrites'],0)
    def test_unprotected_parent_symlink_and_foreign_final_are_not_repaired(self):
        f,d,marker,files,m,stage=self.fixture();d.chmod(0o770)
        with self.assertRaises(Exception):stage.stage()
        self.assertEqual(d.stat().st_mode&0o777,0o770);d.chmod(0o700)
        final=d/('semantic-native-v11-intake-'+fingerprint(m));final.mkdir(mode=0o700)
        with self.assertRaises(Exception):stage.stage()
        self.assertEqual(list(final.iterdir()),[])
    def test_noop_authority_unknown_files_and_credential_slot_are_denied(self):
        f,d,marker,files,m,stage=self.fixture()
        with self.assertRaisesRegex(ValueError,'DUAL_ROLE_AUTHORITY'):
            ProtectedTokenSourceStage(m,files,lambda raw:True,f.authority)
        with self.assertRaises(ValueError):declaration(str(d),'a'*40,{'credential':b'FIXTURE'},directory_identity=m['directoryIdentity'])
        with self.assertRaises(ValueError):declaration(str(d),'a'*40,{'../producer.py':b'pass'},directory_identity=m['directoryIdentity'])

    def test_incomplete_attempt_cannot_be_bypassed_by_a_new_stage_object(self):
        f,d,marker,files,m,stage=self.fixture()
        def gap(point):
            if point=='BEFORE_ATOMIC_PUBLICATION':raise RuntimeError('FIXTURE_INTERRUPTION')
        with self.assertRaises(RuntimeError):stage.stage(gap)
        before=sorted(p.name for p in d.iterdir())
        with self.assertRaisesRegex(ValueError,'INTERRUPTED_SOURCE_STAGE_RECONCILIATION'):
            ProtectedTokenSourceStage(m,files,f.gate(),f.authority).stage()
        self.assertEqual(before,sorted(p.name for p in d.iterdir()))

if __name__=='__main__':unittest.main()
