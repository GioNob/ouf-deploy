"""Actual installed observer/TLS/source/signatures; disposable IAM and unit fence.

The fixture's one token grant is setup only. The recovery constructor must make
no grant, introspection, credential read, worker launch or journal mutation.
"""
import copy,json,sys,unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parent))
from test_current_admission import file_profile
import test_installed_token_owner as owner_fixture
from tools.semantic_policy_token_owner.installed_owner import LegacyWriterFence
from tools.semantic_policy_token_owner.producer import RenewalOperation,CredentialFile
from tools.semantic_lease_recovery.bounded_recovery import Permanent
from tools.semantic_registry_recovery_composition.compose import candidate_contract,GATES
from tools.semantic_registry_recovery_execution import core as c,authorization as a,installed_owner as r

class InstalledObserver(unittest.TestCase):
    def setUp(self):
        self.f,self.server,self.owner,self.recovery,_,_=owner_fixture.InstalledOwnerTest.fixture(self,scheduled=True)
        fence=patch.object(LegacyWriterFence,'guard',return_value=True);fence.start();self.addCleanup(fence.stop)
        RenewalOperation(self.recovery).step()
        before=self.owner.journal.read()
        self.owner.journal.compare_and_save(before,{**before,'bootId':Path('/proc/sys/kernel/random/boot_id').read_text().strip()})
        self.plan=candidate_contract({'registry':{'containerId':'a'*64},'requiredGates':list(GATES),
            'unresolvedGateCount':8},'b'*64,self.f.expected['predecessorIncidentRef'])
        self.manifest_path=self.f.root/'selected-manifest.json'
        self.f.write(self.manifest_path,c.encoded(self.owner.manifest))
        self.reference={'schema':'ouf.semantic-registry-retained-installed-owner-reference.v1',
            'configuration':json.loads(c.encoded(self.owner.configuration)),
            'manifest':file_profile(self.manifest_path)}
        self.trust=self.server.context()
        trust=patch('ssl.create_default_context',return_value=self.trust);trust.start();self.addCleanup(trust.stop)
        self.resign()

    def resign(self,extra=None):
        self.raw=json.loads(self.f.authority)
        self.raw.update(semanticRegistryRecovery=a.scope(self.plan),
            semanticRegistryRecoveryInstalledOwner=r.owner_scope(self.plan,self.reference),**(extra or {}))
        self.f.authority=c.encoded(self.raw)
        self.f.approval.update(executionAuthorityHash=__import__('hashlib').sha256(self.f.authority).hexdigest())
        self.f.write(self.f.mandate,c.encoded(self.f.approval))
        self.f.approved=__import__('hashlib').sha256(self.f.mandate.read_bytes()).hexdigest()
        for role in self.f.grant['roles']:self.f.sign(role)
        self.authority=self.f.gate()

    def build(self):return r.build_observer(self.plan,self.reference,self.authority,self.f.authority)

    def test_reconstructs_same_active_owner_without_credential_network_or_writes(self):
        before=self.owner.journal.read();marker=self.owner.store.read();calls=list(self.server.calls)
        with patch.object(CredentialFile,'read',side_effect=AssertionError('credential construction read')):
            observer=self.build()
        self.assertTrue(observer.observer);self.assertEqual(observer.profile_hash,self.owner.profile_hash)
        self.assertEqual(observer.journal.read(),before);self.assertEqual(observer.store.read(),marker)
        self.assertEqual(self.server.calls,calls)

    def test_parked_or_revoked_owner_stops_without_wait_grant_or_reactivation(self):
        self.owner.pause();before=self.owner.journal.read();marker=self.owner.store.read();calls=list(self.server.calls)
        with self.assertRaises(Permanent):self.build()
        self.assertEqual(self.owner.journal.read(),before);self.assertEqual(self.owner.store.read(),marker)
        self.assertEqual(self.server.calls,calls)

    def test_selected_reference_cannot_be_replaced_by_another_journal(self):
        self.reference['configuration']['journalPath']=str(self.f.root/'another-owner')
        with self.assertRaisesRegex(c.RecoveryDenied,'SIGNED_CURRENT_INSTALLED_OWNER'):self.build()
        self.assertFalse((self.f.root/'another-owner').exists())

    def test_signed_changed_journal_identity_cannot_adopt_existing_manifest(self):
        self.reference['configuration']['journalDirectoryIdentity']['inode']+=1;self.resign()
        with self.assertRaisesRegex(c.RecoveryDenied,'MANIFEST_MUST_BIND_SAME'):self.build()

    def test_source_manifest_drift_is_refused_without_fallback(self):
        self.manifest_path.write_bytes(b'{}')
        with self.assertRaises(Exception):self.build()
        self.assertEqual(self.owner.journal.read()['attempts'],1)

    def test_expired_token_or_previous_boot_is_not_an_active_recovery_lease(self):
        before=self.owner.journal.read();calls=list(self.server.calls)
        for changed in ({'tokenExpiresWall':0},{'tokenExpiresMonotonic':0},{'bootId':'old-boot'}):
            row=self.owner.journal.read();self.owner.journal.compare_and_save(row,{**before,**changed})
            with self.subTest(changed=changed),self.assertRaisesRegex(c.RecoveryDenied,'UNEXPIRED_RETAINED_TOKEN'):self.build()
        self.assertEqual(self.server.calls,calls);self.assertEqual(self.owner.journal.read()['attempts'],1)

    def test_tls_trust_drift_is_refused_before_any_request(self):
        calls=list(self.server.calls)
        with patch.object(r.PinnedIamOpener,'trust_digest',return_value='f'*64):
            with self.assertRaisesRegex(c.RecoveryDenied,'TLS_TRUST_CHANGED'):self.build()
        self.assertEqual(self.server.calls,calls)

    def test_unfenced_legacy_writer_is_not_an_active_owner(self):
        calls=list(self.server.calls)
        with patch.object(LegacyWriterFence,'guard',side_effect=Permanent('INTEGRITY_UNPROVEN')):
            with self.assertRaises(Permanent):self.build()
        self.assertEqual(self.server.calls,calls)

if __name__=='__main__':unittest.main()
