"""Real role signatures/custody/TLS/journal; synthetic HUMAN and legacy-unit fixture."""
import hashlib
import json
import os
from pathlib import Path
import sys
import time
import unittest
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'tests'),str(ROOT/'tools/semantic_application_cutover'),str(ROOT/'tools/semantic_cohort_admission/cohort-draft')]
from test_cutover_authority_native import SignedCutover,encoded,sha
import tools
tools.__path__.append(str(ROOT/'tools'))
from test_iam_token_admission import Fixture
from tools.semantic_policy_token_owner.producer import Binding,CredentialFile,HttpsGrant,TokenRenewalAdapter,RenewalOperation
from tools.semantic_policy_token_owner.iam_admission import OnlineIamAdmission,PinnedIamOpener
from tools.semantic_policy_token_owner.installed_owner import InstalledTokenOwner,AdmissionStore,LegacyWriterFence,owner_binding
from tools.semantic_policy_token_owner.source_stage import declaration,ProtectedTokenSourceStage,FILES
from tools.semantic_lease_recovery.bounded_recovery import Recovery,Policy,Permanent,fingerprint
from tools.semantic_lease_recovery.recovery_journal import Journal

class InstalledOwnerTest(unittest.TestCase):
    def fixture(self,*,scheduled=False):
        f=SignedCutover();f.setUp();self.addCleanup(f.doCleanups)
        server=Fixture(f.root);self.addCleanup(server.close)
        credential=f.root/'credential';credential.write_text('DISPOSABLE_FIXTURE_SECRET');credential.chmod(0o400)
        output=f.root/'output';output.mkdir(mode=0o750)
        try:os.chown(output,0,10001)
        except OSError:
            if os.environ.get('OUF_NATIVE_UIDS')=='1':raise
            self.skipTest('Native group10001 custody requires the mandatory hosted-root fixture')
        state=f.root/'state';state.mkdir(mode=0o700);journal=Journal(state)
        clock=lambda:(time.time(),time.monotonic());policy=Policy();context='1'*64;generation='2'*64
        wall,mono=clock()
        journal.initialize({'schema':'ouf.bounded-recovery.v1','contextRef':context,'generationRef':generation,'policyHash':fingerprint(policy.__dict__),'state':'NEW','attempts':0,'startedWall':wall,'startedMonotonic':mono,'lastWall':wall,'lastMonotonic':mono,'nextWall':None,'nextMonotonic':None,'reason':'NONE'})
        if scheduled:
            from tools.semantic_policy_token_owner.supervisor import ScheduledRecovery
            row=journal.read();journal.compare_and_save(row,{**row,'renewalProfile':ScheduledRecovery.PROFILE,'intervalSeconds':60,'publicationCount':0,'nextRenewalWall':None,'nextRenewalMonotonic':None,'tokenExpiresWall':None,'tokenExpiresMonotonic':None})
        binding=Binding(server.profile.token_endpoint,server.profile.client_id,'authorization.bundle.read',str(output),'token.jwt',10001)
        secret=CredentialFile(credential);transport=PinnedIamOpener(server.profile,clock,server.context());admission=OnlineIamAdmission(server.profile,secret,transport,clock)
        profile=fingerprint(owner_binding(binding,secret,admission,journal,context,generation))
        marker={'schema':'ouf.policy-token-owner-admission.v1','ownerProfileHash':profile,'contextRef':context,'generationRef':generation,'version':0,'state':'BLOCKED','tokenHash':None,'blockedAttempt':None}
        (state/'owner-admission.json').write_bytes(encoded(marker));(state/'owner-admission.json').chmod(0o600)
        sources={
            'bounded-recovery.py':ROOT/'tools/semantic_lease_recovery/bounded_recovery.py',
            'recovery-journal.py':ROOT/'tools/semantic_lease_recovery/recovery_journal.py',
            **{name:ROOT/'tools/semantic_policy_token_owner'/name.replace('-','_') for name in ('producer.py','supervisor.py','mount-observation.py','source-stage.py','installed-owner.py','iam-admission.py','worker-entry.py','reporter.py')}}
        files={name:path.read_bytes() for name,path in sources.items()}
        self.assertEqual(set(files),FILES)
        destination=f.root/'source';destination.mkdir(mode=0o700);s=destination.stat()
        manifest=declaration(str(destination),'a'*40,files,directory_identity={'device':s.st_dev,'inode':s.st_ino},owner_binding_hash=profile)
        f.expected['sourceClosureHash']=fingerprint(manifest)
        authority=json.loads(f.authority);authority.update(sourceClosureHash=f.expected['sourceClosureHash'],tokenOwnerRuntime={'ownerBindingHash':profile,'operation':'RENEW_EXISTING_POLICY_READ_CREDENTIAL','legacyWriterMustBeMasked':True,'credentialReestablishmentRequired':True,'automaticBudgetResetAllowed':False})
        f.authority=encoded(authority);f.approval.update(sourceClosureHash=f.expected['sourceClosureHash'],executionAuthorityHash=sha(f.authority))
        f.write(f.mandate,encoded(f.approval));f.approved=sha(f.mandate.read_bytes())
        for role in f.grant['roles']:f.sign(role)
        result=ProtectedTokenSourceStage(manifest,files,f.gate(),f.authority).stage()
        owner=InstalledTokenOwner(binding,secret,admission,journal,context,generation,manifest,f.gate(),f.authority)
        adapter=TokenRenewalAdapter(binding,secret,owner,HttpsGrant(clock,opener=transport),clock)
        recovery=Recovery(journal,adapter,policy,context,generation,clock,lambda:.5)
        return f,server,owner,recovery,Path(result['directory']),output
    def test_source_authority_and_online_iam_complete_one_retained_owner_operation(self):
        f,server,owner,recovery,source,out=self.fixture()
        with patch.object(LegacyWriterFence,'guard',return_value=True):
            row=RenewalOperation(recovery).step();self.assertEqual(row['state'],'ACTIVE');self.assertEqual(row['attempts'],1)
            self.assertEqual((out/'token.jwt').read_text(),'FIXTURE_TOKEN')
            self.assertEqual(owner.store.read()['state'],'ACTIVE')
            self.assertEqual(sum(p.endswith('/token') for p,_ in server.calls),1)
            # A fresh process reconstructs the owner and reads the same counters.
            reader=InstalledTokenOwner(owner.binding,owner.credential,owner.admission,owner.journal,owner.context,owner.generation,owner.manifest,f.gate(),f.authority,observer=True)
            before=reader.store.read();reader.admit('FIXTURE_TOKEN',time.monotonic()+200,owner.binding.digest(),time.monotonic()+10)
            self.assertEqual(reader.store.read(),before);self.assertEqual(owner.journal.read()['attempts'],1)
    def test_pause_is_durable_deduplicated_and_stale_response_cannot_reactivate(self):
        f,server,owner,recovery,source,out=self.fixture()
        with patch.object(LegacyWriterFence,'guard',return_value=True):
            row=owner.journal.read();owner.journal.compare_and_save(row,{**row,'state':'PUBLISHING','attempts':1})
            before=owner.store.read();server.after=owner.pause
            with self.assertRaises(Permanent):owner.admit('FIXTURE_TOKEN',time.monotonic()+200,owner.binding.digest(),time.monotonic()+10)
            # If already BLOCKED the safe pause is intentionally idempotent, so
            # first admit alone cannot restore authority on an ambiguous replay.
            self.assertEqual(owner.store.read()['state'],'BLOCKED')
            version=owner.store.read()['version'];owner.pause();owner.pause();self.assertEqual(owner.store.read()['version'],version)
    def test_expired_or_changed_human_source_and_unfenced_legacy_writer_deny_before_grant(self):
        for case in ('human','source','writer'):
            with self.subTest(case=case):
                f,server,owner,recovery,source,out=self.fixture()
                if case=='human':f.approval['state']='REVOKED';f.write(f.mandate,encoded(f.approval))
                if case=='source':(source/'producer.py').write_bytes(b'print("UNAPPROVED")')
                with patch.object(LegacyWriterFence,'guard',side_effect=Permanent('INTEGRITY_UNPROVEN') if case=='writer' else None,return_value=True):
                    self.assertEqual(RenewalOperation(recovery).step()['state'],'BLOCKED')
                self.assertEqual(server.calls,[]);self.assertFalse((out/'token.jwt').exists())
    def test_revocation_after_grant_blocks_further_grants_without_replay(self):
        f,server,owner,recovery,source,out=self.fixture();server.body_mode='inactive'
        with patch.object(LegacyWriterFence,'guard',return_value=True):
            # Only introspection is inactive; the grant response remains valid.
            server.active=lambda:{'active':False};server.body_mode=None
            first=RenewalOperation(recovery).step();self.assertEqual(first['state'],'BLOCKED')
            count=len(server.calls);second=RenewalOperation(recovery).step();self.assertEqual(second['state'],'BLOCKED')
            self.assertEqual(len(server.calls),count);self.assertFalse((out/'token.jwt').exists());self.assertEqual(owner.store.read()['state'],'BLOCKED')
    def test_missing_existing_marker_and_changed_context_cannot_invent_new_admission(self):
        f,server,owner,recovery,source,out=self.fixture()
        marker=owner.journal.root/'owner-admission.json';marker.unlink()
        with self.assertRaises(FileNotFoundError):AdmissionStore(owner.journal,owner.profile_hash,owner.context,owner.generation)
        self.assertFalse(marker.exists());self.assertEqual(server.calls,[])
    def test_scope_and_partial_package_cannot_reuse_a_valid_stage_signature(self):
        f,server,owner,recovery,source,out=self.fixture();changed=json.loads(f.authority);changed.pop('tokenOwnerRuntime')
        with self.assertRaises(Permanent):InstalledTokenOwner(owner.binding,owner.credential,owner.admission,owner.journal,owner.context,owner.generation,owner.manifest,f.gate(),encoded(changed))
        self.assertEqual(server.calls,[])

if __name__=='__main__':unittest.main()
