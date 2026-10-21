"""Mapping consistency only; five owner callbacks and authority remain synthetic."""
import sys,tempfile,unittest,types
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT/'tests'),str(ROOT/'tools/semantic_application_cutover')]
import test_core_adapter_factory as core_fixture
from core_adapter_factory import configure_owned_core
from r12_retirement_adapter import R12RetirementChannel,R12RetirementAdapter
from native_evidence_store import NativeEvidenceStore

class OwnedFactory(unittest.TestCase):
    def fixture(self):
        request,intents,owners,t,admin,calls=core_fixture.CoreFactory.fixture(self);del owners['STOP_REVOKE_OLD_LEASE']
        c=R12RetirementChannel.__new__(R12RetirementChannel);c.scope={'authorizationBinding':{'sha256':'9'*64}};c.scope_hash='a'*64;c.capture_history_hash='c'*64;c.capture={'r12-authorization.json':{'incidentRef':'d'*64}}
        intents['STOP_REVOKE_OLD_LEASE']={'scopeHash':c.scope_hash,'stopTimeoutSeconds':55}
        read=t.read;t.read=lambda:{**read(),'predecessorHistoryHash':'c'*64,'predecessorIncidentRef':'d'*64}
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup);root=Path(temp.name);root.chmod(0o700)
        before=root/'before';before.mkdir(mode=0o700);store=root/'store';store.mkdir(mode=0o700)
        return request,intents,owners,t,admin,calls,c,NativeEvidenceStore(before),NativeEvidenceStore(store)
    def test_binds_real_retirement_and_seven_core_phases_without_effects(self):
        request,intents,owners,t,admin,calls,c,before,store=self.fixture()
        a=configure_owned_core(None,t,request,store,admin,intents,owners,lambda point:None,c,before)
        self.assertIs(type(a['STOP_REVOKE_OLD_LEASE']),R12RetirementAdapter);self.assertEqual(len(a),13);self.assertEqual(calls,[])
    def test_missing_owner_changed_history_or_fake_channel_denies_before_effects(self):
        for drift in ('missing','history','channel'):
            request,intents,owners,t,admin,calls,c,before,store=self.fixture()
            if drift=='missing':del owners[next(iter(owners))]
            if drift=='history':c.capture_history_hash='f'*64
            if drift=='channel':c=types.SimpleNamespace(**c.__dict__)
            with self.assertRaises(ValueError):configure_owned_core(None,t,request,store,admin,intents,owners,lambda point:None,c,before)
            self.assertEqual(calls,[])

    def test_gate_request_cannot_use_plain_unpause_factory(self):
        from gated_creation_plan import ENTRY
        request,intents,owners,t,admin,calls,c,before,store=self.fixture();request['Entrypoint']=ENTRY
        # Existing request hashes must be recompiled; a new launch is never an
        # approval alias for the previous private plan or ordinary release.
        from transition_journal import digest
        old_read=t.read;t.read=lambda:{**old_read(),'creationRequestHash':digest(request)}
        with self.assertRaisesRegex(ValueError,'EXPLICIT_GATED_STAGE_AND_RELEASE'):
            configure_owned_core(None,t,request,store,admin,intents,owners,lambda point:None,c,before)
        self.assertEqual(calls,[])

if __name__=='__main__':unittest.main()
