"""Actual profile/signature/file publication; runtime native facts synthetic."""
import copy,sys,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tests')]
import test_m2_provider_profiles as profiles
from tools.m2_discovery_installation_profile import provider_profile_publication as m

class Publication(unittest.TestCase):
    def fixture(self):
        case=profiles.Profiles();issuer,w,auth,state,calls,*_=case.fixture();self.addCleanup(case.doCleanups)
        return m.ProviderProfilePublication(issuer),w,auth,state,calls
    def test_publish_exact_initial_v4_profiles_without_changing_previous_configuration(self):
        owner,w,auth,state,calls=self.fixture();prior=Path(owner.scope['priorRuntimeConfigurationBinding']['path']);before=prior.read_bytes(),prior.stat().st_mtime_ns
        with w.peer_window():
            owner.creation.create_once();owner.issuer.issue_once();owner.apply()
            outcome,proof=owner.observe();self.assertEqual(outcome,'APPLIED');self.assertTrue(proof['exactInitialLedgerReadback'])
            self.assertFalse(proof['runtimeSwitchOrStartPerformed'])
            material=owner.material();self.assertEqual(m.private_json(Path(material['root'])/'adapter.json')['state'],'STAGED')
            self.assertEqual(m.private_json(Path(material['root'])/'deployment.json')['state'],'STAGED')
            self.assertEqual(m.private_json(Path(material['root'])/'broker.json')['schema'],'ouf.semantic-deployment-broker.v1')
            with self.assertRaises(FileExistsError):owner.apply()
        self.assertEqual(before,(prior.read_bytes(),prior.stat().st_mtime_ns))
        self.assertEqual(sum(method=='POST' for method,_,_ in calls),1)
    def test_partial_write_is_preserved_without_adoption_or_republication(self):
        owner,w,auth,*_=self.fixture();real=m.new_file
        with w.peer_window():
            owner.creation.create_once();owner.issuer.issue_once()
            def partial(parent,name,raw,mode=0o600):
                if name=='broker.json':real(parent,name,raw[:11],mode);raise OSError('CI_PARTIAL_PROFILE_WRITE')
                return real(parent,name,raw,mode)
            with patch.object(m,'new_file',side_effect=partial),self.assertRaises(OSError):owner.apply()
            self.assertEqual(owner.observe()[0],'UNKNOWN')
            with self.assertRaises(FileExistsError):owner.apply()
    def test_preexisting_candidate_directory_is_not_overwritten(self):
        owner,w,auth,*_=self.fixture()
        with w.peer_window():
            owner.creation.create_once();owner.issuer.issue_once();root=Path(owner.material()['root']);root.mkdir(mode=0o700)
            old=root/'keep.json';auth.write(old,b'KEEP_EXISTING_SCOPE')
            with self.assertRaisesRegex(ValueError,'EXISTING_PROVIDER_PROFILE_DIRECTORY'):owner.apply()
            self.assertEqual(old.read_bytes(),b'KEEP_EXISTING_SCOPE')
    def test_complete_lost_response_is_read_only_reconciled(self):
        owner,w,auth,*_=self.fixture();real=m.new_file
        with w.peer_window():
            owner.creation.create_once();owner.issuer.issue_once()
            def lost(parent,name,raw,mode=0o600):
                if name=='publication-complete.json':raise TimeoutError('CI_LOST_COMPLETION')
                return real(parent,name,raw,mode)
            with patch.object(m,'new_file',side_effect=lost),self.assertRaises(TimeoutError):owner.apply()
            with patch.object(m,'new_file',side_effect=AssertionError('READ_ONLY_OBSERVATION')):
                self.assertEqual(owner.observe()[0],'APPLIED')
            self.assertEqual(owner.observe(initial=False)[0],'APPLIED')
    def test_running_journals_are_not_reinitialized_or_demanded_to_equal_staged(self):
        owner,w,auth,*_=self.fixture()
        with w.peer_window():
            owner.creation.create_once();owner.issuer.issue_once();owner.apply();root=Path(owner.material()['root'])
            for name in m.MUTABLE_INITIAL:
                p=root/name;replacement=p.with_name(name+'.next');auth.write(replacement,m.encoded({'state':'STARTED','attempts':7}));replacement.replace(p)
            (root/'bundle').mkdir(mode=0o700)
            self.assertEqual(owner.observe(initial=False)[0],'APPLIED')
            with self.assertRaises((ValueError,RuntimeError)):owner.observe(initial=True)
            self.assertEqual(m.private_json(root/'deployment.json')['attempts'],7)

if __name__=='__main__':unittest.main()
