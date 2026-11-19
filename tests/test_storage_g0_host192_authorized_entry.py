import importlib.util,json,os,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
import test_storage_g0_package as fixture
import test_storage_g0_host_profile as profile
from tools.storage_planning import g0_package as p

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('authorized_entry',ROOT/'scripts/execute-storage-g0-host192-authorized-20261106.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

class AuthorizedEntryTests(unittest.TestCase):
    def setUp(self):
        self.mask=os.umask(0o077)
        original=tempfile.TemporaryDirectory
        anchor='/var/lib' if os.environ.get('GITHUB_ACTIONS')=='true' else str(Path.cwd())
        self.profile=profile.ReconciledProfileTests()
        old_install=profile.base.NetworkTest.install
        def with_capacity(f):
            cap={'schema':'ouf.storage-g0-operator-evidence.v1','installationRef':'fixture',
                 'section':'CAPACITY','provenance':'TECHNICAL_OBSERVATION','ownerRef':'fixture',
                 'capturedAt':'2026-11-06','evidenceRefs':['fixture']}
            f.config['operatorEvidenceFiles']['capacity']=fixture.put(f.inputs/'capacity.json',cap)
            return old_install(f)
        with patch.object(tempfile,'TemporaryDirectory',lambda:original(dir=anchor)), patch.object(profile.base.NetworkTest,'install',with_capacity):
            self.profile.setUp()
        self.f=self.profile.f
        self.f.config=self.profile.c
        self.stage=self.f.root/'host192-stage'
        self.parent=self.stage/'inputs'
        self.parent.mkdir(parents=True,mode=0o700)
        self.scope=self.f.output/'fixture-next'
        self.preserved={str(x):x.read_bytes() for x in self.f.root.rglob('*') if x.is_file()}
        self.original=self.parent/'package-input.review.json';fixture.put(self.original,self.f.config)
        self.raw=self.original.read_bytes();self.digest=m.sha(self.raw)
        self.prior=p.preflight(self.original,self.f.bundle,self.f.digest)[-1]
        fixture.put(self.parent/'preflight.private.json',self.prior)
        self.calls=[]
    def tearDown(self):
        self.profile.doCleanups();os.umask(self.mask)
    def invoke(self,candidate,bundle,digest):
        self.calls.append(json.loads(candidate.read_bytes()))
        self.scope.mkdir(mode=0o700)
        result={'schema':'ouf.storage-g0-package-result.v1','scopeConsumed':True,
                'technicalCaptureComplete':True,'runtimeAuthorityIssued':False}
        fixture.put(self.scope/'result.json',result)
        return result
    def run_entry(self,preflight=p.preflight,invoke=None):
        return m.execute(self.stage,self.f.bundle,self.f.digest,self.digest,preflight,
                         invoke or self.invoke,operation='fixture-next',installation='fixture',expected_bindings={},output_parent=self.f.output)
    def test_exact_delta_original_unchanged_and_single_invocation(self):
        self.run_entry();self.assertEqual(len(self.calls),1)
        after=self.calls[0];self.assertEqual(after.pop('collectionDecisionRef'),m.DECISION)
        original=json.loads(self.raw);original.pop('collectionDecisionRef');self.assertEqual(after,original)
        self.assertEqual(self.original.read_bytes(),self.raw)
        self.assertEqual((self.parent/'package-input.collection.json').stat().st_mode&0o777,0o600)
        decision=json.loads((self.parent/'collection-decision.private.json').read_bytes())
        self.assertEqual(decision['boundInputSha256'],self.prior['boundInputSha256'])
        self.assertFalse(decision['authenticatedHumanApproval'])
        self.assertEqual(decision['limits'],p.RECONCILED_LIMITS)
        for path,raw in self.preserved.items():self.assertEqual(Path(path).read_bytes(),raw)
    def test_reentry_reads_result_without_preflight_or_invoke(self):
        self.run_entry()
        def forbidden(*a):raise AssertionError('replay')
        self.assertTrue(self.run_entry(forbidden,forbidden)['existingResultReadOnly'])
        self.assertEqual(len(self.calls),1)
    def test_changed_input_denied_before_local_claim(self):
        fixture.put(self.original,self.raw+b' ')
        self.assertRaises(m.Held,self.run_entry)
        self.assertFalse((self.parent/'collection-decision.private.json').exists());self.assertFalse(self.calls)
    def test_connection_drift_denied_even_if_valid(self):
        path=Path(self.f.config['connectionFiles']['s3']);value=json.loads(path.read_bytes())
        value['connection']['region']='changed';fixture.put(path,value)
        self.assertRaises(ValueError,self.run_entry);self.assertFalse(self.calls)
    def test_partial_entry_is_never_retried(self):
        fixture.put(self.parent/'collection-decision.private.json',{'partial':True})
        self.assertRaises(m.Held,self.run_entry);self.assertFalse(self.calls)
    def test_partial_collection_scope_is_never_retried(self):
        self.scope.mkdir();self.assertRaises(FileNotFoundError,self.run_entry);self.assertFalse(self.calls)
    def test_drift_after_copy_preserves_claim_and_denies_invocation(self):
        count=0
        def preflight(*args):
            nonlocal count
            result=p.preflight(*args);count+=1
            if count==2:result[-1]['boundInputSha256']['operator:capacity']='0'*64
            return result
        self.assertRaises(m.Held,self.run_entry,preflight)
        self.assertTrue((self.parent/'collection-decision.private.json').exists())
        self.assertTrue((self.parent/'package-input.collection.json').exists());self.assertFalse(self.calls)
    def test_bundle_extra_member_denied_before_preflight(self):
        fixture.put(self.f.bundle/'unexpected',b'new')
        def forbidden(*a):raise AssertionError('preflight')
        self.assertRaises(m.Held,self.run_entry,forbidden);self.assertFalse(self.calls)

    def test_changed_prior_receipt_denied_before_claim(self):
        path=Path(self.f.config['priorAttemptFiles']['result']['path'])
        path.write_bytes(path.read_bytes()+b' ')
        self.assertRaises(ValueError,self.run_entry)
        self.assertFalse((self.parent/'collection-decision.private.json').exists())
        self.assertFalse(self.calls)
    def test_operator_profile_exact_public_proposal(self):
        proposal=json.loads((ROOT/'releases/storage-g0-host192-collection-proposal-20261106.json').read_bytes())
        self.assertEqual(m.EXPECTED_LIMITS,proposal['limits'])
        self.assertEqual(m.INPUT_SHA,proposal['baseInputSha256'])
        self.assertEqual(m.MANIFEST_SHA,proposal['packageManifestSha256'])
        self.assertEqual(str(m.OUTPUT_PARENT/m.OPERATION),proposal['scope'])
        self.assertEqual(str(m.STAGING/'inputs/package-input.review.json'),proposal['baseInput'])
        self.assertEqual(m.DECISION,proposal['proposalId'])

if __name__=='__main__':unittest.main()

