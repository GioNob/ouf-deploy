"""Pinned read-only reconciliation closure and unchanged consumed collector."""
import ast,hashlib,importlib.util,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('provider_export',ROOT/'scripts/export-m2-provider-reconciliation.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

class ProviderCapsule(unittest.TestCase):
    def test_published_capsule_reproduces_from_independently_hashed_sources(self):
        raw=m.build(ROOT)
        self.assertEqual(raw,(ROOT/'releases/m2-provider-reconciliation-20261029.py').read_bytes())
        compile(raw,'<provider-capsule>','exec')

    def test_exact_five_modules_and_no_execution_authority(self):
        self.assertEqual(set(Path(p).stem for p in m.PINS),
            {'audit','custody_capture','projections','material_preparation','provider_reconciliation'})
        tree=ast.parse(m.build(ROOT))
        values={x.targets[0].id:ast.literal_eval(x.value) for x in tree.body
            if isinstance(x,ast.Assign) and isinstance(x.targets[0],ast.Name)}
        self.assertEqual(values['MANIFEST']['sourceCommit'],m.SOURCE)
        self.assertFalse(values['MANIFEST']['runtimeAuthorityIssued'])
        self.assertFalse(values['MANIFEST']['targetApplyAuthorized'])

    def test_changed_reader_is_rejected_before_packaging(self):
        with tempfile.TemporaryDirectory() as root:
            for p in m.PINS:
                target=Path(root)/p;target.parent.mkdir(parents=True,exist_ok=True)
                target.write_bytes((ROOT/p).read_bytes())
            p=Path(root)/'tools/m2_discovery_installation_profile/provider_reconciliation.py'
            p.write_bytes(p.read_bytes()+b'\n')
            with self.assertRaisesRegex(AssertionError,'EXACT_PUBLISHED_SOURCE_REQUIRED'):m.build(root)

    def test_consumed_trust_context_and_material_capsules_remain_byte_exact(self):
        pins={'m2-discovery-trust-context-20261029.py':'5e93e2248307b2cd33edf60485eabe085df1c535431f061d34eddbf413641519',
              'm2-discovery-material-roles-20261029.py':'3f213db3cc611490398a097ef334f874726af09c2f3de0344322ad604a108c65'}
        for name,sha in pins.items():
            with self.subTest(name=name):self.assertEqual(hashlib.sha256((ROOT/'releases'/name).read_bytes()).hexdigest(),sha)

if __name__=='__main__':unittest.main()
