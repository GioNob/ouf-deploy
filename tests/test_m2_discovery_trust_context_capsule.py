"""Exact nine-module closure, build reproducibility and unchanged prior capsules."""
import ast,hashlib,importlib.util,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('trust_export',ROOT/'scripts/export-m2-discovery-trust-context.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

class TrustCapsule(unittest.TestCase):
    def test_published_capsule_is_exact_independent_python_export(self):
        raw=m.build(ROOT);self.assertEqual(raw,(ROOT/'releases/m2-discovery-trust-context-20261029.py').read_bytes())
        compile(raw,'<pinned-capsule>','exec')

    def test_source_closure_is_exact_nine_modules_without_key_generation_or_credentials(self):
        self.assertEqual(len(m.PINS),9)
        self.assertEqual(set(Path(p).stem for p in m.PINS),{'audit','custody_capture','projections',
            'material_preparation','public_truststore','trust_inputs','trust_preparation','native_context','trust_context_entry'})
        self.assertTrue(all(hashlib.sha256((ROOT/p).read_bytes()).hexdigest()==s for p,s in m.PINS.items()))
        tree=ast.parse(m.build(ROOT))
        values={x.targets[0].id:ast.literal_eval(x.value) for x in tree.body
                if isinstance(x,ast.Assign) and isinstance(x.targets[0],ast.Name)}
        self.assertFalse(values['MANIFEST']['targetApplyAuthorized'])
        self.assertFalse(values['MANIFEST']['runtimeAuthorityIssued'])
        self.assertEqual(values['MANIFEST']['sourceCommit'],m.SOURCE)

    def test_changed_module_is_refused_before_packaging(self):
        with tempfile.TemporaryDirectory() as root:
            for p in m.PINS:
                target=Path(root)/p;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes((ROOT/p).read_bytes())
            p=Path(root)/'tools/m2_discovery_installation_profile/native_context.py'
            p.write_bytes(p.read_bytes()+b'\n')
            with self.assertRaisesRegex(AssertionError,'EXACT_PUBLISHED_SOURCE_REQUIRED'):m.build(root)

    def test_previous_published_role_capsule_remains_byte_exact(self):
        raw=(ROOT/'releases/m2-discovery-material-roles-20261029.py').read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(),'3f213db3cc611490398a097ef334f874726af09c2f3de0344322ad604a108c65')

if __name__=='__main__':unittest.main()
