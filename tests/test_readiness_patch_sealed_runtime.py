"""Verified-memory import boundary; no target, authority issuance or I/O peers."""
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import unittest

ROOT=Path(__file__).resolve().parents[1]
PATH=ROOT/'tools/ingestion_readiness_patch_execution/runtime.py'
spec=importlib.util.spec_from_file_location('patch_sealed_runtime',PATH)
runtime=importlib.util.module_from_spec(spec);spec.loader.exec_module(runtime)

class SealedRuntime(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sources={n:(ROOT/runtime.SOURCE_PATHS[n]).read_bytes() for n in runtime.MODULES}
        cls.pins={n:'1'*40 for n in ('ouf-deploy','ouf-onboarding','ouf-ingestion-runtime','ouf-api-gateway')}
        cls.loader=PATH.read_bytes()
        cls.declaration=runtime.declaration('1'*40,cls.sources,cls.loader,cls.pins)
    def test_isolated_process_loads_exact_new_entry_with_no_disk_fallback(self):
        source='''import importlib.util,json,sys
from pathlib import Path
path=Path(sys.argv[1]);root=Path(sys.argv[2])
spec=importlib.util.spec_from_file_location('verified_runtime',path)
r=importlib.util.module_from_spec(spec);spec.loader.exec_module(r)
sources={n:(root/r.SOURCE_PATHS[n]).read_bytes() for n in r.MODULES}
pins={n:'1'*40 for n in ('ouf-deploy','ouf-onboarding','ouf-ingestion-runtime','ouf-api-gateway')}
declaration=r.declaration('1'*40,sources,path.read_bytes(),pins)
entry,actual=r.load_entry('1'*40,sources,path.read_bytes(),r.digest(declaration),pins)
assert entry.__name__==r.ENTRY
assert entry.__qualified_source_sha256__==actual['sourceHashes'][r.ENTRY]
assert entry.c.AUTHORITY_KEY=='ingestionReadinessPatch'
assert not any(getattr(sys.modules[n],'__file__',None) for n in r.MODULES if n in sys.modules)
print(json.dumps({'entry':entry.__name__,'modules':actual['moduleCount'],'effects':0}))
'''
        result=subprocess.run([sys.executable,'-I','-B','-S','-c',source,str(PATH),str(ROOT)],
            capture_output=True,text=True,timeout=30)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(json.loads(result.stdout),{'entry':runtime.ENTRY,'modules':139,'effects':0})
    def test_missing_extra_or_foreign_import_sources_fail_closed(self):
        for kind in ('missing','extra','foreign'):
            sources=dict(self.sources)
            if kind=='missing':sources.pop(runtime.ENTRY)
            elif kind=='extra':sources['unreviewed_peer']=b'pass\n'
            else:sources[runtime.ENTRY]=b'import unreviewed_peer\n'
            with self.assertRaises(runtime.RuntimeDenied):runtime.compile_sources(sources)
    def test_source_drift_invalidates_the_independent_declaration(self):
        changed=dict(self.sources);changed[runtime.ENTRY]+=b'\n# changed source\n'
        other=runtime.declaration('1'*40,changed,self.loader,self.pins)
        self.assertNotEqual(runtime.digest(other),runtime.digest(self.declaration))
        with self.assertRaisesRegex(runtime.RuntimeDenied,'DECLARATION_DRIFT'):
            runtime.load_entry('1'*40,changed,self.loader,runtime.digest(self.declaration),self.pins)
    def test_existing_two_container_graph_retains_all_114_frozen_source_hashes(self):
        old=ROOT/'tools/ingestion_rollout_execution/runtime.py'
        spec=importlib.util.spec_from_file_location('frozen_rollout_runtime',old)
        baseline=importlib.util.module_from_spec(spec);spec.loader.exec_module(baseline)
        self.assertEqual(len(baseline.MODULES),114)
        self.assertTrue(baseline.MODULES<runtime.MODULES)
        self.assertTrue(all(runtime.SOURCE_PATHS[n]==baseline.SOURCE_PATHS[n] for n in baseline.MODULES))
        self.assertNotEqual(runtime.ENTRY,baseline.ENTRY)
        raw=(ROOT/'tests/fixtures/ingestion-readiness-patch/frozen-native-source-hashes.json').read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(),'7771116d297cb5c0aa7037d294fb5b72c8e489bc308075a95edc39149699822a')
        original=json.loads(raw)
        self.assertEqual(original['qualifiedArtifactSha256'],'42b2569a0ba1f2234dfbcc011588cdf133d0e5c97a3f3433b903750f010448ea')
        frozen=original['nativeDeclaration']['sourceHashes']
        self.assertEqual(set(frozen),baseline.MODULES)
        self.assertTrue(all(hashlib.sha256(self.sources[n]).hexdigest()==expected for n,expected in frozen.items()))

if __name__=='__main__':unittest.main()
