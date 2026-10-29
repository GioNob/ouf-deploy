"""Exact reproducible six-module capsule and fail-closed source loading."""
import base64,hashlib,importlib.util,json,os,subprocess,sys,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('exporter',ROOT/'scripts/export-m2-stopped-provider-inputs.py')
exporter=importlib.util.module_from_spec(spec);spec.loader.exec_module(exporter)
CAPSULE=ROOT/'releases/m2-stopped-provider-inputs-20261029.py'
SHA='f312b973e0692495838c1e61ed9617bcd35099b5ee795f5a95dee7e52eeaad08'

class Capsule(unittest.TestCase):
    def test_reproducible_exact_six_module_source_and_capsule(self):
        self.assertEqual(exporter.build(ROOT),CAPSULE.read_bytes())
        self.assertEqual(hashlib.sha256(CAPSULE.read_bytes()).hexdigest(),SHA)
        self.assertEqual(len(exporter.PINS),6)
        self.assertIn('tools/m2_discovery_installation_profile/native_context.py',exporter.PINS)
        self.assertNotIn('tools/m2_discovery_installation_profile/provider_reconciliation.py',exporter.PINS)

    def test_changed_export_source_is_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            for p in exporter.PINS:
                target=root/p;target.parent.mkdir(parents=True,exist_ok=True)
                target.write_bytes((ROOT/p).read_bytes())
            p=root/next(iter(exporter.PINS));p.write_bytes(p.read_bytes()+b'\n')
            with self.assertRaisesRegex(AssertionError,'EXACT_PUBLISHED_SOURCE_REQUIRED'):
                exporter.build(root)

    def changed_runtime(self,extra):
        sources={p:(ROOT/p).read_text() for p in exporter.PINS}
        if extra:sources['tools/m2_discovery_installation_profile/unknown.py']=''
        else:sources[next(iter(sources))]+='\n'
        raw=json.dumps(sources,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()
        manifest={'sourcePins':exporter.PINS,'payloadSha256':hashlib.sha256(raw).hexdigest()}
        text=exporter.RUNTIME.replace('__MANIFEST__',repr(manifest)).replace('__PAYLOAD__',repr(base64.b64encode(raw).decode()))
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/'capsule.py';path.write_text(text)
            # Loading only: no main, target path read or root claim is executed.
            program="import os,runpy,sys; os.geteuid=lambda:0; sys.argv=[sys.argv[1]]; runpy.run_path(sys.argv[0])['load']()"
            return subprocess.run([sys.executable,'-I','-B','-S','-c',program,str(path)],
                capture_output=True,text=True,timeout=10)

    def test_runtime_rejects_extra_module_even_with_correct_payload_hash(self):
        result=self.changed_runtime(True)
        self.assertNotEqual(result.returncode,0)
        self.assertIn('EXACT_SIX_MODULE_SOURCE_CLOSURE_REQUIRED',result.stderr)

    def test_runtime_rejects_changed_source_even_with_correct_payload_hash(self):
        result=self.changed_runtime(False)
        self.assertNotEqual(result.returncode,0)
        self.assertIn('STOPPED_PROVIDER_INPUTS_SOURCE_BYTES_CHANGED',result.stderr)

if __name__=='__main__':unittest.main()
