"""Cold isolated subprocesses: exact closure, ambient injection and denial modes."""
import ast,copy,hashlib,importlib.util,json,os,subprocess,sys,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('lease_capsule_builder',ROOT/'tools/m2_discovery_installation_profile/lease_capsule.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)


class Capsule(unittest.TestCase):
    def setUp(self):
        self.assertEqual(os.geteuid(),0)
        tmp=tempfile.TemporaryDirectory(dir=ROOT,prefix='lease-capsule-test-');self.addCleanup(tmp.cleanup)
        self.root=Path(tmp.name);self.path=self.root/'capsule.py'
        self.raw,self.manifest=m.build(ROOT);self.path.write_bytes(self.raw)

    def run_capsule(self,*args,isolated=True,**kw):
        return subprocess.run([sys.executable,*(['-I','-B','-S'] if isolated else ['-B','-S']),
            str(self.path),*args],capture_output=True,text=True,timeout=15,**kw)

    def test_reproducible_exact_closed_source_cold_load(self):
        second,manifest=m.build(ROOT);self.assertEqual(second,self.raw);self.assertEqual(manifest,self.manifest)
        result=self.run_capsule('self-check');self.assertEqual(result.returncode,0,result.stderr)
        value=json.loads(result.stdout);self.assertEqual(value['moduleCount'],37)
        self.assertEqual(value['sourceManifest'],self.manifest)
        self.assertFalse(value['runtimeAuthorityIssued']);self.assertFalse(value['targetApplyAuthorized'])
        self.assertEqual(result.stderr,'')

    def test_pythonpath_cwd_and_sitecustomize_cannot_supply_application_modules(self):
        marker=self.root/'injected';evil=self.root/'evil';evil.mkdir()
        code='from pathlib import Path\nPath('+repr(str(marker))+').write_text("UNTRUSTED")\nraise RuntimeError("AMBIENT")\n'
        for name in ('dns.py','bounded_recovery.py','sitecustomize.py'):(evil/name).write_text(code)
        (evil/'tools').mkdir();(evil/'tools/__init__.py').write_text(code)
        result=self.run_capsule('self-check',cwd=evil,env={**os.environ,'PYTHONPATH':str(evil)})
        self.assertEqual(result.returncode,0,result.stderr);self.assertFalse(marker.exists())

    def test_source_bytes_and_payload_tampering_are_denied(self):
        tree=ast.parse(self.raw)
        payload=next(n.value.value for n in tree.body if isinstance(n,ast.Assign)
            and any(isinstance(t,ast.Name) and t.id=='PAYLOAD' for t in n.targets))
        replacement=('B' if payload[0]!='B' else 'C')+payload[1:]
        self.path.write_bytes(self.raw.replace(payload.encode(),replacement.encode(),1))
        result=self.run_capsule('self-check');self.assertEqual(result.returncode,2)
        self.assertNotIn('sourceManifest',result.stdout);self.assertNotIn('Traceback',result.stderr)
        self.assertEqual(json.loads(result.stdout)['status'],'STOP_RECONCILE')

    def test_unisolated_preloaded_or_unknown_application_import_is_denied(self):
        result=self.run_capsule('self-check',isolated=False);self.assertEqual(result.returncode,2)
        harness='import runpy,sys,types;sys.modules["dns"]=types.ModuleType("dns");ns=runpy.run_path(sys.argv[1]);ns["load"]()'
        result=subprocess.run([sys.executable,'-I','-B','-S','-c',harness,str(self.path)],capture_output=True,text=True,timeout=15)
        self.assertNotEqual(result.returncode,0);self.assertIn('PRELOADED_DISCOVERY_APPLICATION_MODULE_DENIED',result.stderr)
        harness='import runpy,sys,importlib;ns=runpy.run_path(sys.argv[1]);ns["load"]();importlib.import_module("tools.unreviewed")'
        result=subprocess.run([sys.executable,'-I','-B','-S','-c',harness,str(self.path)],capture_output=True,text=True,timeout=15)
        self.assertNotEqual(result.returncode,0);self.assertIn('UNSEALED_DISCOVERY_APPLICATION_IMPORT_DENIED',result.stderr)

    def test_missing_configuration_is_not_created_and_other_modes_are_unavailable(self):
        missing=self.root/'not-installed.json'
        result=self.run_capsule('worker','--configuration',str(missing),'--configuration-anchor','a'*64)
        self.assertEqual(result.returncode,2);self.assertFalse(missing.exists())
        self.assertNotIn(str(missing),result.stdout);self.assertNotIn('Traceback',result.stderr)
        for mode in ('install','sign','start','resume'):
            result=self.run_capsule(mode);self.assertEqual(result.returncode,2)
            self.assertFalse(json.loads(result.stdout)['targetApplyAuthorized'])

    def test_exporter_refuses_source_drift_and_existing_output(self):
        # Refuse even a whitespace delta; do not normalize source bytes.
        name=next(iter(m.PINS));path=ROOT/m.PINS[name]['path'];original=path.read_bytes()
        from unittest import mock
        real_read=Path.read_bytes
        def drift(p):return original+b'\n' if p==path else real_read(p)
        with mock.patch.object(Path,'read_bytes',drift):
            with self.assertRaisesRegex(ValueError,'EXACT_PUBLISHED'):m.build(ROOT)
        output=self.root/'exported.py';output.write_bytes(b'PRESERVE')
        result=subprocess.run([sys.executable,'-I','-B','-S',str(ROOT/'scripts/export-m2-discovery-lease-runtime.py'),
            '--root',str(ROOT),'--output',str(output)],capture_output=True,text=True,timeout=15)
        self.assertNotEqual(result.returncode,0);self.assertEqual(output.read_bytes(),b'PRESERVE')

if __name__=='__main__':unittest.main()
