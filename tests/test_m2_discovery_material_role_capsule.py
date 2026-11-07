"""Exact source closure and early denial, without executing target preparation."""
import ast
import base64
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
EXPORTER=ROOT/'scripts/export-m2-discovery-material-roles.py'
CAPSULE=ROOT/'releases/m2-discovery-material-roles-20261029.py'
spec=importlib.util.spec_from_file_location('material_exporter',EXPORTER)
exporter=importlib.util.module_from_spec(spec);spec.loader.exec_module(exporter)


class MaterialRoleCapsule(unittest.TestCase):
    def values(self):
        return {n.targets[0].id:ast.literal_eval(n.value) for n in ast.parse(CAPSULE.read_bytes()).body
                if isinstance(n,ast.Assign) and isinstance(n.targets[0],ast.Name)
                and n.targets[0].id in ('MANIFEST','PAYLOAD')}

    def test_rebuilds_byte_exact_capsule_and_all_five_published_sources(self):
        self.assertEqual(exporter.build(ROOT),CAPSULE.read_bytes())
        values=self.values();raw=base64.b64decode(values['PAYLOAD'],validate=True)
        self.assertEqual(hashlib.sha256(raw).hexdigest(),values['MANIFEST']['payloadSha256'])
        sources=json.loads(raw);self.assertEqual(set(sources),set(exporter.PINS))
        for name,source in sources.items():
            self.assertEqual(source,(ROOT/name).read_text())
            self.assertEqual(hashlib.sha256(source.encode()).hexdigest(),exporter.PINS[name])

    def test_changed_source_is_refused_before_capsule_emission(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)
            for name in exporter.PINS:
                p=root/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes((ROOT/name).read_bytes())
            p=root/next(iter(exporter.PINS));p.write_bytes(p.read_bytes()+b'\n')
            with self.assertRaisesRegex(AssertionError,'EXACT_PUBLISHED_SOURCE_REQUIRED'):exporter.build(root)

    def test_arguments_and_missing_isolation_are_refused_before_loading_modules(self):
        for flags,args,reason in [(['-I','-B','-S'],['unexpected'],'ROOT_NO_ARGUMENT'),
                                  (['-I','-B'],[],'ISOLATED_NO_SITE')]:
            reply=subprocess.run([sys.executable,*flags,str(CAPSULE),*args],capture_output=True,text=True,timeout=10)
            self.assertNotEqual(reply.returncode,0);self.assertIn(reason,reply.stderr)
            self.assertNotIn('preparedInputsHash',reply.stdout)

    def test_preloaded_application_module_is_refused(self):
        code="import runpy,sys,types;v=runpy.run_path(sys.argv[1]);sys.argv=[sys.argv[1]];sys.modules['tools']=types.ModuleType('tools');v['load']()"
        reply=subprocess.run([sys.executable,'-I','-B','-S','-c',code,str(CAPSULE)],capture_output=True,text=True,timeout=10)
        self.assertNotEqual(reply.returncode,0);self.assertIn('PRELOADED_APPLICATION_MODULE_DENIED',reply.stderr)

    def test_changed_payload_cannot_load_any_module(self):
        code="import runpy,sys;v=runpy.run_path(sys.argv[1]);sys.argv=[sys.argv[1]];v['load'].__globals__['PAYLOAD']='e30=';v['load']()"
        reply=subprocess.run([sys.executable,'-I','-B','-S','-c',code,str(CAPSULE)],capture_output=True,text=True,timeout=10)
        self.assertNotEqual(reply.returncode,0);self.assertIn('EXACT_MATERIAL_PREPARATION_PAYLOAD_REQUIRED',reply.stderr)

if __name__=='__main__':unittest.main()
