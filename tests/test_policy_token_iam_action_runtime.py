import base64
import copy
import json
from pathlib import Path
import subprocess
import sysconfig
import sys
import unittest
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT/'tools/semantic_policy_token_owner'),str(ROOT/'tests')]
import iam_action_runtime as runtime
from test_policy_token_iam_owner_action import sources

class IamActionRuntimeTest(unittest.TestCase):
    def test_complete_closure_and_missing_extra_foreign_dependency_denials(self):
        raw=sources();loader=(ROOT/'tools/semantic_policy_token_owner/iam_action_runtime.py').read_bytes()
        self.assertEqual(runtime.declaration('a'*40,raw,loader)['moduleCount'],22)
        for case in ('missing','extra','foreign'):
            changed=dict(raw)
            if case=='missing':changed.pop('cutover_authority')
            if case=='extra':changed['foreign']=b'pass'
            if case=='foreign':changed['iam_owner_action']+=b'\nimport foreign_dependency\n'
            with self.assertRaises(runtime.RuntimeDenied):runtime.compile_sources(changed)
    def native(self,alter='none'):
        raw=sources();loader=(ROOT/'tools/semantic_policy_token_owner/iam_action_runtime.py').read_bytes()
        decl=runtime.declaration('a'*40,raw,loader)
        script=r'''
import base64,json,sys,types,hashlib
p=json.loads(sys.stdin.buffer.read(1048577));m=types.ModuleType('sealed_action_loader')
loader=base64.b64decode(p['loader']);exec(compile(loader,'sealed-loader','exec'),m.__dict__)
sources={n:base64.b64decode(v) for n,v in p['sources'].items()}
if p['alter']=='hash':sources['iam_owner_action']+=b'\n# changed\n'
if p['alter']=='preloaded':sys.modules['tools']=types.ModuleType('tools')
try:
 entry,manifest=m.load_entry('a'*40,sources,loader,p['declarationHash'])
 library=entry.stdlib_binding() if p['alter']=='stdlib' else None
 print(json.dumps({'loaded':True,'modules':manifest['moduleCount'],'stdlibFiles':len(library['fileHashes']) if library else None,'keysRead':0}))
except Exception as e:
 print(json.dumps({'denied':str(e),'safeDiagnostics':getattr(e,'safe_diagnostics',None)}));raise SystemExit(1)
'''
        payload={'loader':base64.b64encode(loader).decode(),'sources':{n:base64.b64encode(v).decode() for n,v in raw.items()},
            'declarationHash':runtime.digest(decl),'alter':alter}
        return subprocess.run([sys.executable,'-I','-B','-S','-c',script],input=json.dumps(payload).encode(),
            stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=40)
    def test_actual_isolated_no_site_full_signer_authority_action_import_from_memory(self):
        result=self.native();self.assertEqual(result.returncode,0,result.stderr.decode())
        value=json.loads(result.stdout);self.assertTrue(value['loaded']);self.assertEqual(value['modules'],22)
    def test_actual_hash_drift_and_preloaded_namespace_block_before_entry(self):
        for case in ('hash','preloaded'):
            result=self.native(case);self.assertNotEqual(result.returncode,0,result.stderr.decode())
            self.assertIn('denied',json.loads(result.stdout))
    def test_actual_no_site_standard_library_byte_bindings(self):
        result=self.native('stdlib');root=Path(sysconfig.get_path('stdlib')).resolve().stat()
        if root.st_uid!=0 or root.st_gid!=0 or root.st_mode&0o022:
            self.assertNotEqual(result.returncode,0)
            self.assertIn('STDLIB_DIRECTORY_CUSTODY_UNPROVEN',result.stdout.decode()+result.stderr.decode())
        else:
            self.assertEqual(result.returncode,0,result.stdout.decode()+result.stderr.decode())
            self.assertGreater(json.loads(result.stdout)['stdlibFiles'],100)

if __name__=='__main__':unittest.main()
