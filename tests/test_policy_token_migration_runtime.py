import base64
import json
from pathlib import Path
import subprocess
import sys
import unittest
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT/'tools/semantic_policy_token_owner'),str(ROOT/'tests')]
import migration_runtime as runtime
from test_policy_token_iam_owner_action import sources as original_sources

def sources():
    result=original_sources()
    for name in runtime.MODULES-set(result):
        path=ROOT/(name.replace('.','/')+'.py') if name.startswith('tools.') else ROOT/'tools/semantic_policy_token_owner'/(name+'.py')
        result[name]=path.read_bytes()
    return result

class MigrationRuntimeTest(unittest.TestCase):
    def test_exact_closure_rejects_missing_extra_and_foreign_dependencies(self):
        raw=sources();loader=(ROOT/'tools/semantic_policy_token_owner/migration_runtime.py').read_bytes()
        self.assertEqual(runtime.declaration('a'*40,raw,loader)['moduleCount'],32)
        for case in ('missing','extra','foreign'):
            changed=dict(raw)
            if case=='missing':changed.pop('credential_transaction')
            if case=='extra':changed['unexpected']=b'pass'
            if case=='foreign':changed['first_controlled_grant']+=b'\nimport unexpected\n'
            with self.assertRaises(runtime.RuntimeDenied):runtime.compile_sources(changed)
    def native(self,alter):
        raw=sources();loader=(ROOT/'tools/semantic_policy_token_owner/migration_runtime.py').read_bytes()
        decl=runtime.declaration('a'*40,raw,loader)
        script=r'''
import base64,json,sys,types
p=json.loads(sys.stdin.buffer.read(1048577));m=types.ModuleType('verified_migration_loader')
loader=base64.b64decode(p['loader']);exec(compile(loader,'verified-migration-loader','exec'),m.__dict__)
sources={n:base64.b64decode(v) for n,v in p['sources'].items()}
if p['alter']=='hash':sources['credential_transaction']+=b'\n# tampered\n'
if p['alter']=='preloaded':sys.modules['tools']=types.ModuleType('tools')
try:
 entry,manifest=m.load_entry('a'*40,sources,loader,p['hash'])
 print(json.dumps({'entry':entry.__name__,'modules':manifest['moduleCount'],'installerQualified':manifest['fullOwnerInstallerQualified']}))
except Exception as e:
 print(json.dumps({'denied':str(e)}));raise SystemExit(1)
'''
        payload={'loader':base64.b64encode(loader).decode(),'sources':{n:base64.b64encode(v).decode()for n,v in raw.items()},'hash':runtime.digest(decl),'alter':alter}
        return subprocess.run([sys.executable,'-I','-B','-S','-c',script],input=json.dumps(payload).encode(),stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10)
    def test_actual_isolated_no_site_all_migration_components_load_from_verified_memory(self):
        result=self.native('none');self.assertEqual(result.returncode,0,result.stdout.decode()+result.stderr.decode())
        row=json.loads(result.stdout);self.assertEqual(row['entry'],'first_controlled_grant');self.assertEqual(row['modules'],32)
        self.assertFalse(row['installerQualified'])
    def test_tampered_and_preloaded_code_cannot_enter(self):
        for case in ('hash','preloaded'):
            result=self.native(case);self.assertNotEqual(result.returncode,0)
            self.assertIn('denied',json.loads(result.stdout))

if __name__=='__main__':unittest.main()
