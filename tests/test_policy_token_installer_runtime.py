"""Actual isolated closed import of all installation/worker/authentication code."""
import base64
import json
from pathlib import Path
import subprocess
import sys
import unittest
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'tests'),str(ROOT/'tools/semantic_policy_token_owner')]
import installer_runtime as runtime
from test_policy_token_migration_runtime import sources as migration_sources
from test_policy_token_sealed_runtime import source_paths

def sources():
    result=migration_sources()
    for name in ('file_only_profile','gated_creation_plan','transition_journal'):
        result[name]=(ROOT/'tools/semantic_application_cutover'/(name+'.py')).read_bytes()
    result.update({name:path.read_bytes()for name,path in source_paths().items()})
    result[runtime.ENTRY]=(ROOT/'tools/semantic_policy_token_owner/owner_installation.py').read_bytes()
    return result

class InstallerRuntimeTest(unittest.TestCase):
    def test_complete_closed_actual_sources_and_no_foreign_import(self):
        raw=sources();loader=(ROOT/'tools/semantic_policy_token_owner/installer_runtime.py').read_bytes()
        manifest=runtime.declaration('a'*40,raw,loader)
        self.assertEqual(manifest['moduleCount'],39)
        script='''import base64,json,sys,types
p=json.loads(sys.stdin.buffer.read(2000000));raw=base64.b64decode(p['loader']);m=types.ModuleType('approved_installer_loader')
exec(compile(raw,'approved-installer-loader','exec'),m.__dict__)
sources={k:base64.b64decode(v)for k,v in p['sources'].items()}
entry,manifest=m.load_entry('a'*40,sources,raw,p['hash'])
assert entry.InstalledTokenOwner.__module__=='tools.semantic_policy_token_owner.installed_owner'
assert callable(entry.OwnerInstallation.install) and callable(entry.AggregateAction.guard)
assert sys.modules['tools'].__path__==[]
print(json.dumps({'entry':entry.__name__,'modules':manifest['moduleCount'],'providerCalls':0}))
'''
        payload={'loader':base64.b64encode(loader).decode(),'sources':{n:base64.b64encode(v).decode()for n,v in raw.items()},'hash':runtime.digest(manifest)}
        completed=subprocess.run([sys.executable,'-I','-B','-S','-c',script],input=json.dumps(payload).encode(),capture_output=True,timeout=20)
        self.assertEqual(completed.returncode,0,completed.stdout.decode()+completed.stderr.decode())
        self.assertEqual(json.loads(completed.stdout)['modules'],39)
        changed=dict(raw);changed.pop('first_controlled_grant')
        with self.assertRaises(runtime.RuntimeDenied):runtime.declaration('a'*40,changed,loader)
        changed=dict(raw);changed[runtime.ENTRY]+=b'\nimport arbitrary_runtime\n'
        with self.assertRaises(runtime.RuntimeDenied):runtime.declaration('a'*40,changed,loader)

if __name__=='__main__':unittest.main()
