"""Actual complete source graph, isolated in-memory loader, no host effects."""
import copy,hashlib,importlib.util,json,subprocess,sys,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def module(name,path):
 spec=importlib.util.spec_from_file_location(name,ROOT/path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
runtime=module('mcp_runtime','tools/semantic_mcp_update/runtime.py')
bootstrap=module('mcp_bootstrap','scripts/execute-semantic-mcp-scoped-20261017.py')
def sources():
 paths=json.loads((ROOT/'tools/chatbot_file_cohort/source_paths.json').read_bytes())
 result={name:b'pass\n'if path.startswith('ouf-onboarding:')else(ROOT/path).read_bytes()for name,path in paths.items()}
 for name in ('entry','authority','permit','plan','session','owner','native'):
  result['tools.semantic_mcp_update.'+name]=(ROOT/'tools/semantic_mcp_update'/str(name+'.py')).read_bytes()
 return result
class Bootstrap(unittest.TestCase):
 def test_actual_closed_entry_imports_in_isolated_process_with_all_effects_disabled(self):
  script='''import json,sys,os,subprocess,urllib.request
from pathlib import Path
root=Path(sys.argv[1]);loader=(root/'tools/semantic_mcp_update/runtime.py').read_bytes()
ns={'__name__':'sealed_mcp_test_loader'};exec(compile(loader,'<loader>','exec'),ns)
paths=json.loads((root/'tools/chatbot_file_cohort/source_paths.json').read_bytes())
sources={n:b'pass\\n'if p.startswith('ouf-onboarding:')else(root/p).read_bytes()for n,p in paths.items()}
for n in('entry','authority','permit','plan','session','owner','native'):
 sources['tools.semantic_mcp_update.'+n]=(root/'tools/semantic_mcp_update'/str(n+'.py')).read_bytes()
pins={'ouf-deploy':'a'*40,'ouf-onboarding':'b'*40};extra={'executorSha256':'c'*64,'caseSha256':'d'*64,'mode':'TOKEN_SESSION'}
d=ns['declaration']('a'*40,sources,loader,pins,extra)
def denied(*a,**k):raise AssertionError('NO_EFFECTS_DURING_CLOSED_IMPORT')
os.open=denied;os.mkdir=denied;subprocess.run=denied;subprocess.Popen=denied;urllib.request.OpenerDirector.open=denied
entry,_=ns['load_entry']('a'*40,sources,loader,ns['digest'](d),pins,extra)
assert callable(entry.token_main)and callable(entry.update_main)
assert not hasattr(entry,'run_original_eight_phases')
print('SEALED_SCOPED_MCP_ENTRY_IMPORTED_WITHOUT_EFFECTS')
'''
  result=subprocess.run([sys.executable,'-I','-B','-S','-c',script,str(ROOT)],capture_output=True,timeout=20)
  self.assertEqual(result.returncode,0,result.stderr.decode());self.assertEqual(result.stdout,b'SEALED_SCOPED_MCP_ENTRY_IMPORTED_WITHOUT_EFFECTS\n')
 def test_bootstrap_bytes_selection_mode_and_source_maps_are_bound(self):
  source=sources();loader=(ROOT/'tools/semantic_mcp_update/runtime.py').read_bytes()
  pins={'ouf-deploy':'a'*40,'ouf-onboarding':'b'*40};extra={'executorSha256':'c'*64,'caseSha256':'d'*64,'mode':'TOKEN_SESSION'}
  d=runtime.declaration('a'*40,source,loader,pins,extra)
  self.assertEqual(d['entryModule'],'tools.semantic_mcp_update.entry');self.assertEqual(d['bootstrapBindings'],extra)
  changed={**extra,'mode':'MCP_UPDATE'}
  self.assertNotEqual(runtime.digest(d),runtime.digest(runtime.declaration('a'*40,source,loader,pins,changed)))
  with self.assertRaises(runtime.RuntimeDenied):runtime.declaration('a'*40,source,loader,pins,{'mode':'RUN_EIGHT_PHASES'})
  altered=copy.deepcopy(source);altered['tools.semantic_mcp_update.entry']+=b'\nimport outside_closure\n'
  with self.assertRaises(runtime.RuntimeDenied):runtime.compile_sources(altered)
  altered=copy.deepcopy(source);altered.pop('tools.semantic_mcp_update.entry')
  with self.assertRaises(runtime.RuntimeDenied):runtime.compile_sources(altered)
 def test_retained_target_and_budget_bindings_are_exact(self):
  self.assertEqual(bootstrap.MCP_REVIEW['sha256'],'69e052d9bfab8607bc871af3027c1da3a09781faa1f2778b365d0779af0cf9e8')
  self.assertEqual(len(bootstrap.OVERLAYS),14)
  self.assertIn('f06a7e0d3bcd3ccb8f05b1fcd744b6f33ba003b4d74fa472c9e7950ee00d27ac',bootstrap.WORKER_HASHES.values())
if __name__=='__main__':unittest.main()
