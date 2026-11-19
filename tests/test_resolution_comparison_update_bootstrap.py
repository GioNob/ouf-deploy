"""Actual complete source graph, isolated in-memory loader, no host effects."""
import copy,hashlib,importlib.util,json,subprocess,sys,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def module(name,path):
 spec=importlib.util.spec_from_file_location(name,ROOT/path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
runtime=module('mcp_runtime','tools/resolution_comparison_update/runtime.py')
bootstrap=module('mcp_bootstrap','scripts/execute-resolution-comparison-update-20261017.py')
def sources():
 paths=json.loads((ROOT/'tools/chatbot_file_cohort/source_paths.json').read_bytes())
 result={name:b'pass\n'if path.startswith('ouf-onboarding:')else(ROOT/path).read_bytes()for name,path in paths.items()}
 for name in ('entry','authority','permit','plan','session','owner','native'):
  result['tools.semantic_mcp_update.'+name]=(ROOT/'tools/semantic_mcp_update'/str(name+'.py')).read_bytes()
 for name in ('entry','authority','plan','owner','native'):
  result['tools.ingestion_readiness_update.'+name]=(ROOT/'tools/ingestion_readiness_update'/str(name+'.py')).read_bytes()
 for name in ('entry','authority','owner','native','preparation'):
  result['tools.onboarding_audit_update.'+name]=(ROOT/'tools/onboarding_audit_update'/str(name+'.py')).read_bytes()
 for name in ('entry','authority','owner','native','plan'):
  result['tools.resolution_ths_update.'+name]=(ROOT/'tools/resolution_ths_update'/str(name+'.py')).read_bytes()
 result.update({'tools.resolution_ths_configuration.'+n:(ROOT/'tools/resolution_ths_configuration'/ (n+'.py')).read_bytes()for n in('entry','authority','owner','native','plan')})
 result.update({'tools.udp_resolution_update.'+n:(ROOT/'tools/udp_resolution_update'/(n+'.py')).read_bytes()for n in('entry','authority','owner','native','plan','preparation')})
 result.update({'tools.resolution_comparison_update.'+n:(ROOT/'tools/resolution_comparison_update'/(n+'.py')).read_bytes()for n in('entry','authority','owner','native','plan','preparation')})
 return result
class Bootstrap(unittest.TestCase):
 def test_actual_closed_entry_imports_in_isolated_process_with_all_effects_disabled(self):
  script='''import json,sys,os,subprocess,urllib.request
from pathlib import Path
root=Path(sys.argv[1]);
loader=(root/'tools/resolution_comparison_update/runtime.py').read_bytes()
ns={'__name__':'sealed_mcp_test_loader'};exec(compile(loader,'<loader>','exec'),ns)
paths=json.loads((root/'tools/chatbot_file_cohort/source_paths.json').read_bytes())
sources={n:b'pass\\n'if p.startswith('ouf-onboarding:')else(root/p).read_bytes()for n,p in paths.items()}
for n in('entry','authority','permit','plan','session','owner','native'):
 sources['tools.semantic_mcp_update.'+n]=(root/'tools/semantic_mcp_update'/str(n+'.py')).read_bytes()
for n in('entry','authority','plan','owner','native'):
 sources['tools.ingestion_readiness_update.'+n]=(root/'tools/ingestion_readiness_update'/str(n+'.py')).read_bytes()
for n in('entry','authority','owner','native','preparation'):
 sources['tools.onboarding_audit_update.'+n]=(root/'tools/onboarding_audit_update'/str(n+'.py')).read_bytes()
for n in('entry','authority','owner','native','plan'):
 sources['tools.resolution_ths_update.'+n]=(root/'tools/resolution_ths_update'/str(n+'.py')).read_bytes()
sources.update({'tools.resolution_ths_configuration.'+n:(root/'tools/resolution_ths_configuration'/(n+'.py')).read_bytes()for n in('entry','authority','owner','native','plan')})
sources.update({'tools.udp_resolution_update.'+n:(root/'tools/udp_resolution_update'/(n+'.py')).read_bytes()for n in('entry','authority','owner','native','plan','preparation')})
sources.update({'tools.resolution_comparison_update.'+n:(root/'tools/resolution_comparison_update'/(n+'.py')).read_bytes()for n in('entry','authority','owner','native','plan','preparation')})
pins={'ouf-deploy':'a'*40,'ouf-onboarding':'b'*40};extra={'executorSha256':'c'*64,'caseSha256':'d'*64,'mode':'RESOLUTION_COMPARISON_UPDATE'}
d=ns['declaration']('a'*40,sources,loader,pins,extra)
def denied(*a,**k):raise AssertionError('NO_EFFECTS_DURING_CLOSED_IMPORT')
os.open=denied;os.mkdir=denied;subprocess.run=denied;subprocess.Popen=denied;urllib.request.OpenerDirector.open=denied
entry,_=ns['load_entry']('a'*40,sources,loader,ns['digest'](d),pins,extra)
assert callable(entry.main)
assert not hasattr(entry,'run_original_eight_phases')
print('SEALED_SCOPED_MCP_ENTRY_IMPORTED_WITHOUT_EFFECTS')
'''
  result=subprocess.run([sys.executable,'-I','-B','-S','-c',script,str(ROOT)],capture_output=True,timeout=20)
  self.assertEqual(result.returncode,0,result.stderr.decode());self.assertEqual(result.stdout,b'SEALED_SCOPED_MCP_ENTRY_IMPORTED_WITHOUT_EFFECTS\n')
 def test_bootstrap_bytes_selection_mode_and_source_maps_are_bound(self):
  source=sources();loader=(ROOT/'tools/resolution_comparison_update/runtime.py').read_bytes()
  pins={'ouf-deploy':'a'*40,'ouf-onboarding':'b'*40};extra={'executorSha256':'c'*64,'caseSha256':'d'*64,'mode':'RESOLUTION_COMPARISON_UPDATE'}
  d=runtime.declaration('a'*40,source,loader,pins,extra)
  self.assertEqual(d['entryModule'],'tools.resolution_comparison_update.entry');self.assertEqual(d['bootstrapBindings'],extra)
  changed={**extra,'executorSha256':'e'*64}
  self.assertNotEqual(runtime.digest(d),runtime.digest(runtime.declaration('a'*40,source,loader,pins,changed)))
  with self.assertRaises(runtime.RuntimeDenied):runtime.declaration('a'*40,source,loader,pins,{'mode':'RUN_EIGHT_PHASES'})
  altered=copy.deepcopy(source);altered['tools.udp_resolution_update.entry']+=b'\nimport outside_closure\n'
  with self.assertRaises(runtime.RuntimeDenied):runtime.compile_sources(altered)
  altered=copy.deepcopy(source);altered.pop('tools.udp_resolution_update.entry')
  with self.assertRaises(runtime.RuntimeDenied):runtime.compile_sources(altered)
if __name__=='__main__':unittest.main()
