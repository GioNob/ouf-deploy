"""Load the complete real entrypoint with external effects disabled."""
import json,subprocess,sys,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
class Bootstrap(unittest.TestCase):
 def test_closed_memory_import_without_external_effects(self):
  script=r'''import json,os,sys,subprocess,urllib.request
from pathlib import Path
root=Path(sys.argv[1]); boot={'__name__':'bootstrap_metadata'}
exec(compile((root/'scripts/execute-source-revision-update-20261018.py').read_bytes(),'<bootstrap>','exec'),boot)
paths=json.loads((root/'tools/chatbot_file_cohort/source_paths.json').read_bytes())
sources={n:b'pass\n' if p.startswith('ouf-onboarding:')else(root/p).read_bytes()for n,p in paths.items()}
for n,(_,p)in boot['OVERLAYS'].items():sources[n]=(root/p).read_bytes()
loader=(root/'tools/source_revision_update/runtime.py').read_bytes();ns={'__name__':'runtime_metadata'}
exec(compile(loader,'<runtime>','exec'),ns)
pins={'ouf-deploy':'a'*40,'ouf-onboarding':'b'*40};extra={'executorSha256':'c'*64,'caseSha256':'d'*64,'mode':'SOURCE_REVISION_UPDATE'}
d=ns['declaration']('a'*40,sources,loader,pins,extra)
def denied(*a,**k):raise AssertionError('EFFECT_DURING_IMPORT')
os.open=denied;os.mkdir=denied;subprocess.Popen=denied;subprocess.run=denied;urllib.request.OpenerDirector.open=denied
entry,_=ns['load_entry']('a'*40,sources,loader,ns['digest'](d),pins,extra)
assert callable(entry.main)
print('CLOSED_IMPORT_OK')
'''
  r=subprocess.run([sys.executable,'-I','-B','-S','-c',script,str(ROOT)],capture_output=True,timeout=30)
  self.assertEqual(r.returncode,0,r.stderr.decode());self.assertEqual(r.stdout,b'CLOSED_IMPORT_OK\n')
