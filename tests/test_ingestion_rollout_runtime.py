"""Real isolated verified-memory import of the complete native source closure.

Import does not initialize a journal, read credentials or dispatch target I/O.
This is loader qualification, separate from representative platform acceptance.
"""
import base64
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import unittest
ROOT=Path(__file__).resolve().parents[1]
SOURCE=ROOT/'tools/ingestion_rollout_execution/runtime.py'
spec=importlib.util.spec_from_file_location('native_rollout_loader',SOURCE)
r=importlib.util.module_from_spec(spec);spec.loader.exec_module(r)
CHILD=r'''import base64,json,sys
v=json.loads(sys.stdin.buffer.read(4194305))
loader=base64.b64decode(v['loader'],validate=True);ns={'__name__':'verified_native_loader'}
exec(compile(loader,'<verified-native-loader>','exec'),ns)
sources={n:base64.b64decode(b,validate=True)for n,b in v['sources'].items()}
try:
    entry,manifest=ns['load_entry'](v['commit'],sources,loader,v['approvedDeclarationHash'],v['sourcePins'])
    assert entry.__qualified_source_sha256__==manifest['sourceHashes'][ns['ENTRY']]
    assert entry.NativePorts.__module__=='tools.ingestion_rollout_execution.native'
    print(json.dumps({'sealedEntryImported':True,'moduleCount':manifest['moduleCount'],'runtimeAuthorityIssued':False}))
except BaseException as error:
    print(json.dumps({'denied':type(error).__name__,'reason':str(error)}))
    sys.exit(2)
'''

class SealedRuntime(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sources={n:(ROOT/p).read_bytes()for n,p in r.SOURCE_PATHS.items()};cls.loader=SOURCE.read_bytes()
        cls.pins={n:'1'*40 for n in('ouf-deploy','ouf-onboarding','ouf-ingestion-runtime','ouf-api-gateway')}
    def request(self,sources=None,flags=('-I','-B','-S'),approved=None):
        sources=self.sources if sources is None else sources
        manifest=r.declaration('1'*40,self.sources,self.loader,self.pins)
        value={'loader':base64.b64encode(self.loader).decode(),'sources':{n:base64.b64encode(b).decode()for n,b in sources.items()},
            'commit':'1'*40,'sourcePins':self.pins,'approvedDeclarationHash':r.digest(manifest)if approved is None else approved}
        result=subprocess.run([sys.executable,*flags,'-c',CHILD],input=json.dumps(value).encode(),capture_output=True,timeout=30)
        return result,json.loads(result.stdout)
    def test_actual_isolated_memory_import_has_no_disk_source_fallback(self):
        result,proof=self.request();self.assertEqual(result.returncode,0,result.stdout.decode()+result.stderr.decode()[-2000:])
        self.assertTrue(proof['sealedEntryImported']);self.assertEqual(proof['moduleCount'],len(r.MODULES))
        self.assertFalse(proof['runtimeAuthorityIssued'])
    def test_changed_source_bytes_do_not_match_reviewed_declaration(self):
        changed=dict(self.sources);changed[r.ENTRY]=b'# changed after review\n'+changed[r.ENTRY]
        result,proof=self.request(changed);self.assertEqual(result.returncode,2)
        self.assertEqual(proof['reason'],'INSTALLER_SOURCE_DECLARATION_DRIFT')
    def test_missing_or_extra_module_and_foreign_import_are_denied(self):
        for change in('missing','extra','foreign','dynamic'):
            sources=dict(self.sources)
            if change=='missing':sources.pop(r.ENTRY)
            elif change=='extra':sources['foreign_module']=b'pass\n'
            elif change=='foreign':sources[r.ENTRY]=b'import unqualified_local_source\n'+sources[r.ENTRY]
            else:sources[r.ENTRY]=b'__import__(input())\n'+sources[r.ENTRY]
            with self.subTest(change=change),self.assertRaises(r.RuntimeDenied):r.compile_sources(sources)
    def test_python_without_isolation_or_site_exclusion_is_denied(self):
        result,proof=self.request(flags=('-B',));self.assertEqual(result.returncode,2)
        self.assertEqual(proof['reason'],'ISOLATED_NO_SITE_INSTALLER_PROCESS_REQUIRED')
    def test_owner_source_pins_are_explicit_not_latest_or_environment_defaults(self):
        for missing in('ouf-onboarding','ouf-api-gateway','ouf-ingestion-runtime'):
            pins=copy.deepcopy(self.pins);pins.pop(missing)
            with self.assertRaises(r.RuntimeDenied):r.declaration('1'*40,self.sources,self.loader,pins)

if __name__=='__main__':unittest.main()
