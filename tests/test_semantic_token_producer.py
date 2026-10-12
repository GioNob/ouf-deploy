import importlib.util,json,os,types,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
def load(name,path):
    s=importlib.util.spec_from_file_location(name,ROOT/path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
reader=load('token_producer_reader','scripts/read-semantic-token-producer.py')
fixtures=load('token_producer_fixture','tests/test_retained_v11_source_expectations.py')
planner_raw=(ROOT/'scripts/prepare-retained-v11-source-expectations.py').read_bytes()
atomic_raw=(ROOT/'tools/semantic_application_cutover/atomic_review_intake.py').read_bytes()
class Producer(unittest.TestCase):
    def test_command_only_direct_root_python_source_no_inline_module_or_secret_output(self):
        raw='Type=oneshot\nUser=root\nExecStart={ path=/usr/bin/python3 ; argv[]=/usr/bin/python3 -I -B /usr/local/bin/ouf-token.py semantic --secret DO_NOT_PRINT ; ignore_errors=no ; }'
        path,args,role=reader.command(raw);self.assertEqual(path,Path('/usr/local/bin/ouf-token.py'));self.assertTrue(role)
        for bad in (raw.replace('-I -B /usr/local/bin/ouf-token.py','-c "secretcode"'),raw.replace('-I -B /usr/local/bin/ouf-token.py','-m secrets'),raw.replace('Type=oneshot','Type=simple'),raw.replace('User=root','User=10001')):
            with self.assertRaises(reader.Denied):reader.command(bad)
    def test_ast_redacts_literal_values_even_when_equal_to_public_keys_or_numbers(self):
        token=Path('/private/semantic/token.jwt')
        code=b'''import os
secret="semantic"
password=10001
cfg={"semantic":{"client_secret":"semantic","grant_type":"client_credentials","access_token":"RAW_JWT_DO_NOT_PRINT"}}
output="/private/semantic/token.jwt"
os.replace("PRIVATE_TMP_PATH",output)
'''
        out=reader.redact(code,token);text=out['redactedSource']
        self.assertIn("'semantic':",text);self.assertIn('MOUNT0_TOKEN_FILE',text)
        for private in ('RAW_JWT','PRIVATE_TMP_PATH','/private','10001',"secret = 'semantic'","'client_secret': 'semantic'"):
            self.assertNotIn(private,text)
        self.assertFalse(out['redactedSourceTruncated'])
    def test_source_read_excludes_credential_scopes_and_symlinks(self):
        f=fixtures.Expectations();f.setUp();self.addCleanup(f.doCleanups)
        p=reader.load_planner(planner_raw)
        with patch.object(reader,'SOURCE_ROOTS',(str(f.root)+'/',)):
            with self.assertRaises(reader.Denied):reader.source(p,f.file,[f.file])
            with self.assertRaises(reader.Denied):reader.source(p,f.directory/'code.py',[f.directory])
            code=f.root/'code.py';code.write_bytes(b'import os\n');code.chmod(0o600)
            raw,info=reader.source(p,code,[f.file,f.directory]);self.assertEqual(raw,b'import os\n')
            link=f.root/'linked.py';link.symlink_to(code)
            with self.assertRaises(OSError):reader.source(p,link,[f.file,f.directory])
        with self.assertRaises(reader.Denied):reader.load_planner(planner_raw+b'\n')
    def test_complete_selected_parent_read_never_runs_producer_and_is_redacted(self):
        f=fixtures.Expectations();f.setUp();self.addCleanup(f.doCleanups)
        bindings,files=f.fixture(mixed=True);p=reader.load_planner(planner_raw)
        for k,v in bindings.items():
            if k!='sys':setattr(p,k,v)
        atomic=p.atomic_source(atomic_raw);code=b'import os\nsecret="RAW_SECRET_DO_NOT_PRINT"\nos.replace("TMP","OUT")\n'
        info=types.SimpleNamespace(st_uid=0,st_gid=0,st_mode=0o100755)
        original=p.identity;p.identity=lambda v: (0,0,0o100755) if v is info else original(v)
        wire='Type=oneshot\nUser=root\nExecStart={ path=/usr/bin/python3 ; argv[]=/usr/bin/python3 /usr/local/bin/ouf-token.py semantic ; }'
        before={x.name:x.read_bytes() for x in p.PARENT.iterdir()}
        with patch.object(reader,'unit_read',return_value=wire),patch.object(reader,'source',return_value=(code,info)):
            out=reader.collect(p,atomic)
        self.assertTrue(out['stableSourceAndCommand']);self.assertTrue(out['semanticArgumentObserved'])
        self.assertNotIn('RAW_SECRET',json.dumps(out))
        self.assertEqual(before,{x.name:x.read_bytes() for x in p.PARENT.iterdir()})
        self.assertEqual(len(list(p.BASE.iterdir())),1)
if __name__=='__main__':unittest.main()
