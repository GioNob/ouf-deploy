import hashlib, importlib.util, json, os, tempfile, unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('binding',ROOT/'scripts/read-semantic-token-output-binding.py')
binding=importlib.util.module_from_spec(spec); spec.loader.exec_module(binding)

class Binding(unittest.TestCase):
    def config(self):
        return {key:'PRIVATE_VALUE' for key in binding.KEYS}|{
            'OUF_POLICY_TOKEN_RUNTIME_DIR':'/private/runtime',
            'OUF_POLICY_TOKEN_RUNTIME_GID':'10001',
            'OUF_POLICY_TOKEN_ENDPOINT':'https://PRIVATE_HOST/token'}

    def test_sealed_observer_and_no_config_evaluation(self):
        self.assertEqual(hashlib.sha256(binding.OBSERVER_SOURCE).hexdigest(),binding.OBSERVER_HASH)
        cfg=self.config(); raw='\n'.join(key+'="'+value+'"' for key,value in cfg.items()).encode()
        self.assertEqual(binding.parse_config(raw),cfg)
        for bad in (raw+b'\nUNKNOWN_SECRET=DO_NOT_PRINT',raw+b'\nOUF_POLICY_TOKEN_CLIENT_ID=duplicate',
                    raw.replace(b'PRIVATE_VALUE',b'$(DO_NOT_EXECUTE)\\x',1)):
            with self.assertRaises(ValueError): binding.parse_config(bad)

    def test_correspondence_is_boolean_only_not_authority(self):
        old=[{'binding':{'Source':'/private/runtime','RW':False},'sourceMetadata':[
            {'kind':'directory','gid':10001},{'path':'token.jwt','gid':10001}]}]
        result=binding.compare(self.config(),'token.jwt',old)
        self.assertTrue(result['configuredOutputMatchesHistoricalMount0'])
        self.assertTrue(result['configuredRuntimeGidMatchesHistoricalMount0'])
        self.assertNotIn('/private',json.dumps(result)); self.assertNotIn('PRIVATE_VALUE',json.dumps(result))
        self.assertFalse(binding.compare(self.config(),'different.jwt',old)['configuredOutputMatchesHistoricalMount0'])
        cfg=self.config(); cfg['OUF_POLICY_TOKEN_RUNTIME_GID']='1234'
        self.assertFalse(binding.compare(cfg,'token.jwt',old)['configuredRuntimeGidMatchesHistoricalMount0'])

    def test_static_output_flow_never_executes_source(self):
        raw=b'''def config():
 runtime_dir=Path(required("OUF_POLICY_TOKEN_RUNTIME_DIR"))
 return {"dir":runtime_dir}
def refresh():
 directory=cfg["dir"]
 os.replace(temporary,directory/"token.jwt")
raise RuntimeError("DO_NOT_EXECUTE")
'''
        self.assertEqual(binding.output_member(raw),'token.jwt')
        with self.assertRaises(ValueError): binding.output_member(raw.replace(b'directory/',b'foreign/'))

    def fixture(self):
        temporary=tempfile.TemporaryDirectory(dir=ROOT); self.addCleanup(temporary.cleanup)
        path=Path(temporary.name)/'selected.env'; path.write_bytes(b'PRIVATE_CONFIG'); path.chmod(0o600)
        return path

    def test_private_native_read_denies_symlinks_hardlinks_and_modes(self):
        path=self.fixture(); self.assertEqual(binding.private_read(path),b'PRIVATE_CONFIG')
        link=path.parent/'link.env'; link.symlink_to(path)
        with self.assertRaises(ValueError): binding.private_read(link)
        os.link(path,path.parent/'hardlink.env')
        with self.assertRaises(ValueError): binding.private_read(path)
        (path.parent/'hardlink.env').unlink(); path.chmod(0o644)
        with self.assertRaises(ValueError): binding.private_read(path)

    def test_private_replacement_during_read_denied(self):
        path=self.fixture(); original=os.read; replaced=False
        def read(fd,count):
            nonlocal replaced
            raw=original(fd,count)
            if not replaced:
                other=path.parent/'replacement'; other.write_bytes(b'PRIVATE_CONFIG'); other.chmod(0o600)
                other.replace(path); replaced=True
            return raw
        with patch.object(binding.os,'read',side_effect=read):
            with self.assertRaises(ValueError): binding.private_read(path)

    def test_duplicate_private_json_denied(self):
        with self.assertRaises(ValueError): binding.decode(b'{"key":1,"key":2}')

    def test_remapped_or_optional_config_source_denied(self):
        good='EnvironmentFiles=/private/selected.env (ignore_errors=no)\nUnsetEnvironment=\nRootDirectory=\nRootImage=\nBindPaths=\nBindReadOnlyPaths=\nTemporaryFileSystem=\n'
        for bad in (good.replace('ignore_errors=no','ignore_errors=yes'),
                    good.replace('RootDirectory=','RootDirectory=/other'),
                    good.replace('UnsetEnvironment=','UnsetEnvironment=OUF_POLICY_TOKEN_RUNTIME_DIR')):
            result=type('Result',(),{'returncode':0,'stdout':bad.encode()})()
            with patch.object(binding.subprocess,'run',return_value=result):
                with self.assertRaises(ValueError): binding.routing()

if __name__=='__main__': unittest.main()
