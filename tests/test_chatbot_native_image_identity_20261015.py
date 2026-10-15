import importlib.util
import io
import json
import os
from pathlib import Path
import socket
import stat
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch, Mock

FILE=Path(__file__).resolve().parents[1]/'scripts/read-chatbot-native-image-identity-20261015.py'
spec=importlib.util.spec_from_file_location('image_readback',FILE)
reader=importlib.util.module_from_spec(spec);spec.loader.exec_module(reader)

class Readback(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)
        self.audit={'imageId':'sha256:'+'a'*64,'layers':[{'diffId':'sha256:'+'b'*64}],
            'imageConfig':{'Env':['SECRET=never-print'], 'WorkingDir':'/'}}
        self.native={'Id':self.audit['imageId'],'Os':'linux','Architecture':'amd64',
            'RootFS':{'Type':'layers','Layers':['sha256:'+'b'*64]},'Config':dict(self.audit['imageConfig'])}
    def test_exact_and_absent(self):
        value=reader.comparisons(self.audit,self.native)
        self.assertTrue(value['identityPass'] and value['rootfsPass'] and value['executionConfigPass'])
        self.assertEqual(reader.comparisons(self.audit,None),{'imagePresent':False})
    def test_private_config_mismatch_only_names_and_types(self):
        self.native['Config']['Env']=['PASSWORD=must-never-print']
        value=reader.comparisons(self.audit,self.native)
        self.assertEqual(value['executionConfigMismatchFields'],['Env'])
        self.assertNotIn('PASSWORD',json.dumps(value));self.assertNotIn('SECRET',json.dumps(value))
    def test_native_manifest_id_is_distinct_from_exact_configuration(self):
        self.native['Id']='sha256:'+'c'*64
        value=reader.comparisons(self.audit,self.native)
        self.assertFalse(value['identityPass']);self.assertTrue(value['rootfsPass']);self.assertTrue(value['executionConfigPass'])
    def test_rootfs_drift(self):
        self.native['RootFS']['Layers']=[]
        self.assertFalse(reader.comparisons(self.audit,self.native)['rootfsPass'])
    def test_private_json_hash_and_symlink(self):
        path=self.root/'input.json';path.write_text('{"a":1}');path.chmod(0o600)
        self.assertEqual(reader.read(path,100),{'a':1})
        with self.assertRaisesRegex(ValueError,'READ_BINDING_DRIFT'):reader.read(path,100,'0'*64)
        link=self.root/'alias';link.symlink_to(path)
        with self.assertRaisesRegex(ValueError,'EXACT_READ_PATH_REQUIRED'):reader.read(link,100)
    def test_overlarge_or_public_file_denied(self):
        path=self.root/'input.json';path.write_text('{}');path.chmod(0o644)
        with self.assertRaises(ValueError):reader.read(path,100)
        path.chmod(0o600)
        with self.assertRaises(ValueError):reader.read(path,1)
    def test_exception_body_redacted(self):
        self.assertEqual(reader.safe_reason(ValueError('private /credentials/token')), 'ValueError')
        self.assertEqual(reader.safe_reason(RuntimeError('SECRET')), 'RuntimeError')
        self.assertEqual(reader.safe_reason(ValueError('READ_BINDING_DRIFT')), 'READ_BINDING_DRIFT')
    def test_http_transport_is_get_only(self):
        path=str(self.root/'engine.sock')
        info=Mock(st_mode=stat.S_IFSOCK|0o600,st_dev=1,st_ino=2,st_uid=0,st_gid=0)
        engine={'socketPath':path,'socketBinding':[1,2,0,0,0o600]}
        response=Mock(status=200);response.read.return_value=json.dumps(self.native).encode()
        with patch.object(reader.os,'stat',return_value=info), \
             patch.object(reader.http.client.HTTPConnection,'request') as request, \
             patch.object(reader.http.client.HTTPConnection,'getresponse',return_value=response):
            code,value=reader.inspect(engine,self.audit['imageId'])
        self.assertEqual(code,200);self.assertEqual(value,self.native)
        request.assert_called_once_with('GET','/v1.44/images/'+self.audit['imageId']+'/json')
    def test_complete_readback_preserves_files_and_reports_all_modules(self):
        context=self.root/'context';context.mkdir(mode=0o700)
        prepared={'engine':{},'imagePlan':{'images':[]}}
        directories={}
        for module in reader.MODULES:
            audit=dict(self.audit,sourceCommit='a'*40,archiveSha256='b'*64)
            prepared['imagePlan']['images'].append({'module':module,'audit':audit})
            directory=context/('image'+module.capitalize());directory.mkdir(mode=0o700)
            directories['image'+module.capitalize()]=str(directory)
        for name in ('containers','databases','gateway','gatewayRuntime'):
            directory=context/name;directory.mkdir(mode=0o700);directories[name]=str(directory)
        def write(path,value):
            path.write_text(json.dumps(value,sort_keys=True,separators=(',',':')));path.chmod(0o600)
        bundle=self.root/'bundle.json';write(bundle,{'prepared':prepared})
        process={'authorityDirectory':str(context),'unit':'ouf-file-cohort-'+'d'*32+'.service',
            'bundle':{'path':str(bundle),'sha256':reader.hashlib.sha256(bundle.read_bytes()).hexdigest()},'directoryPlan':directories}
        write(context/'authority.json',{'finiteActionProcess':process})
        authority=reader.hashlib.sha256((context/'authority.json').read_bytes()).hexdigest()
        write(context/'review.json',{'sourceClosure':{'declaration':{'sourceCommit':reader.SOURCE}},
            'scopes':{'finiteActionProcess':process},'privateInputHashes':{'preparedInputs':reader.digest(prepared)}})
        write(context/'delivery-status.json',{'phase':'PAUSED_REQUIRES_RECONCILIATION','reason':'ValueError','authorityHash':authority})
        for row in prepared['imagePlan']['images']:
            intent={k:row['audit'][k] for k in ('imageId','sourceCommit','archiveSha256')}
            write(Path(directories['image'+row['module'].capitalize()])/'recovery.json',
                {'schema':'ouf.image-import-journal.v1','authorityHash':authority,'intent':intent,
                'contextHash':reader.digest({'intent':intent,'authorityHash':authority}),
                'state':'IN_FLIGHT','version':1,'effectAttemptCount':1,'imageCustodyProven':False})
        before={p:p.read_bytes() for p in self.root.rglob('*') if p.is_file()}
        output=io.StringIO()
        with patch.object(reader,'CONTEXT',context),patch.object(reader,'AUTHORITY',authority), \
             patch.object(reader,'inspect',return_value=(200,self.native)), \
             patch.object(reader,'get',return_value=(200,[{'Id':self.audit['imageId']}])), \
             patch.object(reader.subprocess,'run',return_value=Mock(returncode=0,stdout=b'ActiveState=inactive\nMainPID=0\n')),redirect_stdout(output):
            reader.main()
        records=[json.loads(line) for line in output.getvalue().splitlines()]
        self.assertEqual([r['module'] for r in records if r['check']=='NATIVE_IDENTITY'],list(reader.MODULES))
        self.assertEqual(before,{p:p.read_bytes() for p in self.root.rglob('*') if p.is_file()})
        self.assertEqual(records[-1]['imageImportRequests'],0)
        self.assertNotIn('never-print',output.getvalue())
    def test_invalid_image_cannot_connect(self):
        with self.assertRaisesRegex(ValueError,'EXACT_IMAGE_ID_REQUIRED'):reader.inspect({},'invalid')

if __name__=='__main__':unittest.main()
