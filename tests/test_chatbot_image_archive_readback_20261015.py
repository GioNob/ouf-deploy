import importlib.util
import io
import base64
import gzip
import tarfile
import json
import os
from pathlib import Path
import socket
import stat
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch, Mock

FILE=Path(__file__).resolve().parents[1]/'scripts/read-chatbot-image-archives-20261015.py'
spec=importlib.util.spec_from_file_location('image_readback',FILE)
reader=importlib.util.module_from_spec(spec);spec.loader.exec_module(reader)
ROOT=Path(__file__).resolve().parents[1]
VALIDATOR=ROOT/'tools/semantic_application_cutover/image_custody.py'
if not VALIDATOR.is_file():VALIDATOR=ROOT.parent/'ouf-deploy/tools/semantic_application_cutover/image_custody.py'
def bundle_source():
    return {'sources':{'image_custody':base64.b64encode(VALIDATOR.read_bytes()).decode()},
        'declaration':{'sourceHashes':{'image_custody':reader.VALIDATOR_SHA256}}}


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
            prepared['imagePlan']['images'].append({'module':module,'audit':audit,'archivePath':str(self.root/(module+'.tar'))})
            directory=context/('image'+module.capitalize());directory.mkdir(mode=0o700)
            directories['image'+module.capitalize()]=str(directory)
        for name in ('containers','databases','gateway','gatewayRuntime'):
            directory=context/name;directory.mkdir(mode=0o700);directories[name]=str(directory)
        def write(path,value):
            path.write_text(json.dumps(value,sort_keys=True,separators=(',',':')));path.chmod(0o600)
        bundle=self.root/'bundle.json';write(bundle,dict(bundle_source(),prepared=prepared))
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
             patch.object(reader.subprocess,'run',return_value=Mock(returncode=0,stdout=b'ActiveState=inactive\nMainPID=0\n')),redirect_stdout(output):
            reader.main()
        records=[json.loads(line) for line in output.getvalue().splitlines()]
        self.assertEqual([r['module'] for r in records if r['check']=='IMAGE'],list(reader.MODULES))
        self.assertEqual(before,{p:p.read_bytes() for p in self.root.rglob('*') if p.is_file()})
        self.assertEqual(records[-1]['imageImportRequests'],0)
        self.assertNotIn('never-print',output.getvalue())
    def test_invalid_image_cannot_connect(self):
        with self.assertRaisesRegex(ValueError,'EXACT_IMAGE_ID_REQUIRED'):reader.inspect({},'invalid')

class ArchiveReadback(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)
        self.validator=reader.validator_from_bundle(bundle_source())
    def archive(self):
        raw_layer=b'disposable uncompressed layer bytes'
        layer=gzip.compress(raw_layer,mtime=0)
        image={'os':'linux','architecture':'amd64',
            'config':{'Env':['SECRET=private-fixture'],'Labels':{'org.opencontainers.image.revision':'c'*40}},
            'rootfs':{'type':'layers','diff_ids':['sha256:'+reader.hashlib.sha256(raw_layer).hexdigest()]}}
        config=json.dumps(image).encode();identity='sha256:'+reader.hashlib.sha256(config).hexdigest()
        path=self.root/'image.tar'
        with tarfile.open(path,'w') as tar:
            rows={'manifest.json':json.dumps([{'Config':'config.json','RepoTags':None,'Layers':['layer.tar.gz']}]).encode(),
                'config.json':config,'layer.tar.gz':layer}
            for name,body in rows.items():
                info=tarfile.TarInfo(name);info.size=len(body);tar.addfile(info,io.BytesIO(body))
        path.chmod(0o600)
        sha=reader.hashlib.sha256(path.read_bytes()).hexdigest()
        with path.open('rb') as stream:audit=self.validator.archive(stream,sha,identity,'c'*40)
        return {'archivePath':str(path),'audit':audit}
    def test_exact_gzip_archive_and_serialized_audit_no_file_mutation(self):
        row=self.archive();path=Path(row['archivePath']);before=path.read_bytes()
        value=reader.archive_readback(json.loads(json.dumps(row)),self.validator)
        self.assertTrue(value['archiveAuditMatches']);self.assertTrue(value['tagless'])
        self.assertEqual(path.read_bytes(),before);self.assertNotIn('SECRET',json.dumps(value))
    def test_tampered_validator_never_executes(self):
        bundle=bundle_source();bundle['sources']['image_custody']=base64.b64encode(b'raise RuntimeError("MUST_NOT_EXECUTE")').decode()
        with self.assertRaisesRegex(ValueError,'EXACT_READ_ONLY_IMAGE_VALIDATOR_REQUIRED'):reader.validator_from_bundle(bundle)
    def test_changed_archive_reports_safe_original_validator_code(self):
        row=self.archive();row['audit']['archiveSha256']='0'*64
        with self.assertRaisesRegex(ValueError,'AUTHENTICATED_ARCHIVE_BYTES_CHANGED'):reader.archive_readback(row,self.validator)
    def test_same_archive_different_approved_audit_reports_only_field(self):
        row=self.archive();row['audit']['targetApplyAuthorized']=True
        value=reader.archive_readback(row,self.validator)
        self.assertFalse(value['archiveAuditMatches']);self.assertEqual(value['archiveAuditMismatchFields'],['targetApplyAuthorized'])

if __name__=='__main__':unittest.main()
