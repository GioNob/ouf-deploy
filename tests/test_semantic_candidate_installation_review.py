import ast
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import patch
import zipfile

spec=importlib.util.spec_from_file_location('delivery',Path(__file__).parents[1]/'scripts/prepare-semantic-candidate-installation-review.py')
delivery=importlib.util.module_from_spec(spec);spec.loader.exec_module(delivery)

def helpers():
    tree=ast.parse(delivery.ROOT_BODY)
    selected=[n for n in tree.body if isinstance(n,(ast.Import,ast.ImportFrom,ast.Assign,ast.FunctionDef))
              and not(isinstance(n,ast.FunctionDef)and n.name in {'execute','main_root'})]
    scope={};exec(compile(ast.Module(body=selected,type_ignores=[]),'actual-review-helpers','exec'),scope)
    return scope

class ReviewTests(unittest.TestCase):
    def setUp(self):
        self.scope=helpers()
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)/'packages';self.root.mkdir(mode=0o700)
        self.scope['PACKAGE_DIRECTORY']=self.root

    def package(self,authority=False):
        if os.geteuid()==0:os.chown(self.root,1000,1000)
        path=self.root/'semantic.zip'
        manifest={'schema':'ouf.semantic-proposal-unsigned-candidate.v1','module':'semantic',
          'sourceCommit':self.scope['PACKAGES']['semantic'][1],'imageId':self.scope['IMAGE'],
          'runtimeAuthorityIssued':False,'signatureIssued':False,'targetApplyAuthorized':authority,
          'r12Touched':False,'budgetReset':False,'notReleaseAcceptance':True,'vpsOperations':0}
        with zipfile.ZipFile(path,'w')as z:z.writestr('candidate-manifest.json',json.dumps(manifest))
        if os.geteuid()==0:os.chown(path,1000,1000)
        expected=hashlib.sha256(path.read_bytes()).hexdigest()
        self.scope['PACKAGES']={**self.scope['PACKAGES'],'semantic':(expected,manifest['sourceCommit'])}
        return path

    def test_exact_bytes_read_without_establishing_root_custody(self):
        self.package();value=self.scope['delivered_package']('semantic')
        self.assertFalse(value['rootCustodyEstablished'])
        self.assertEqual(value['manifest']['imageId'],self.scope['IMAGE'])

    def test_changed_bytes_and_symlink_are_denied(self):
        path=self.package();path.write_bytes(b'drift')
        with self.assertRaisesRegex(ValueError,'SHA256_MISMATCH'):self.scope['delivered_package']('semantic')
        path.unlink();path.symlink_to(self.root/'missing')
        with self.assertRaises(OSError):self.scope['delivered_package']('semantic')

    def test_unsigned_manifest_cannot_claim_authority(self):
        self.package(authority=True)
        with self.assertRaisesRegex(ValueError,'NO_AUTHORITY'):self.scope['delivered_package']('semantic')

    def test_native_query_omits_environment_and_denies_generation_drift(self):
        value=dict(id=self.scope['CID'],image=self.scope['OLD_IMAGE'],pid=123,startedAt='fixture',running=True,
          restartPolicy={'Name':'unless-stopped'},mounts=[])
        def run(argv,**kwargs):
            self.assertEqual(argv[0:3],['/usr/bin/docker','inspect','--type'])
            self.assertNotIn('.Config',argv[argv.index('--format')+1])
            return types.SimpleNamespace(returncode=0,stdout=json.dumps(value).encode())
        with patch.object(self.scope['subprocess'],'run',side_effect=run):
            self.assertEqual(self.scope['registry_metadata'](),value)
            value['image']='sha256:changed'
            with self.assertRaisesRegex(ValueError,'GENERATION_CHANGED'):self.scope['registry_metadata']()

    def test_existing_portable_client_is_used_before_sudo_and_bad_download_never_reaches_root(self):
        preferred=Path.home()/'ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh'
        calls=[]
        def command(argv,**kwargs):
            calls.append(argv)
            return types.SimpleNamespace(stdout=__import__('base64').b64encode(b'wrong'))
        with patch.object(delivery.Path,'is_file',return_value=True),patch.object(delivery.os,'access',return_value=True),\
             patch.object(delivery.shutil,'which',side_effect=AssertionError('PATH fallback must not run')),\
             patch.object(delivery.subprocess,'run',side_effect=command):
            with self.assertRaisesRegex(SystemExit,'HASH_MISMATCH'):delivery.main()
        self.assertEqual(len(calls),1);self.assertEqual(calls[0][0],str(preferred))

    def test_actual_root_body_loads_exact_capsule_and_fails_before_private_target_access(self):
        capsule=Path(__file__).parents[1]/delivery.CAPSULE_PATH
        raw=capsule.read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(),delivery.CAPSULE_SHA)
        bootstrap='CAPSULE_SHA='+repr(delivery.CAPSULE_SHA)+'\nROOT_BODY_HASH='+repr(hashlib.sha256(delivery.ROOT_BODY.encode()).hexdigest())+'\n'+delivery.ROOT_BODY
        reply=subprocess.run([sys.executable,'-I','-B','-S','-c',bootstrap],input=raw,
                             stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30)
        self.assertEqual(reply.returncode,1)
        row=json.loads(reply.stdout)
        self.assertEqual(row['phase'],'EXACT_DELIVERED_CANDIDATE_READ')
        self.assertEqual(row['errno'],2)
        self.assertEqual(row['runtimeOperations'],0)
        self.assertEqual(row['privateEvidenceWrites'],0)

if __name__=='__main__':unittest.main()
