"""Actual isolated capsule and shell wrapper; no target or provider calls."""
import base64
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT),str(ROOT/'tests')]
import test_readiness_patch_archive_preparation as fixture
from tools.ingestion_readiness_patch_execution import archive_delivery as d

@unittest.skipUnless(os.environ.get('OUF_NATIVE_UIDS')=='1','actual isolated root capsule required')
class ArchiveDelivery(unittest.TestCase):
    def setUp(self):
        self.fixture=fixture.ArchivePreparation();self.fixture.setUp();self.addCleanup(self.fixture.doCleanups)
        self.root=self.fixture.root;self.case=self.fixture.case
        self.pins={n:'1'*40 for n in ('ouf-deploy','ouf-onboarding','ouf-ingestion-runtime','ouf-api-gateway')}
        self.raw,self.declaration=d.generate(ROOT,self.case,'1'*40,self.pins)
        self.path=self.root/'operator.py';self.path.write_bytes(self.raw);self.path.chmod(0o400)
    def run_capsule(self,mode='prepare'):
        return subprocess.run(['/usr/bin/python3','-I','-B','-S',str(self.path),mode],capture_output=True,text=True,timeout=30)
    def test_capsule_reproduces_and_executes_full_offline_preparation(self):
        self.assertEqual(d.generate(ROOT,self.case,'1'*40,self.pins)[0],self.raw)
        self.assertEqual(self.declaration['nativeDeclaration']['moduleCount'],139)
        result=self.run_capsule();self.assertEqual(result.returncode,0,result.stderr)
        value=json.loads(result.stdout);self.assertTrue(value['complete']);self.assertEqual(value['imagesImported'],0)
        self.assertEqual(value['runtimeEffectsDispatched'],0)
        self.assertEqual((self.fixture.target/'native-image.tar').read_bytes(),self.fixture.expected_archive)
        again=self.run_capsule();self.assertEqual(again.returncode,2)
        stopped=json.loads(again.stdout);self.assertEqual(stopped['status'],'STOP_RECONCILE')
        self.assertEqual(stopped['reasonCode'],'NATIVE_ARCHIVE_PREPARATION_EXISTS_RECONCILE_ONLY')
    def test_changed_case_or_wrong_mode_stops_before_creating_target(self):
        changed=copy.deepcopy(self.case);changed['nativeImageId']='sha256:'+'f'*64
        raw=self.raw.decode().replace('CASE='+repr(self.case),'CASE='+repr(changed),1)
        self.path.chmod(0o600);self.path.write_text(raw);self.path.chmod(0o400)
        result=self.run_capsule();self.assertEqual(result.returncode,2)
        self.assertEqual(json.loads(result.stdout)['reasonCode'],'NATIVE_ARCHIVE_CASE_CHANGED')
        self.assertFalse(self.fixture.target.exists())
        result=self.run_capsule('step');self.assertEqual(result.returncode,2)
        self.assertEqual(json.loads(result.stdout)['reasonCode'],'ONE_EXPLICIT_OFFLINE_ARCHIVE_PREPARATION_REQUIRED')
    def test_real_shell_wrapper_downloads_verifies_logs_and_preserves_stop(self):
        home=self.root/'home';home.mkdir(mode=0o700)
        portable=home/'ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin';portable.mkdir(parents=True)
        encoded=self.root/'source.b64';encoded.write_bytes(base64.b64encode(self.raw))
        gh=portable/'gh';gh.write_text('#!/bin/sh\ncat '+str(encoded)+'\n');gh.chmod(0o700)
        binary=self.root/'bin';binary.mkdir(mode=0o700)
        sudo=binary/'sudo';sudo.write_text('#!/bin/sh\nexec "$@"\n');sudo.chmod(0o700)
        script=self.root/'launcher.sh';script.write_bytes(d.launcher(self.raw,'2'*40));script.chmod(0o700)
        subprocess.run(['bash','-n',str(script)],check=True,capture_output=True)
        env={**os.environ,'HOME':str(home),'PATH':str(binary)+os.pathsep+os.environ['PATH']}
        result=subprocess.run(['bash',str(script)],env=env,capture_output=True,text=True,timeout=30)
        self.assertEqual(result.returncode,0,result.stderr);logs=list(home.glob('ouf-native-archive.*/operator.log'))
        self.assertEqual(len(logs),1);self.assertTrue(json.loads(logs[0].read_bytes())['complete'])
        self.assertIn('Log conservato:',result.stdout)
        again=subprocess.run(['bash',str(script)],env=env,capture_output=True,text=True,timeout=30)
        self.assertEqual(again.returncode,2);self.assertIn('STOP_RECONCILE',again.stdout)
        self.assertTrue(logs[0].exists())
    def test_corrupt_download_is_rejected_before_sudo(self):
        home=self.root/'home';home.mkdir(mode=0o700)
        portable=home/'ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin';portable.mkdir(parents=True)
        gh=portable/'gh';gh.write_text('#!/bin/sh\nprintf %s Zm9yZWlnbg==\n');gh.chmod(0o700)
        binary=self.root/'bin';binary.mkdir(mode=0o700)
        marker=self.root/'sudo-was-called';sudo=binary/'sudo'
        sudo.write_text('#!/bin/sh\ntouch '+str(marker)+'\nexit 99\n');sudo.chmod(0o700)
        script=self.root/'launcher.sh';script.write_bytes(d.launcher(self.raw,'2'*40))
        result=subprocess.run(['bash',str(script)],env={**os.environ,'HOME':str(home),
            'PATH':str(binary)+os.pathsep+os.environ['PATH']},capture_output=True,text=True,timeout=30)
        self.assertNotEqual(result.returncode,0);self.assertFalse(marker.exists());self.assertFalse(self.fixture.target.exists())

if __name__=='__main__':unittest.main()
