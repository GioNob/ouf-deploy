"""Actual archive FD and signed/CAS import protocol; synthetic image loader.

No archive audit or Docker load is performed. Existing release-byte and native
image qualification remain separate from these once-only protocol tests.
"""
import copy
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tests'),str(ROOT/'tools/semantic_policy_token_owner'),
             str(ROOT/'tools/semantic_application_cutover'),str(ROOT/'tools/semantic_cohort_admission/cohort-draft')]
from tools.ingestion_rollout_execution import image_import as i,private_file as f,contract as c
from test_ingestion_rollout_gateway_transport import binding
from tools.ingestion_rollout_execution.database_read import empty_config_directory

class ArchiveDescriptor(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(dir=os.environ.get('OUF_TEST_ROOT',str(ROOT)))
        self.addCleanup(self.temp.cleanup);self.path=Path(self.temp.name)/'archive';self.path.write_bytes(b'public archive fixture')
        self.path.chmod(0o600);self.binding=binding(self.path)
    def test_verified_fd_is_at_start_and_closes_after_use(self):
        with f.opened(self.binding)as fd:self.assertEqual(os.read(fd,100),self.path.read_bytes())
        with self.assertRaises(OSError):os.fstat(fd)
    def test_changed_archive_during_consumption_is_not_a_successful_context(self):
        with self.assertRaises(c.Denied):
            with f.opened(self.binding):self.path.write_bytes(b'changed')
    def test_large_archive_requires_explicit_limit_without_raising_private_secret_limit(self):
        self.path.write_bytes(b'x'*1048577);selected=binding(self.path)
        with self.assertRaises(c.Denied):f.read(selected)
        with f.opened(selected,maximum=1048577)as fd:self.assertEqual(os.read(fd,1),b'x')
        with self.assertRaises(c.Denied):f.validate(selected,maximum=2147483649)
    def test_metadata_guard_detects_replacement_without_reauditing_contents(self):
        f.check_metadata(self.binding)
        self.path.rename(self.path.with_name('retained'));self.path.write_bytes(b'public archive fixture');self.path.chmod(0o600)
        with self.assertRaises(c.Denied):f.check_metadata(self.binding)

@unittest.skipUnless(os.environ.get('OUF_NATIVE_UIDS')=='1','actual root roles and journal required')
class SignedImageImport(unittest.TestCase):
    def setUp(self):
        import test_ingestion_rollout_execution as core
        from engine_creation import Engine
        from tools.ingestion_rollout_execution.replacement import EngineReader
        from tools.chatbot_file_cohort.human_session import HumanSession
        self.temp=tempfile.TemporaryDirectory(dir=os.environ['OUF_TEST_ROOT']);self.addCleanup(self.temp.cleanup)
        root=Path(self.temp.name);root.chmod(0o700)
        archive=root/'already-qualified-fixture.tar';archive.write_bytes(b'qualified fixture archive bytes');archive.chmod(0o600)
        self.archive=archive;config=root/'empty-docker-config';config.mkdir(mode=0o700)
        self.profile={'schema':'ouf.ingestion-rollout-native-image-load.v1',
            'engineBinding':{'socketPath':'/ente-fixture/engine.sock','socketBinding':[1,2,0,0,0o600]},
            'dockerExecutable':i.governance.executable(os.environ.get('OUF_TEST_PYTHON',sys.executable)),
            'dockerConfigDirectory':str(config),'dockerConfigIdentity':empty_config_directory(str(config)),
            'archive':binding(archive)}
        original=core.review_fixture
        def fixture(context='/fixture/execution',key_path=None):
            review,packet,inputs=original(context,key_path)
            candidate=inputs['candidate'];candidate['nativeArchiveBinding']={k:self.profile['archive'][k]for k in('path','sha256','metadata')}
            candidate['sourceCommit']='1'*40
            candidate['imageConfig'].setdefault('Labels',{})['org.opencontainers.image.revision']=candidate['sourceCommit']
            packet['candidate']=candidate;packet['verifiedInputsHash']=c.digest(inputs)
            review=c.compile_review(packet,{'path':'/fixture/packet-plan','sha256':c.digest(packet)},inputs,
                                    review['humanBinding'],context)
            review['imageImportProfile']=copy.deepcopy(self.profile);self.packet=packet
            return review,packet,inputs
        with patch.object(core,'review_fixture',side_effect=fixture):core.SignedFiniteRunner.setUp(self)
        self.mono=time.monotonic()
        row=self.runner.record();self.runner.journal.compare_and_save(row,{**row,'lastMonotonic':self.mono,
            'expiresMonotonic':self.mono+480,'nextReadMonotonic':self.mono,'version':row['version']+1})
        engine=Engine.__new__(Engine);engine.path=self.profile['engineBinding']['socketPath']
        engine.binding=tuple(self.profile['engineBinding']['socketBinding']);engine.check_socket=lambda:None
        self.image_present=False;self.image_drift=False
        def request(method,path,body=None):
            self.assertEqual(method,'GET');self.assertIn('/images/',path)
            if not self.image_present:return 404,None
            candidate=self.packet['candidate']
            config=copy.deepcopy(candidate['imageConfig'])
            if self.image_drift:config['Cmd']=['foreign']
            return 200,{'Id':candidate['nativeImageId'],'Os':'linux','Architecture':'amd64','Config':config,
                        'RootFS':{'Type':'layers','Layers':candidate['rootfs']['diff_ids']}}
        engine.request=request
        human=HumanSession.__new__(HumanSession);human.current=lambda:self.scope['humanBinding']
        self.native=i.NativeImageImport(self.action,self.runner.journal,self.review,self.packet,human,EngineReader(engine))
        original_apply=self.ports.apply;original_observe=self.ports.observe
        self.ports.apply=lambda s:self.native.apply()if s['name']=='IMPORT_INGESTION_IMAGE'else original_apply(s)
        self.ports.observe=lambda s:self.native.observe()if s['name']=='IMPORT_INGESTION_IMAGE'else original_observe(s)
        while self.runner.record()['nextStage']<self.native.index:self.runner.step()
        self.loads=0;self.failure=None
        def load(args,fd):
            self.loads+=1;self.assertTrue(self.runner.record()['effects'][-1]['nativeImageImportAttempted'])
            self.assertEqual(args[-1],'load');self.assertNotIn('--input',args)
            self.assertEqual(os.read(fd,100),b'qualified fixture archive bytes')
            if self.failure=='before':raise OSError('synthetic load interrupted before image')
            self.image_present=True
            if self.failure=='after':raise OSError('synthetic load response lost')
        loading=patch.object(i,'load',side_effect=load);loading.start();self.addCleanup(loading.stop)
    def test_claim_precedes_load_from_verified_fd_and_exact_image_reconciliation(self):
        self.runner.step();self.assertEqual(self.loads,1)
        effect=self.runner.record()['effects'][self.native.index]
        self.assertTrue(effect['evidence']['qualifiedNativeImageMatched']);self.assertTrue(effect['evidence']['importAttemptedByThisAction'])
        with self.assertRaises(c.Denied):self.native.apply()
        self.assertEqual(self.loads,1)
    def test_existing_exact_image_is_adopted_without_loading(self):
        self.image_present=True;self.runner.step();self.assertEqual(self.loads,0)
        proof=self.runner.record()['effects'][self.native.index]['evidence'];self.assertTrue(proof['existingQualifiedImageAdopted'])
        self.assertFalse(proof['importAttemptedByThisAction'])
    def test_lost_success_response_reconciles_without_second_load(self):
        self.failure='after'
        with self.assertRaises(OSError):self.runner.step()
        with self.assertRaises(c.Paused):self.runner.step()
        result=self.runner.reconcile();self.assertFalse(result['effectReplayed']);self.assertEqual(self.loads,1)
    def test_lost_before_image_retains_unknown_claim_and_cannot_reload(self):
        self.failure='before'
        with self.assertRaises(OSError):self.runner.step()
        with self.assertRaises(c.Paused):self.runner.reconcile()
        with self.assertRaises(c.Denied):self.native.apply()
        self.assertEqual(self.loads,1)
    def test_changed_archive_cannot_be_loaded_or_adopted(self):
        self.archive.write_bytes(b'changed')
        with self.assertRaises(c.Denied):self.runner.step()
        self.assertEqual(self.loads,0)
    def test_existing_foreign_config_is_not_adopted(self):
        self.image_present=True;self.image_drift=True
        with self.assertRaises(c.Denied):self.runner.step()
        self.assertEqual(self.loads,0)
    def test_revoked_role_blocks_before_load(self):
        import json
        policy=json.loads(self.crypto.policy.read_bytes());policy['keys'][0]['state']='REVOKED'
        self.crypto.write(self.crypto.policy,c.encoded(policy))
        with self.assertRaises(Exception):self.runner.step()
        self.assertEqual(self.loads,0)

if __name__=='__main__':unittest.main()
