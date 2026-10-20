"""Real role/CAS reservations around synthetic direct Engine HTTP dispatch."""
import copy
import os
from pathlib import Path
import sys
import time
import unittest
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tests'),str(ROOT/'tools/semantic_policy_token_owner'),
             str(ROOT/'tools/semantic_application_cutover'),str(ROOT/'tools/semantic_cohort_admission/cohort-draft')]
import test_ingestion_rollout_execution as core
from tools.ingestion_rollout_execution import contract as c,engine_channel as e
from tools.chatbot_file_cohort.human_session import HumanSession
from engine_creation import Engine

@unittest.skipUnless(os.environ.get('OUF_NATIVE_UIDS')=='1','actual role signatures and CAS required')
class SignedEngineChannel(unittest.TestCase):
    def setUp(self):
        original=core.review_fixture
        def fixture(context='/fixture/execution',key_path=None):
            review,packet,inputs=original(context,key_path)
            review.update(maximumDirectEngineGets=4096,maximumDirectEnginePosts=32,
                engineBinding={'socketPath':'/fixture/engine.sock','socketBinding':[1,2,0,0,0o600]})
            return review,packet,inputs
        with patch.object(core,'review_fixture',side_effect=fixture):core.SignedFiniteRunner.setUp(self)
        row=self.runner.journal.read();mono=time.monotonic()
        self.runner.journal.compare_and_save(row,{**row,'expiresMonotonic':mono+480,
            'lastMonotonic':mono,'nextReadMonotonic':mono,'version':row['version']+1})
        self.human=HumanSession.__new__(HumanSession);self.human.current=lambda:self.scope['humanBinding']
        self.calls=[];self.fail=False
        def dispatch(engine,method,path,body=None):
            self.assertGreater(self.runner.journal.read()[e.COUNTERS[method]],0)
            self.calls.append((method,path))
            if self.fail:raise RuntimeError('synthetic lost response')
            return 200,{'fixture':True}
        p=patch.object(Engine,'request',dispatch);p.start();self.addCleanup(p.stop)
        self.engine=self.instance();self.channel=e.NativeEngineChannel(self.action,self.runner.journal,self.review,self.human,self.engine)
        self.path='/v1.44/containers/'+'a'*64+'/json'
    def instance(self):
        engine=Engine.__new__(Engine);engine.path=self.review['engineBinding']['socketPath']
        engine.binding=tuple(self.review['engineBinding']['socketBinding']);engine.check_socket=lambda:None
        return engine
    def save(self,**updates):
        row=self.runner.journal.read();self.runner.journal.compare_and_save(row,{**row,**updates,'version':row['version']+1})
    def claim(self):
        i=next(i for i,s in enumerate(self.review['stages'])if s['name']=='ingestion.DISABLE_OLD_RESTART')
        effects=[{'stage':s['name'],'intentHash':s['intentHash'],'state':'APPLIED'if j<i else'CLAIMED',
                  'nativeRequestAttempted':True}for j,s in enumerate(self.review['stages'][:i+1])]
        self.save(nextStage=i,effects=effects);return self.review['stages'][i]
    def test_shared_get_counter_survives_new_channel_instance(self):
        self.engine.request('GET',self.path)
        another=self.instance();e.NativeEngineChannel(self.action,self.runner.journal,self.review,self.human,another)
        another.request('GET',self.path)
        self.assertEqual(self.runner.journal.read()['nativeDirectEngineGets'],2)
        with self.assertRaises(c.Denied):e.NativeEngineChannel(self.action,self.runner.journal,self.review,self.human,self.engine)
    def test_failed_dispatch_consumes_attempt_without_implicit_retry(self):
        self.fail=True
        with self.assertRaises(RuntimeError):self.engine.request('GET',self.path)
        self.assertEqual(self.runner.journal.read()['nativeDirectEngineGets'],1);self.assertEqual(len(self.calls),1)
    def test_exhausted_budget_and_unreviewed_get_never_dispatch(self):
        with self.assertRaises(c.Denied):self.engine.request('GET','/v1.44/containers/by-name/json')
        self.save(nativeDirectEngineGets=4096)
        with self.assertRaises(c.Denied):self.engine.request('GET',self.path)
        self.assertEqual(self.calls,[])
    def test_current_human_or_window_drift_blocks_before_reservation(self):
        self.human.current=lambda:{**self.scope['humanBinding'],'sessionId':'foreign'}
        with self.assertRaises(c.Denied):self.engine.request('GET',self.path)
        self.human.current=lambda:self.scope['humanBinding'];self.save(expiresAt=time.time()+10)
        with self.assertRaises(c.Denied):self.engine.request('GET',self.path)
        self.assertNotIn('nativeDirectEngineGets',self.runner.journal.read());self.assertEqual(self.calls,[])
    def test_post_requires_exact_existing_claim_resource_and_body(self):
        stage=self.claim();path='/v1.44/containers/'+stage['intent']['oldContainerId']+'/update'
        with self.assertRaises(c.Denied):self.engine.request('POST',path,{'RestartPolicy':{'Name':'always'}})
        self.assertEqual(self.calls,[])
        self.engine.request('POST',path,{'RestartPolicy':stage['intent']['restartPolicy']})
        row=self.runner.journal.read();self.assertTrue(row['effects'][-1]['nativeEnginePostAttempted'])
        self.assertEqual(row['nativeDirectEnginePosts'],1)
        with self.assertRaises(c.Denied):self.engine.request('POST',path,{'RestartPolicy':stage['intent']['restartPolicy']})
        self.assertEqual(len(self.calls),1)
    def test_lost_post_cannot_be_redispatched_by_another_channel(self):
        stage=self.claim();path='/v1.44/containers/'+stage['intent']['oldContainerId']+'/update'
        self.fail=True
        with self.assertRaises(RuntimeError):self.engine.request('POST',path,{'RestartPolicy':stage['intent']['restartPolicy']})
        another=self.instance();e.NativeEngineChannel(self.action,self.runner.journal,self.review,self.human,another)
        with self.assertRaises(c.Denied):another.request('POST',path,{'RestartPolicy':stage['intent']['restartPolicy']})
        self.assertEqual(len(self.calls),1)

if __name__=='__main__':unittest.main()
