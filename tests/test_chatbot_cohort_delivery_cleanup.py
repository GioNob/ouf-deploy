"""A predecessor read must not overwrite native signal cleanup state."""
import signal
import threading
import unittest
from types import SimpleNamespace
from unittest.mock import patch
import test_chatbot_cohort_assemble as bootstrap
from tools.chatbot_file_cohort import delivery as d,postgrant_recovery as recovery

class RecoveryCleanup(unittest.TestCase):
    def test_authorization_read_pause_waits_then_retries_only_observation(self):
        from tools.chatbot_file_cohort.authorization import OBSERVATION_POLICY,AuthorizationPaused
        owner=d.Delivery.__new__(d.Delivery)
        checks=[];waits=[];reports=[]
        owner.current=lambda *args:checks.append(args)
        owner.wait=lambda *args:waits.append(args)
        owner.report=lambda *args,**kwargs:reports.append((args,kwargs))
        from unittest.mock import MagicMock
        delta=SimpleNamespace(plan={'observationPolicy':OBSERVATION_POLICY},
            verify_resilient=MagicMock(side_effect=[AuthorizationPaused('AUTHORIZATION_HTTP_503'),{'readVerified':True}]),
            observation_retry_status=MagicMock(return_value={'observation':'AFTER_GATEWAY','nextAttemptAt':d.time.time(),
                'attempts':1,'failureReason':'AUTHORIZATION_HTTP_503'}))
        self.assertEqual(owner.await_authorization_verification(delta,'AFTER_GATEWAY'),{'readVerified':True})
        self.assertEqual(delta.verify_resilient.call_count,2);self.assertEqual(len(waits),1)
        self.assertEqual(reports[0][0],('AUTHORIZATION_READINESS_WAIT',))
        self.assertEqual(d.public_failure_reason(AuthorizationPaused('AUTHORIZATION_HTTP_503')),'AUTHORIZATION_HTTP_503')
        self.assertEqual(d.public_failure_reason(AuthorizationPaused('PRIVATE_SENTINEL')),'AuthorizationPaused')

    def test_preflight_error_keeps_original_failure_and_restores_signal_handlers(self):
        session={'sessionDirectory':'/synthetic/session','tokenPath':'/synthetic/token','expiresAt':123}
        auth={'plan':{'sessionBinding':session,'selection':{}},'catalogue':'{}','helperBindings':{},
            'adminTokenFile':'/synthetic/token','mcpTokenFile':'/synthetic/token'}
        owner=d.Delivery.__new__(d.Delivery)
        owner.prepared={'ingestionConfigurationBinding':{'path':'/synthetic/config','sha256':'a'*64,'metadata':{}},
            'authorization':auth,'postGrantRecovery':{'profile':'synthetic-history'}}
        owner.review={'sourceClosure':{'executables':{'docker':{}}}}
        owner.stop=threading.Event();owner.action=object();owner.engine=object()
        owner.current=lambda *args:None;owner.emit=lambda *args:None
        reports=[];owner.report=lambda *args,**kwargs:reports.append((args,kwargs))
        owner.worker_thread=owner.human_thread=None
        human=SimpleNamespace(start_refresh=lambda *args:None,binding=lambda:session)
        before={sig:signal.getsignal(sig)for sig in (signal.SIGINT,signal.SIGTERM)}
        with (patch.object(d,'private_config'),patch.object(d,'create_directories',return_value={'dockerCli':'/synthetic','authorization':'/synthetic'}),
              patch.object(d,'native_environment'),patch.object(d,'HumanSession',return_value=human),
              patch.object(d.OwnerPrimitives,'from_qualified_modules'),patch.object(d,'AuthorizationDelta'),
              patch.object(d,'OwnerTransport'),patch.object(d,'Journal'),
              patch.object(recovery,'read_predecessor',return_value={'retainedHistory':'synthetic'}),
              patch.object(recovery,'current_baseline',side_effect=ValueError('SYNTHETIC_NATIVE_DRIFT')),
              self.assertRaisesRegex(ValueError,'SYNTHETIC_NATIVE_DRIFT')):
            owner.run()
        self.assertEqual({sig:signal.getsignal(sig)for sig in before},before)
        self.assertTrue(owner.stop.is_set())
        self.assertEqual(reports[-1][1]['reason'],'ValueError')

if __name__=='__main__':unittest.main()
