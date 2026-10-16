"""A predecessor read must not overwrite native signal cleanup state."""
import signal
import threading
import unittest
from types import SimpleNamespace
from unittest.mock import patch
import test_chatbot_cohort_assemble as bootstrap
from tools.chatbot_file_cohort import delivery as d,postgrant_recovery as recovery

class RecoveryCleanup(unittest.TestCase):
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
