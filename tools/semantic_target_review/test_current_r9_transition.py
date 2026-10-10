"""Read projection must not turn retained receipts into current authority."""
import importlib.util, json, unittest
from pathlib import Path
spec=importlib.util.spec_from_file_location('review',Path(__file__).with_name('read_current_r9_transition.py'))
review=importlib.util.module_from_spec(spec);spec.loader.exec_module(review)

class Review(unittest.TestCase):
    def setUp(self):
        self.status={'schema':'ouf.provider-lease-worker-status.v1','status':'LEASE_ACTIVE','workerPid':123,'refreshCount':4,'privateCredential':'DO_NOT_EXPORT'}
        self.unit={'MainPID':'123','ActiveState':'active','SubState':'running','Restart':'no','ExecStart':str(review.ROOT/'activate.py')}
        self.lease={'journalAndMembershipConsistent':True,'leaseAuthorized':True,'journalState':'LEASE_READY','providerSetsEmpty':False}
    def test_current_generation_needed_not_activation_receipt(self):
        result=review.project_worker(self.status,self.unit,self.lease)
        self.assertTrue(result['r9WorkerAndLeaseActiveAtStableObservation'])
        self.assertNotIn('DO_NOT_EXPORT',json.dumps(result));self.assertNotIn('ExecStart',result['service'])
        self.assertFalse(result['consumedR9ReplayAllowed']);self.assertFalse(result['applicationHealthProven'])
        for changes in ({'MainPID':'124'},{'ActiveState':'failed'},{'ExecStart':'/other/activate.py'}):
            self.assertFalse(review.project_worker(self.status,{**self.unit,**changes},self.lease)['r9WorkerAndLeaseActiveAtStableObservation'])
        for changes in ({'leaseAuthorized':False},{'providerSetsEmpty':True},{'journalState':'QUIESCED'},{'journalAndMembershipConsistent':False}):
            self.assertFalse(review.project_worker(self.status,self.unit,{**self.lease,**changes})['r9WorkerAndLeaseActiveAtStableObservation'])
    def test_failure_diagnostics_do_not_export_arbitrary_private_fields(self):
        window={'minimumObservedTtlSeconds':0,'elapsedSeconds':1.3,'ttlNoncacheable':True,'freshObservationAttempts':3}
        status={**self.status,'status':'LEASE_WORKER_FAILED','exceptionChain':[{'errorType':'DNSDenied','reason':'DNS_OBSERVATION_EXPIRED_OR_NONCACHEABLE','dnsObservationWindow':window}]}
        result=review.project_worker(status,self.unit,self.lease)
        self.assertFalse(result['r9WorkerAndLeaseActiveAtStableObservation']);self.assertEqual(result['exceptionChain'][0]['dnsObservationWindow'],window)
        status['exceptionChain'][0]['dnsObservationWindow']={**window,'credential':'DO_NOT_EXPORT'}
        status['exceptionChain'][0]['reason']='https://private.example/token';status['exceptionChain'][0]['errorType']='secret/token'
        result=review.project_worker(status,self.unit,self.lease)
        self.assertNotIn('DO_NOT_EXPORT',json.dumps(result));self.assertNotIn('private.example',json.dumps(result));self.assertNotIn('dnsObservationWindow',result['exceptionChain'][0])
    def test_unsealed_source_is_never_executed(self):
        with self.assertRaisesRegex(ValueError,'PINNED_READ_ONLY_SOURCE_REQUIRED'):
            review.load_reader(b'raise RuntimeError("untrusted code executed")')
    def test_only_exact_show_command_is_issued_and_command_rechecked(self):
        from unittest.mock import patch
        class Reader:
            calls=[]
            def private(self,*args,**kwargs):self.calls.append((args,kwargs));return b'executable'
        reader=Reader();binding={'path':'/usr/bin/systemctl','sha256':'a'*64}
        completed=type('Completed',(),{'returncode':0,'stdout':b'LoadState=loaded\nActiveState=active\n','stderr':b''})()
        with patch.object(review.subprocess,'run',return_value=completed) as run:
            review.service(reader,binding)
        self.assertEqual(run.call_args.args[0],['/usr/bin/systemctl','show',review.UNIT,'--no-pager','--property='+','.join(review.PROPERTIES)])
        self.assertEqual(len(reader.calls),2)

if __name__=='__main__':unittest.main()
