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
    def test_rejected_lease_keeps_worker_diagnostics_without_claiming_liveness(self):
        from types import SimpleNamespace
        from unittest.mock import patch
        context=Path('/sealed/context');owner='a'*64
        human={'approvalRef':'SOURCE_APPROVED','configurationHash':'b'*64}
        cfg={'commandBindings':{'systemctl':{'path':'/usr/bin/systemctl','sha256':'c'*64}}}
        records={str(context/'human-approval-binding.json'):human,str(context/'execution-configuration.json'):cfg,
            str(review.CLAIM):{'schema':'ouf.provider-dns-recovery-activation-claim.v1','approvalRef':review.APPROVAL,'directory':str(review.ROOT),'startAuthorized':False},
            str(review.ROOT/'authorization.json'):{'schema':'ouf.provider-dns-recovery-authorization.v1','approvalRef':review.APPROVAL,'ownerConfigurationHash':owner,'serviceUnit':review.UNIT,'programHashes':review.PROGRAMS,'automaticRestart':False,'enableAtBoot':False,'containerLifecycleAuthorized':False},
            str(review.ROOT/'activation-receipt.json'):{'status':'TWO_FLOW_LEASE_ACTIVE_AND_RENEWED','serviceUnit':review.UNIT,'doNotRerunApply':True},str(review.ROOT/'worker-status.json'):self.status}
        def private(path,*args,**kwargs):return json.dumps(records[str(path)]).encode() if str(path) in records else b'sealed-program'
        def blocked():raise ValueError('LEASE_ADDRESS_OR_TTL_UNPROVEN')
        reader=SimpleNamespace(CONTEXT=context,APPROVAL='SOURCE_APPROVED',OWNER_HASH=owner,private=private,parse=json.loads,collect_cutover=blocked,ReadDenied=ValueError)
        with patch.object(review,'service',return_value=self.unit),patch.object(review,'lease_diagnostics',return_value={'observationalOnly':True}):
            result=review.collect(reader)
        self.assertFalse(result['completeCutoverBindingsProven']);self.assertEqual(result['cutover']['reason'],'LEASE_ADDRESS_OR_TTL_UNPROVEN')
        self.assertEqual(result['r9']['worker']['refreshCount'],4);self.assertFalse(result['r9']['r9WorkerAndLeaseActiveAtStableObservation'])
    def test_ttl_diagnostics_preserve_rejection_and_hide_address(self):
        from types import SimpleNamespace
        flow={'source':'172.18.0.1','allowedPrivateAddresses':[],'leaseSeconds':30}
        owner={'kernel':{'tableName':'ouf_test','providerFlows':[flow]},'expectedStructureHash':'0'*64}
        tables={family:{'nftables':[{'set':{'family':family,'table':'ouf_test','name':'provider_0','elem':[{'elem':{'val':'8.8.8.8','expires':ttl}}]}}]} for family,ttl in [('inet',31000),('bridge','29s')]}
        def run(bindings,name,args,**kwargs):
            self.assertEqual(name,'nft');self.assertEqual(args[:4],['-j','list','table',args[3]])
            return json.dumps(tables[args[3]]).encode()
        reader=SimpleNamespace(GUARD=Path('/sealed/guard'),OWNER_HASH='a'*64,private=lambda *a:json.dumps(owner).encode(),parse=json.loads,run=run,encoded=lambda v:json.dumps(v).encode(),structure=lambda v:v)
        result=review.lease_diagnostics(reader,{'commandBindings':{}})
        self.assertTrue(result['grantsNoLeaseAuthority']);self.assertNotIn('8.8.8.8',json.dumps(result))
        self.assertTrue(all(not r['expiresAcceptedByOriginalPredicate'] for r in result['elements']))
        self.assertEqual([r['expiresType'] for r in result['elements']],['int','str'])

if __name__=='__main__':unittest.main()
