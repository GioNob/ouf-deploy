"""Real protected metadata files; systemd/Engine replies are synthetic.

The reader executes no retained source, IAM call, grant or node acceptance.
"""
import base64,contextlib,copy,hashlib,importlib.util,io,json,os,tempfile,time,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]

class Reader(unittest.TestCase):
    def setUp(self):
        self.assertEqual(os.geteuid(),0)
        spec=importlib.util.spec_from_file_location('retained_checkpoint_reader',ROOT/'scripts/read-chatbot-retained-attestation-20261015.py')
        self.r=importlib.util.module_from_spec(spec);spec.loader.exec_module(self.r);r=self.r
        temp=tempfile.TemporaryDirectory(dir=ROOT,prefix='retained-reader-fixture-');self.addCleanup(temp.cleanup)
        self.root=Path(temp.name);self.root.chmod(0o700);self.context=self.root/'context';self.context.mkdir(mode=0o700);r.CONTEXT=self.context
        self.paths={name:str(self.root/name)for name in('node','evidence','transition','owner','authorization','containers','databases','gateway')}
        for path in self.paths.values():Path(path).mkdir(mode=0o700)
        now=int(time.time());body=b'raise RuntimeError("RETAINED_SOURCE_MUST_NOT_EXECUTE")\n';pin=hashlib.sha256(body).hexdigest()
        r.SOURCE_PINS={name:pin for name in r.SOURCE_PINS}
        declaration={'sourceCommit':r.SOURCE,'sourceHashes':r.SOURCE_PINS}
        session={'schema':'ouf.policy-token-new-finite-worker-session.v3','predecessorGrantAttempts':3}
        prepared={'registry':{'directoryPlan':{k:self.paths[k]for k in('node','evidence','transition')}},
            'engine':{'socketPath':'/fixture/not-used','socketBinding':[]},'privateFixtureValue':'DO_NOT_PRINT_PRIVATE_VALUES'}
        bundle={'declaration':declaration,'prepared':prepared,'sources':{name:base64.b64encode(body).decode()for name in r.SOURCE_PINS}}
        self.bundle=bundle;self.bundle_path=self.root/'bundle.json';self.put(self.bundle_path,bundle)
        process={'unit':r.UNIT,'authorityDirectory':str(self.context),'bundle':{'path':str(self.bundle_path),'sha256':r.digest(bundle)},
            'directoryPlan':{k:self.paths[k]for k in('authorization','containers','databases','gateway')}}
        scopes={'finiteActionProcess':process,'policyTokenOwnerInstallation':{'journalPath':self.paths['owner']},'policyTokenFiniteWorkerSession':session}
        authority={**scopes,'issuedAt':now-10,'expiresAt':now+3500};r.AUTHORITY=r.digest(authority);self.put(self.context/'authority.json',authority)
        review={'sourceClosureHash':'a'*64,'sourceClosure':{'declaration':declaration,'executables':{'systemctl':{'path':'/usr/bin/systemctl','sha256':'0'*64}}},
            'scopes':scopes,'privateInputHashes':{'preparedInputs':r.digest(prepared)}}
        r.REVIEW=r.digest(review);self.put(self.context/'review.json',review);self.put(self.context/'decision.json',{'approvedReviewHash':r.REVIEW})
        self.put(self.context/'delivery-status.json',{'authorityHash':r.AUTHORITY,'phase':'PAUSED_REQUIRES_RECONCILIATION','reason':'CURRENT_ATTESTATION_PHASE_AND_CREATION_SCOPE_REQUIRED'})
        self.put(self.context.parent/r.CLAIM,{'authorityHash':r.AUTHORITY,'state':'CONTINUATION_RESERVED_NO_AUTOMATIC_REPLAY'})
        self.node=Path(self.paths['node']);self.put(self.node/'frame-policy.json',{'fixture':True})
        authorization={'schema':'ouf.semantic-paused-node-acceptance-authorization.v1','transitionContextHash':'b'*64,
            'creationRequestHash':'c'*64,'sourceClosureHash':'a'*64,'containerId':r.CID,'expiresAt':authority['expiresAt']}
        self.put(self.node/'paused-acceptance.json',authorization)
        self.put(self.node/'attestation-issuance-claim.json',{'authorizationHash':r.digest(authorization),'nodeRecipeHash':'d'*64})
        receipt={'schema':'ouf.semantic-owner-signed-paused-node-phase.v1','transitionContextHash':'b'*64,'creationRequestHash':'c'*64,
            'intentHash':'e'*64,'completeNativeObservationPerformed':True,'currentScopedAcceptanceSignatureVerified':True}
        self.put(Path(self.paths['evidence'])/'ATTEST_NEW_OCI_PEER.json',receipt)
        effects=[{'phase':name,'state':'APPLIED'if i<7 else'IN_FLIGHT','intentHash':'e'*64,'authorityEvidenceHash':r.AUTHORITY,
            **({'nativeEvidenceHash':r.digest(receipt)if i==6 else'f'*64}if i<7 else{})}for i,name in enumerate(r.PHASES[:8])]
        self.transition={'state':'IN_FLIGHT','version':19,'nextPhase':7,'contextHash':'b'*64,'creationRequestHash':'c'*64,'effects':effects,
            'databaseMayHaveChanged':True,'governedUnsignedReprocessing':{'predecessorJournalHash':r.OLD_TRANSITION,'previousReprocessing':{'fixture':True}}}
        self.put(Path(self.paths['transition'])/'recovery.json',self.transition)
        worker={'state':'CANCELLED','version':5,'attempts':1,'publicationCount':1,'controlledPredecessorGrantAttempts':3,
            'controlledCumulativeGrantAttempts':4,'workerSessionHash':r.digest(session),'firstGrantReceiptHash':'4bb904ea93df0766647641fd397cac7d8504f1ca81252ce597d1db363a86105a'}
        for name,value in(('recovery.json',worker),('owner-session.json',session),('owner-admission.json',{'state':'BLOCKED','version':3})):
            self.put(Path(self.paths['owner'])/name,value)
        for name in('authorization','containers','databases','gateway'):self.put(Path(self.paths[name])/'recovery.json',{'state':'READY','version':1,'effects':[]})
        self.native={'Id':r.CID,'RestartCount':0,'State':{'Running':True,'Paused':True,'Status':'paused','Pid':3484588,'StartedAt':'fixture'}}
    def put(self,path,value):
        path.write_bytes(self.r.encoded(value));path.chmod(0o600)
    def run_reader(self):
        output=io.StringIO()
        with patch.object(self.r,'systemd',return_value={'stopped':True}),patch.object(self.r,'inspect',side_effect=lambda _:copy.deepcopy(self.native))as native,\
            patch.object(self.r.signal,'alarm'),patch.object(self.r.subprocess,'run',side_effect=AssertionError('UNEXPECTED_COMMAND')),contextlib.redirect_stdout(output):
            self.r.main()
        self.assertEqual(native.call_count,2)
        text=output.getvalue();self.assertNotIn('DO_NOT_PRINT_PRIVATE_VALUES',text);self.assertNotIn('RETAINED_SOURCE_MUST_NOT_EXECUTE',text)
        return [json.loads(x)for x in text.splitlines()]
    def test_complete_signed_boundary_and_four_grants_are_read_without_source_execution(self):
        values=self.run_reader();by={x['check']:x for x in values}
        self.assertTrue(by['REGISTRY_TRANSITION']['firstSevenApplied']);self.assertTrue(by['REGISTRY_TRANSITION']['databaseMayHaveChanged'])
        self.assertFalse(by['REGISTRY_TRANSITION']['migrationNativeReceiptPresent']);self.assertEqual(by['WORKER_HISTORY']['cumulativeAttempts'],4)
        self.assertTrue(by['COMPLETED_NODE_PHASE']['scopedSignatureVerificationRecorded']);self.assertFalse(by['COMPLETED_NODE_PHASE']['attestationAcceptedByReader'])
        self.assertTrue(by['END']['complete']);self.assertFalse(by['END']['databaseFenceQueried']);self.assertFalse(by['END']['credentialOrTokenFilesRead'])
    def test_node_claim_mismatch_is_reported_and_later_metadata_still_read(self):
        self.put(self.node/'attestation-issuance-claim.json',{'authorizationHash':'0'*64})
        values=self.run_reader();self.assertFalse(values[-1]['complete']);self.assertEqual(values[-1]['unavailableChecks'],['COMPLETED_NODE_PHASE'])
        self.assertIn('LATER_EFFECTS_databases',{x['check']for x in values})
    def test_unknown_engine_status_cannot_print_private_values(self):
        self.native['State']['Status']='DO_NOT_PRINT_PRIVATE_VALUES'
        values=self.run_reader();self.assertFalse(values[-1]['complete']);self.assertEqual(values[-1]['unavailableChecks'],['REGISTRY_NATIVE'])
    def test_private_read_rejects_symlink_hardlink_wrong_mode_and_duplicate_json(self):
        path=self.root/'record.json';self.put(path,{'fixture':True})
        link=self.root/'link';link.symlink_to(path)
        with self.assertRaises((self.r.ReadDenied,OSError)):self.r.read(link)
        link.unlink();os.link(path,link)
        with self.assertRaises(self.r.ReadDenied):self.r.read(path)
        link.unlink();path.chmod(0o644)
        with self.assertRaises(self.r.ReadDenied):self.r.read(path)
        path.chmod(0o600);path.write_bytes(b'{"duplicate":1,"duplicate":2}')
        with self.assertRaises(self.r.ReadDenied):self.r.read(path)
    def test_large_artifact_is_bounded_and_changed_frozen_source_is_never_executed(self):
        path=self.root/'large.json';self.put(path,{'fixture':'x'*(2*1024*1024)})
        self.assertEqual(len(self.r.read(path,8388608)['fixture']),2*1024*1024)
        bundle=copy.deepcopy(self.bundle);name=next(iter(bundle['sources']));bundle['sources'][name]=base64.b64encode(b'raise AssertionError()').decode()
        with self.assertRaisesRegex(self.r.ReadDenied,'FAILED_SOURCE_BYTES_PIN_DRIFT'):self.r.source_check(bundle)
    def test_stable_record_reread_denies_changed_body(self):
        path=self.root/'record.json';self.put(path,{'fixture':True});self.r.read(path);h=self.r.READS[str(path)][0]
        self.put(path,{'fixture':False})
        with self.assertRaises(self.r.ReadDenied):self.r.read(path,expected=h)

if __name__=='__main__':unittest.main()
