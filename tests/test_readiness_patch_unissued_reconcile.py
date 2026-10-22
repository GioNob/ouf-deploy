"""Root-private no-authority ISSUING fixture, real FD custody and reader CLI."""
import copy
import fcntl
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT)]
from tools.ingestion_readiness_patch_execution import unissued_reconcile as r,unissued_delivery as d

@unittest.skipUnless(os.environ.get('OUF_NATIVE_UIDS')=='1','actual root fixture custody required')
class Unissued(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory(dir=os.environ['OUF_TEST_ROOT']);self.addCleanup(temp.cleanup)
        self.root=Path(temp.name);self.root.chmod(0o700)
        runtime=json.loads((ROOT/'releases/ingestion-readiness-patch-runtime-case-20261022.json').read_bytes())
        runtime['snapshotRoot']=str(self.root);native={'kind':'synthetic immutable inputs'}
        runtime['nativeInputsHash']=r.digest(native);closure={'declaration':{'fixture':'sealed source'}}
        runtime['nativeDeclarationHash']=r.digest(closure['declaration']);h=r.digest(runtime)
        self.context=self.root/('ingestion-readiness-execution-'+h);self.context.mkdir(mode=0o700)
        self.control=self.context/'operator-control';self.control.mkdir(mode=0o700)
        binding={'caseHash':h,'controlSourceHash':runtime['controlSourceHash'],'nativeInputsHash':runtime['nativeInputsHash'],
            'modeContract':'EXPLICIT_ONE_PATCH_STAGE_NO_REPLAY_V1'}
        packet=self.pad({'nativeInputs':native},1320265);profile={'fixtureReference':'no credential journal opened'}
        review=self.pad({'packetHash':r.digest(packet),'operatorControlBinding':binding,'sourceClosure':closure,
            'authorityDirectory':str(self.context),'executionReview':{'executionContext':str(self.context),
                'logicalOperationRef':runtime['logicalOperationRef'],'preparedInputsHash':runtime['nativeInputsHash'],
                'humanReadProfile':profile}},545058)
        material={'caseHash':h,'nativeInputsHash':runtime['nativeInputsHash'],'operatorControlBinding':binding,
            'sourceClosure':closure,'humanProfileHash':r.digest(profile)}
        self.row={'schema':r.ROW,'caseHash':h,'state':'ISSUING','complete':False,'budgetReset':False,
            'runtimeAuthorityIssued':False,'decisionHash':'d'*64,'reviewHash':r.digest(review),
            'packetHash':r.digest(packet),'materialHash':r.digest(material)}
        for name,value in (('review.json',review),('packet.json',packet),('material.json',material),('human-profile.json',profile)):
            self.write(self.context/name,value)
        self.write(self.control/'recovery.json',self.row)
        for name in ('recovery.lock','invocation.lock'):
            p=self.control/name;p.write_bytes(b'');p.chmod(0o600)
        self.claim=self.root/('ingestion-readiness-review-'+runtime['logicalOperationRef']+'.claim.json')
        self.write(self.claim,{'schema':r.ROW,'caseHash':h,'logicalOperationRef':runtime['logicalOperationRef'],
            'contextPath':str(self.context),'reviewHash':r.digest(review),'automaticReplayAllowed':False,'budgetReset':False})
        self.case={'schema':'ouf.ingestion-readiness-unissued-reconcile-case.v1','runtimeCase':runtime,
            'reviewHash':r.digest(review),'reviewBytes':545058,'packetBytes':1320265}
    def pad(self,value,size):
        value['explicitSyntheticMetadata']='';value['explicitSyntheticMetadata']='x'*(size-len(r.encoded(value)))
        self.assertEqual(len(r.encoded(value)),size);return value
    def write(self,p,value):p.write_bytes(r.encoded(value));p.chmod(0o600)
    def test_complete_unissued_snapshot_is_read_only_and_keeps_every_original_byte(self):
        before={str(p):p.read_bytes()for p in self.root.rglob('*')if p.is_file()}
        value=r.inspect(self.case);self.assertTrue(value['complete']);self.assertEqual(value['retainedState'],'ISSUING')
        self.assertFalse(value['authorityArtifactsPresent']);self.assertFalse(value['nativeJournalPresent'])
        self.assertTrue(value['originalReviewClaimRetained']);self.assertEqual(value['humanCredentialJournalsRead'],0)
        self.assertEqual(before,{str(p):p.read_bytes()for p in self.root.rglob('*')if p.is_file()})
    def test_partial_authority_claim_or_signature_always_blocks_no_adoption(self):
        for name in ('ingestion-readiness-patch-issuance.claim.json','authority.json','human.json','decision.json',
                     'recovery.json','a'*64+'.DEPLOYMENT_INTENT.json'):
            p=self.context/name;self.write(p,{'partial':'not authoritative'})
            with self.assertRaisesRegex(ValueError,'AUTHORITY_OR_OTHER'):r.inspect(self.case)
            p.unlink()
    def test_native_initialization_claim_blocks(self):
        p=self.root/('ingestion-readiness-patch-'+self.case['runtimeCase']['logicalOperationRef']+'.claim.json')
        self.write(p,{})
        with self.assertRaisesRegex(ValueError,'NATIVE_INITIALIZATION_CLAIM'):r.inspect(self.case)
    def test_state_decision_review_and_global_claim_drift_are_denied(self):
        for key,value in (('state','REVIEW_READY'),('runtimeAuthorityIssued',True),('decisionHash','bad'),('reviewHash','f'*64)):
            row=copy.deepcopy(self.row);row[key]=value;self.write(self.control/'recovery.json',row)
            with self.assertRaises(ValueError):r.inspect(self.case)
        self.write(self.control/'recovery.json',self.row);claim=json.loads(self.claim.read_bytes());claim['caseHash']='f'*64
        self.write(self.claim,claim)
        with self.assertRaisesRegex(ValueError,'ORIGINAL_REVIEW_CLAIM'):r.inspect(self.case)
    def test_exclusive_operator_invocation_cannot_be_raced(self):
        fd=os.open(self.control/'invocation.lock',os.O_RDONLY)
        try:
            fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            with self.assertRaises(BlockingIOError):r.inspect(self.case)
        finally:os.close(fd)
    def test_wrong_custody_or_changed_document_is_denied(self):
        p=self.context/'review.json';p.chmod(0o400)
        with self.assertRaisesRegex(ValueError,'CUSTODY_UNPROVEN'):r.inspect(self.case)
        p.chmod(0o600);value=json.loads(p.read_bytes());value['explicitSyntheticMetadata']='changed';self.write(p,value)
        with self.assertRaisesRegex(ValueError,'STOPPED_DOCUMENTS'):r.inspect(self.case)
    def test_real_isolated_reader_cli_and_reproducible_source(self):
        raw,pins=d.generate(ROOT,self.case);self.assertEqual(raw,d.generate(ROOT,self.case)[0])
        path=self.root/'reader.py';path.write_bytes(raw);path.chmod(0o600)
        value=subprocess.run([sys.executable,'-I','-B','-S',str(path)],capture_output=True,text=True,timeout=10)
        self.assertEqual(value.returncode,0,value.stderr+value.stdout)
        self.assertEqual(json.loads(value.stdout)['status'],'STOPPED_UNISSUED_PATCH_REVIEW_RECONCILED_NO_AUTHORITY')
        self.assertTrue(pins['readOnly'])

class ProductionReader(unittest.TestCase):
    def test_pinned_production_reader_reproduces_without_target_access(self):
        case=json.loads((ROOT/'releases/ingestion-readiness-unissued-reconcile-case-20261022.json').read_bytes())
        pins=json.loads((ROOT/'evidence/ingestion-readiness-unissued-reader-pins-20261022.json').read_bytes())
        raw,observed=d.generate(ROOT,case)
        self.assertEqual((ROOT/pins['artifactPath']).read_bytes(),raw)
        self.assertEqual(observed['artifactSha256'],pins['artifactSha256'])
        self.assertEqual(case['reviewBytes'],545058);self.assertEqual(case['packetBytes'],1320265)

if __name__=='__main__':unittest.main()
