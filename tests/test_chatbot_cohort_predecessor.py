"""Real protected files and preserved claims; explicit inactive systemd fixture."""
import copy,hashlib,json,os,shutil,subprocess,tempfile,time,unittest
from pathlib import Path
from unittest.mock import patch
import test_file_only_preparation
from tools.chatbot_file_cohort import action_process as process
from tools.semantic_lease_recovery.bounded_recovery import Permanent

ROOT=Path(__file__).resolve().parents[1]

class Predecessor(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(dir=ROOT,prefix='predecessor-fixture-');self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.root.chmod(0o700)
        self.operation='a'*64;self.manifest='b'*64
        self.context=self.root/('chatbot-file-cohort-signed-'+self.operation);self.context.mkdir(mode=0o700)
        self.unit='ouf-file-cohort-'+self.operation[:32]+'.service'
        self.paths={n:str(self.context/n) for n in ('authorization','containers','databases','gateway','gatewayRuntime',
            'backups','dockerCli','imageSemantic','imageUdp','imageOnboarding','imageIngestion','imageMcp')}
        for p in self.paths.values():Path(p).mkdir(mode=0o700)
        self.plan={'logicalOperationHash':self.operation,'unit':self.unit,'authorityDirectory':str(self.context),'directoryPlan':self.paths}
        self.review={'schema':'ouf.chatbot-file-cohort-full-action-review.v1',
            'sourceClosure':{'declaration':{'sourceCommit':process.AUTHORIZATION_ONLY_PREDECESSOR_SOURCE}},
            'sourceClosureHash':'c'*64,'privateInputHashes':{'cohortManifest':self.manifest},
            'scopes':{'finiteActionProcess':self.plan,'chatbotFileAuthorization':{'planHash':'d'*64}}}
        self.decision={'approvedReviewHash':process.digest(self.review),'approvedSourceClosureHash':'c'*64,
            'approvedAt':int(time.time())-3620,'expiresAt':int(time.time())-20,
            'decision':'APPROVE_ONE_FINITE_CHATBOT_FILE_COHORT_ACTION','state':'ACTIVE'}
        self.authority={'expiresAt':self.decision['expiresAt'],'finiteActionProcess':self.plan,
            'sourceClosureHash':'c'*64,'chatbotFileAuthorization':self.review['scopes']['chatbotFileAuthorization']}
        self.authority_hash=process.digest(self.authority)
        self.status={'schema':'ouf.chatbot-file-cohort-delivery-status.v1','phase':'PAUSED_REQUIRES_RECONCILIATION',
            'reason':'PlanDenied','authorityHash':self.authority_hash,'budgetReset':False}
        self.claim={'authorityHash':self.authority_hash,'planHash':process.digest(self.plan),
            'state':'START_CONSUMED_OUTCOME_UNPROVEN','automaticReplayAllowed':False,'runtimeMaxSeconds':3599}
        self.journal={'schema':'ouf.chatbot-file-authorization-journal.v1','authorityHash':self.authority_hash,
            'planHash':'d'*64,'budgetReset':False,'effects':{'role-proposal':{'state':'APPLIED','attempts':2,
                'evidence':{'state':'EXPIRED'}}}}
        self.completed={'authorityHash':self.authority_hash,'planHash':process.digest(self.paths),
            'identities':{p:{'device':Path(p).stat().st_dev,'inode':Path(p).stat().st_ino} for p in self.paths.values()}}
        for name,v in [('review.json',self.review),('decision.json',self.decision),('authority.json',self.authority),
                       ('delivery-status.json',self.status),('directories.completed.json',self.completed)]:self.write(self.context/name,v)
        self.claim_path=self.root/('chatbot-file-cohort-process-'+self.operation+'.claim.json');self.write(self.claim_path,self.claim)
        self.journal_path=Path(self.paths['authorization'])/'recovery.json';self.write(self.journal_path,self.journal)
        binary=Path(shutil.which('true')).resolve();self.systemctl={'path':str(binary),'sha256':hashlib.sha256(binary.read_bytes()).hexdigest()}
        for p in (patch.object(process.evidence,'PARENT',self.root),
                  patch.object(process.subprocess,'run',return_value=subprocess.CompletedProcess([],0,b'ActiveState=inactive\nMainPID=0\n'))):
            p.start();self.addCleanup(p.stop)
    def write(self,p,value):p.write_bytes(process.encoded(value));p.chmod(0o600)
    def observe(self):return process.previous_authorization_actions(self.manifest,self.systemctl)
    def test_stopped_expired_auth_only_window_preserves_bindings_attempts_and_claims(self):
        original={p:p.read_bytes() for p in self.root.rglob('*') if p.is_file()}
        receipt=self.observe();self.assertEqual(len(receipt),1)
        self.assertEqual(receipt[0]['priorAuthorizationEffectAttempts'],{'role-proposal':2})
        self.assertFalse(receipt[0]['firstGrantStageClaimsPresent']);self.assertTrue(receipt[0]['startClaimRetained'])
        process.verify_previous_authorization_actions(receipt,self.manifest,self.systemctl,self.root/'new-context')
        self.assertEqual(original,{p:p.read_bytes() for p in self.root.rglob('*') if p.is_file()})
    def test_unexpired_old_window_blocks_new_one(self):
        self.decision['expiresAt']=int(time.time())+600;self.write(self.context/'decision.json',self.decision)
        with self.assertRaisesRegex(process.evidence.CandidateDenied,'WINDOW_MUST_BE_EXPIRED'):self.observe()
    def test_active_old_process_blocks(self):
        with patch.object(process.subprocess,'run',return_value=subprocess.CompletedProcess([],0,b'ActiveState=active\nMainPID=123\n')):
            with self.assertRaisesRegex(process.evidence.CandidateDenied,'PROCESS_MUST_BE_STOPPED'):self.observe()
    def test_any_application_or_first_grant_stage_record_blocks(self):
        for name in ('imageSemantic','containers','databases','gatewayRuntime'):
            p=Path(self.paths[name])/'recovery.json';self.write(p,{'attempts':1})
            with self.subTest(stage=name),self.assertRaisesRegex(process.evidence.CandidateDenied,'STAGE_HISTORY_REQUIRES_OWNER'):self.observe()
            p.unlink()
    def test_ambiguous_authorization_effect_is_not_replayed(self):
        self.journal['effects']['role-proposal']['state']='DISPATCHED';self.write(self.journal_path,self.journal)
        with self.assertRaisesRegex(process.evidence.CandidateDenied,'AMBIGUOUS_PREVIOUS'):self.observe()
    def test_mutated_history_denies_execution_of_prepared_readback(self):
        receipt=self.observe();self.journal['effects']['role-proposal']['attempts']=3;self.write(self.journal_path,self.journal)
        with self.assertRaisesRegex(process.evidence.CandidateDenied,'HISTORY_CHANGED_BEFORE_NEW_EXECUTION'):
            process.verify_previous_authorization_actions(receipt,self.manifest,self.systemctl,self.root/'new-context')
    def test_unknown_previous_source_or_missing_start_claim_blocks(self):
        self.claim_path.unlink()
        with self.assertRaises(FileNotFoundError):self.observe()
        self.write(self.claim_path,self.claim);self.review['sourceClosure']['declaration']['sourceCommit']='f'*40
        self.write(self.context/'review.json',self.review)
        with self.assertRaisesRegex(process.evidence.CandidateDenied,'SOURCE_REQUIRES_OWNER'):self.observe()
    def test_omitting_predecessor_from_new_review_is_denied(self):
        with self.assertRaisesRegex(process.evidence.CandidateDenied,'HISTORY_CHANGED_BEFORE_NEW_EXECUTION'):
            process.verify_previous_authorization_actions([],self.manifest,self.systemctl,self.root/'new-context')
    def test_root_owned_public_snapshot_parent_keeps_private_child_custody(self):
        self.root.chmod(0o755)
        self.assertEqual(len(self.observe()),1)
        self.context.chmod(0o755)
        with self.assertRaisesRegex(Permanent,'INTEGRITY_UNPROVEN'):self.observe()

if __name__=='__main__':unittest.main()
