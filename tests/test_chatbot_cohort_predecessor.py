"""Real protected files and preserved claims; explicit inactive systemd fixture."""
import copy,hashlib,json,os,shutil,subprocess,tempfile,time,unittest
from pathlib import Path
from unittest.mock import patch
import test_file_only_preparation
import test_chatbot_cohort_image_identity as image_fixture
from tools.chatbot_file_cohort.images import prepare_imports,image_import_scope,IMAGE_MODULES
from image_custody import archive,native_identity,runtime_image_id
from image_import import Import
from engine_creation import Engine
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

class ImagePredecessor(unittest.TestCase):
    write=Predecessor.write
    observe=Predecessor.observe
    def setUp(self):
        Predecessor.setUp(self)
        package=self.root/'package';package.mkdir(mode=0o700);output=self.root/'tagless';output.mkdir(mode=0o700)
        records=[]
        for module in IMAGE_MODULES:
            directory=package/module;directory.mkdir(mode=0o700);path=directory/'image.docker.tar'
            audit=image_fixture.tiny_archive(path)
            records.append({'module':module,'sourceCommit':audit['sourceCommit'],'imageId':audit['imageId'],
                'artifactKind':'DOCKER_SAVE','scanGate':'PASS_HIGH_CRITICAL_UNKNOWN_INCLUDING_UNFIXED',
                'files':{'image.docker.tar':audit['archiveSha256']}})
        records.append({'module':'gateway'})
        self.image_plan=prepare_imports(package,{'modules':records},output)
        self.image_plan['cohortManifestHash']=self.manifest
        self.engine=Engine.__new__(Engine);self.engine.path='/fixture-socket';self.engine.check_socket=lambda:None
        self.native=None
        for row in self.image_plan['images']:
            audit=row['audit']
            if row['module']=='semantic':
                bound=copy.deepcopy(audit);bound['nativeIdentity']=native_identity(audit)
                self.native={'Id':runtime_image_id(bound),'Os':'linux','Architecture':'amd64',
                    'RootFS':{'Type':'layers','Layers':[r['diffId'] for r in audit['layers']]},'Config':copy.deepcopy(audit['imageConfig'])}
            del audit['configBytes'] # Exact b646 predecessor archive-audit schema.
            initial=Import.initial(audit,'0'*64)
        self.review['sourceClosure']['declaration']['sourceCommit']=process.IMAGE_IDENTITY_PREDECESSOR_SOURCE
        scope=image_import_scope(self.image_plan);self.review['scopes']['cohortImageImport']=scope
        prepared={'imagePlan':self.image_plan,'engine':{'socketPath':'/fixture-socket','socketBinding':[]}}
        self.review['privateInputHashes']['preparedInputs']=process.digest(prepared)
        bundle={'declaration':self.review['sourceClosure']['declaration'],'prepared':prepared}
        path=self.context/'bundle.json';self.write(path,bundle)
        self.plan['bundle']={'path':str(path),'sha256':hashlib.sha256(path.read_bytes()).hexdigest()}
        self.authority['cohortImageImport']=scope;self.authority_hash=process.digest(self.authority)
        self.status.update(authorityHash=self.authority_hash,reason='ValueError')
        self.claim.update(authorityHash=self.authority_hash,planHash=process.digest(self.plan))
        self.completed['authorityHash']=self.authority_hash
        self.journal.update(authorityHash=self.authority_hash,effects={})
        self.decision['approvedReviewHash']=process.digest(self.review)
        for name,value in [('review.json',self.review),('decision.json',self.decision),('authority.json',self.authority),
            ('delivery-status.json',self.status),('directories.completed.json',self.completed)]:self.write(self.context/name,value)
        self.write(self.claim_path,self.claim);self.write(self.journal_path,self.journal)
        for row in self.image_plan['images']:
            initial=Import.initial(row['audit'],self.authority_hash)
            if row['module']=='semantic':initial.update(version=1,state='IN_FLIGHT',effectAttemptCount=1)
            self.write(Path(self.paths['image'+row['module'].capitalize()])/'recovery.json',initial)
        self.engine.request=lambda method,path:(200,copy.deepcopy(self.native))
        patcher=patch('engine_creation.Engine',return_value=self.engine);patcher.start();self.addCleanup(patcher.stop)
    def test_loaded_manifest_is_reconciled_with_no_old_file_or_journal_changes(self):
        before={p:p.read_bytes() for p in self.root.rglob('*') if p.is_file()}
        result=self.observe();image=result[0]['imageImportReadback']
        self.assertEqual(image[0]['effectAttemptCount'],1);self.assertEqual(image[0]['nativeImageId'],self.native['Id'])
        self.assertEqual(image[0]['outcome'],'APPLIED_NATIVE_MANIFEST_VERIFIED')
        self.assertTrue(all(r['effectAttemptCount']==0 for r in image[1:]))
        process.verify_previous_authorization_actions(result,self.manifest,self.systemctl,self.root/'next')
        self.assertEqual(before,{p:p.read_bytes() for p in self.root.rglob('*') if p.is_file()})
    def test_wrong_native_identity_or_execution_config_blocks(self):
        self.native['Config']['Env']=['INJECTED=1']
        with self.assertRaisesRegex(ValueError,'EXECUTION_CONFIG_DRIFT'):self.observe()
        self.native['Config'].pop('Env');self.native['Id']='sha256:'+'0'*64
        with self.assertRaisesRegex(ValueError,'IDENTITY_DRIFT'):self.observe()
    def test_later_database_stage_or_second_image_attempt_blocks(self):
        path=Path(self.paths['databases'])/'recovery.json';self.write(path,{'attempt':1})
        with self.assertRaisesRegex(process.evidence.CandidateDenied,'STAGE_HISTORY'):self.observe()
        path.unlink();path=Path(self.paths['imageUdp'])/'recovery.json';value=json.loads(path.read_text())
        value.update(version=1,state='IN_FLIGHT',effectAttemptCount=1);self.write(path,value)
        with self.assertRaisesRegex(process.evidence.CandidateDenied,'UNATTEMPTED_PREVIOUS_IMAGE'):self.observe()
    def test_archive_drift_blocks_reconciliation(self):
        path=Path(self.image_plan['images'][0]['archivePath']);path.write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError,'ARCHIVE_BYTES_CHANGED'):self.observe()
    def test_native_manifest_absence_is_never_permission_to_reimport(self):
        self.engine.request=lambda *args:(404,None)
        with self.assertRaisesRegex(process.evidence.CandidateDenied,'NATIVE_MANIFEST_IMAGE_REQUIRED'):self.observe()

if __name__=='__main__':unittest.main()
