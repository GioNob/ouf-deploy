"""Real signed authority, durable journals and archive IO; synthetic native effects."""
import copy,json,hashlib,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
import test_chatbot_cohort_signed_recovery as prior
import test_chatbot_cohort_databases as dbfixture
from tools.chatbot_file_cohort import backup_recovery as b,postgrant_recovery as root
from tools.chatbot_file_cohort.plan import digest
from tools.chatbot_file_cohort.review import REQUIRED_SCOPES
from tools.semantic_policy_token_owner.owner_installation import AggregateAction
from tools.semantic_lease_recovery.recovery_journal import Journal
from cutover_authority import CutoverAuthority
from cutover_executor import Executor
from transition_journal import Transition
from file_only_profile import PHASES


class VerifiedRegistrySuccessor(unittest.TestCase):
    def setUp(self):
        h=prior.SignedAdmissionSuccessor();self.addCleanup(h.doCleanups);h.setUp();self.h=h;self.f=h.f;self.profile=h.profile
        old=h.successor();adapter=old.adapters['VERIFY_APPLICATION'];observe=adapter.observe;calls=[0]
        def once(intent):
            calls[0]+=1
            if calls[0]==1:return 'UNKNOWN',{'fixtureReadinessWait':True}
            return observe(intent)
        adapter.observe=once
        with self.assertRaises(Exception):old.run(10)
        old.run(10);self.old=old;self.row=old.t.read();self.assertEqual(self.row['version'],29)
        self.preserved={**h.preserved,str(old.t.journal.record):old.t.journal.record.read_bytes()}
        for name,value in (('AUTHORITY',old.authority_hash),('TRANSITION_HASH',digest(self.row))):
            override=patch.object(b,name,value);override.start();self.addCleanup(override.stop)
        self.prepared={'postGrantRecovery':h.proof,'registry':{'creationRequest':self.profile.request,'intents':h.intents}}
        b.validate_boundary(self.row,self.prepared)
        self.proof={'profile':b.PROFILE,'predecessorAuthorityHash':root.AUTHORITY,'backupPredecessorAuthorityHash':b.AUTHORITY,
            'predecessorTransitionHash':digest(self.row),'transitionContextHash':self.row['contextHash'],
            'appliedPrefixHash':digest(self.row['effects']),'recordBindings':[]}
        self.intents=copy.deepcopy(h.intents)
        self.intents['ATTEST_NEW_OCI_PEER']={'unusedNewSourceRecipe':True}
        self.intents['RELEASE_PRODUCERS']={'newCohortPlan':True}
        self.scope={'postGrantRecovery':self.proof,'creationRequestHash':self.row['creationRequestHash'],
            'executionProfileHash':self.profile.sha256,'sourceClosureHash':'5'*64,
            'phaseIntentHashes':{k:digest(v) for k,v in self.intents.items()}}
        authority=json.loads(self.f.authority);authority.update(sourceClosureHash='5'*64,phaseIntentHashes=self.scope['phaseIntentHashes'])
        authority.update({key:{'fixtureScope':key} for key in REQUIRED_SCOPES});authority['applicationRegistryCutover']=self.scope
        self.f.expected['sourceClosureHash']='5'*64;self.f.authority=prior.prior.prior.fixture.crypto.encoded(authority)
        self.f.approval.update(sourceClosureHash='5'*64,executionAuthorityHash=digest(authority),approvalRef='EXACT_VERIFIED_REGISTRY_BACKUP_RECOVERY')
        self.f.write(self.f.mandate,prior.prior.prior.fixture.crypto.encoded(self.f.approval));self.f.approved=hashlib.sha256(self.f.mandate.read_bytes()).hexdigest()
        for role in self.f.grant['roles']:self.f.sign(role)
        gate=CutoverAuthority(self.f.verifier,self.f.binding(self.f.mandate),self.f.approved,self.f.context,self.f.expected,self.f.clock,execution_profile=self.profile)
        self.action=AggregateAction(gate,self.f.authority,'5'*64)
        self.paths={name:str(self.f.root/('backup-successor-'+name)) for name in ('transition','evidence','before','retirementBefore')}
        for path in self.paths.values():Path(path).mkdir(mode=0o700)
        self.previous={'transition':self.row,'prepared':self.prepared,'payloads':h.previous['payloads']}
        self.calls=[]
    def successor(self):
        with patch.object(b,'retained_bindings'):
            journal=b.seed_registry(self.previous,self.paths,self.action,self.scope)
        t=Transition(journal,self.old.t.context,execution_profile=self.profile)
        def checkpoint(phase,point,row):
            return {'schema':'ouf.semantic-cutover-native-checkpoint.v1','phase':phase,'point':point,'journalVersion':row['version'],
                'intentHash':digest(self.intents[phase]),'authorityHash':self.action.authority_hash,'sourceClosureHash':self.action.closure,'nativeEvidenceHash':'f'*64}
        adapters={p:SimpleNamespace(apply=lambda _,p=p:self.calls.append(p),observe=lambda _:('APPLIED',{'syntheticEffect':True})) for p in PHASES}
        return Executor(t,self.action.raw,self.action.authority,checkpoint,adapters,self.intents,self.f.clock,aggregate_action=self.action,aggregate_scope=self.scope)
    def unchanged(self):
        for path,data in self.preserved.items():self.assertEqual(Path(path).read_bytes(),data)
    def test_ten_effects_unchanged_only_final_release_can_run(self):
        new=self.successor();new.run(10);self.assertEqual(self.calls,[])
        new.run();self.assertEqual(self.calls,['RELEASE_PRODUCERS'])
        self.assertEqual(new.t.read()['effects'][:10],self.row['effects'])
        new.run();self.assertEqual(self.calls,['RELEASE_PRODUCERS']);self.unchanged()
    def test_changed_historical_effect_flags_marker_and_authority_are_denied(self):
        new=self.successor();seed=new.t.read()
        for change in ('effect','db','writes','marker','authority','cursor'):
            row=copy.deepcopy(seed)
            if change=='effect':row['effects'][9]['nativeEvidenceHash']='f'*64
            if change=='db':row['databaseMayHaveChanged']=False
            if change=='writes':row['applicationWritesMayHaveOccurred']=False
            if change=='marker':row['governedVerifiedRegistryContinuation']['proofHash']='f'*64
            if change=='authority':row['governedVerifiedRegistryContinuation']['newAuthorityHash']='f'*64
            if change=='cursor':row['nextPhase']=6
            with self.subTest(change=change),self.assertRaises(Exception):b.verify_successor_transition(row,self.scope,self.action.authority_hash)
        self.unchanged()
    def test_duplicate_publication_and_revocation_do_not_replay(self):
        new=self.successor();before=new.t.journal.record.read_bytes()
        with self.assertRaises(Exception):self.successor()
        self.f.mandate.write_bytes(b'{}')
        with self.assertRaises(Exception):new.run()
        self.assertEqual(self.calls,[]);self.assertEqual(new.t.journal.record.read_bytes(),before);self.unchanged()
    def test_changed_consumed_database_intent_is_denied_before_seed(self):
        self.scope['phaseIntentHashes']['ADMIT_MIGRATION']='f'*64
        with self.assertRaises(Exception):self.successor()
        self.assertEqual(list(Path(self.paths['transition']).iterdir()),[]);self.unchanged()


class BackupAdoption(unittest.TestCase):
    def setUp(self):
        h=dbfixture.DatabaseRuntime();self.addCleanup(h.doCleanups)
        self.owner,self.native,self.f,self.observed,_,self.log=h.fixture(mcp_pending=True,backup_reader=True)
        old_plan=copy.deepcopy(self.owner.plan);old_plan.pop('mcpBackupReader')
        self.oldroot=self.f.root/'retained-archives';self.oldroot.mkdir(mode=0o700)
        old={'schema':'ouf.chatbot-cohort-database-journal.v1','planHash':digest(old_plan),'authorityHash':b.AUTHORITY,
            'version':8,'backups':{},'mcpMigration':None,'mcpAuditRole':None,'restorePerformed':False,'budgetReset':False}
        archives={}
        for row in self.owner.plan['modules']:
            module=row['module']
            if module=='mcp':
                data=b'';record={'state':'CLAIMED','scopeHash':digest(row)}
            else:
                record=self.owner.capture(row);path=self.owner.root/(module+'.dump');data=path.read_bytes();path.unlink()
            path=self.oldroot/(module+'.dump');path.write_bytes(data);path.chmod(0o600)
            old['backups'][module]=record;archives[module]=(len(data),hashlib.sha256(data).hexdigest())
        for key,value in (('ARCHIVES',archives),('DATABASE_HASH',digest(old))):
            p=patch.object(b,key,value);p.start();self.addCleanup(p.stop)
        self.previous={'databaseJournal':old,'prepared':{'databasePlan':old_plan},'backupRoot':str(self.oldroot)}
        self.proof={'retainedCohortBackupDirectory':str(self.oldroot)}
        self.preserved={p:p.read_bytes() for p in self.oldroot.iterdir()}
        def retained(proof):
            for module in archives:b.archive_bytes(proof['retainedCohortBackupDirectory'],module)
        p=patch.object(b,'retained_bindings',side_effect=retained);p.start();self.addCleanup(p.stop)
        self.before=self.log.read_text().count('dump')
    def unchanged(self):
        for path,data in self.preserved.items():self.assertEqual(path.read_bytes(),data)
    def test_copy_three_backups_then_only_one_new_mcp_dump(self):
        b.adopt_backups(self.owner,self.previous,self.proof)
        self.assertNotIn('mcp',self.owner.record()['backups'])
        self.assertEqual(self.owner.record()['governedBackupRecovery']['failedMcpClaim'],self.previous['databaseJournal']['backups']['mcp'])
        self.owner.backup_quiesced();self.owner.backup_quiesced()
        self.assertEqual(self.log.read_text().count('dump'),self.before+1);self.unchanged()
    def test_copy_crash_remains_consumed_no_backup_or_adoption_replay(self):
        original=b.archive_bytes
        def broken(root,module,consume=None):
            if consume is not None and module=='onboarding':raise OSError('synthetic disk failure')
            return original(root,module,consume)
        with patch.object(b,'archive_bytes',side_effect=broken),self.assertRaises(OSError):b.adopt_backups(self.owner,self.previous,self.proof)
        for operation in (lambda:b.adopt_backups(self.owner,self.previous,self.proof),self.owner.backup_quiesced):
            with self.assertRaisesRegex(Exception,'PARTIAL_BACKUP_ADOPTION'):operation()
        self.assertEqual(self.log.read_text().count('dump'),self.before);self.unchanged()
    def test_revoked_human_cannot_copy(self):
        self.f.mandate.write_bytes(b'{}')
        with self.assertRaises(Exception):b.adopt_backups(self.owner,self.previous,self.proof)
        self.assertEqual(list(self.owner.root.iterdir()),[]);self.unchanged()
    def test_old_archive_tamper_denies_before_journal_claim(self):
        path=self.oldroot/'udp.dump';path.write_bytes(b'changed')
        before=self.owner.journal.record.read_bytes()
        with self.assertRaises(Exception):b.adopt_backups(self.owner,self.previous,self.proof)
        self.assertEqual(self.owner.journal.record.read_bytes(),before)
    def test_duplicate_copy_is_denied_and_complete_archives_unchanged(self):
        b.adopt_backups(self.owner,self.previous,self.proof);before=self.owner.journal.record.read_bytes()
        with self.assertRaisesRegex(Exception,'ALREADY_CONSUMED'):b.adopt_backups(self.owner,self.previous,self.proof)
        self.assertEqual(self.owner.journal.record.read_bytes(),before);self.unchanged()
    def test_symlink_or_nonempty_failed_archive_is_denied(self):
        path=self.oldroot/'mcp.dump';path.write_bytes(b'x')
        with self.assertRaises(Exception):b.adopt_backups(self.owner,self.previous,self.proof)
        path.unlink();path.symlink_to(self.oldroot/'udp.dump')
        with self.assertRaises(Exception):b.adopt_backups(self.owner,self.previous,self.proof)

if __name__=='__main__':unittest.main()
