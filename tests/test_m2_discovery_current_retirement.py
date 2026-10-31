"""Real current parent/child crypto and private marker/archive/evidence bytes.

Legacy systemd/process/nft metadata and application/executor lineage are modeled.
No live retirement, backup payload parser, PostgreSQL fence or target is proved.
"""
import copy,hashlib,sys,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock,patch
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT),str(ROOT/'tests')]
import test_m2_discovery_current_cohort as cohort
from tools.m2_discovery_installation_profile import current_retirement as m
from tools.semantic_target_review.prepare_application_runtime_inputs import file_bytes
from database_gate import Psql
from transition_journal import PHASES


class CurrentRetirement(unittest.TestCase):
    setUp=cohort.Cohort.setUp
    native=cohort.Cohort.native
    write=cohort.Cohort.write
    binding=cohort.Cohort.binding
    sign=cohort.Cohort.sign
    authority=cohort.Cohort.authority
    child=cohort.crypto.Parent.child
    runtime_fixture=cohort.Cohort.owner

    def prepared(self):
        runtime,_,_=self.runtime_fixture();old=self.root/'old-r12';old.mkdir(mode=0o700)
        store_root=self.root/'new-evidence';store_root.mkdir(mode=0o700);store=m.NativeEvidenceStore(store_root)
        root=self.root/'backup';root.mkdir(mode=0o700);context='4'*64;request='9'*64
        final={'authorizationHash':'a'*64,'history':{'state':'CANCELLED','reason':'CANCELLED_BY_OWNER','attempts':197,'publicationCount':3},
            'worker':{'state':'CANCELLED','ready':False,'live':False,'setsRevoked':True,'attempts':197,'refreshCount':3},
            'service':{'LoadState':'not-found','ActiveState':'inactive','SubState':'dead','MainPID':'0'},'processGeneration':None,
            'lease':{'journalState':'QUIESCED','leaseAuthorized':False,'startAuthorized':False,'providerSetsEmpty':True,
                'journalAndMembershipConsistent':True,'nativeStructureVerified':True,'flowCount':2,
                'flows':[{'inetAddressCount':0,'bridgeAddressCount':0} for _ in range(2)]}}
        marker={'schema':'ouf.semantic-r12-retirement-marker.v1','transitionContextHash':'5'*64,'intentHash':'6'*64,
            'authorizationHash':'a'*64,'r12ReplayAuthorized':False,'budgetReset':False}
        self.write(old/'revoked',m.encoded(marker))
        channel=object.__new__(m.R12RetirementChannel);channel.scope={'r12Root':str(old),'authorizationBinding':{'sha256':'a'*64}}
        channel.scope_hash=m.digest(channel.scope);channel.current=Mock(side_effect=lambda:copy.deepcopy(final))
        channel.read=lambda path,expected=None:file_bytes(path,0,{0o600},limit=2097152,expected=expected)
        channel.stop=Mock(side_effect=AssertionError('LEGACY_STOP_FORBIDDEN'));channel.marker=Mock(side_effect=AssertionError('LEGACY_MARKER_MUTATION_FORBIDDEN'))
        retirement={'scopeHash':channel.scope_hash,'stopTimeoutSeconds':55}
        backup_intent={'containerId':runtime.inputs['peers']['postgres']['runtimeBinding']['containerId'],'user':'fixture_admin',
            'database':'fixture_semantic','databaseOid':1234,'directory':str(root),'maxArchiveBytes':1048576}
        intents={p:{'modeledPhase':p} for p in PHASES};intents.update(STOP_REVOKE_OLD_LEASE=retirement,FENCED_BACKUP=backup_intent)
        child,raw=self.child(expires=90,creation_request_hash=request,phase_intent_hashes={p:request if p=='CREATE_REPLACEMENT' else m.digest(i) for p,i in intents.items()})
        inputs={k:runtime.inputs[k] for k in ('sourceClosureHash','installationInputsHash','desiredProfileHash','cohortManifestHash')}
        inputs.update(schema=m.SCHEMA,retirement={'mode':m.MODE,'scopeHash':channel.scope_hash,
            'expectedFinalStateHash':m.digest(final),'existingMarkerSha256':hashlib.sha256((old/'revoked').read_bytes()).hexdigest()},
            backupIntentHash=m.digest(backup_intent))
        bound=m.bind_retirement_inputs(runtime.inputs,inputs)
        review=copy.deepcopy(self.review);review['components']['cohortInstallation']['currentAdmission']=copy.deepcopy(
            review['components']['cohortInstallation']['currentAdmission']['requirements'])
        self.review=cohort.m.bind_runtime_review(review,bound);parent=self.authority(seconds=300)
        row={'state':'READY','nextPhase':0,'effects':[],'version':0,'creationRequestHash':request,
            'transitionAuthorityEvidenceHash':hashlib.sha256(raw).hexdigest()}
        transition=SimpleNamespace(context=context,read=Mock(side_effect=lambda:copy.deepcopy(row)))
        legacy=object.__new__(m.R12RetirementAdapter);legacy.channel=channel;legacy.transition=transition;legacy.store=store
        legacy.intent=retirement;legacy.intent_hash=m.digest(retirement)
        backup=m.FencedBackupAdapter(object.__new__(Psql),backup_intent,Mock(side_effect=AssertionError('BACKUP_DISPATCH_FORBIDDEN')),context,store)
        executor=object.__new__(m.DiscoveryExecutor);executor.discovery_parent=parent;executor.adapters={m.PHASE:legacy,'FENCED_BACKUP':backup}
        app=object.__new__(m.DiscoveryApplication);app.executor=executor;app.discovery_parent=parent;app.transition=transition
        app.store=store;app.authority=child;app.raw=raw;app.request_hash=request;app.intents=intents
        app.verify_scope=Mock() # only actual application assembly/native leaves are modeled
        return m.CurrentRetirementAndBackup(app,bound,inputs),row,final,old,backup

    def test_new_read_mode_observes_already_final_state_without_stopping_or_adopting_history(self):
        reader,row,_,old,_=self.prepared();before=(old/'revoked').read_bytes();reader.attach_before_transition()
        row.update(state='IN_FLIGHT',effects=[{'phase':m.PHASE,'state':'IN_FLIGHT','intentHash':reader.intent_hash}],version=1)
        reader.apply(reader.intent);outcome,proof=reader.observe(reader.intent)
        self.assertEqual(outcome,'APPLIED');self.assertFalse(proof['retirementEvidence']['retirementExecutedByThisAction'])
        self.assertFalse(proof['retirementEvidence']['oldRecoveryHistoryAdopted']);self.assertEqual(proof['retirementEvidence']['retirementMutations'],0)
        self.assertEqual(reader.observe(reader.intent),(outcome,proof));self.assertEqual((old/'revoked').read_bytes(),before)
        reader.legacy.channel.stop.assert_not_called();reader.legacy.channel.marker.assert_not_called()
        self.assertEqual(reader.store.read(m.PHASE,m.digest(proof)),proof)

    def test_read_mode_cannot_replace_owner_after_any_phase_claim_or_review_drift(self):
        reader,row,*_=self.prepared();row['state']='IN_FLIGHT'
        with self.assertRaisesRegex(ValueError,'BEFORE_TRANSITION_START'):reader.attach_before_transition()
        self.assertIs(reader.app.executor.adapters[m.PHASE],reader.legacy)
        row['state']='READY';reader.inputs['retirement']['mode']='STOP_AND_RESTART'
        with self.assertRaises(ValueError):reader.attach_before_transition()

    def test_final_state_mismatch_denies_before_owner_attachment_or_phase_claim(self):
        reader,row,final,*_=self.prepared();before=copy.deepcopy(row);final['worker']['live']=True
        with self.assertRaisesRegex(ValueError,'FINAL_RETIRED_WORKER'):reader.attach_before_transition()
        self.assertEqual(row,before);self.assertFalse(reader.installed)
        self.assertIs(reader.app.executor.adapters[m.PHASE],reader.legacy)
        self.assertEqual(list(reader.store.root.iterdir()),[]);reader.legacy.channel.stop.assert_not_called()

    def test_live_worker_nonempty_sets_and_boolean_counters_never_mean_final_retirement(self):
        reader,_,final,_,_=self.prepared()
        cases=[('worker','live',True),('worker','attempts',True),('history','attempts',True),
            ('service','ActiveState','active'),('lease','providerSetsEmpty',False)]
        for part,key,changed in cases:
            old=final[part][key];final[part][key]=changed
            with self.subTest(part=part,key=key),self.assertRaises(ValueError):reader.retired(m.ObservationBudget(30))
            final[part][key]=old
        final['lease']['flows'][0]['inetAddressCount']=False
        with self.assertRaisesRegex(ValueError,'RETIRED_LEASES_MUST_BE_EMPTY'):reader.retired(m.ObservationBudget(30))
        reader.legacy.channel.stop.assert_not_called()

    def test_marker_or_current_state_drift_is_preserved_and_denied(self):
        reader,_,final,old,_=self.prepared();(old/'revoked').write_bytes(b'{}')
        with self.assertRaises(ValueError):reader.retired(m.ObservationBudget(30))
        self.assertEqual((old/'revoked').read_bytes(),b'{}')

    def test_expired_child_cannot_borrow_current_parent_or_final_historical_state(self):
        reader,*_=self.prepared();self.now+=91
        with self.assertRaises((ValueError,RuntimeError)):reader.retired(m.ObservationBudget(30))
        reader.legacy.channel.current.assert_not_called()

    def backup_files(self,reader,backup):
        root=backup.root;archive=b'PGDMP'+b'disposable-existing-archive'*10;self.write(root/'semantic.dump',archive)
        gate={'schema':'ouf.discovery.database-gate.v1','status':'WRITERS_FENCED','databaseScopeHash':m.digest({'name':backup.intent['database'],'oid':backup.intent['databaseOid']}),
            'newConnectionsDenied':True,'otherSessionsAbsent':True,'automaticReopen':False,'restorePerformed':False,'migrationPerformed':False}
        receipt={'schema':'ouf.discovery.fenced-backup.v1','status':'PRIVATE_FENCED_SNAPSHOT_PAYLOAD_VALIDATED',
            'gateReceiptHash':m.digest(gate),'archiveSha256':hashlib.sha256(archive).hexdigest(),'archiveBytes':len(archive),
            'archivePayloadParsed':True,'databaseAdmissionRemainsClosed':True,'allOtherSessionsAbsentAtGate':True,
            'restorePerformed':False,'migrationPerformed':False,'targetAuthorityGranted':False}
        for name,value in [('backup-phase-binding.json',backup.context),('gate-receipt.json',gate),('backup-receipt.json',receipt)]:
            self.write(root/name,m.encoded(value))
        proof={**backup.retained_snapshot(),'currentDatabaseState':{'oid':backup.intent['databaseOid'],'closed':True,'prepared':0,'sessions':0}}
        reader.store.publish('FENCED_BACKUP',proof);return proof

    def test_late_backup_read_uses_retained_archive_without_asserting_migrated_db_is_closed(self):
        reader,row,_,_,backup=self.prepared();proof=self.backup_files(reader,backup)
        row.update(state='READY',nextPhase=12,effects=[{'phase':'FENCED_BACKUP','state':'APPLIED','intentHash':backup.intent_hash,'nativeEvidenceHash':m.digest(proof)}])
        with patch.object(backup,'snapshot',side_effect=AssertionError('CURRENT_CLOSED_DATABASE_ASSERTION_FORBIDDEN')):
            result=reader.retained_backup()
        self.assertTrue(result['retainedArchiveObserved']);self.assertFalse(result['currentDatabaseFenceProvenHere'])
        self.assertFalse(result['backupOrRestoreDispatched']);backup.checkpoint.assert_not_called()

    def test_corrupt_retained_archive_is_not_rebacked_up_or_restored(self):
        reader,row,_,_,backup=self.prepared();proof=self.backup_files(reader,backup)
        row.update(effects=[{'phase':'FENCED_BACKUP','state':'APPLIED','intentHash':backup.intent_hash,'nativeEvidenceHash':m.digest(proof)}])
        path=backup.root/'semantic.dump';path.write_bytes(b'corrupt')
        with self.assertRaises((ValueError,RuntimeError)):reader.retained_backup()
        self.assertEqual(path.read_bytes(),b'corrupt');backup.checkpoint.assert_not_called()

if __name__=='__main__':unittest.main()
