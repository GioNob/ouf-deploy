"""Composition boundaries only; fixture state confers no target authority."""
import hashlib,json,sys,types,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'tools/semantic_application_cutover'),str(ROOT/'tools/semantic_database_cutover'),str(ROOT/'tests')]
import test_cutover_executor as fixtures
from test_cutover_executor import j
from cutover_executor import Executor,digest,CutoverDenied
from transition_journal import Transition,PHASES
from database_gate import Psql,durable,GateDenied
from fenced_backup_adapter import FencedBackupAdapter

class BackupComposition(unittest.TestCase):
    def fixture(self, native_admin=None, native_intent=None):
        owner=fixtures.Composition();self.addCleanup(owner.doCleanups)
        e,calls,*rest=owner.fixture();root=rest[-1]
        evidence=root/'backup';evidence.mkdir(mode=0o700)
        intent={'containerId':'a'*64,'user':'postgres','database':'semantic','databaseOid':21558,'directory':str(evidence),'maxArchiveBytes':1048576}
        admin=Psql.__new__(Psql);admin.database='postgres';admin.temp=types.SimpleNamespace(name='/fixture/private')
        admin.process=types.SimpleNamespace(args=['docker','--config',admin.temp.name,'exec','-i','a'*64,'env','PGAPPNAME=ouf-cutover-admin-fixture','psql','-X','-q','-A','-t','-v','ON_ERROR_STOP=1','-U','postgres','-d','postgres'])
        native={'oid':21558,'closed':True,'prepared':0,'sessions':0}
        admin.query=lambda *a:dict(native)
        if native_admin is not None:
            admin=native_admin;intent=native_intent;evidence=Path(intent['directory'])
        e.intents['FENCED_BACKUP']=intent;e.authority['phaseIntentHashes']={p:digest(i) for p,i in e.intents.items()}
        raw=json.dumps(e.authority,sort_keys=True,separators=(',',':')).encode();sha=hashlib.sha256(raw).hexdigest()
        directory=root/'composed';directory.mkdir(mode=0o700);initial=Transition.initial(sha,'b'*64,'c'*64,'d'*64)
        journal=j.Journal(directory);journal.initialize(initial);transition=Transition(journal,initial['contextHash'])
        adapter=FencedBackupAdapter(admin,intent,lambda p:None,transition.context)
        if not hasattr(self,'contexts'):self.contexts={}
        self.contexts[str(evidence)]=adapter.context
        original=e.checkpoint
        def checkpoint(p,point,row):
            value=original(p,point,row);value['authorityHash']=sha;value['intentHash']=digest(e.intents[p]);return value
        e.adapters['FENCED_BACKUP']=adapter
        e=Executor(transition,raw,e.authenticate,checkpoint,e.adapters,e.intents,e.clock)
        return e,calls,adapter,intent,evidence,native
    def complete(self,root,intent):
        if not (root/'backup-phase-binding.json').exists():durable(root/'backup-phase-binding.json',self.contexts[str(root)])
        raw=b'fixture-archive-only'*30;archive=root/'semantic.dump';archive.write_bytes(raw);archive.chmod(0o600)
        gate={'schema':'ouf.discovery.database-gate.v1','status':'WRITERS_FENCED','databaseScopeHash':digest({'name':intent['database'],'oid':intent['databaseOid']}),'newConnectionsDenied':True,'otherSessionsAbsent':True,'automaticReopen':False,'restorePerformed':False,'migrationPerformed':False}
        durable(root/'gate-receipt.json',gate)
        backup={'schema':'ouf.discovery.fenced-backup.v1','status':'PRIVATE_FENCED_SNAPSHOT_PAYLOAD_VALIDATED','gateReceiptHash':digest(gate),'archiveSha256':hashlib.sha256(raw).hexdigest(),'archiveBytes':len(raw),'archivePayloadParsed':True,'databaseAdmissionRemainsClosed':True,'allOtherSessionsAbsentAtGate':True,'restorePerformed':False,'migrationPerformed':False,'targetAuthorityGranted':False}
        durable(root/'backup-receipt.json',backup)
    def test_crash_after_backup_reconciles_without_resending_primitive(self):
        e,calls,a,i,root,n=self.fixture()
        def effect(*args,**kwargs):self.complete(root,i);raise RuntimeError('fixture-crash-after-backup')
        with patch('fenced_backup_adapter.fenced_backup',side_effect=effect) as apply:
            with self.assertRaisesRegex(RuntimeError,'fixture-crash'):e.run(3)
            self.assertEqual(e.t.read()['state'],'IN_FLIGHT')
            e.t=Transition(j.Journal(root.parent/'composed'),e.t.context)
            e.run(3);e.run(3);self.assertEqual(apply.call_count,1)
        self.assertEqual(e.t.read()['nextPhase'],3);self.assertFalse(e.report(e.t.read())['releaseAcceptance'])
    def test_missing_receipts_remain_ambiguous_without_second_backup(self):
        e,calls,a,i,root,n=self.fixture()
        with patch('fenced_backup_adapter.fenced_backup') as apply:
            with self.assertRaises(CutoverDenied):e.run(3)
            with self.assertRaises(CutoverDenied):e.run(3)
            self.assertEqual(apply.call_count,1);self.assertEqual(e.t.read()['state'],'IN_FLIGHT')
    def test_archive_corruption_reopened_database_and_foreign_scope_block(self):
        for change in ('archive','database','scope','sessions'):
            with self.subTest(change=change):
                e,calls,a,i,root,n=self.fixture();self.complete(root,i)
                if change=='archive':(root/'semantic.dump').write_bytes(b'corrupt')
                if change=='database':n['closed']=False
                if change=='sessions':n['sessions']=1
                if change=='scope':n['oid']+=1
                with self.assertRaises(GateDenied):a.observe(i)
    def test_wrong_channel_intent_links_and_mode_block(self):
        for change in ('channel','intent','link','mode'):
            with self.subTest(change=change):
                e,calls,a,i,root,n=self.fixture();self.complete(root,i)
                if change=='channel':a.admin.process.args[5]='b'*64
                if change=='intent':i={**i,'databaseOid':1}
                if change=='link':(root/'semantic.dump').unlink();(root/'semantic.dump').symlink_to(root/'backup-receipt.json')
                if change=='mode':(root/'semantic.dump').chmod(0o644)
                with self.assertRaises((GateDenied,OSError)):a.observe(i)
    def test_current_fence_changes_between_reads_blocks(self):
        e,calls,a,i,root,n=self.fixture();self.complete(root,i);counter=[0]
        def query(*args):
            counter[0]+=1;return {**n,'closed':counter[0]==1}
        a.admin.query=query
        with self.assertRaises(GateDenied):a.observe(i)
    def test_retained_archive_read_does_not_assert_historical_fence_is_current(self):
        e,calls,a,i,root,n=self.fixture();self.complete(root,i)
        expected=a.snapshot();expected.pop('currentDatabaseState')
        n['closed']=False;n['sessions']=3
        with patch.object(a.admin,'query',side_effect=AssertionError('archive read cannot query SQL')):
            self.assertEqual(a.retained_snapshot(),expected)
        with self.assertRaises(GateDenied):a.snapshot()
    def test_retained_archive_read_still_rejects_corruption_and_foreign_context(self):
        for change in ('archive','context'):
            with self.subTest(change=change):
                e,calls,a,i,root,n=self.fixture();self.complete(root,i)
                if change=='archive':(root/'semantic.dump').write_bytes(b'corrupt')
                else:(root/'backup-phase-binding.json').write_text(json.dumps({**a.context,'transitionContextHash':'f'*64}))
                with self.assertRaises(GateDenied):a.retained_snapshot()
    def test_foreign_transition_or_unbound_old_backup_cannot_be_adopted(self):
        for change in ('foreign','absent'):
            e,calls,a,i,root,n=self.fixture();self.complete(root,i)
            path=root/'backup-phase-binding.json'
            if change=='foreign':path.write_text(json.dumps({**a.context,'transitionContextHash':'f'*64}))
            else:path.unlink()
            if change=='foreign':
                with self.assertRaises(GateDenied):a.observe(i)
            else:self.assertEqual(a.observe(i)[0],'UNKNOWN')
            with patch('fenced_backup_adapter.fenced_backup') as apply:
                with self.assertRaises(GateDenied):a.apply(i)
                apply.assert_not_called()

if __name__=='__main__':unittest.main()
