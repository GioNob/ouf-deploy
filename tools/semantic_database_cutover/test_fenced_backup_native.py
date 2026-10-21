"""Real fenced dump, clone restoration, late writes and incomplete failure."""
import json, subprocess, unittest
from pathlib import Path
from database_gate import GateDenied, Psql
from fenced_backup import fenced_backup
from test_database_gate_native import NativeGate, call

class FencedBackupNative(NativeGate):
    def setUp(self):
        super().setUp()
        self.writer.query('true','CREATE SCHEMA ouf_sem; ALTER TABLE fixture SET SCHEMA ouf_sem; CREATE SEQUENCE ouf_sem.seq; INSERT INTO ouf_sem.fixture VALUES(2);')
        self.assertEqual(self.writer.query("SELECT nextval('ouf_sem.seq')"),1)
    def backup(self,checkpoint=None):
        return fenced_backup(self.admin,self.cid,'postgres',self.db,self.oid,self.directory.name,checkpoint=checkpoint)
    def test_fenced_backup_preserves_committed_rows_sequence_and_does_not_overwrite_later_writes(self):
        receipt=self.backup()
        self.assertEqual(receipt['status'],'PRIVATE_FENCED_SNAPSHOT_PAYLOAD_VALIDATED')
        self.assertFalse(self.admin.query("SELECT datallowconn FROM pg_database WHERE datname='"+self.db+"'"))
        self.admin.query('true','CREATE DATABASE restored;')
        archive=Path(self.directory.name)/'semantic.dump'
        with archive.open('rb') as stream:
            p=subprocess.run(['docker','exec','-i',self.cid,'pg_restore','-U','postgres','-d','restored','--exit-on-error'],stdin=stream,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=45)
        self.assertEqual(p.returncode,0,'RESTORE_TO_FRESH_FIXTURE_FAILED')
        restored=self.channel('restored','restore')
        self.assertEqual(restored.query('SELECT json_agg(id ORDER BY id) FROM ouf_sem.fixture'),[1,2])
        self.assertEqual(restored.query('SELECT last_value FROM ouf_sem.seq'),1)
        self.assertTrue(self.other.query('true','INSERT INTO fixture VALUES(2);'))
        # Explicit fixture operator transition only, absent from production
        # helper: reopen the live fixture and make a write AFTER the backup.
        self.admin.query('true','ALTER DATABASE '+self.db+' ALLOW_CONNECTIONS true;')
        later=self.channel(self.db,'later')
        self.assertTrue(later.query('true','INSERT INTO ouf_sem.fixture VALUES(3);'))
        self.assertEqual(later.query('SELECT json_agg(id ORDER BY id) FROM ouf_sem.fixture'),[1,2,3])
        self.assertEqual(restored.query('SELECT json_agg(id ORDER BY id) FROM ouf_sem.fixture'),[1,2])
        self.assertFalse(receipt['restorePerformed']);self.assertFalse(receipt['migrationPerformed'])
    def test_interruption_before_writer_fence_does_not_accept_backup_or_reopen(self):
        def interrupt(phase):
            if phase=='ADMISSION_CLOSED_NOT_YET_WRITER_FENCED':raise RuntimeError('FIXTURE_INTERRUPTION')
        with self.assertRaisesRegex(GateDenied,'FENCED_BACKUP_INCOMPLETE'):self.backup(interrupt)
        self.assertFalse((Path(self.directory.name)/'backup-receipt.json').exists())
        denial=json.loads((Path(self.directory.name)/'backup-denial.json').read_bytes())
        self.assertFalse(denial['gateCompleted']);self.assertFalse(denial['backupOrMigrationAuthorityGranted'])
        self.assertFalse(self.admin.query("SELECT datallowconn FROM pg_database WHERE datname='"+self.db+"'"))
        with self.assertRaisesRegex(GateDenied,'DO_NOT_REPLAY'):self.backup()
    def test_corrupted_actual_dump_payload_rejected_without_automatic_reopen(self):
        def corrupt(phase):
            if phase=='PARSE_COMPLETE_ARCHIVE_PAYLOAD':
                with (Path(self.directory.name)/'semantic.dump.partial').open('r+b') as stream:stream.write(b'CORRUPT')
        with self.assertRaisesRegex(GateDenied,'PARSE_COMPLETE_ARCHIVE_PAYLOAD'):self.backup(corrupt)
        self.assertFalse((Path(self.directory.name)/'backup-receipt.json').exists())
        self.assertFalse(self.admin.query("SELECT datallowconn FROM pg_database WHERE datname='"+self.db+"'"))
        with self.assertRaises(GateDenied):self.writer.query('true')
    def test_foreign_schema_relation_rejected_before_any_gate_mutation(self):
        self.writer.query('true','CREATE TABLE public.unreviewed(id int);')
        with self.assertRaisesRegex(GateDenied,'PRECHECK'):self.backup()
        self.assertTrue(self.admin.query("SELECT datallowconn FROM pg_database WHERE datname='"+self.db+"'"))
        self.assertFalse((Path(self.directory.name)/'backup-claim.json').exists())

if __name__=='__main__':
    # Inherited native gate tests are intentionally not repeated. This suite
    # covers the linked backup primitive against its own disposable instance.
    names=[name for name in FencedBackupNative.__dict__ if name.startswith('test_')]
    suite=unittest.TestSuite(FencedBackupNative(name) for name in names)
    result=unittest.TextTestRunner(verbosity=2).run(suite)
    if result.wasSuccessful():print('OUF_FENCED_BACKUP_NATIVE='+json.dumps({'status':'PASS','tests':result.testsRun,'actualPostgresql':True,'actualPgDumpAndFreshDatabaseRestore':True,'committedRowsAndSequencePreserved':True,'lateWritesNotOverwritten':True,'corruptArchiveDenied':True,'partialFenceDoesNotAcceptBackup':True,'automaticReopen':False,'targetApplied':False,'notReleaseAcceptance':True}))
    raise SystemExit(not result.wasSuccessful())
