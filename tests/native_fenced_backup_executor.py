"""Actual PG17 backup + Executor process death and read-only reconciliation.

The first two phase adapters and signatures/checkpoints are synthetic fixtures.
No target authority or target producer/lease qualification is claimed.
"""
import json,os,sys,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'tests'),str(ROOT/'tools/semantic_application_cutover'),str(ROOT/'tools/semantic_database_cutover')]
from test_fenced_backup_native import FencedBackupNative
from test_fenced_backup_adapter import BackupComposition
from database_gate import Psql,GateDenied
from fenced_backup_adapter import FencedBackupAdapter
from transition_journal import Transition
from cutover_executor import CutoverDenied

class NativeComposition(FencedBackupNative):
    def compose(self):
        fixture=BackupComposition();self.addCleanup(fixture.doCleanups)
        intent={'containerId':self.cid,'user':'postgres','database':self.db,'databaseOid':self.oid,'directory':self.directory.name,'maxArchiveBytes':16*1024**2}
        return fixture.fixture(self.admin,intent)[0],intent
    def test_actual_process_death_after_backup_does_not_replay_or_reopen(self):
        executor,intent=self.compose()
        pid=os.fork()
        if pid==0:
            # A separate process/channel owns the effect; never share a parent
            # psql pipe across controller processes.
            admin=Psql(self.cid,'postgres','postgres','ouf-cutover-admin-composed-child')
            adapter=FencedBackupAdapter(admin,intent,lambda point:None,executor.t.context)
            adapter.apply_original=adapter.apply
            def crash(value):
                adapter.apply_original(value);admin.close();os._exit(71)
            adapter.apply=crash;executor.adapters['FENCED_BACKUP']=adapter
            try:executor.run(3)
            except BaseException:os._exit(72)
            os._exit(73)
        _,status=os.waitpid(pid,0)
        self.assertEqual(os.waitstatus_to_exitcode(status),71,'CHILD_DID_NOT_REACH_COMPLETED_NATIVE_BACKUP')
        self.assertEqual(executor.t.read()['state'],'IN_FLIGHT')
        executor.t=Transition(executor.t.journal,executor.t.context)
        adapter=executor.adapters['FENCED_BACKUP']
        def forbidden(value):raise AssertionError('BACKUP_PRIMITIVE_REPLAYED_AFTER_PROCESS_DEATH')
        adapter.apply=forbidden
        before=sorted((p.name,p.read_bytes()) for p in Path(self.directory.name).iterdir())
        report=executor.run(3);executor.run(3)
        after=sorted((p.name,p.read_bytes()) for p in Path(self.directory.name).iterdir())
        self.assertEqual(before,after);self.assertEqual(report['completedPhaseCount'],3)
        self.assertFalse(report['releaseAcceptance'])
        denied=self.channel(self.db,'newclient')
        with self.assertRaises(GateDenied):denied.query('true')
        self.assertTrue(self.other.query('true','INSERT INTO fixture VALUES(2);'))
    def test_completed_archive_cannot_reconcile_after_fixture_operator_reopens_database(self):
        executor,intent=self.compose();executor.run(2)
        original=executor.adapters['FENCED_BACKUP'].apply
        def interrupt(value):original(value);raise RuntimeError('fixture-controller-interruption')
        executor.adapters['FENCED_BACKUP'].apply=interrupt
        with self.assertRaises(RuntimeError):executor.run(3)
        self.admin.query('true','ALTER DATABASE '+self.db+' ALLOW_CONNECTIONS true;')
        with self.assertRaises(GateDenied):executor.run(3)
        self.assertEqual(executor.t.read()['state'],'IN_FLIGHT')

if __name__=='__main__':
    names=[n for n in NativeComposition.__dict__ if n.startswith('test_')]
    result=unittest.TextTestRunner(verbosity=2).run(unittest.TestSuite(NativeComposition(n) for n in names))
    if result.wasSuccessful():print('OUF_FENCED_BACKUP_EXECUTOR_NATIVE='+json.dumps({'status':'PASS','tests':result.testsRun,'actualPostgresql':True,'actualControllerProcessDeath':True,'actualFencedArchiveReconciled':True,'backupReplay':False,'automaticReopen':False,'precedingPhasesSynthetic':True,'authoritySynthetic':True,'targetApplied':False,'targetInstallerQualified':False,'notReleaseAcceptance':True}))
    raise SystemExit(not result.wasSuccessful())
