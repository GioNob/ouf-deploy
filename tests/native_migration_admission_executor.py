"""Actual fenced PG17 backup → paused process → admission → native release.
Lease/attestation/transport/authority and producer inventory are synthetic.
"""
import json,os,subprocess,sys,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT/'tests'),str(ROOT/'tools/semantic_application_cutover'),str(ROOT/'tools/semantic_database_cutover')]
from test_fenced_backup_native import FencedBackupNative
from native_runtime_executor import NativeRuntime
from executor_composition_fixture import compose
from database_gate import Psql,GateDenied,digest
from engine_creation import Engine
from creation_adapter import CreationAdapter
from runtime_adapters import PausedStageAdapter,ReleasePausedAdapter
from fenced_backup_adapter import FencedBackupAdapter
from migration_admission_adapter import MigrationAdmissionAdapter
from transition_journal import Transition

class NativeAdmission(FencedBackupNative):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        subprocess.run(['docker','pull','alpine:3.21'],check=True,stdout=subprocess.DEVNULL,timeout=90)
        cls.image=subprocess.check_output(['docker','image','inspect','alpine:3.21','--format','{{.Id}}'],timeout=15).decode().strip()
    def compose(self):
        socket='/var/run/docker.sock';s=os.stat(socket,follow_symlinks=False);engine=Engine(socket,(s.st_dev,s.st_ino,s.st_uid,s.st_gid,s.st_mode&0o777))
        request={'Image':self.image,'Cmd':['sleep','600'],'HostConfig':{'NetworkMode':'none','RestartPolicy':{'Name':'no','MaximumRetryCount':0}}}
        backup={'containerId':self.cid,'user':'postgres','database':self.db,'databaseOid':self.oid,'directory':self.directory.name,'maxArchiveBytes':16*1024**2}
        admission={'containerId':self.cid,'user':'postgres','database':self.db,'databaseOid':self.oid,'priorBackupEvidencePhase':'FENCED_BACKUP','priorPausedEvidencePhase':'STAGE_PAUSED_REPLACEMENT'}
        stage={'creationRequestHash':digest(request),'priorEvidencePhase':'CREATE_REPLACEMENT'};release={'creationRequestHash':digest(request),'priorEvidencePhase':'STAGE_PAUSED_REPLACEMENT'}
        additional={'FENCED_BACKUP':(backup,lambda t,s:FencedBackupAdapter(self.admin,backup,lambda point:None,t.context,s)),
                    'CREATE_REPLACEMENT':(request,lambda t,s:CreationAdapter(engine,t,request,s)),
                    'STAGE_PAUSED_REPLACEMENT':(stage,lambda t,s:PausedStageAdapter(engine,t,request,s)),
                    'START_REPLACEMENT':(release,lambda t,s:ReleasePausedAdapter(engine,t,request,s))}
        e,store=compose(self,'ADMIT_MIGRATION',admission,lambda t,s:MigrationAdmissionAdapter(self.admin,engine,t,admission,s),additional,request)
        def cleanup():
            actual=engine.inspect(e.t)
            if actual is not None:engine.request('DELETE','/v1.44/containers/'+actual['Id']+'?force=true')
        self.addCleanup(cleanup)
        return e,engine,store,admission
    def test_controller_death_after_admission_reconciles_then_releases_exact_paused_generation(self):
        e,engine,store,intent=self.compose();e.run(9);before=engine.runtime_binding(engine.inspect(e.t))
        self.assertFalse(self.admin.query('SELECT datallowconn FROM pg_database WHERE oid='+str(self.oid)))
        pid=os.fork()
        if pid==0:
            admin=Psql(self.cid,'postgres','postgres','ouf-cutover-admin-migration-child')
            adapter=MigrationAdmissionAdapter(admin,engine,e.t,intent,store);original=adapter.apply
            def crash(value):original(value);admin.close();os._exit(71)
            adapter.apply=crash;e.adapters['ADMIT_MIGRATION']=adapter
            try:e.run(10)
            except BaseException:os._exit(72)
            os._exit(73)
        _,status=os.waitpid(pid,0);self.assertEqual(os.waitstatus_to_exitcode(status),71)
        e.t=Transition(e.t.journal,e.t.context)
        for adapter in e.adapters.values():
            if hasattr(adapter,'transition'):adapter.transition=e.t
        e.adapters['ADMIT_MIGRATION'].apply=lambda value:self.fail('DATABASE_ADMISSION_REPLAYED')
        e.run(10);e.run(10);e.run(11)
        self.assertEqual(engine.runtime_binding(engine.inspect(e.t)),before)
        later=self.channel(self.db,'later');later.query('true','INSERT INTO ouf_sem.fixture VALUES(3);')
        self.assertEqual(later.query('SELECT json_agg(id ORDER BY id) FROM ouf_sem.fixture'),[1,2,3])
        self.assertTrue(e.t.read()['databaseMayHaveChanged']);self.assertFalse(e.t.read()['preMigrationRestoreAllowed'])
    def test_foreign_admitted_session_after_interruption_blocks_release(self):
        e,engine,store,intent=self.compose();e.run(9);a=e.adapters['ADMIT_MIGRATION'];original=a.apply
        def interrupt(value):original(value);raise RuntimeError('fixture-crash-after-open')
        a.apply=interrupt
        with self.assertRaises(RuntimeError):e.run(10)
        other=self.channel(self.db,'foreignwriter');self.assertTrue(other.query('true'))
        with self.assertRaises(GateDenied):e.run(10)
        self.assertTrue(engine.inspect(e.t)['State']['Paused']);self.assertEqual(e.t.read()['state'],'IN_FLIGHT')
        self.assertTrue(self.other.query('true','INSERT INTO fixture VALUES(2);'))

if __name__=='__main__':
    names=[n for n in NativeAdmission.__dict__ if n.startswith('test_')]
    result=unittest.TextTestRunner(verbosity=2).run(unittest.TestSuite(NativeAdmission(n) for n in names))
    if result.wasSuccessful():print('OUF_MIGRATION_ADMISSION_EXECUTOR_NATIVE='+json.dumps({'status':'PASS','tests':result.testsRun,'actualFencedPostgresqlBackup':True,'actualPausedAndReleasedProcess':True,'actualControllerDeathAfterAdmission':True,'admissionReplayDenied':True,'sameProcessGenerationReleased':True,'lateCommittedRowsPreserved':True,'foreignSessionBlocksRelease':True,'authorityAndLeaseAndAttestationAndTransportSynthetic':True,'semanticJvmStarted':False,'targetApplied':False,'targetInstallerQualified':False,'notReleaseAcceptance':True}))
    raise SystemExit(not result.wasSuccessful())
