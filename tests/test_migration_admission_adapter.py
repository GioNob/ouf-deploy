import copy,sys,types,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT/'tests'),str(ROOT/'tools/semantic_application_cutover'),str(ROOT/'tools/semantic_database_cutover')]
from database_gate import Psql,GateDenied,digest
from engine_creation import Engine
from migration_admission_adapter import MigrationAdmissionAdapter
from executor_composition_fixture import compose
from cutover_executor import CutoverDenied

class Admission(unittest.TestCase):
    def fixture(self):
        admin=Psql.__new__(Psql);admin.database='postgres';admin.temp=types.SimpleNamespace(name='/fixture/private')
        cid='a'*64;admin.process=types.SimpleNamespace(args=['docker','--config',admin.temp.name,'exec','-i',cid,'env','PGAPPNAME=ouf-cutover-admin-fixture','psql','-X','-q','-A','-t','-v','ON_ERROR_STOP=1','-U','postgres','-d','postgres'])
        state={'oid':21558,'allowConnections':False,'prepared':0,'sessions':0};writes=[]
        def query(expression,statement=''):
            if statement.startswith('ALTER DATABASE'):writes.append(statement);state['allowConnections']=True;return True
            return dict(state)
        admin.query=query
        paused={'Id':'1'*64,'Image':'sha256:'+'b'*64,'Config':{},'HostConfig':{},'Mounts':[],'NetworkSettings':{},'State':{'Running':True,'Paused':True,'Status':'paused','Pid':500,'StartedAt':'2026-10-12T00:00:00Z'}}
        engine=Engine.__new__(Engine);engine.inspect=lambda t:copy.deepcopy(paused)
        intent={'containerId':cid,'user':'postgres','database':'semantic','databaseOid':21558,'priorBackupEvidencePhase':'FENCED_BACKUP','priorPausedEvidencePhase':'STAGE_PAUSED_REPLACEMENT'}
        def prior(phase):
            def create(t,store):
                def observe(value):
                    record=copy.deepcopy(paused) if phase=='STAGE_PAUSED_REPLACEMENT' else {'schema':'ouf.semantic-fenced-backup-executor-evidence.v1','transitionContextHash':t.context,'databaseContainerId':cid,'databaseScopeHash':digest({'name':'semantic','oid':21558}),'currentDatabaseState':{'oid':21558,'closed':True,'prepared':0,'sessions':0}}
                    store.publish(phase,record);return 'APPLIED',record
                return types.SimpleNamespace(apply=lambda value:None,observe=observe)
            return create
        additional={p:({'syntheticFixture':p},prior(p)) for p in ('FENCED_BACKUP','STAGE_PAUSED_REPLACEMENT')}
        e,store=compose(self,'ADMIT_MIGRATION',intent,lambda t,s:MigrationAdmissionAdapter(admin,engine,t,intent,s),additional)
        return e,state,paused,writes
    def test_crash_after_admission_never_reopens_and_keeps_migration_boundary(self):
        e,state,paused,writes=self.fixture();a=e.adapters['ADMIT_MIGRATION'];original=a.apply
        def crash(value):original(value);raise RuntimeError('fixture-crash-after-open')
        a.apply=crash
        with self.assertRaises(RuntimeError):e.run(10)
        a.apply=lambda value:self.fail('ADMISSION_REPLAYED')
        e.run(10);e.run(10);self.assertEqual(len(writes),1)
        self.assertTrue(e.t.read()['databaseMayHaveChanged']);self.assertFalse(e.t.read()['preMigrationRestoreAllowed'])
    def test_unproven_open_stays_consumed_without_another_attempt(self):
        e,state,paused,writes=self.fixture();a=e.adapters['ADMIT_MIGRATION']
        a.apply=lambda value:None
        with self.assertRaises(CutoverDenied):e.run(10)
        with self.assertRaises(CutoverDenied):e.run(10)
        self.assertEqual(writes,[]);self.assertEqual(e.t.read()['state'],'IN_FLIGHT');self.assertTrue(e.t.read()['databaseMayHaveChanged'])
    def test_foreign_session_oid_or_paused_generation_blocks_before_open(self):
        for change in ('session','oid','generation','unpaused'):
            e,state,paused,writes=self.fixture();e.run(9)
            if change=='session':state['sessions']=1
            if change=='oid':state['oid']+=1
            if change=='generation':paused['State']['Pid']+=1
            if change=='unpaused':paused['State']['Paused']=False
            with self.assertRaises(GateDenied):e.run(10)
            self.assertEqual(writes,[])

if __name__=='__main__':unittest.main()
