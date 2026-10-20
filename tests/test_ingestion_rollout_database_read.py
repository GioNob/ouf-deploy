"""Explicit SQL channel and real role/CAS protocol; synthetic Engine/SQL facts.

These are component tests, not actual PostgreSQL/JVM or full runtime admission.
"""
import copy
import json
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tests'),str(ROOT/'tools/semantic_policy_token_owner'),
             str(ROOT/'tools/semantic_application_cutover'),str(ROOT/'tools/semantic_cohort_admission/cohort-draft')]
from tools.ingestion_rollout_execution import database_read as d,database_policy as policy,contract as c
from test_ingestion_rollout_database_policy import facts
from engine_creation import Engine

def fixture_profile(directory,program=None):
    pg={'Id':'a'*64,'Image':'sha256:'+'b'*64,'Config':{'fixture':'postgres'},
        'HostConfig':{'fixture':True},'Mounts':[],'NetworkSettings':{'Networks':{}},'RestartCount':2,
        'State':{'Pid':42,'StartedAt':'retained-process','Running':True,'Paused':False,'Restarting':False}}
    p={'schema':'ouf.ingestion-rollout-native-database-read.v1',
        'engineBinding':{'socketPath':'/ente-fixture/engine.sock','socketBinding':[1,2,0,0,0o600]},
        'postgresRuntimeBinding':Engine.runtime_binding(pg),'postgresRestartCount':2,
        'identity':{'database':'ente_db','user':'ente_runtime','databaseOid':42,'postgresPort':15432},
        'dockerExecutable':program or {'path':'/ente-fixture/docker','sha256':'c'*64},
        'dockerConfigDirectory':str(directory),'dockerConfigIdentity':d.empty_config_directory(str(directory)),
        'containerPrograms':{'env':'/ente-fixture/env','timeout':'/ente-fixture/timeout','psql':'/ente-fixture/psql'},
        'unixSocketDirectory':'/ente-fixture/postgres-socket'}
    return p,pg

class NativeReadProfile(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(dir=os.environ.get('OUF_TEST_ROOT',str(ROOT)))
        self.addCleanup(self.temp.cleanup);self.directory=Path(self.temp.name);self.directory.chmod(0o700)
        self.profile,self.pg=fixture_profile(self.directory)
    def test_all_native_paths_identity_and_port_are_explicit_and_credentials_disabled(self):
        args=d.arguments(self.profile);self.assertEqual(args[0],self.profile['dockerExecutable']['path'])
        self.assertEqual(args[args.index('-p')+1],'15432');self.assertEqual(args[args.index('-h')+1],'/ente-fixture/postgres-socket')
        self.assertIn('PGPASSFILE=/dev/null',args);self.assertIn('PGSERVICEFILE=/dev/null',args)
        self.assertIn('-i',args);self.assertEqual(args[-1],policy.SQL);self.assertNotIn('PGPASSWORD',str(args))
        other=copy.deepcopy(self.profile);other['identity']['postgresPort']=25432
        other['unixSocketDirectory']='/other-ente/socket'
        other['containerPrograms']['psql']='/other-ente/psql'
        self.assertEqual(d.arguments(other)[d.arguments(other).index('-p')+1],'25432')
    def test_implicit_binary_socket_identity_or_port_is_rejected(self):
        mutations=[lambda p:p.pop('containerPrograms'),lambda p:p['identity'].pop('postgresPort'),
                   lambda p:p['engineBinding'].update(socketPath='../docker.sock'),
                   lambda p:p['containerPrograms'].update(psql='psql'),lambda p:p['identity'].update(user='user;injection'),
                   lambda p:p['identity'].update(postgresPort=True),lambda p:p.pop('dockerConfigIdentity')]
        for mutate in mutations:
            p=copy.deepcopy(self.profile);mutate(p)
            with self.assertRaises(c.Denied):d.arguments(p)
    def test_credential_config_and_symlink_directory_are_rejected(self):
        selected=self.directory/'config.json';selected.write_text('{}')
        with self.assertRaises(c.Denied):d.empty_config_directory(str(self.directory))
        selected.unlink();link=self.directory/'alias';link.symlink_to(self.directory,target_is_directory=True)
        with self.assertRaises(OSError):d.empty_config_directory(str(link))

@unittest.skipUnless(os.environ.get('OUF_NATIVE_UIDS')=='1','actual root role signatures and CAS required')
class SignedDatabaseReads(unittest.TestCase):
    def setUp(self):
        import test_ingestion_rollout_execution as core
        self.temp=tempfile.TemporaryDirectory(dir=os.environ['OUF_TEST_ROOT']);self.addCleanup(self.temp.cleanup)
        root=Path(self.temp.name);root.chmod(0o700)
        self.profile,self.pg=fixture_profile(root,d.governance.executable(os.environ.get('OUF_TEST_PYTHON',sys.executable)))
        original=core.review_fixture
        def fixture(context='/fixture/execution',key_path=None):
            review,packet,inputs=original(context,key_path)
            review['databaseControlProfile']=copy.deepcopy(self.profile);review['maximumDatabaseReadSessions']=d.MAX_SESSIONS
            return review,packet,inputs
        with patch.object(core,'review_fixture',side_effect=fixture):core.SignedFiniteRunner.setUp(self)
        from tools.chatbot_file_cohort.human_session import HumanSession
        from tools.ingestion_rollout_execution.replacement import EngineReader
        self.human=HumanSession.__new__(HumanSession);self.human.current=lambda:self.scope['humanBinding']
        engine=Engine.__new__(Engine);engine.path=self.profile['engineBinding']['socketPath']
        engine.binding=tuple(self.profile['engineBinding']['socketBinding']);engine.check_socket=lambda:None
        self.reader=EngineReader(engine);self.reader.container=lambda cid:copy.deepcopy(self.pg)
        row=self.runner.record()
        self.runner.journal.compare_and_save(row,{**row,'expiresMonotonic':time.monotonic()+240,'version':row['version']+1})
        self.native=d.NativeDatabaseRead(self.action,self.runner.journal,self.review,self.human,self.reader)
    def test_actual_reservation_precedes_synthetic_sql_and_never_grants_admission(self):
        snapshot=facts();snapshot['observedAtUnix']=int(time.time())
        def query(args):
            self.assertEqual(self.runner.record()['nativeDatabaseReadSessions'],1)
            self.assertEqual(args[-1],policy.SQL);return 0,c.encoded(snapshot),b''
        with patch.object(d,'bounded_read',side_effect=query)as native,patch.object(policy,'REFERENCE_CATALOG_SHA256',c.digest(snapshot['catalog'])):
            report=self.native.snapshot();self.assertEqual(native.call_count,1)
        self.assertTrue(report['databaseReadPrerequisitesProven']);self.assertFalse(report['databaseAdmissionProven'])
        self.assertFalse(report['runtimeAuthorityIssued'])
    def test_failed_dispatch_consumes_one_session_and_never_retries_implicitly(self):
        with patch.object(d,'bounded_read',side_effect=OSError('synthetic dispatch loss'))as native:
            with self.assertRaises(OSError):self.native.snapshot()
            self.assertEqual(native.call_count,1)
        self.assertEqual(self.runner.record()['nativeDatabaseReadSessions'],1)
    def test_exhausted_session_budget_cannot_be_reset_by_another_component_instance(self):
        row=self.runner.record();self.runner.journal.compare_and_save(row,{**row,'nativeDatabaseReadSessions':127,'version':row['version']+1})
        self.native.reserve()
        second=d.NativeDatabaseRead(self.action,self.runner.journal,self.review,self.human,self.reader)
        with self.assertRaises(c.Denied):second.reserve()
        self.assertEqual(self.runner.record()['nativeDatabaseReadSessions'],128)
    def test_generation_role_drift_or_credential_config_blocks_before_dispatch(self):
        self.pg['State']['Pid']+=1
        with patch.object(d,'bounded_read')as native:
            with self.assertRaises(c.Denied):self.native.snapshot()
            native.assert_not_called()
        self.pg['State']['Pid']-=1
        (Path(self.profile['dockerConfigDirectory'])/'config.json').write_text('{}')
        with patch.object(d,'bounded_read')as native:
            with self.assertRaises(c.Denied):self.native.snapshot()
            native.assert_not_called()
    def test_invalid_stale_sql_facts_cannot_be_admitted(self):
        snapshot=facts();snapshot['observedAtUnix']=int(time.time())-6
        with patch.object(d,'bounded_read',return_value=(0,c.encoded(snapshot),b'')):
            with self.assertRaises(c.Denied):self.native.snapshot()
        self.assertEqual(self.runner.record()['nativeDatabaseReadSessions'],1)

if __name__=='__main__':unittest.main()
