"""Actual crypto/files/budget/subprocess; simulated Docker/PostgreSQL replies.

The executable fixture asserts readonly SQL and explicit Engine selection.
It is not a real PostgreSQL/production token-owner qualification.
"""
import copy,json,os,sys,time,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[3];sys.path[:0]=[str(ROOT/'tests'),str(Path(__file__).resolve().parent),str(ROOT)]
import test_node_owner as base
from cutover_authority import CutoverAuthority
from tools.ingestion_readiness_patch_execution import private_file,runtime_bindings
from tools.ingestion_readiness_patch_execution.contract import Denied
from tools.semantic_registry_recovery_execution import core as c,authorization as a,database as d,admission as adm
from tools.semantic_registry_recovery_execution import read_budget as b

def file_profile(path):
    path=Path(path).resolve();parents=list(reversed(path.parents))
    return {'path':str(path),'sha256':__import__('hashlib').sha256(path.read_bytes()).hexdigest(),
        'metadata':private_file.metadata(path.stat()),
        'ancestors':[{'path':str(parent),'identity':[s.st_dev,s.st_ino,s.st_uid,s.st_gid,s.st_mode]}
            for parent in parents for s in [parent.stat()]]}

class CurrentAdmission(unittest.TestCase):
    native=base.NodeOwner.native;write=base.NodeOwner.write;binding=base.NodeOwner.binding;sign=base.NodeOwner.sign
    def setUp(self):
        base.NodeOwner.setUp(self);self.lifecycle=self.owner.lifecycle
        self.lifecycle.engine.path='/fixture/explicit-engine.sock';self.lifecycle.engine.binding=(1,2,0,0,0o600)
        self.lifecycle.engine.check_socket=lambda:None
        self.pg={'Id':'a'*64,'Image':'sha256:'+'b'*64,'Config':{'Env':[]},'HostConfig':{},'Mounts':[],
            'NetworkSettings':{},'RestartCount':0,
            'State':{'Running':True,'Paused':False,'Restarting':False,'Pid':4321,'StartedAt':'fixture'}}
        self.pin={'binding':runtime_bindings.observed(self.pg,runtime_bindings.SORTED),
            'bindingProfile':runtime_bindings.SORTED,'restartCount':0}
        self.history=[{'version':'1','type':'SQL','script':'V1__fixture.sql','checksum':123,'success':True}]
        self.readiness={'databaseContainerId':self.pg['Id'],'databaseUser':'fixture_user','database':'fixture_db',
            'databaseOid':123,'flywaySchema':'ouf_sem','flywayHistoryHash':c.digest(self.history),
            'health':{'address':'192.0.2.1','port':8080,'path':'/actuator/health/readiness','timeoutSeconds':1}}
        self.reply={'database':'fixture_db','databaseOid':123,'allowConnections':True,'role':'fixture_user',
            'transactionReadOnly':True,'history':self.history}
        self.reply_path=self.root/'pg-reply.json';self.reply_path.write_bytes(c.encoded(self.reply))
        self.argv_path=self.root/'argv.json';program=self.root/'fixture-docker'
        source=("#!/usr/bin/python3\nimport json,os,sys\nfrom pathlib import Path\n"
            +"args=sys.argv[1:]\nassert args[0:2]==['--host','unix:///fixture/explicit-engine.sock']\n"
            +"assert args[2]=='--config' and os.listdir(args[3])==[]\n"
            +"assert '--single-transaction' in args and '-X' in args and 'exec' in args\n"
            +"assert 'PGOPTIONS=-c default_transaction_read_only=on -c statement_timeout=10000 -c lock_timeout=3000' in args\n"
            +"assert 'ALTER ' not in args[-1] and 'INSERT ' not in args[-1] and 'UPDATE ' not in args[-1]\n"
            +"assert not any(k in os.environ for k in ('DOCKER_HOST','DOCKER_CONTEXT','PGPASSWORD'))\n"
            +"Path("+repr(str(self.argv_path))+").write_text(json.dumps(args))\n"
            +"sys.stdout.buffer.write(Path("+repr(str(self.reply_path))+").read_bytes())\n")
        program.write_text(source);program.chmod(0o700);self.program=file_profile(program)
        self.audit={'disposableFixtureImageAudit':True}
        self.lifecycle.engine.request=lambda method,path:(200,copy.deepcopy(self.pg) if '/containers/' in path else {'fixtureImage':True})
        if hasattr(self,'configure_database'):self.configure_database()
        loaded=patch.object(d,'loaded',return_value={'syntheticImageAdmission':True});loaded.start();self.addCleanup(loaded.stop)
        lease=patch.object(adm,'guard_lease',return_value={'explicitSyntheticTokenLease':True})
        lease.start();self.addCleanup(lease.stop)
        # Compile all extra scopes before signing a new disposable mandate.
        scope=d.database_scope(self.lifecycle,self.readiness,self.pin,self.program,self.audit)
        dummy=d.CurrentDatabase.__new__(d.CurrentDatabase);dummy.lifecycle=self.lifecycle;dummy.scope=scope
        self.resign({'semanticRegistryRecoveryReads':b.read_scope(self.plan,self.store.root),
            'semanticRegistryRecoveryDatabase':scope,'semanticRegistryRecoveryAdmission':adm.admission_scope(dummy,self.owner)})
        self.budget=b.ReadBudget.initialize(self.store,self.lifecycle.authority,self.plan)
        self.database=d.CurrentDatabase(self.lifecycle,self.readiness,self.pin,self.program,self.audit,self.budget)
        self.admission=adm.CurrentAdmission(self.database,self.owner)

    def resign(self,scopes):
        raw=json.loads(self.authority);raw.update(scopes);self.authority=c.encoded(raw)
        self.approval['executionAuthorityHash']=__import__('hashlib').sha256(self.authority).hexdigest()
        self.write(self.mandate,c.encoded(self.approval));approved=__import__('hashlib').sha256(self.mandate.read_bytes()).hexdigest()
        for role in self.grant['roles']:self.sign(role)
        authority=CutoverAuthority(self.verifier,self.binding(self.mandate),approved,self.context,self.expected,self.clock,execution_profile=self.profile)
        scope=a.AuthorityScope(authority,self.authority,self.plan,self.lifecycle.request)
        row=self.store.read();after=copy.deepcopy(row);after['authorityHash']=scope.hash;after['version']+=1
        for effect in after['effects']:effect['authorityHash']=scope.hash
        self.store.cas(row,after);self.lifecycle.authority=scope
        self.owner.token_owner.authority=authority;self.owner.token_owner.raw=self.authority

    def test_readonly_session_uses_exact_socket_and_checks_identity_history(self):
        before=self.store.read()
        with patch.dict(os.environ,{'DOCKER_HOST':'tcp://WRONG','DOCKER_CONTEXT':'WRONG','PGPASSWORD':'FIXTURE'}):
            proof=self.database.snapshot()
        self.assertTrue(proof['transactionReadOnly']);self.assertEqual(proof['databaseMutations'],0)
        self.assertEqual(self.store.read(),before)
        self.assertEqual(self.budget.read()['counts']['databaseSessions'],1)
        args=json.loads(self.argv_path.read_text());self.assertIn('"ouf_sem".flyway_schema_history',args[-1])
        self.assertNotIn('FIXTURE',json.dumps(proof))

    def test_expired_retained_token_blocks_before_a_database_session(self):
        before=self.budget.read()
        with patch.object(adm,'guard_lease',side_effect=c.RecoveryDenied('FIXTURE_EXPIRED_RETAINED_TOKEN')):
            with self.assertRaisesRegex(c.RecoveryDenied,'EXPIRED_RETAINED_TOKEN'):self.admission.prerequisites()
        self.assertEqual(self.budget.read(),before)

    def test_wrong_oid_role_readonly_state_or_history_cannot_admit(self):
        for name,value in [('databaseOid',124),('role','wrong'),('transactionReadOnly',False),('allowConnections',False),('history',[])]:
            reply=copy.deepcopy(self.reply);reply[name]=value;self.reply_path.write_bytes(c.encoded(reply))
            with self.subTest(field=name),self.assertRaises(c.RecoveryDenied):self.database.snapshot()

    def test_unknown_session_response_consumes_a_read_slot_without_reset(self):
        self.reply_path.write_bytes(b'not-json')
        with self.assertRaisesRegex(c.RecoveryDenied,'JSON_UNCONFIRMED'):self.database.snapshot()
        self.assertEqual(self.budget.read()['counts']['databaseSessions'],1)
        with self.assertRaises(FileExistsError):b.ReadBudget.initialize(self.store,self.lifecycle.authority,self.plan)
        self.assertEqual(self.budget.read()['counts']['databaseSessions'],1)

    def test_changed_docker_executable_or_postgres_generation_blocks_session(self):
        self.pg['State']['Pid']+=1
        with self.assertRaises(Denied):self.database.snapshot()
        self.assertFalse(self.argv_path.exists());self.pg['State']['Pid']-=1
        Path(self.program['path']).write_text('#!/bin/false\n')
        with self.assertRaises(Denied):self.database.snapshot()
        self.assertFalse(self.argv_path.exists())

    def test_parked_or_revoked_actual_owner_never_passes_admission(self):
        from tools.semantic_lease_recovery.bounded_recovery import Permanent
        with patch.object(self.owner.token_owner,'guard',side_effect=Permanent('AUTHORITY_REVOKED')):
            with self.assertRaises(Permanent):self.admission.prerequisites()
        self.assertFalse(self.argv_path.exists())

    def test_read_counter_is_finite_persistent_and_scope_bound(self):
        for _ in range(b.LIMITS['semanticGets']):self.budget.reserve('semanticGets')
        with self.assertRaisesRegex(c.RecoveryDenied,'BUDGET_EXHAUSTED'):self.budget.reserve('semanticGets')
        reopened=b.ReadBudget(self.store,self.lifecycle.authority,self.plan)
        self.assertEqual(reopened.read()['counts']['semanticGets'],b.LIMITS['semanticGets'])
        with self.assertRaises(FileExistsError):b.ReadBudget.initialize(self.store,self.lifecycle.authority,self.plan)

    def test_expired_recovery_clock_refuses_a_new_read_even_with_wider_mandate(self):
        with patch('time.time',return_value=self.now+111):
            with self.assertRaisesRegex(c.RecoveryDenied,'CURRENT_FINITE'):self.budget.reserve('databaseSessions')

if __name__=='__main__':unittest.main()
