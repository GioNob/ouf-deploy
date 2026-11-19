"""Exact installed V36 preservation, immutable history, closed commands/readiness."""
import copy,importlib.util,json,unittest
from pathlib import Path
BASE=Path(__file__).resolve().parents[1]
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
fixture=load('retained_fence_fixture',BASE/'tests/test_profile_recovery_update_state_fence.py')
base=fixture.m
m=load('new_installed_fence',BASE/'tools/managed_csv_control_update/state_fence.py').bind(base)
base_ports=load('retained_two_owner_ports',BASE/'tools/acquisition_redaction_update/ports.py')
Ports=load('new_control_ports',BASE/'tools/managed_csv_control_update/ports.py').bind(base_ports)
class State(unittest.TestCase):
    def test_exact_installed36_baseline_is_not_a_new_migration(self):
        facts=fixture.facts(True);proof=m.validate(facts,fixture.PROFILE,fixture.MIGRATIONS)
        after=m.validate(copy.deepcopy(facts),fixture.PROFILE,fixture.MIGRATIONS,facts)
        self.assertEqual(proof['installedSchemaVersion'],36);self.assertEqual(after['databaseMigrationsPerformed'],0)
        self.assertTrue(after['entireV36SnapshotUnchanged']);self.assertNotIn('additiveV36AndZeroNewBudgetsProven',after)
        self.assertEqual(m.query(False),base.query(True));self.assertEqual(m.query(True),base.query(True))
    def test_existing35_cannot_be_adopted(self):
        with self.assertRaises(base.StateFenceDenied):m.validate(fixture.facts(),fixture.PROFILE,fixture.MIGRATIONS)
    def test_job_attempt_reset_new_budget_event_or_guard_change_denied(self):
        for field,value in [('attempts',0),('attempts',6),('state','READY'),('profileId','new')]:
            facts=fixture.facts(True);facts['job'][field]=value
            with self.assertRaises(base.StateFenceDenied):m.validate(facts,fixture.PROFILE,fixture.MIGRATIONS)
        for field in fixture.facts(True)['migrationAddition']:
            facts=fixture.facts(True);facts['migrationAddition'][field]+=1
            with self.assertRaises(base.StateFenceDenied):m.validate(facts,fixture.PROFILE,fixture.MIGRATIONS)
    def test_every_domain_table_and_entire_history_literal_baseline_fenced(self):
        baseline=fixture.facts(True)
        for table in m.TABLES:
            facts=copy.deepcopy(baseline);facts['states'][table]['sha256']='b'*64
            with self.assertRaisesRegex(base.StateFenceDenied,'V36_STATE_HISTORY_COUNTERS'):m.validate(facts,fixture.PROFILE,fixture.MIGRATIONS,baseline)
        facts=copy.deepcopy(baseline);facts['history'].insert(0,{'type':'BASELINE','version':'0','success':True})
        with self.assertRaisesRegex(base.StateFenceDenied,'V36_STATE_HISTORY_COUNTERS'):m.validate(facts,fixture.PROFILE,fixture.MIGRATIONS,baseline)
    def test_only_closed_readonly_query_no_ddl_or_restore(self):
        for verb in('UPDATE ','INSERT ','DELETE ','ALTER ','CREATE ','TRUNCATE '):self.assertNotIn(verb,m.query())
        with self.assertRaises(base.StateFenceDenied):m.arguments({},Path('/fixture'),'SELECT 1')
        for value in(None,0,1,'true'):
            with self.assertRaises(base.StateFenceDenied):m.query(value)
    def port(self):
        ports=Ports.__new__(Ports)
        def require(ok,reason):
            if not ok:raise RuntimeError(reason)
        ports.require=require;return ports
    def test_permanent_or_unknown_readiness_never_retried(self):
        ports=self.port()
        for role in('onboarding','mcp'):
            for status in(400,401,403,404,409,429,500):
                with self.assertRaisesRegex(RuntimeError,'PERMANENT_OR_UNKNOWN'):ports.owner_readiness(role,{'status':status})
            for status in(0,502,503,504):self.assertFalse(ports.owner_readiness(role,{'status':status}))
        self.assertTrue(ports.owner_readiness('mcp',{'status':204}))
        ports.ctx=type('C',(),{'p':type('P',(),{'decode':staticmethod(json.loads)})()})()
        self.assertTrue(ports.owner_readiness('onboarding',{'status':200,'rawBodyHex':b'{"status":"UP"}'.hex()}))
        with self.assertRaisesRegex(RuntimeError,'UNKNOWN_OWNER'):ports.owner_readiness('onboarding',{'status':200,'rawBodyHex':b'{"status":"UNKNOWN"}'.hex()})
    def test_signed_stage_has_only_exact_owner_command(self):
        ports=self.port();ports.core=type('Core',(),{'ROLES':('onboarding','mcp')})()
        cid='a'*64;row={'oldBinding':{'containerId':cid},'name':'ci-owner','retiredName':'ci-retained','network':{'id':'f'*64},'request':{'Image':'sha256:'+'b'*64}}
        ports.proposal=lambda role:row
        for role in ports.core.ROLES:
            stage='STOP_OLD_'+role.upper()+'_OWNER';ports.stages=(stage,);state={'nextStage':0,'effects':[{'state':'CLAIMED'}]}
            ports.execution=type('E',(),{'record':lambda _:state})()
            ports.assert_write('/v1.44/containers/'+cid+'/stop?t=10',None)
            for path,body in [('/v1.44/containers/'+('c'*64)+'/stop?t=10',None),('/v1.44/containers/'+cid+'/stop?t=2',None),('/v1.44/containers/'+cid+'/stop?t=10',{})]:
                with self.assertRaisesRegex(RuntimeError,'EXACT_SIGNED'):ports.assert_write(path,body)
            state['effects'][0]['state']='APPLIED'
            with self.assertRaisesRegex(RuntimeError,'CLAIMED_SIGNED'):ports.assert_write('/v1.44/containers/'+cid+'/stop?t=10',None)
if __name__=='__main__':unittest.main()
