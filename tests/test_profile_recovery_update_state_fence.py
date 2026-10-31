import copy,importlib.util,json,pathlib,unittest
ROOT=pathlib.Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('v36_fence',ROOT/'tools/onboarding_profile_recovery_update/state_fence.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
MIGRATIONS=json.loads((ROOT/'releases/onboarding-profile-recovery-migration-fence-20261027.json').read_bytes())
def facts(after=False):
    rows=MIGRATIONS if after else MIGRATIONS[:35]
    value={'readOnly':'on','standby':False,'database':'onboarding','databaseOid':42,'user':'pgadmin','serverVersionNum':170010,'pendingProfiles':0,'activeReadiness':0,
        'job':{'jobId':m.JOB,'assetId':m.ASSET,'state':'FAILED','attempts':5,'profileId':None},
        'history':[{'version':r['version'],'script':r['script'],'checksum':r['flywayChecksum'],'success':True,'type':'SQL'}for r in rows],
        'states':{table:{'rows':1,'sha256':'a'*64}for table in m.TABLES}}
    if after:value['migrationAddition']={'newColumnCount':6,'legacyDefaultViolations':0,'recoverySessions':0,'recoveryEvents':0,'enabledGuards':3}
    else:value['schemaDeltaAbsent']=True
    return value
PROFILE={'identity':{'database':'onboarding','databaseOid':42,'adminRole':'pgadmin'}}
class Tests(unittest.TestCase):
    def test_exact35_before_and_exact36_after_preserve_same_operational_hash(self):
        before=facts();first=m.validate(before,PROFILE,MIGRATIONS);last=m.validate(facts(True),PROFILE,MIGRATIONS,before,after=True)
        self.assertEqual(first['operationalStateHash'],last['operationalStateHash']);self.assertTrue(last['additiveV36AndZeroNewBudgetsProven'])
    def test_cannot_accept36_before_or35_after(self):
        with self.assertRaises(m.StateFenceDenied):m.validate(facts(True),PROFILE,MIGRATIONS)
        with self.assertRaises(m.StateFenceDenied):m.validate(facts(),PROFILE,MIGRATIONS,facts(),after=True)
    def test_cannot_reset_job_attempts_or_change_failed_state(self):
        for key,value in(('attempts',0),('attempts',6),('state','READY'),('profileId','new')):
            current=facts(True);current['job'][key]=value
            with self.assertRaises(m.StateFenceDenied):m.validate(current,PROFILE,MIGRATIONS,facts(),after=True)
    def test_no_new_session_event_adoption_or_missing_guard(self):
        for key in('newColumnCount','legacyDefaultViolations','recoverySessions','recoveryEvents','enabledGuards'):
            current=facts(True);current['migrationAddition'][key]+=1
            with self.assertRaises(m.StateFenceDenied):m.validate(current,PROFILE,MIGRATIONS,facts(),after=True)
    def test_existing_source_quarantine_and_all_other_table_hashes_exact(self):
        for table in m.TABLES:
            current=facts(True);current['states'][table]['sha256']='b'*64
            with self.assertRaisesRegex(m.StateFenceDenied,'STATE_OR_COUNTER'):m.validate(current,PROFILE,MIGRATIONS,facts(),after=True)
    def test_pending_work_or_unexpected_schema_stops_before_effects(self):
        for key,value in(('pendingProfiles',1),('activeReadiness',1),('schemaDeltaAbsent',False)):
            current=facts();current[key]=value
            with self.assertRaises(m.StateFenceDenied):m.validate(current,PROFILE,MIGRATIONS)
    def test_partial_unknown_or_changed_history_rejected(self):
        for variant in('checksum','success','type','duplicate'):
            current=facts(True)
            if variant=='duplicate':current['history'].append(copy.deepcopy(current['history'][-1]))
            else:current['history'][-1][variant]={'checksum':0,'success':False,'type':'UNKNOWN'}[variant]
            with self.assertRaises(m.StateFenceDenied):m.validate(current,PROFILE,MIGRATIONS,facts(),after=True)
    def test_no_new_table_reference_in35_query_and_no_ddl_in_read_query(self):
        self.assertNotIn('FROM ouf_onboarding.managed_profile_budget_session',m.query(False));self.assertIn('FROM ouf_onboarding.managed_profile_budget_session',m.query(True))
        for query in(m.query(False),m.query(True)):
            self.assertTrue(query.startswith('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY;'))
            for verb in('UPDATE ','DELETE ','INSERT ','ALTER ','CREATE ','TRUNCATE '):self.assertNotIn(verb,query)
    def test_only_job_new_columns_projected_other_rows_unchanged(self):
        query=m.query(False);self.assertEqual(query.count("to_jsonb(x)-ARRAY['generation'"),1)
        self.assertEqual(query.count('to_jsonb(x) AS payload'),len(m.TABLES)-1)
if __name__=='__main__':unittest.main()
