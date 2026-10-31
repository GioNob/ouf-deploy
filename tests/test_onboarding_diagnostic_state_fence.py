import copy,importlib.util,json,pathlib,unittest
ROOT=pathlib.Path(__file__).parents[1]
s=importlib.util.spec_from_file_location('fence',ROOT/'tools/onboarding_diagnostic_update/state_fence.py');f=importlib.util.module_from_spec(s);s.loader.exec_module(f)
MIGRATIONS=json.loads((ROOT/'releases/onboarding-diagnostic-migration-fence-20261027.json').read_text())

class Fence(unittest.TestCase):
    def setUp(self):
        self.profile={'schema':'ouf.current-onboarding-database-snapshot-profile.v1','identity':{'database':'onboarding','databaseOid':123,'adminRole':'postgres','runtimeRole':'onboarding','postgresPort':5432},'postgresRuntimeBinding':{'containerId':'a'*64},'engineBinding':{'socketPath':'/run/docker.sock'},'dockerExecutable':{'path':'/usr/bin/docker'},'containerPrograms':{'env':'/usr/bin/env','timeout':'/usr/bin/timeout','psql':'/usr/bin/psql'},'unixSocketDirectory':'/var/run/postgresql'}
        self.facts={'readOnly':'on','standby':False,'database':'onboarding','databaseOid':123,'user':'postgres','serverVersionNum':170006,'pendingProfiles':0,'activeReadiness':0,'job':{'jobId':f.JOB,'assetId':f.ASSET,'state':'FAILED','attempts':5,'profileId':None},'history':[{**{k:m[k]for k in ('version','script')},'checksum':m['flywayChecksum'],'success':True,'type':'SQL'}for m in MIGRATIONS],'states':{k:{'rows':1,'sha256':'a'*64}for k in f.TABLES}}
    def validate(self):return f.validate(self.facts,self.profile,MIGRATIONS)
    def test_exact_snapshot(self):self.assertTrue(self.validate()['retainedFailedJobUnchanged'])
    def test_failed_job_never_reset_or_replaced(self):
        for key,value in [('attempts',0),('state','READY'),('jobId','another'),('profileId','new')]:
            with self.subTest(key=key):
                facts=copy.deepcopy(self.facts);facts['job'][key]=value
                with self.assertRaises(f.StateFenceDenied):f.validate(facts,self.profile,MIGRATIONS)
    def test_pending_work_or_activation_blocks(self):
        for k in ['pendingProfiles','activeReadiness']:
            facts=copy.deepcopy(self.facts);facts[k]=1
            with self.assertRaises(f.StateFenceDenied):f.validate(facts,self.profile,MIGRATIONS)
    def test_source_budget_or_other_table_drift_rejected(self):
        for table in f.TABLES:
            facts=copy.deepcopy(self.facts);facts['states'][table]['sha256']='b'*64
            with self.assertRaises(f.StateFenceDenied):f.validate(facts,self.profile,MIGRATIONS,self.facts)
    def test_migration_drift_or_extra_row_rejected(self):
        facts=copy.deepcopy(self.facts);facts['history'][0]['checksum']+=1
        with self.assertRaises(f.StateFenceDenied):f.validate(facts,self.profile,MIGRATIONS)
        facts=copy.deepcopy(self.facts);facts['history'].append({'version':'36','script':'unreviewed','checksum':1,'success':True,'type':'SQL'})
        with self.assertRaises(f.StateFenceDenied):f.validate(facts,self.profile,MIGRATIONS)
    def test_writable_or_wrong_identity_rejected(self):
        for key,value in [('readOnly','off'),('standby',True),('database','wrong'),('databaseOid',0),('user','other')]:
            facts=copy.deepcopy(self.facts);facts[key]=value
            with self.assertRaises(f.StateFenceDenied):f.validate(facts,self.profile,MIGRATIONS)
    def test_query_cannot_be_substituted(self):
        with self.assertRaises(f.StateFenceDenied):f.arguments(self.profile,'/root/empty','SELECT 1')
        args=f.arguments(self.profile,'/root/empty',f.query())
        self.assertIn('PGPASSFILE=/dev/null',args);self.assertIn('-w',args);self.assertNotIn('PGPASSWORD',str(args));self.assertEqual(args[-1],f.query())
    def test_oversized_table_fails_closed(self):
        self.facts['states']['source']['rows']=10001
        with self.assertRaises(f.StateFenceDenied):self.validate()
    def test_query_is_readonly_no_details_and_bounded(self):
        q=f.query();self.assertTrue(q.startswith('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY;'));self.assertTrue(q.endswith('ROLLBACK;'))
        self.assertEqual(q.count('LIMIT 10001'),len(f.TABLES));self.assertNotIn('last_error',q);self.assertNotIn('FOR UPDATE',q)

if __name__=='__main__':unittest.main()
