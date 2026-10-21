"""Read-only metadata projection/dispatch; SQL backend remains a target readback."""
import copy,importlib.util,json,sys,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('claim_reader',ROOT/'scripts/read-chatbot-semantic-mcp-claim-20261016.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class Reader(unittest.TestCase):
 def facts(self):
  return {'readOnly':True,'databaseMatched':True,'roleMatched':True,'databaseOid':42,'claimCount':1,
   'claims':[{'attemptId':'11111111-1111-4111-8111-111111111111','requestHash':'a'*64,'state':'FAILED',
    'dispatchState':'ACKNOWLEDGED','lockVersion':2,'reservationState':'RECONCILED','actualToolCalls':1,
    'reservedToolCalls':1,'admissionContextPresent':True}]}
 def test_exact_read_only_sql_and_injection_rejected(self):
  q=m.query('tenant-fixture','db_fixture','admin_fixture')
  for text in ('BEGIN READ ONLY','SET LOCAL statement_timeout',m.KEY,m.SUBJECT,"c.owner='semantic'",
               "c.operation_class='COMMAND'","c.tenant_id='tenant-fixture'",'LIMIT 4','ROLLBACK'):
   self.assertIn(text,q)
  for bad in ("tenant'; DELETE",'x\n','x y','', 'a'*129):
   with self.assertRaises(m.ReadDenied):m.query(bad,'db_fixture','admin_fixture')
 def test_projection_denies_secrets_unknown_states_and_hidden_truncation(self):
  f=self.facts();self.assertEqual(m.project(f,{'databaseOid':42}),f)
  for change in ({'claimCount':5},{'readOnly':False},{'databaseOid':43},{'claims':[]}):
   with self.assertRaises(m.ReadDenied):m.project({**f,**change},{'databaseOid':42})
  for key,value in [('state','secret-token'),('requestHash','secret-token'),('actualToolCalls',-1),('lockVersion',True)]:
   row=copy.deepcopy(f);row['claims'][0][key]=value
   with self.assertRaises(m.ReadDenied):m.project(row,{'databaseOid':42})
  row=copy.deepcopy(f);row['claims'][0]['payload']='PRIVATE'
  with self.assertRaises(m.ReadDenied):m.project(row,{'databaseOid':42})
 def invoke(self,*,drift=False,sql_error=False):
  pg={'Id':'a'*64,'Image':'sha256:'+'b'*64,'State':{'Pid':4,'StartedAt':'fixture','Running':True,'Paused':False},
      'Config':{'Env':['POSTGRES_USER=admin_fixture']},'HostConfig':{},'Mounts':[],'NetworkSettings':{}}
  p={'engine':{'socketPath':'/sealed/socket'},'databasePlan':{'postgresRuntimeBinding':m.runtime_pin(pg),
      'modules':[{'module':'mcp','database':'db_fixture','databaseOid':42}],
      'mcpAuditRoleAdministration':{'admin':'admin_fixture'}},
     'authorization':{'plan':{'selection':{'subject':m.SUBJECT,'tenant':'tenant-fixture'}}}}
  review={'sourceClosure':{'declaration':{'sourceCommit':m.SOURCE},'executables':{'docker':{'path':'/bin/docker','sha256':'c'*64}}},
   'scopes':{'finiteActionProcess':{'unit':m.UNIT,'authorityDirectory':str(m.CONTEXT),
      'bundle':{'path':'/sealed/bundle.json','sha256':'d'*64}}},'privateInputHashes':{'preparedInputs':m.digest(p)}}
  bundle={'declaration':review['sourceClosure']['declaration'],'prepared':p}
  records={str(m.CONTEXT/'review.json'):review,str(m.CONTEXT/'authority.json'):review['scopes'],'/sealed/bundle.json':bundle}
  def bounded(argv,**kw):
   self.argv=argv;self.assertEqual(kw['maximum'],65536)
   return (1 if sql_error else 0,json.dumps(self.facts()).encode(),b'PRIVATE_ERROR_NOT_PRINTED',10)
  after=copy.deepcopy(pg)
  if drift:after['State']['Pid']=5
  self.events=[]
  with patch.object(m,'read',side_effect=lambda path,*a:records[str(path)]),patch.object(m,'executable',return_value='/bin/docker'),\
       patch.object(m,'engine_get',side_effect=[pg,after]),patch.object(m,'bounded',side_effect=bounded),\
       patch.object(m.signal,'alarm'),patch.object(m,'emit',side_effect=lambda check,**v:self.events.append((check,v))):
   m.main()
 def test_full_reader_constructs_one_read_only_sql_session_and_no_credential_arguments(self):
  self.invoke();self.assertEqual([x[0]for x in self.events],['BEGIN','EXACT_MCP_CLAIM','END'])
  self.assertIn('PGOPTIONS=-c default_transaction_read_only=on -c statement_timeout=10000 -c lock_timeout=3000',self.argv)
  self.assertEqual(self.argv[self.argv.index('exec')+1],'a'*64)
  self.assertEqual(self.argv[-2],'-c');self.assertIn('BEGIN READ ONLY',self.argv[-1])
  self.assertNotIn('password',' '.join(self.argv).lower())
  self.assertNotIn('PRIVATE_ERROR',json.dumps(self.events))
 def test_generation_drift_prevents_claim_output_and_completion(self):
  with self.assertRaisesRegex(m.ReadDenied,'POSTGRES_CHANGED'):self.invoke(drift=True)
  self.assertEqual([x[0]for x in self.events],['BEGIN'])
 def test_failed_sql_is_not_reported_as_no_claim(self):
  with self.assertRaisesRegex(m.ReadDenied,'READ_ONLY_SQL_FAILED'):self.invoke(sql_error=True)
  self.assertEqual([x[0]for x in self.events],['BEGIN'])
 def test_real_bounded_child_output_does_not_leak_stderr_or_overrun(self):
  code,out,err,count=m.bounded([sys.executable,'-c',"import sys; print('PUBLIC'); print('PRIVATE',file=sys.stderr)"],maximum=64)
  self.assertEqual(code,0);self.assertEqual(out,b'PUBLIC\n');self.assertEqual(err,b'PRIVATE\n')
  with self.assertRaises(m.ReadDenied):m.bounded([sys.executable,'-c',"print('x'*1000)"],maximum=32)
if __name__=='__main__':unittest.main()
