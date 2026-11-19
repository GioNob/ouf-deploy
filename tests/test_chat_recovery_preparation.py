import contextlib,copy,hashlib,importlib.util,io,json,os,signal,tempfile,unittest
from unittest.mock import patch
from pathlib import Path
SOURCE=Path(__file__).resolve().parents[1]/'scripts/prepare-chat-recovery-inputs-20261018.py'
spec=importlib.util.spec_from_file_location('preparation',SOURCE)
p=importlib.util.module_from_spec(spec);spec.loader.exec_module(p)
class MigrationContract(unittest.TestCase):
 def udp(self):
  return {'transactionReadOnly':True,'ownsMaterializationJob':True,'recoveryColumnCount':0,
   'migrations':[{'installed_rank':i+1,**{k:r[k] for k in('version','script','checksum','success')}}for i,r in enumerate(p.PROFILE['udpMigrations'][:-1])]}
 def test_current_prefix_and_unchanged_mcp(self):
  p.validate_database('udp',self.udp(),p.PROFILE)
  p.validate_database('mcp',{'transactionReadOnly':True,'migrations':p.PROFILE['mcpMigrations']},p.PROFILE)
 def test_stale_schema_and_partial_migration_rejected(self):
  for change in('checksum','success','version','recoveryColumnCount','ownsMaterializationJob','transactionReadOnly'):
   row=self.udp()
   if change in('checksum','success','version'):row['migrations'][-1][change]=None
   else:row[change]=1 if change=='recoveryColumnCount' else False
   with self.subTest(change=change),self.assertRaises(ValueError):p.validate_database('udp',row,p.PROFILE)
 def test_mcp_missing_or_changed_history_rejected(self):
  for rows in(p.PROFILE['mcpMigrations'][:-1],[{'version':1,'checksum':'0'*64}]):
   with self.assertRaises(ValueError):p.validate_database('mcp',{'transactionReadOnly':True,'migrations':rows},p.PROFILE)
 def test_sql_scoped_to_readonly_and_current_role(self):
  for module in('udp','mcp'):
   query=p.sql(module,'ouf_app')
   self.assertTrue(query.startswith('BEGIN READ ONLY;'))
   self.assertTrue(query.endswith('ROLLBACK;'))
   for forbidden in('UPDATE ','DELETE ','INSERT ','ALTER ','CREATE ','GRANT '):self.assertNotIn(forbidden,query)
  with self.assertRaises(ValueError):p.sql('udp',"x'; select secret")
 def test_private_write_never_overwrites_and_keeps_mode(self):
  with tempfile.TemporaryDirectory()as tmp:
   path=Path(tmp)/'plan.json';p.private_write(path,b'private')
   self.assertEqual(path.stat().st_mode&0o777,0o600)
   with self.assertRaises(FileExistsError):p.private_write(path,b'changed')
   self.assertEqual(path.read_bytes(),b'private')
 def test_private_root_rejects_writable_ancestor(self):
  if os.geteuid()!=0:self.skipTest('root fixture')
  with tempfile.TemporaryDirectory(dir='/root')as tmp:
   root=Path(tmp);root.chmod(0o700);p.root_dir(root)
   root.chmod(0o777)
   with self.assertRaises(ValueError):p.root_dir(root)

class WholePreparation(MigrationContract):
 def exercise(self, mode='success', duplicate=False):
  if os.geteuid()!=0:self.skipTest('root fixture')
  with tempfile.TemporaryDirectory(dir='/root')as tmp:
   root=Path(tmp);root.chmod(0o700)
   profile=copy.deepcopy(p.PROFILE);profile['privateParent']=str(root)
   actuals={}
   for name,row in profile['components'].items():
    actuals[row['id']]={'Id':row['id'],'Image':row['image'],
     'State':{'Running':True,'Paused':False,'Restarting':False,'Pid':7,'StartedAt':'fixture'},
     'Config':{'Labels':{'org.opencontainers.image.revision':row['revision']},'Env':['FIXTURE=PRIVATE_CANARY']},
     'HostConfig':{},'Mounts':[],'NetworkSettings':{}}
   pg={'Id':'postgres-fixture','Image':'sha256:fixture','State':{'Running':True,'Pid':9,'StartedAt':'fixture'},
       'Config':{'Env':['POSTGRES_USER=fixture_admin']},'HostConfig':{},'Mounts':[],'NetworkSettings':{}}
   actuals[pg['Id']]=pg
   db={'postgresRuntimeBinding':p.runtime_pin(pg),'mcpAuditRoleAdministration':{'admin':'fixture_admin'},
    'modules':[{'module':m,'user':'fixture_app','database':'fixture_'+m,'databaseOid':i}for i,m in enumerate(('udp','mcp'),1)]}
   prepared={'engine':{'socketPath':'/fixture'},'databasePlan':db}
   old={'scopes':{'finiteActionProcess':{'bundle':{'path':'/fixture/bundle','sha256':'fixture'}}},
    'privateInputHashes':{'preparedInputs':p.digest(prepared)},'sourceClosure':{'executables':{'docker':{'path':'/fixture/docker'}}}}
   documents={'/fixture/review.json':old,'/fixture/bundle':{'prepared':prepared}}
   helper=("from pathlib import Path\nimport json\nCONTEXT=Path('/fixture');REVIEW='fixture'\n"
    +"documents=json.loads("+repr(json.dumps(documents))+")\n"
    +"actuals=json.loads("+repr(json.dumps(actuals))+")\n"
    +"def read(path,*args):return documents[str(path)]\n"
    +"def engine_get(engine,kind,cid):return actuals[cid]\n")
   boot=root/'execute.py';boot.write_text(helper);boot.chmod(0o600)
   source=p.__dict__
   if duplicate:
    source={'__name__':'reproduction'}
    raw=SOURCE.read_text().replace("emit('PRIVATE_CONTEXT',contextPath=str(context))","emit('PRIVATE_CONTEXT',contextPath=str(context),runtimeReadOnly=True)")
    exec(compile(raw,str(SOURCE),'exec'),source)
   sql_calls=[]
   def bounded(argv,**kwargs):
    sql_calls.append(argv)
    self.assertIn('BEGIN READ ONLY;',argv[-1]);self.assertTrue(argv[-1].endswith('ROLLBACK;'))
    if mode=='sql_failure':return 1,b'',b'PRIVATE_CANARY',0
    module=argv[argv.index('-d')+1].removeprefix('fixture_')
    fact=self.udp() if module=='udp' else {'transactionReadOnly':True,'migrations':profile['mcpMigrations']}
    if mode=='history_drift':fact['migrations']=[]
    binding=next(v for v in db['modules']if v['module']==module)
    fact.update(database=binding['database'],databaseOid=binding['databaseOid'],role='fixture_admin')
    return 0,json.dumps(fact).encode(),b'',0
   output=io.StringIO()
   with patch.dict(source,BOOT=boot,BOOT_HASH=hashlib.sha256(helper.encode()).hexdigest(),
        executable=lambda binding:binding['path'],bounded=bounded),contextlib.redirect_stdout(output):
    try:
     if duplicate:
      with self.assertRaises(TypeError):source['main'](profile)
     elif mode!='success':
      with self.assertRaises(ValueError):source['main'](profile)
     else:source['main'](profile)
    finally:signal.alarm(0)
   self.assertNotIn('PRIVATE_CANARY',output.getvalue())
   contexts=list(root.glob('chat-recovery-prepared-*'));self.assertEqual(len(contexts),1)
   plan=contexts[0]/'prepared-inputs.json'
   if duplicate:
    self.assertEqual(sql_calls,[]);self.assertEqual(list(contexts[0].iterdir()),[])
   elif mode!='success':self.assertFalse(plan.exists())
   else:
    self.assertEqual(len(sql_calls),2)
    events=[json.loads(line)for line in output.getvalue().splitlines()]
    self.assertEqual([r['check']for r in events],['PRIVATE_CONTEXT','DATABASE_PREFLIGHT','DATABASE_PREFLIGHT','END'])
    self.assertTrue(events[-1]['complete']);self.assertFalse(events[-1]['readyForExecution'])
    self.assertEqual(events[-1]['preparedInputsSha256'],hashlib.sha256(plan.read_bytes()).hexdigest())
    self.assertEqual(plan.stat().st_mode&0o777,0o600)
    self.assertIn('PRIVATE_CANARY',plan.read_text())
    self.assertEqual(json.loads(plan.read_bytes())['beforeApplications']['mcp'],p.runtime_pin(actuals[profile['components']['mcp']['id']]))
 def test_original_duplicate_reproduces_before_sql(self):self.exercise(duplicate=True)
 def test_whole_preparation_saves_private_plan(self):self.exercise()
 def test_sql_failure_never_publishes_plan(self):self.exercise('sql_failure')
 def test_history_drift_never_publishes_plan(self):self.exercise('history_drift')
if __name__=='__main__':unittest.main()

