"""Reproduce missing configured key in the exact image, then repair on V12."""
import copy,importlib.util,json,os,pathlib,subprocess,time,unittest,uuid
ROOT=pathlib.Path(__file__).resolve().parents[1]
def module(name,path):
 s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
base=module('base_native',ROOT/'tests/test_semantic_application_upgrade_native.py')
q=module('repair',ROOT/'scripts/repair-semantic-discovery-key-20261108.py')
r,u,mac,D,cmd=base.r,base.u,base.m,base.D,base.cmd

class RepairNative(base.Native):
 @classmethod
 def setUpClass(cls):
  super().setUpClass();cls.keyfile=cls.p/'owner.key';cls.keyfile.write_text('a'*64+'\n')
  os.chown(cls.keyfile,10001,10001);cls.keyfile.chmod(0o400)
 def old(self,explicit):
  name=self.tag+'-'+uuid.uuid4().hex[:6];address='02:42:ac:44:01:07'
  request={'Image':self.image,'User':'10001:10001','Entrypoint':r.ENTRY,'Cmd':r.JAVA,
   'Env':['OUF_SEM_DB_URL='+self.url,'OUF_SEM_DB_USER=fixture','SPRING_CONFIG_IMPORT=configtree:/run/fixture/',
    'OUF_DISCOVERY_WORKER_ENABLED=false','OUF_SCHEMA_GOV_ENABLED=false',
    'OUF_IAM_ISSUER=https://issuer.example.test/realms/ouf','OUF_IAM_AUDIENCE=fixture-audience',
    'OUF_SEMANTIC_DELEGATION_WORKLOAD=fixture-workload','OUF_SEMANTIC_DISCOVERY_DELEGATION_WORKLOAD=fixture-workload',
    'OUF_SEMANTIC_DELEGATION_KEY_FILE='+q.GOOD,'OUF_SEMANTIC_DISCOVERY_DELEGATION_KEY_FILE='+q.BAD],
   'HostConfig':{'NetworkMode':self.tag,'RestartPolicy':{'Name':'no','MaximumRetryCount':0},
    'Binds':[str(self.p)+':/run/fixture:ro',str(self.keyfile)+':'+q.GOOD+':ro']},
   'NetworkingConfig':{'EndpointsConfig':{self.tag:{'MacAddress':address,'Aliases':['semantic-fixture']}}}}
  if explicit:request['MacAddress']=address
  cid=self.e.api('POST','/containers/create?name='+name,request)['Id'];self.ids.append(cid)
  self.e.api('POST','/containers/'+cid+'/start');gated=self.e.inspect(cid)
  self.assertEqual(gated['Config'].get('MacAddress'),address,'real legacy MAC precondition required')
  return gated
 def exercise(self,explicit):
  oid=self.baseline();gated=self.old(explicit);r.gate_running(gated)
  host,path=u.stage_class(gated,self.bundle)
  result=u.invoke(base.Binding,gated,path,self.url,'fixture',oid)
  rows=[json.loads(l.split(b' ',1)[1])for l in result.stdout.splitlines()if l.startswith(b'OUF_SEMANTIC_UPGRADE ')]
  self.assertEqual(result.returncode,0);self.assertEqual(rows[-1]['status'],'SEMANTIC_V11_V12_MIGRATED_VALIDATED')
  for leaf in ('SemanticMigration.class','loader.properties'):(host/leaf).unlink()
  host.rmdir()
  history=self.sql('select json_agg(t) from (select * from ouf_sem.flyway_schema_history order by installed_rank)t')
  self.assertEqual(self.sql('select max(version::int) from ouf_sem.flyway_schema_history'),'12')
  self.e.api('POST','/containers/'+gated['Id']+'/kill?signal=USR1')
  for _ in range(60):
   failed=self.e.inspect(gated['Id'])
   if not failed['State']['Running']:break
   time.sleep(1)
  else:raise AssertionError('configured missing key did not stop application')
  self.assertEqual(failed['State']['ExitCode'],1);self.assertFalse(failed['State']['OOMKilled'])
  self.assertIn(b'SEM_DISCOVERY_DELEGATION_KEY_UNAVAILABLE',cmd(*D,'logs',gated['Id']))
  self.assertEqual(failed['Config']['MacAddress'],gated['Config']['MacAddress'])
  q.exited_frame(r,gated,failed)
  key,identity=q.read_host_key(failed);self.assertEqual(key,'a'*64)
  req,changed=q.repair_request(r,gated)
  self.assertEqual(changed,'OUF_SEMANTIC_DISCOVERY_DELEGATION_KEY_FILE')
  before=dict(x.split('=',1)for x in gated['Config']['Env']);after=dict(x.split('=',1)for x in req['Env'])
  self.assertEqual({k for k in before if before[k]!=after[k]},{changed})
  self.assertEqual(after[changed],q.GOOD)
  report={};events={};new=None
  try:
   new=q.replace_exited(r,mac,self.e,gated,failed,req,lambda n,v:events.setdefault(n,v),report)
   self.assertEqual(r.file_sha(pathlib.Path('/proc',str(new['State']['Pid']),'root/app/application.jar')),r.JAR_SHA)
   self.assertEqual(cmd(*D,'exec',new['Id'],'cat',q.GOOD).strip(),b'a'*64)
   live=q.start_application(r,self.e,new,lambda n,v:events.setdefault(n,v),report)
   r.verify_replacement(gated,req,live,True)
   self.assertEqual(self.sql('select json_agg(t) from (select * from ouf_sem.flyway_schema_history order by installed_rank)t'),history)
   self.assertEqual(self.sql("select result_json->>'retained' from ouf_sem.proposal_command_receipt where idempotency_key='keep-me'"),'true')
   self.assertEqual(self.sql('select count(*) from ouf_sem.discovery_request'),'0')
   self.assertFalse(self.e.inspect(gated['Id'])['State']['Running'])
   self.assertEqual(self.e.inspect(gated['Id'])['NetworkSettings']['Networks'],{})
   print(json.dumps({'profile':'EXPLICIT_LEGACY_CONFIG' if explicit else 'ENDPOINT_ONLY_COMPAT_CONFIG',
    'legacyInitiallyPresent':True,'missingConfiguredKeyFailureReproduced':True,'sameArchivedApplicationImage':True,
    'onlyDiscoveryKeyEnvChanged':True,'failedMacTransition':report['failedMacTransition'],
    'existingKeyMountPreserved':True,'readinessUp':True,'v12HistoryAndReceiptUnchanged':True,
    'providerAndWorkerDisabled':True,'productionAccess':False}),flush=True)
  except Exception:
   if report.get('replacementContainerId'):
    print(cmd(*D,'logs','--tail','85',report['replacementContainerId']).decode())
   raise
  finally:
   if report.get('replacementContainerId'):self.ids.append(report['replacementContainerId'])
  for cid in (new['Id'],gated['Id']):cmd(*D,'rm','-f',cid);self.ids.remove(cid)

if __name__=='__main__':unittest.main(verbosity=2)
