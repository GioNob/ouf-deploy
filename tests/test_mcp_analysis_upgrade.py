import copy, importlib.util, json, pathlib, unittest
ROOT=pathlib.Path(__file__).resolve().parents[1]
def load(n,p):
 s=importlib.util.spec_from_file_location(n,p);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
m=load('upgrade',ROOT/'scripts/upgrade-mcp-analysis-20261108.py')
p=load('preflight',ROOT/'scripts/read-mcp-analysis-preflight-20261108.py');c,h=p.helpers()

def old():
 return {'Config':{'User':'10005:10005','WorkingDir':'/app','Env':['MCP_DATABASE_URL=PRIVATE','X=keep'],
  'Image':'old','MacAddress':'02:42:ac:44:01:07','Labels':{'keep':'me'}},
  'HostConfig':{'NetworkMode':'backend','RestartPolicy':{'Name':'no','MaximumRetryCount':0},'Binds':['/host:/run/files:ro'],'OomKillDisable':None},
  'Mounts':[{'Type':'bind','RW':False,'Destination':'/run/files'}],
  'NetworkSettings':{'Networks':{'backend':{'IPAddress':'172.28.0.4','MacAddress':'02:42:ac:44:01:07','Aliases':['ouf-mcp']}}}}

def db(n=13):
 return {'readOnly':True,'databaseOid':21560,'migrations':[{'version':i,'checksum':c.MCP_CHECKSUMS[str(i)],'appliedAt':'fixed'} for i in range(1,n+1)],
  'analysisTablePresent':n==14,'analysisTaskTablePresent':n==14,'analysisRows':0,'analysisTaskRows':0,
  'applicationRole':{'superuser':False,'canCreateInSchema':True,'canUseSchema':True,'canReadMigrationHistory':True,'canRecordMigration':True}}

class Unit(unittest.TestCase):
 def test_request_preserves_environment_mount_bindings_and_network_identity(self):
  source=old();saved=copy.deepcopy(source);r=m.request(source,'candidate')
  self.assertEqual(source,saved);self.assertEqual(r['Env'],source['Config']['Env']);self.assertEqual(r['HostConfig']['Binds'],source['HostConfig']['Binds'])
  self.assertNotIn('MacAddress',r);ep=r['NetworkingConfig']['EndpointsConfig']['backend']
  self.assertEqual(ep['MacAddress'],source['Config']['MacAddress']);self.assertEqual(ep['IPAMConfig']['IPv4Address'],'172.28.0.4')
  self.assertEqual(r['Entrypoint'],m.ENTRY);self.assertEqual(r['Cmd'],m.APP)
 def test_request_refuses_other_user_mutable_mount_or_restart_policy(self):
  for which in ('user','mount','restart','networks'):
   d=old()
   if which=='user':d['Config']['User']='root'
   if which=='mount':d['Mounts'][0]['RW']=True
   if which=='restart':d['HostConfig']['RestartPolicy']['Name']='always'
   if which=='networks':d['NetworkSettings']['Networks']['extra']={}
   with self.assertRaises(RuntimeError):m.request(d,'candidate')
 def test_exact_prefix14_and_preserved_applied_times(self):
  before=db();m.verify_database(before,c.MCP_CHECKSUMS,'21560');m.verify_database(db(14),c.MCP_CHECKSUMS,'21560',before)
  for which in ('checksum','timestamp','oid','role','rows'):
   d=db(14)
   if which=='checksum':d['migrations'][0]['checksum']='0'*64
   if which=='timestamp':d['migrations'][0]['appliedAt']='changed'
   if which=='oid':d['databaseOid']=2
   if which=='role':d['applicationRole']['superuser']=True
   if which=='rows':d['analysisRows']=1
   with self.assertRaises(RuntimeError):m.verify_database(d,c.MCP_CHECKSUMS,'21560',before)
 def test_failure_log_never_emits_arbitrary_details(self):
  raw=b'{"msg":"database connection failed","error":"PRIVATE_DSN"}\n{"msg":"PRIVATE_SECRET"}\n'
  result=m.summarize(raw);self.assertEqual(result['knownStartupMessages'],['database connection failed']);self.assertNotIn('PRIVATE',json.dumps(result))

if __name__=='__main__':unittest.main(verbosity=2)
