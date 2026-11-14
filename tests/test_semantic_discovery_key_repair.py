import copy,importlib.util,pathlib,unittest
s=importlib.util.spec_from_file_location('repair',pathlib.Path(__file__).resolve().parents[1]/'scripts/repair-semantic-discovery-key-20261108.py')
q=importlib.util.module_from_spec(s);s.loader.exec_module(q)
class Request:
 @staticmethod
 def request(gated,image):return copy.deepcopy(gated['Config'])
class Mounts:
 @staticmethod
 def mounts(doc):return doc['Mounts']

class RepairTests(unittest.TestCase):
 def test_only_one_exact_env_changes(self):
  d={'Image':'image','Config':{'Env':['OTHER=keep','OUF_SEMANTIC_DISCOVERY_DELEGATION_KEY_FILE='+q.BAD]}}
  before=copy.deepcopy(d);req,k=q.repair_request(Request,d)
  self.assertEqual(d,before);self.assertEqual(req['Env'],['OTHER=keep',k+'='+q.GOOD])
 def test_missing_duplicate_or_unexpected_path_denied(self):
  for values in ([],['OUF_SEMANTIC_DISCOVERY_DELEGATION_KEY_FILE=/unexpected'],
    ['OUF_SEMANTIC_DISCOVERY_DELEGATION_KEY_FILE='+q.BAD]*2):
   with self.assertRaises(RuntimeError):q.repair_request(Request,{'Image':'image','Config':{'Env':values}})
 def test_exited_generation_and_configuration_must_match(self):
  gated={'Id':'id','Image':'image','Name':'/name','Config':{'MacAddress':'02:42:ac:44:01:07'},'HostConfig':{},
   'Mounts':[],'Path':'sh','Args':[],'State':{'StartedAt':'before'},
   'NetworkSettings':{'Networks':{'n':{'IPAMConfig':{'IPv4Address':'192.0.2.10'},'Aliases':['semantic'],'NetworkID':'network'}}}}
  current=copy.deepcopy(gated);current['State'].update(Running=False,Pid=0,ExitCode=1,OOMKilled=False)
  q.exited_frame(Mounts,gated,current)
  for where,key,val in [('State','Running',True),('State','StartedAt','different'),('Config','MacAddress',None),('HostConfig','Privileged',True)]:
   bad=copy.deepcopy(current);bad[where][key]=val
   with self.assertRaises(RuntimeError):q.exited_frame(Mounts,gated,bad)
 def test_v12_history_exact_and_read_only(self):
  value={'databaseOid':'21558','readOnly':True,'recoveryColumnPresent':True,'discoveryStates':[],
   'migrations':[{'version':str(i+1),'checksum':v,'success':True}for i,v in enumerate(q.CHECKSUMS)]}
  q.database_v12(value)
  for mutation in ('checksum','version','readOnly','discovery'):
   bad=copy.deepcopy(value)
   if mutation=='checksum':bad['migrations'][-1]['checksum']=0
   elif mutation=='version':bad['migrations'].pop()
   elif mutation=='readOnly':bad['readOnly']=False
   else:bad['discoveryStates']=[{'state':'RUNNING'}]
   with self.assertRaises(RuntimeError):q.database_v12(bad)
 def test_gateway_and_key_must_match_and_differ_from_mcp(self):
  key='a'*64;cfg={'OWNER_KEY_ENV':'OUF_SEMANTIC_READ_OWNER_KEY','DELEGATION_KEY_ENV':'MCP_KEY',
   'ISSUER':'issuer','AUDIENCE':'audience','MCP_WORKLOAD':'workload'}
  values={p:[{'origin':'ENV','value':v}] for p,v in {
   q.PROPERTY:q.BAD,'ouf.semantic.delegation.key-file':q.GOOD,'ouf.iam.issuer':'issuer',
   'ouf.iam.audience':'audience','ouf.semantic.discovery-delegation.workload':'workload'}.items()}
  class K:
   PATHS=['/internal/capabilities/v1/execute/semantic/discovery/request']
   @staticmethod
   def selected(doc,h):return values
   @staticmethod
   def constants(row):return cfg
  class H:
   @staticmethod
   def environment(doc):return doc
   @staticmethod
   def digest(value):return '1d1c62ed4bc50337493f9198a11ce7cc23aaa69acde9e9be0f7e550eefec1dbd'
  rows={'r':{'uri':K.PATHS[0],'plugins':{'serverless-post-function':{}}}}
  q.signer_binding(K,H,rows,{'OUF_SEMANTIC_READ_OWNER_KEY':key,'MCP_KEY':'b'*64},{},key)
  for owner,mcp in [('c'*64,'b'*64),(key,key),(key,'')]:
   with self.assertRaises(RuntimeError):q.signer_binding(K,H,rows,{'OUF_SEMANTIC_READ_OWNER_KEY':owner,'MCP_KEY':mcp},{},key)

if __name__=='__main__':unittest.main()
