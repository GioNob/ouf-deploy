import ast,base64,copy,hashlib,importlib.util,json,os,socket,stat,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
SCRIPT=ROOT/'scripts/read-mcp-ingestion503-topology.py'
if not SCRIPT.exists():SCRIPT=Path(__file__).with_name('read.py')
spec=importlib.util.spec_from_file_location('qualified_topology_reader',SCRIPT);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
def route(mode,port=8080):
 return {'uri':'/internal/capabilities/v1/execute/ouf.ingestion.'+mode,'methods':['POST'],
  'upstream':{'scheme':'http','nodes':{'owner-service:'+str(port):1}},
  'plugins':{'serverless-post-function':{'functions':['local DELEGATION_KEY_ENV = "DELEGATION_KEY"\n']}}}
def fixtures():
 routes={mode:route(mode)for mode in('status','history')}
 gateway={'Config':{'Env':['DELEGATION_KEY='+'a'*64,'PASSWORD=DO_NOT_PRINT']},'HostConfig':{},'NetworkSettings':{'Networks':{'shared':{}}}}
 owner={'Name':'/owner','NetworkSettings':{'Networks':{'shared':{'Aliases':['owner-service'],'IPAddress':'10.9.0.2'}}}}
 return routes,gateway,owner
class Topology(unittest.TestCase):
 def test_correct_alias_key_and_listener_are_only_safe_projection(self):
  routes,gateway,owner=fixtures();result=m.topology(routes,gateway,owner,{8080:{'WILDCARD'}})
  self.assertTrue(all(r['ownerAliasOnSharedNetwork']and r['upstreamPortListeningInOwnerNamespace']and r['gatewayDelegationKeyHasExpectedShape']for r in result))
  text=m.encoded(result).decode();self.assertNotIn('a'*64,text);self.assertNotIn('DO_NOT_PRINT',text);self.assertNotIn('10.9.0.2',text);self.assertNotIn('owner-service',text)
 def test_wrong_port_and_unshared_network_remain_distinct(self):
  routes,gateway,owner=fixtures();owner['NetworkSettings']['Networks']={'different':owner['NetworkSettings']['Networks']['shared']}
  result=m.topology(routes,gateway,owner,{8090:{'WILDCARD'}})
  self.assertTrue(all(r['sharedNetworkCount']==0 and not r['ownerAliasOnSharedNetwork']and not r['upstreamPortListeningInOwnerNamespace']for r in result))
 def test_missing_or_wrong_shape_key_is_reported_without_value(self):
  routes,gateway,owner=fixtures()
  for env in([],['DELEGATION_KEY=wrong'],['DELEGATION_KEY='+'f'*64]):
   gateway['Config']['Env']=env;result=m.topology(routes,gateway,owner,{})
   self.assertEqual(result[0]['gatewayDelegationKeyHasExpectedShape'],bool(env and len(env[0])==79))
 def test_duplicate_key_and_ambiguous_or_nonprojected_route_denied(self):
  routes,gateway,owner=fixtures();gateway['Config']['Env']*=2
  with self.assertRaises(Exception):m.topology(routes,gateway,owner,{})
  routes['extra']=copy.deepcopy(routes['status'])
  with self.assertRaises(Exception):m.selected(routes)
  routes,gateway,owner=fixtures();routes['status']['upstream']['nodes']={'https://caller.invalid:8080':1}
  with self.assertRaises(Exception):m.selected(routes)
 def test_kernel_v4_v6_listeners_select_ports_and_address_classes(self):
  header=b'  sl local_address rem_address st\n'
  raw=header+b'0: 00000000:1F90 00000000:0000 0A\n1: 0100007F:2382 00000000:0000 0A\n2: 0100007F:FFFF 00000000:0000 01\n'
  self.assertEqual(m.listeners(raw),{8080:{'WILDCARD'},9090:{'LOOPBACK'}})
  self.assertEqual(m.listeners(header+b'0: 00000000000000000000000000000000:1F90 00000000:0000 0A\n'),{8080:{'WILDCARD'}})
  with self.assertRaises(Exception):m.listeners(b'invalid table')
 def test_closed_engine_surface_rejects_exec_logs_network_list_and_seventh_read(self):
  reader=m.Reader({'socketPath':'/fixture/socket','socketBinding':[]},['a'*64,'b'*64,'c'*64])
  for path in('/v1.44/containers/json','/v1.44/containers/'+'a'*64+'/logs','/v1.44/containers/'+'a'*64+'/exec','/v1.44/networks'):
   with self.assertRaises(Exception):reader.get(path)
  reader.calls=6
  with self.assertRaises(Exception):reader.get('/v1.44/containers/'+'a'*64+'/json')
 def test_runtime_matches_canonical_mount_order_and_denies_stopped_generation(self):
  v={'Id':'a'*64,'Image':'image','State':{'Running':True,'Pid':1,'StartedAt':'start'},'Config':{},'HostConfig':{},'Mounts':[{'Destination':'/z'},{'Destination':'/a'}],'NetworkSettings':{}}
  before=m.runtime(v);v['Mounts'].reverse();self.assertEqual(m.runtime(v),before)
  v['State']['Running']=False
  with self.assertRaises(Exception):m.runtime(v)
 def test_source_has_no_journal_write_login_program_or_main_replay(self):
  tree=ast.parse(SCRIPT.read_bytes());calls=[ast.unparse(n.func)for n in ast.walk(tree)if isinstance(n,ast.Call)]
  for suffix in('.login','.refresh_if_due','.write_text','.write_bytes','.Popen','.execv','.setns','.migrate'):
   self.assertFalse(any(v.endswith(suffix)for v in calls))
  self.assertNotIn('entry.main',calls);self.assertNotIn('reader.main',calls)
class Custody(unittest.TestCase):
 def test_real_private_file_hash_mode_and_symlink(self):
  with tempfile.TemporaryDirectory(dir=os.environ.get('OUF_TEST_ROOT',str(ROOT)))as directory:
   root=Path(directory);path=root/'file';path.write_bytes(b'{}');path.chmod(0o600)
   self.assertEqual(m.read(path,m.sha(b'{}')),b'{}')
   with self.assertRaises(Exception):m.read(path,'0'*64)
   link=root/'link';link.symlink_to(path)
   with self.assertRaises(Exception):m.read(link)
   path.chmod(0o440)
   with self.assertRaises(Exception):m.read(path)
if __name__=='__main__':unittest.main()

class CompletedHistory(unittest.TestCase):
 def records(self):
  routes={str(n):{'id':str(n)}for n in range(82)}
  p={'gateway':{'beforeRoutes':routes,'afterRoutes':copy.deepcopy(routes)}}
  scope={'planHash':m.digest(p)};hashes={str(n):m.sha(b'pass\n')for n in range(205)}
  package={'sourceCommit':m.SOURCE,'schema':'ouf.mcp-ingestion-read-transport-package.v1','closure':{'declaration':{'moduleCount':205,'entryModule':'tools.mcp_read_transport_gateway82_continuation.entry','sourceHashes':hashes}},'fileHashes':{}}
  case={'preparationClaimBinding':{'path':str(m.CONTEXT/'preparation-fence.json'),'sha256':'fixture'}}
  review={'scopes':{'mcpReadTransportUpdate':scope},'sourceClosureHash':m.digest(package['closure'])}
  stages=['VERIFY_INPUTS']+['mcp.'+n for n in('IMPORT_IMAGE','DISABLE_OLD_RESTART','STOP_OLD','DETACH_OLD_ENDPOINT','RENAME_OLD','CREATE_REPLACEMENT','START_REPLACEMENT','READINESS','RESTORE_RESTART_POLICY')]+['VERIFY_FINAL']
  evidence={'mcp':{'health':{'httpStatus':204},'runtimeBinding':{'containerId':m.MCP,'pid':312624,'startedAt':'2026-10-19T13:07:59.712730076Z'}},'routeMapHash':m.digest(routes)}
  j={'schema':'ouf.mcp-ingestion-read-transport-update-journal.v1','scopeHash':m.digest(scope),'nextStage':11,'effects':[{'stage':s,'state':'APPLIED','intentHash':m.digest({'planHash':m.digest(p),'stage':s})}for s in stages],'incidentState':'RECOVERED','budgetReset':False,'version':27}
  j['effects'][-1]['evidence']=evidence
  result={'schema':'ouf.mcp-ingestion-read-transport-update-result.v1','status':'MCP_TRANSPORT_UPDATE_READBACK_COMPLETE','contextPath':str(m.CONTEXT),'sourceCommit':'1f2c28d7abadae78680b040ba7b58be62ef85ee9','oauthAttemptsAfter':236,'result':{'complete':True,'applicationReady':True,'journalVersion':27,'acceptanceGranted':False},'finalEvidence':evidence,'gatewayWrites':0,'databaseMigrationsPerformed':0,'grantChanges':0,'jobsRetried':0,'sourceActivated':False,'publicMetadataChanged':False}
  data={'package.json':package,'runtime.claim.json':{'packageHash':m.digest(package),'automaticReplayAllowed':False},'case.json':case,'preparation-fence.json':{'context':str(m.CONTEXT),'maximumCumulativeOAuthAttempts':256,'budgetReset':False,'automaticReplayAllowed':False},'sources.json':{n:base64.b64encode(b'pass\n').decode()for n in hashes},'execution-plan.json':p,'recovery.json':j,'update-result.json':result,'review.json':review,'decision.json':{'reviewHash':m.digest(review)}}
  # Package file hashes are proper raw JSON bindings; package claim follows final package bytes.
  package['fileHashes']={n:m.digest(data[n])for n in('case.json','sources.json')};data['runtime.claim.json']['packageHash']=m.digest(package)
  return data,m.digest(routes)
 def test_completed205_history_can_be_read_without_executing_source_or_old_main(self):
  data,route_hash=self.records();before=copy.deepcopy(data)
  def parse(path,expected=None):
   value=data[Path(path).name]
   if expected not in(None,'fixture'):self.assertEqual(m.digest(value),expected)
   return value
  with patch.object(m,'ROUTES',route_hash):plan,result,package=m.history(parse)
  self.assertEqual(result['oauthAttemptsAfter'],236);self.assertEqual(data,before);self.assertEqual(len(plan['gateway']['afterRoutes']),82)
 def test_incomplete_or_drifted_completed_effect_history_denies(self):
  for mutate in('state','hash','counter'):
   data,route_hash=self.records()
   if mutate=='state':data['recovery.json']['effects'][0]['state']='CLAIMED'
   if mutate=='hash':data['review.json']['scopes']['mcpReadTransportUpdate']['planHash']='0'*64
   if mutate=='counter':data['update-result.json']['oauthAttemptsAfter']=229
   with self.subTest(mutate=mutate),patch.object(m,'ROUTES',route_hash),self.assertRaises(Exception):m.history(lambda path,expected=None:data[Path(path).name])
