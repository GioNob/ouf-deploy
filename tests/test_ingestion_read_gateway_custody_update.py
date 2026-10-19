"""Real Ed25519/owner journal; production Gateway compiler; finite HTTP boundary fixtures."""
import ast,base64,copy,hashlib,importlib.util,json,os,sys,tempfile,time,unittest
from pathlib import Path
from unittest.mock import patch,Mock
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tests'),str(ROOT/'tools/semantic_policy_token_owner'),str(ROOT/'tools/semantic_application_cutover'),str(ROOT/'tools/semantic_cohort_admission/cohort-draft')]
from tools.ingestion_read_gateway_custody import owner as o,authority as a,runtime as loader,entry as e
from tools.ingestion_read_gateway_update import compiler as g
from tools.semantic_lease_recovery.recovery_journal import Journal
from engine_creation import Engine
import test_ingestion_read_administrative_authority as old
GATEWAY=Path(os.environ['OUF_INGESTION_GATEWAY_ROOT'])
BUNDLE=ROOT/'releases/ingestion-read-gateway-compiler-20261019.json'

def inputs():
 bundle=json.loads(BUNDLE.read_text());projection=json.loads((GATEWAY/'tests/fixtures/installation-projection-lab.json').read_text())
 constants={'ISSUER':projection['gateway']['issuerUrl'].rstrip('/'),'AUDIENCE':projection['gateway']['requiredAudience'],'MCP_WORKLOAD':projection['iam']['workloadClients']['mcpServer'],'DELEGATION_KEY_ENV':'DELEGATION_KEY'}
 lua='\n'.join('local '+k+' = '+json.dumps(v)for k,v in constants.items())
 oidc={'bearer_only':True,'ssl_verify':True,'use_jwks':True,'unauth_action':'deny','client_secret':'$ENV://FIXTURE'}
 before={str(i):{'id':str(i)}for i in range(79)}
 before['execute']={'id':'execute','uri':'/internal/capabilities/v1/execute','methods':['POST'],'labels':{},'plugins':{
  'openid-connect':oidc,'limit-count':{'count':100,'time_window':60,'rejected_code':429},'request-validation':{},
  'serverless-pre-function':{'functions':[]},'serverless-post-function':{'phase':'access','functions':[lua]},'proxy-rewrite':{}}}
 return bundle,projection,before

def fixture(context,hb):
 bundle,projection,before=inputs();gateway=g.compile_routes(bundle,projection,before,context)
 plan={'schema':'ouf.ingestion-read-gateway-plan.v1','authorityDirectory':str(context),'privateReviewBinding':{'path':str(context/'candidate-review.json'),'sha256':o.digest({})},
  'engine':{},'gateway':{**gateway,'transport':{},'projectionBinding':{'path':'/fixture/projection.json'}},'unchangedApplications':{name:{'containerId':str(n)*64}for n,name in enumerate(('mcp','onboarding','udp','ingestion'),1)},
  'retainedMcpMetadata':[],'humanBinding':hb,'replacements':{},'databaseMigration':None,'maximumExecutionSeconds':900,'maximumEffectAttemptsPerStage':1,'maximumGatewayWrites':2,
  **{k:False for k in o.FORBIDDEN}}
 return plan

class Compiler(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory(dir=os.environ.get('OUF_TEST_ROOT',str(ROOT)));self.addCleanup(self.tmp.cleanup);self.context=Path(self.tmp.name)
 def test_authenticated_bundle_is_exact_gateway_commit_files(self):
  bundle,_,_=inputs()
  for name,item in bundle['files'].items():
   raw=(GATEWAY/name).read_bytes();self.assertEqual(base64.b64decode(item['base64']),raw)
   self.assertEqual(hashlib.sha256(raw).hexdigest(),item['sha256'])
   self.assertEqual(hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest(),item['gitBlobSha'])
 def test_actual_production_modules_generate_exact82_without_private_key_or_network(self):
  bundle,projection,before=inputs();got=g.compile_routes(bundle,projection,before,self.context)
  self.assertEqual(len(got['afterRoutes']),82);self.assertTrue(all(got['afterRoutes'][k]==v for k,v in before.items()))
  self.assertEqual(set(got['additions']),{'status','history'})
  self.assertTrue(all(row['plugins']['request-validation']['body_schema']['properties']['Owner']=={'const':'ingestion'}for row in got['additions'].values()))
 def test_modified_source_bundle_or_missing_template_identity_denies(self):
  bundle,projection,before=inputs();bundle['files']['tools/lua/delegation.lua']['base64']=base64.b64encode(b'changed').decode()
  with self.assertRaises(Exception):g.compile_routes(bundle,projection,before,self.context)
  bundle,projection,before=inputs();before['execute']['plugins']['serverless-post-function']['functions']=[]
  with self.assertRaises(Exception):g.compile_routes(bundle,projection,before,self.context)

class Native(unittest.TestCase):
 @classmethod
 def setUpClass(cls):old.Issuance.setUpClass()
 def setUp(self):
  previous=old.Issuance();previous.setUp();self.addCleanup(previous.doCleanups);self.previous=previous;self.c=previous.c;self.human=previous.human;self.hb=previous.hb
  self.context=self.c.root/'mcp-ingestion-read-transport-execution-abcdefgh';self.context.mkdir(mode=0o700)
  self.plan=fixture(self.context,self.hb)
  p=patch.object(o,'BEFORE_HASH',o.digest(self.plan['gateway']['beforeRoutes']));p.start();self.addCleanup(p.stop)
  self.install_predecessor_and_metadata()
  self.plan['logicalUpdateRef']=o.logical_ref()
  self.closure=copy.deepcopy(previous.closure);self.closure['declaration']['entryModule']='tools.ingestion_read_gateway_custody.entry'
  self.scopes={o.SCOPE_KEY:o.scope(self.plan)}
  self.review=a.compile_action_review('INGESTION_READ_GATEWAY_CUSTODY_UPDATE',self.closure,self.scopes,self.hb,self.context,{'predecessorHistoryHash':'b'*64,'predecessorIncidentRef':self.plan['logicalUpdateRef']},480)
  self.c.write(self.context/'review.json',a.encoded(self.review));self.c.write(self.context/'candidate-review.json',b'{}')
 def install_predecessor_and_metadata(self):
  origin=self.c.root/'retained-zero-effect195';origin.mkdir(mode=0o700)
  records={'plan':('execution-plan.json',{'old':'plan'}),'review':('review.json',{'old':'review'}),
   'journal':('recovery.json',{'version':0,'nextStage':0,'effects':[]}),
   'runtimeClaim':('runtime.claim.json',{'consumed':True})}
  bindings={}
  for key,(name,value)in records.items():
   path=origin/name;self.c.write(path,o.encoded(value));bindings[key]={'path':str(path),'sha256':o.digest(value)}
  old_fence=origin.parent/('ingestion-read-gateway-'+('c'*64)+'.claim.json');self.c.write(old_fence,b'{}')
  bindings['logicalClaim']={'path':str(old_fence),'sha256':o.digest({})}
  expiry=int(time.time())-60
  for key,value in(('ORIGIN',origin),('ORIGIN_PLAN',bindings['plan']['sha256']),('ORIGIN_REVIEW',bindings['review']['sha256']),('PREDECESSOR_EXPIRES',expiry)):
   pa=patch.object(o,key,value);pa.start();self.addCleanup(pa.stop)
  self.plan['custodyPredecessor']={'originContext':str(origin),'originPackageHash':o.ORIGIN_PACKAGE,
   'originPlanHash':o.ORIGIN_PLAN,'originReviewHash':o.ORIGIN_REVIEW,'originalAuthorityExpiresAt':expiry,'bindings':bindings}
  directory=self.c.root/'metadata';directory.mkdir(mode=0o700)
  for name in('profile.json','policy.json','permit.json'):
   path=directory/name;self.c.write(path,o.encoded({'member':name}));path.chmod(0o440);info=path.lstat()
   self.plan['retainedMcpMetadata'].append({'path':str(path),'sha256':o.digest({'member':name}),
    'custody':{k:getattr(info,k)for k in('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size')}})
 def test_real0440_metadata_rejects_old_private_reader_and_passes_corrected_full_owner_without_chmod(self):
  binding=self.plan['retainedMcpMetadata'][0]
  with self.assertRaisesRegex(Exception,'PRIVATE_FILE_CUSTODY_REQUIRED'):o.private_file(binding['path'],binding['sha256'],65536)
  self.assertEqual(o.metadata_file(binding)['mode'],0o440)
  update=self.update();update.initialize();update.run()
  self.assertTrue(all(Path(b['path']).stat().st_mode&0o777==0o440 for b in self.plan['retainedMcpMetadata']))
 def test_wrong_hash_custody_mode_symlink_or_replaced_inode_is_denied(self):
  binding=self.plan['retainedMcpMetadata'][0];path=Path(binding['path'])
  bad=copy.deepcopy(binding);bad['sha256']='a'*64
  with self.assertRaises(Exception):o.metadata_file(bad)
  bad=copy.deepcopy(binding);bad['custody']['st_gid']+=1
  with self.assertRaises(Exception):o.metadata_file(bad)
  path.chmod(0o600)
  with self.assertRaises(Exception):o.metadata_file(binding)
  path.chmod(0o440);raw=path.read_bytes();retained=path.with_name('retained-profile.json');path.rename(retained);path.write_bytes(raw);path.chmod(0o440)
  with self.assertRaises(Exception):o.metadata_file(binding)
  path.unlink();path.symlink_to(retained)
  with self.assertRaises(Exception):o.metadata_file(binding)
  path.unlink();os.link(retained,path)
  with self.assertRaises(Exception):o.metadata_file(binding)
 def test_old_authority_still_live_or_old_journal_changed_stops_before_new_effect(self):
  with self.assertRaisesRegex(Exception,'PREDECESSOR_AUTHORITY_STILL_LIVE_NO_REPLACEMENT'):
   o.predecessor_unchanged(self.plan['custodyPredecessor'],o.PREDECESSOR_EXPIRES-1)
  update=self.update();update.initialize()
  Path(self.plan['custodyPredecessor']['bindings']['journal']['path']).write_bytes(b'{"changed":true}')
  with self.assertRaises(Exception):update.run()
  self.assertEqual(self.puts,[])
 def decision(self):
  now=int(time.time());return {'schema':'ouf.semantic-scoped-terminal-decision.v1','reviewHash':a.digest(self.review),'approvalRef':'mcp-scoped-'+a.digest(self.review)[:24]+'-'+str(now),'sourceClosureHash':self.review['sourceClosureHash'],'humanSessionHash':a.digest(self.hb),'approvedAt':now,'expiresAt':now+480,'decision':'APPROVE_EXACT_FINITE_SCOPED_ACTION','state':'ACTIVE'}
 def action(self):return a.issue_action(self.review,self.decision(),self.human)
 def test_actual_two_role_signatures_cover_gateway_only_scope_and_specific_entry(self):
  action=self.action();self.assertTrue(action.guard(o.SCOPE_KEY,self.scopes[o.SCOPE_KEY]))
  self.assertEqual(len(list(self.context.glob('*.DEPLOYMENT_INTENT.json'))),1);self.assertEqual(len(list(self.context.glob('*.FINAL_DEPLOYMENT_APPROVAL.json'))),1)
  with self.assertRaises(Exception):action.guard('mcpReadTransportUpdate',self.scopes[o.SCOPE_KEY])
  self.assertFalse((self.c.root/'UNREAD-ATTESTOR.pem').exists())
 def test_every_forbidden_effect_or_extra_scope_is_denied(self):
  for flag in o.FORBIDDEN:
   plan=copy.deepcopy(self.plan);plan[flag]=True
   with self.subTest(flag=flag),self.assertRaises(Exception):o.scope(plan)
  for change in ('replacement','migration','gateway-count','route','method','owner','scope-key'):
   plan=copy.deepcopy(self.plan)
   if change=='replacement':plan['replacements']={'mcp':{}}
   if change=='migration':plan['databaseMigration']={}
   if change=='gateway-count':plan['maximumGatewayWrites']=3
   if change=='route':plan['gateway']['afterRoutes']['extra']={}
   if change in('method','owner'):
    row=plan['gateway']['additions']['status']
    if change=='method':row['methods']=['PUT']
    else:row['plugins']['request-validation']['body_schema']['properties']['Owner']={'const':'udp'}
    plan['gateway']['afterRoutes'][row['id']]=copy.deepcopy(row)
   if change=='scope-key':
    with self.assertRaises(Exception):a.compile_action_review('INGESTION_READ_GATEWAY_CUSTODY_UPDATE',self.closure,{**self.scopes,'mcpReadTransportUpdate':{}},self.hb,self.context,{'predecessorHistoryHash':'b'*64,'predecessorIncidentRef':'c'*64},480)
    continue
   with self.subTest(change=change),self.assertRaises(Exception):o.scope(plan)
 def test_changed_human_decision_review_or_login_gate_never_signs(self):
  with patch.object(a.ExistingEd25519Signer,'sign')as signing:
   decision=self.decision();decision['reviewHash']='f'*64
   with self.assertRaises(Exception):a.issue_action(self.review,decision,self.human)
   with patch.object(self.human,'current',return_value={**self.hb,'subject':'other'}),self.assertRaises(Exception):self.action()
   with self.assertRaises(Exception):a.terminal_consent(self.review,'no login',login=True)
  signing.assert_not_called()
 def update(self,fail=None):
  action=self.action();outer=self;actual=copy.deepcopy(self.plan['gateway']['beforeRoutes']);self.puts=[];self.engine_calls=[]
  class Gateway:
   def __init__(self,*args):pass
   def check(self):pass
   def routes(self):return copy.deepcopy(actual)
   def request(self,method,path,body):
    outer.puts.append((method,path,copy.deepcopy(body)));actual[body['id']]=copy.deepcopy(body)
    if fail=='after-status'and body['id'].endswith('status'):raise TimeoutError('unknown fixture response')
    if fail=='unrelated':actual['other']={'id':'other'}
    return 201,{}
  engine=Engine.__new__(Engine)
  def request(method,path,body=None):
   self.engine_calls.append((method,path));binding=next(b for b in self.plan['unchangedApplications'].values()if b['containerId']in path)
   return 200,{'State':{'Running':True},'binding':binding}
  for target,key,value in((o,'NamespaceAdmin',Gateway),(o,'private_config',lambda *args:None),(o,'runtime',lambda value:value['binding']),
   (engine,'check_socket',lambda:None),(engine,'request',request)):
   p=patch.object(target,key,value);p.start();self.addCleanup(p.stop)
  return o.GatewayUpdate(action,engine,self.plan,self.human,Journal(self.context))
 def test_durable_owner_publishes_exactly_two_puts_and_readbacks_preserving80_and_four_containers(self):
  update=self.update();update.initialize();result=update.run()
  self.assertEqual(result['routeCount'],82);self.assertEqual(result['gatewayWrites'],2)
  self.assertEqual([p[1]for p in self.puts],['/apisix/admin/routes/mcp-ingestion-status','/apisix/admin/routes/mcp-ingestion-history'])
  self.assertTrue(all(method=='GET'for method,_ in self.engine_calls));self.assertEqual(update.record()['nextStage'],4)
  self.assertEqual(update.record()['incidentState'],'RECOVERED')
 def test_ambiguous_applied_put_stays_claimed_and_second_run_never_repeats(self):
  update=self.update('after-status');update.initialize()
  with self.assertRaises(TimeoutError):update.run()
  self.assertEqual(len(self.puts),1);self.assertEqual(update.record()['effects'][-1]['state'],'CLAIMED')
  with self.assertRaisesRegex(Exception,'CLAIMED_GATEWAY_EFFECT_REQUIRES_READ_ONLY_RECONCILIATION'):update.run()
  self.assertEqual(len(self.puts),1)
 def test_unrelated_gateway_drift_stops_without_second_put(self):
  update=self.update('unrelated');update.initialize()
  with self.assertRaisesRegex(Exception,'GATEWAY_ROUTE_MAP_DRIFT'):update.run()
  self.assertEqual(len(self.puts),1)
 def test_second_context_cannot_publish_same_logical_gateway_action(self):
  update=self.update();update.initialize()
  with self.assertRaises(Exception):update.initialize()
  self.assertEqual(self.puts,[])
 def test_expired_authority_or_changed_human_stops_before_put(self):
  update=self.update();update.initialize()
  with patch.object(self.human,'current',return_value={**self.hb,'subject':'other'}),self.assertRaises(Exception):update.run()
  self.assertEqual(self.puts,[])
  update.expires=0
  with self.assertRaises(Exception):update.run()
  self.assertEqual(self.puts,[])

class Closure(unittest.TestCase):
 def test_closed198_modules_keeps_all195_and_adds_only_three_custody_modules(self):
  from tools.ingestion_read_gateway_update import runtime as previous
  self.assertEqual(len(loader.MODULES),198);self.assertEqual(loader.MODULES-previous.MODULES,{'tools.ingestion_read_gateway_custody.'+n for n in('entry','authority','owner')})
  sources={name:b'pass\n'for name in loader.MODULES}
  for name in('entry','authority','owner'):sources['tools.ingestion_read_gateway_custody.'+name]=(ROOT/'tools/ingestion_read_gateway_custody'/(name+'.py')).read_bytes()
  loader.compile_sources(sources);self.assertEqual(loader.ENTRY,'tools.ingestion_read_gateway_custody.entry')
 def test_only_get_engine_requests_no_login_install_image_database_or_historical_main(self):
  for name in('entry','owner'):
   tree=ast.parse((ROOT/'tools/ingestion_read_gateway_custody'/(name+'.py')).read_bytes())
   calls=[ast.unparse(n.func)for n in ast.walk(tree)if isinstance(n,ast.Call)]
   self.assertFalse(any(n.endswith(('.login','.authenticate','.apply_stage','.ensure','.backup','.migrate'))for n in calls))
   for node in ast.walk(tree):
    if isinstance(node,ast.Call)and ast.unparse(node.func)=='engine.request':self.assertEqual(ast.literal_eval(node.args[0]),'GET')
if __name__=='__main__':unittest.main()
