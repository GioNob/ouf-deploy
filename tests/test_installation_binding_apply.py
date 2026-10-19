"""Actual root signatures/journals and frozen HUMAN flow; no mocked native authority."""
import ast,copy,hashlib,importlib.util,json,os,stat,sys,tempfile,time,unittest
from pathlib import Path
from unittest.mock import Mock,patch
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tests')]
import test_installation_owner_update as existing
import test_installation_ingestion_binding_plan as prior
from tools.installation_binding_apply import owner as o,authority as a,native as n,entry as e,login as l,runtime as loader
from tools.semantic_lease_recovery.recovery_journal import Journal
from tools.chatbot_file_cohort import human_session as h

def fixture(context,hb,kind='INSTALLATION_BINDING_APPLY'):
 old=prior.OwnerPlan();old.setUp();b=old.compile();b['expectedActive']['generation']=1;b['expectedActiveETag']='"4:'+b['expectedActive']['checksum']+':1"'
 before={str(i):{'id':str(i)}for i in range(80)}
 for mode in('status','history'):before['mcp-ingestion-'+mode]={'id':'mcp-ingestion-'+mode,'upstream':{'nodes':{'old-owner:8080':1},'scheme':'http'},'plugins':{'security':'preserve'}}
 after=copy.deepcopy(before)
 for mode in('status','history'):after['mcp-ingestion-'+mode]['upstream']['nodes']={'verified-owner:8080':1}
 # The old fixture's verified alias is already 'verified-owner'.
 p={'schema':'ouf.installation-binding-native-plan.v1','kind':kind,'authorityDirectory':str(context),'logicalRef':'b'*64,
  'bindingPlan':b,'humanBinding':hb,'maximumExecutionSeconds':210,'maximumEffectAttemptsPerStage':1,
  'gateway':{'beforeRoutes':before,'afterRoutes':after},'currentApplications':{},**{k:False for k in o.FORBIDDEN}}
 return p

class Scopes(unittest.TestCase):
 def setUp(self):
  self.plan=fixture(Path('/fixture/installation-binding-apply-execution-abcdefgh'),{'subject':'human'})
  p=patch.object(o,'CANDIDATE_HASH',prior.p.canonical_owner(self.plan['bindingPlan']['candidatePayload']));p.start();self.addCleanup(p.stop)
 def test_two_disjoint_scope_effect_surfaces_and_closed219_imports(self):
  first=o.scope(self.plan);self.assertEqual([first[k]for k in('maximumOwnerPosts','maximumProjectionExports','maximumActiveProjectionWrites','maximumGatewayPuts')],[3,1,0,0])
  second=copy.deepcopy(self.plan);second['kind']='INSTALLATION_PROJECTION_ROUTE_APPLY';self.assertEqual(o.scope(second)['maximumGatewayPuts'],2)
  sources={key:b'pass\n'for key in loader.MODULES}
  for name in('entry','authority','owner','native','baseline','login'):sources['tools.installation_binding_apply.'+name]=(ROOT/'tools/installation_binding_apply'/(name+'.py')).read_bytes()
  self.assertEqual(len(loader.compile_sources(sources)),219)
 def test_payload_hidden_changes_flags_extra_routes_security_or_ports_are_denied(self):
  for key in o.FORBIDDEN:
   changed=copy.deepcopy(self.plan);changed[key]=True
   with self.subTest(flag=key),self.assertRaises(Exception):o.scope(changed)
  changed=copy.deepcopy(self.plan);changed['bindingPlan']['candidatePayload']['extra']='hidden'
  with self.assertRaises(Exception):o.scope(changed)
  for mutation in('port','security','other'):
   changed=copy.deepcopy(self.plan);changed['kind']='INSTALLATION_PROJECTION_ROUTE_APPLY'
   if mutation=='port':changed['gateway']['afterRoutes']['mcp-ingestion-status']['upstream']['nodes']={'verified-owner:9999':1}
   if mutation=='security':changed['gateway']['afterRoutes']['mcp-ingestion-status']['plugins']={}
   if mutation=='other':changed['gateway']['afterRoutes']['1']={'id':'changed'}
   with self.subTest(mutation=mutation),self.assertRaises(Exception):o.scope(changed)

class CryptoAndJournal(unittest.TestCase):
 @classmethod
 def setUpClass(cls):existing.existing_crypto.Issuance.setUpClass()
 def setUp(self):
  previous=existing.existing_crypto.Issuance();previous.setUp();self.addCleanup(previous.doCleanups);self.old=previous
  self.context=previous.c.root/'installation-binding-apply-execution-abcdefgh';self.context.mkdir(mode=0o700)
  self.plan=fixture(self.context,previous.hb);p=patch.object(o,'CANDIDATE_HASH',prior.p.canonical_owner(self.plan['bindingPlan']['candidatePayload']));p.start();self.addCleanup(p.stop)
  self.closure=copy.deepcopy(previous.closure);self.closure['declaration']['entryModule']='tools.installation_binding_apply.entry';self.closure['declaration']['moduleCount']=219
 def issue(self,kind=None):
  if kind:self.plan['kind']=kind
  selected=o.scope(self.plan);key=o.scope_key(self.plan['kind']);self.review=a.compile_action_review(self.plan['kind'],self.closure,{key:selected},self.old.hb,self.context,
   {'predecessorHistoryHash':'b'*64,'predecessorIncidentRef':self.plan['logicalRef']},210)
  self.old.c.write(self.context/'review.json',a.encoded(self.review));now=int(time.time())
  decision={'schema':'ouf.semantic-scoped-terminal-decision.v1','reviewHash':a.digest(self.review),'approvalRef':'installation-binding-scoped-'+a.digest(self.review)[:24]+'-'+str(now),
   'sourceClosureHash':self.review['sourceClosureHash'],'humanSessionHash':a.digest(self.old.hb),'approvedAt':now,'expiresAt':now+210,'decision':'APPROVE_EXACT_FINITE_SCOPED_ACTION','state':'ACTIVE'}
  return a.issue_action(self.review,decision,self.old.human)
 def test_actual_two_role_signatures_owner_and_no_scope_escalation(self):
  action=self.issue();self.assertTrue(action.guard('installationBindingApply',o.scope(self.plan)))
  self.assertEqual(len(list(self.context.glob('*.DEPLOYMENT_INTENT.json'))),1);self.assertEqual(len(list(self.context.glob('*.FINAL_DEPLOYMENT_APPROVAL.json'))),1)
  with self.assertRaises(Exception):action.guard('installationProjectionRouteApply',o.scope(self.plan))
  with self.assertRaises(Exception):a.issue_action(self.review,{},self.old.human)
 def test_actual_two_role_signatures_projection_route_scope(self):
  action=self.issue('INSTALLATION_PROJECTION_ROUTE_APPLY');self.assertTrue(action.guard('installationProjectionRouteApply',o.scope(self.plan)))
 def ports(self):
  outer=self
  class P:
   def __init__(self):self.dispatched=[]
   def boot(self):return 'fixture-boot'
   def guard_current(self,*args):pass
   def apply(self,stage,row):self.dispatched.append(stage);return {'fixture':stage}
   def verify(self,*args):pass
  return P()
 def test_real_durable_journal_finishes_once_and_persistent_logical_fence_blocks_second_launch(self):
  action=self.issue();ports=self.ports();update=o.FiniteUpdate(action,self.plan,ports,Journal(self.context));update.initialize();row=update.run()
  self.assertEqual(row['incidentState'],'RECOVERED');self.assertEqual(ports.dispatched,list(o.STAGES[self.plan['kind']]))
  count=len(ports.dispatched);update.run();self.assertEqual(len(ports.dispatched),count)
  with self.assertRaises(Exception):update.initialize()
 def test_ambiguous_effect_stays_claimed_and_no_automatic_redispatch(self):
  action=self.issue();ports=self.ports()
  def unknown(stage,row):ports.dispatched.append(stage);raise ValueError('UNKNOWN_EFFECT')
  ports.apply=unknown;update=o.FiniteUpdate(action,self.plan,ports,Journal(self.context));update.initialize()
  with self.assertRaises(Exception):update.run()
  with self.assertRaises(Exception):update.run()
  self.assertEqual(len(ports.dispatched),1);self.assertEqual(update.record()['effects'][0]['state'],'CLAIMED')

class ProfilePublisher(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory(dir=os.environ['OUF_TEST_ROOT']);self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name);self.root.chmod(0o700)
  self.path=self.root/'active-projection.json';self.path.write_bytes(b'{"old":true}');self.path.chmod(0o600)
  self.raw,self.binding=n.private_config(self.path)
 def test_atomic_profile_publish_preserves_private_custody_and_stale_writer_is_rejected(self):
  new=b'{"new":true}';n.publish_active_projection(self.binding,new,'b'*64)
  self.assertEqual(self.path.read_bytes(),new);self.assertEqual(stat.S_IMODE(self.path.stat().st_mode),0o600)
  with self.assertRaises(Exception):n.publish_active_projection(self.binding,b'{"stale":true}','c'*64)
  self.assertEqual(self.path.read_bytes(),new)
 def test_symlink_or_busy_common_lock_is_not_followed_or_waited(self):
  import fcntl
  lock=self.root/'.ouf-active-projection.publish.lock';fd=os.open(lock,os.O_CREAT|os.O_RDWR,0o600)
  try:
   fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
   with self.assertRaises(BlockingIOError):n.publish_active_projection(self.binding,b'{}','d'*64)
  finally:os.close(fd)
  lock.unlink();lock.symlink_to(self.path)
  with self.assertRaises(Exception):n.publish_active_projection(self.binding,b'{}','e'*64)
  self.assertEqual(self.path.read_bytes(),self.raw)

class FreshLogin(unittest.TestCase):
 def setUp(self):
  self.old=prior.NativeScopeLogin();self.old.setUp();self.addCleanup(self.old.doCleanups)
  with patch.object(h.HumanSession,'_http',lambda instance,*args,**kw:self.old.provider(instance,*args,**kw)),self.old.actual_login():self.human=self.old.authenticate()
  self.row=self.human._read();self.row.update(attempts=251,state='READY',accessExpiresAt=time.time()-1)
  (self.human.directory/'recovery.json').write_bytes(o.encoded(self.row));self.old.calls.clear();self.old.emits.clear()
  self.context=self.old.root/'installation-binding-apply-execution-abcdefgh';self.context.mkdir(mode=0o700)
  for obj,key,value in((l,'EXPIRES',self.human.expires_at),(l,'ORIGINAL_REVIEW',o.digest(self.row['governedWindowRenewal']['review'])),(l,'PROFILE',self.old.profile),(l,'SCOPES',prior.t.REQUESTED),(a.evidence,'PARENT',self.old.root)):
   p=patch.object(obj,key,value);p.start();self.addCleanup(p.stop)
  self.case={'humanBinding':self.row['binding']};self.closure={'declaration':{'moduleCount':219}};self.ack=0
  def phrase(summary,phrase):
   if phrase.startswith('LOGIN COMPLETATO '):
    self.ack+=1;claim=json.loads((self.human.directory/'successor-window.claim.json').read_bytes());directory=Path(claim['destination'])
    following=h.HumanSession(self.old.selection,directory,directory/'human-access.jwt',self.human.expires_at)
    # A separate invocation can acquire the lock: no HUMAN wait under it.
    with following.journal.invocation():self.assertEqual(following._read()['attempts'],253)
    self.assertFalse(any(call[0].endswith('/token')for call in self.old.calls))
  p=patch.object(l,'terminal_phrase',side_effect=phrase);self.prompt=p.start();self.addCleanup(p.stop)
 def authenticate(self,provider=None):
  with patch.object(h.HumanSession,'_http',lambda instance,*args,**kw:provider(*args,**kw)if provider else self.old.provider(instance,*args,**kw)),self.old.actual_login():
   return l.authenticate(self.old.selection,self.row['binding'],self.context,self.closure,e.publish_json,self.old.emits.append,self.case)
 def test_actual_frozen_guard_four_requests_251_to255_after_ack_no_old_credentials(self):
  following=self.authenticate();row=following._read();self.assertEqual(row['attempts'],255);self.assertEqual(len(self.old.calls),4);self.assertEqual(self.ack,1)
  self.assertEqual(row['governedWindowRenewal'],self.row['governedWindowRenewal']);self.assertEqual(row['monotonicDeadline'],self.row['monotonicDeadline']);self.assertEqual(following.expires_at,self.human.expires_at)
  self.assertEqual(self.human._read(),self.row);self.assertFalse((self.context/'authority.json').exists());self.assertNotIn('DO_NOT_',str(self.old.calls))
  with self.assertRaises(Exception):self.authenticate()
 def test_declined_native_consent_creates_no_successor_or_oauth(self):
  self.prompt.side_effect=ValueError('DECLINED')
  with self.assertRaises(Exception):self.authenticate()
  self.assertEqual(self.old.calls,[]);self.assertFalse((self.human.directory/'successor-window.claim.json').exists())
 def test_one_pending_still_verifies_at256_and_second_pending_cannot_reset_budget(self):
  polls=[0]
  def provider(url,values=None,bearer=None):
   if url.endswith('/token')and polls[0]<1:polls[0]+=1;return 400,{'error':'authorization_pending'},0
   return self.old.provider(None,url,values,bearer)
  following=self.authenticate(provider);self.assertEqual(following._read()['attempts'],256)
 def test_provider_device_denial_keeps253_and_blocks_replay_without_authority(self):
  def deny(url,values=None,bearer=None):
   if url.endswith('/device'):return 400,{'error':'unauthorized_client'},0
   return self.old.provider(None,url,values,bearer)
  with self.assertRaises(h.HumanSessionPaused):self.authenticate(deny)
  claim=json.loads((self.human.directory/'successor-window.claim.json').read_bytes());row=json.loads((Path(claim['destination'])/'recovery.json').read_bytes());self.assertEqual(row['attempts'],253);self.assertEqual(row['state'],'BLOCKED');self.assertEqual(self.ack,0)
  self.assertFalse((self.context/'authority.json').exists())
if __name__=='__main__':unittest.main()

def actual_owner_protocol(self):
 source=prior.OwnerPlan();source.setUp();self.plan['sourceProjection']=source.projection
 action=self.issue();b=self.plan['bindingPlan'];active=copy.deepcopy(b['expectedActive']);calls=[]
 class Response:
  def __init__(self,body,headers=None,status=200):self.status=status;self.headers=headers or{};self.raw=o.encoded(body)
  def read(self,maximum):return self.raw[:maximum]
  def __enter__(self):return self
  def __exit__(self,*args):pass
 def opened(req,timeout):
  nonlocal active
  method=req.get_method();url=req.full_url;calls.append((method,url,req.get_header('If-match')))
  if url.endswith('/active'):return Response(active,{'ETag':'"'+str(active['revision'])+':'+active['checksum']+':'+str(active['generation'])+'"'})
  if method=='POST'and url.endswith('/revisions'):
   self.assertEqual(json.loads(req.data),b['candidatePayload']);return Response({'installationId':active['installationId'],'revision':5,'checksum':b['candidatePayloadChecksum'],'payload':b['candidatePayload'],'validationState':'VALIDATED','validationFindings':[]},status=201)
  if url.endswith(':validate-environment'):return Response({'installationId':active['installationId'],'revision':5,'overallStatus':'PASS','validationId':'fixture-validation'})
  if url.endswith(':activate'):
   self.assertEqual(req.get_header('If-match'),b['expectedActiveETag']);active={**active,'revision':5,'checksum':b['candidatePayloadChecksum'],'generation':2};return Response(active)
  if '/projection?revision=5'in url:
   projection=copy.deepcopy(source.projection);projection.update(revision=5,checksum=b['candidatePayloadChecksum']);projection['services']['bindings']={**projection['services']['bindings'],**b['addedBindings']}
   return Response(projection,{'X-OUF-Installation-Revision':'5','X-OUF-Installation-Checksum':b['candidatePayloadChecksum']})
  raise AssertionError('UNEXPECTED_OWNER_HTTP')
 credentials=Mock();credentials.token.return_value='FIXTURE_BEARER'
 with patch.object(n,'OwnerTransport',return_value=credentials),patch.object(n.urllib.request,'build_opener')as opener:
  opener.return_value.open.side_effect=opened
  http=n.OwnerHttp({'origin':'https://owner.fixture.invalid'},self.old.human,active['installationId'],'fixed-correlation')
  http.human=Mock();http.human._read.return_value={'accessExpiresAt':time.time()+600}
  parent=self
  class P(n.Ports):
   def __init__(self):self.action=action;self.plan=copy.deepcopy(parent.plan);self.human=parent.old.human;self.http=http;self.context=parent.context
   def guard_current(self,stage,row):
    observed=self.http.active();done=self.evidence(row,'ACTIVATE_EXPECTED');expected=done['active']if done else{**b['expectedActive'],'etag':b['expectedActiveETag']}
    parent.assertEqual(observed,expected)
  update=o.FiniteUpdate(action,self.plan,P(),Journal(self.context));update.initialize();row=update.run()
 self.assertEqual(row['incidentState'],'RECOVERED');self.assertEqual(http.posts,3);self.assertEqual(http.exports,1)
 self.assertEqual(sum(method=='POST'for method,_,_ in calls),3);self.assertTrue((self.context/'owner-active-projection.json').exists())
 self.assertEqual(next(e['evidence']['active']['generation']for e in row['effects']if e['stage']=='ACTIVATE_EXPECTED'),2)
CryptoAndJournal.test_actual_https_owner_sequence_uses_if_match_and_retains_export=actual_owner_protocol
