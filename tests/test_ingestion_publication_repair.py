"""Real private publisher integration; no simulated document writer."""
import ast,base64,copy,hashlib,importlib.util,json,os,re,signal,stat,sys,tempfile,threading,time,types,unittest
from pathlib import Path
from unittest.mock import Mock,patch
ROOT=Path(__file__).resolve().parents[1]
ENTRY=ROOT/'scripts/ingestion-publication-repair-entry.py'
PREP=ROOT/'scripts/prepare-ingestion-publication-repair.py'
HELPER=ROOT/'tools/linked_property_rollout/preparation.py'
if not ENTRY.exists():
 ENTRY=Path(__file__).with_name('ingestion-existing-session-entry.py')
 PREP=Path(__file__).with_name('prepare-ingestion-publication-repair.py')
 HELPER=Path(__file__).with_name('qualified-helper.py')
def module(path,name):
 spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
legacy=module(HELPER,'qualified_legacy_private_preparation');prep=module(PREP,'qualified_publisher_repair_preparation')
def entry_namespace(parent):
 tree=ast.parse(ENTRY.read_bytes());tree.body=[n for n in tree.body if not isinstance(n,(ast.Import,ast.ImportFrom))]
 ns={'Path':Path,'require':legacy.require,'digest':legacy.digest,'encoded':legacy.encoded,
  'root_directory':legacy.root_directory,'write_new':legacy.write_new,'read_file':legacy.read_file,
  'os':os,'re':re,'stat':stat,'hashlib':hashlib,'time':time,'signal':signal,'threading':threading,
  'authority':types.SimpleNamespace(evidence=types.SimpleNamespace(PARENT=parent))}
 exec(compile(tree,'<qualified-repaired-entry>','exec'),ns);return ns
class RealPrivateDocuments(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory(dir=os.environ.get('OUF_TEST_ROOT',str(ROOT)));self.addCleanup(self.tmp.cleanup)
  self.root=Path(self.tmp.name);self.root.chmod(0o700)
  self.context=self.root/'ingestion-read-authorization-execution-abcdefgh';self.context.mkdir(mode=0o700)
  self.ns=entry_namespace(self.root)
 def test_legacy_real_publisher_reproduces_both_actual_name_failures_before_any_write(self):
  for name in ('authorization-plan.json','administrative-result.json'):
   with self.assertRaisesRegex(ValueError,'EXACT_ROLLOUT_DOCUMENT_REQUIRED'):
    legacy.publish_json(self.context,name,{'schema':'fixture'})
   self.assertFalse((self.context/name).exists())
 def test_repaired_plan_review_and_result_are_durable_exact_private_documents(self):
  for name,schema in (('authorization-plan.json','ouf.chatbot-file-authorization-plan.v1'),
   ('review.json','ouf.semantic-scoped-infrastructure-review.v1'),
   ('administrative-result.json','ouf.ingestion-read-administrative-result.v1')):
   value={'schema':schema,'proof':'fixture'};self.ns['publish_json'](self.context,name,value)
   path=self.context/name;self.assertEqual(path.read_bytes(),legacy.encoded(value))
   self.assertEqual(stat.S_IMODE(path.stat().st_mode),0o600)
   self.assertEqual(path.stat().st_nlink,1)
 def test_wrong_names_schema_and_path_traversal_fail_before_file_creation(self):
  for name,value in (('../escape',{}),('authority.json',{}),('human.json',{}),
   ('authorization-plan.json',{'schema':'wrong'}),('review.json',[])):
   with self.subTest(name=name),self.assertRaises(Exception):self.ns['publish_json'](self.context,name,value)
  self.assertEqual(list(self.context.iterdir()),[])
 def test_existing_document_or_link_never_overwritten(self):
  name='authorization-plan.json';value={'schema':'ouf.chatbot-file-authorization-plan.v1'}
  self.ns['publish_json'](self.context,name,value);before=(self.context/name).read_bytes()
  with self.assertRaises(FileExistsError):self.ns['publish_json'](self.context,name,value)
  self.assertEqual((self.context/name).read_bytes(),before)
  target=self.context/'untouched';target.write_text('unchanged');link=self.context/'review.json';link.symlink_to(target)
  with self.assertRaises(FileExistsError):self.ns['publish_json'](self.context,'review.json',{'schema':'ouf.semantic-scoped-infrastructure-review.v1'})
  self.assertEqual(target.read_text(),'unchanged')
 def test_wrong_parent_group_readable_context_and_unbounded_doc_rejected(self):
  value={'schema':'ouf.chatbot-file-authorization-plan.v1'}
  with self.assertRaises(Exception):self.ns['publish_json'](self.root,'authorization-plan.json',value)
  self.context.chmod(0o750)
  with self.assertRaises(Exception):self.ns['publish_json'](self.context,'authorization-plan.json',value)
  self.context.chmod(0o700)
  with self.assertRaises(Exception):self.ns['publish_json'](self.context,'authorization-plan.json',{**value,'value':'x'*8388608})
  self.assertFalse((self.context/'authorization-plan.json').exists())
 def test_frozen_guard_probe_uses_only_literal_name_condition_and_never_writes(self):
  before=list(self.context.iterdir());result=prep.publisher_guard_proof(HELPER.read_bytes())
  self.assertEqual(result['guardCode'],'EXACT_ROLLOUT_DOCUMENT_REQUIRED')
  self.assertEqual(result['rejectedNames'],['authorization-plan.json','administrative-result.json'])
  self.assertEqual(result['sourceHash'],hashlib.sha256(HELPER.read_bytes()).hexdigest())
  self.assertEqual(before,list(self.context.iterdir()))
 def test_changed_or_effectful_guard_is_rejected_without_execution(self):
  for raw in (b'def publish_json(c,name,v):\n require(name in dynamic(),"EXACT_ROLLOUT_DOCUMENT_REQUIRED")\n',
   b'def publish_json(c,name,v):\n require(name in ("authorization-plan.json",),"EXACT_ROLLOUT_DOCUMENT_REQUIRED")\n',
   b'def publish_json(c,name,v):\n open("/MUST_NOT_WRITE","w")\n'):
   with self.assertRaises(ValueError):prep.publisher_guard_proof(raw)
 def test_entire_entry_with_real_publication_crosses_approval_and_writes_result(self):
  ns=self.ns;events=[];now=int(time.time())
  binding={'sessionDirectory':str(self.context),'tokenPath':str(self.context/'human-access.jwt'),'expiresAt':now+7200}
  human=Mock(directory=self.context,token_path=self.context/'human-access.jwt',expires_at=now+7200,thread=None)
  human._read.return_value={'attempts':214,'binding':binding,'state':'READY'};human.current.return_value=binding
  plan={'schema':'ouf.chatbot-file-authorization-plan.v1','selection':{},'baseline':{'policy':'same'},'helperBindings':{}}
  case={'humanBinding':binding,'priorOAuthAttempts':214,'sourceId':'fixture','predecessorHistoryHash':'a'*64}
  auth=Mock();auth.OwnerTransport.return_value.observe.return_value=copy.deepcopy(plan['baseline'])
  delta=Mock();delta.apply.return_value={'fixtureReadback':True};auth.AuthorizationDelta.return_value=delta
  authority=Mock();authority.evidence.PARENT=self.root
  authority.compile_action_review.return_value={'schema':'ouf.semantic-scoped-infrastructure-review.v1'}
  authority.terminal_consent.side_effect=lambda *a:events.append('APPROVO')or{'native':'fixture'}
  authority.issue_action.side_effect=lambda *a:events.append('issue')or Mock()
  ns.update(authority=authority,authorization=auth,HumanSession=lambda *a:human,validate_continuation=lambda *a:plan,
   validate_plan=lambda *a:None,primitives=lambda *a:types.SimpleNamespace(bindings={}),Journal=lambda *a:Mock())
  ns['main']({'authorization':{'plan':{'selection':{}}}}, {}, {},case,self.context,Mock(),events.append)
  self.assertTrue((self.context/'authorization-plan.json').exists());self.assertTrue((self.context/'review.json').exists())
  result=json.loads((self.context/'administrative-result.json').read_bytes())
  self.assertEqual(result['status'],'ADMINISTRATIVE_READBACK_COMPLETE');self.assertFalse(result['sourceActivated'])
  self.assertLess(events.index('APPROVO'),events.index('issue'));delta.apply.assert_called_once()
  self.assertIn('OUF_INGESTION_ADMIN_PHASE=PRIVATE_PLAN_PUBLICATION',events)
 def test_repaired_entry_fits_exact_existing_181_module_closure(self):
  path=ROOT/'tools/ingestion_read_authorization/runtime.py'
  if not path.exists():path=Path(__file__).parents[1]/'repo/tools/ingestion_read_authorization/runtime.py'
  ns={'__name__':'verified_closed_loader'};exec(compile(path.read_bytes(),str(path),'exec'),ns)
  sources={n:b'pass\n'for n in ns['MODULES']};sources[ns['ENTRY']]=ENTRY.read_bytes()
  self.assertEqual(len(ns['compile_sources'](sources)),181)
 def test_runtime_rechecks_repaired_predecessor_has_no_authority_or_effects(self):
  ns=self.ns;binding={'session':'same'};plan={'sessionBinding':binding};plan_hash=legacy.digest(plan)
  proof=prep.publisher_guard_proof(HELPER.read_bytes());proof['predecessorContext']=str(self.context)
  case={'sourceId':'fixture','humanBinding':binding,'priorOAuthAttempts':214,'publisherRepair':proof,
   'existingSessionContinuation':{'schema':'ouf.ingestion-existing-session-continuation.v1','newHumanLoginAllowed':False,
    'budgetReset':False,'maximumCumulativeOAuthAttempts':256,'fileBindings':{},'planPath':'/fixture/plan',
    'planHash':plan_hash,'originalContext':'/fixture/original','preflightContext':'/fixture/preflight',
    'claimBinding':{'path':'/fixture/claim','sha256':'c'*64}}}
  child=self.root/'child';claim={'context':str(child),'originalContext':'/fixture/original','preflightContext':'/fixture/preflight',
   'planHash':plan_hash,'priorOAuthAttempts':214,'maximumCumulativeOAuthAttempts':256,'budgetReset':False,'automaticReplayAllowed':False}
  def read(path,**kwargs):return copy.deepcopy(plan if path=='/fixture/plan'else claim)
  ns['validate_plan']=lambda *a:None
  self.assertEqual(ns['validate_continuation'](case,read,child),plan)
  (self.context/'authorization').mkdir(mode=0o700)
  with self.assertRaisesRegex(ValueError,'REPAIRED_PREDECESSOR_EFFECT_RECONCILIATION_REQUIRED'):
   ns['validate_continuation'](case,read,child)
 def repair_fixture(self):
  original=self.root/'original';original.mkdir(mode=0o700)
  stopped=self.context;old_entry=b'pass\n';helper=HELPER.read_bytes()
  sources={'tools.ingestion_read_authorization.entry':old_entry,'tools.linked_property_rollout.preparation':helper}
  claim_path=self.root/'consumed-continuation.claim.json'
  claim={'context':str(stopped),'sourceCommit':'37184220c2a565367a194d41e862a704f87dbdb8',
   'originalContext':str(original),'budgetReset':False,'maximumCumulativeOAuthAttempts':256,'automaticReplayAllowed':False}
  claim_path.write_bytes(prep.encoded(claim));claim_path.chmod(0o600)
  case={'humanBinding':{'session':'same'},'existingSessionContinuation':{'originalContext':str(original),'planHash':prep.PLAN,
   'claimBinding':{'path':str(claim_path),'sha256':prep.sha(claim_path.read_bytes())},'fileBindings':{}}}
  closure={'declaration':{'sourceHashes':{n:prep.sha(v)for n,v in sources.items()}}}
  files={'case.json':prep.encoded(case),'bootstrap.py':b'pass\n','runtime.py':b'pass\n','reader.py':b'pass\n',
   'sources.json':prep.encoded({n:base64.b64encode(v).decode()for n,v in sources.items()})}
  package={'schema':'ouf.ingestion-read-administrative-package.v1','sourceCommit':claim['sourceCommit'],
   'closure':closure,'executionPins':{'caseSha256':prep.digest(case)},'fileHashes':{n:prep.sha(v)for n,v in files.items()}}
  for name,value in files.items():(stopped/name).write_bytes(value)
  (stopped/'package.json').write_bytes(prep.encoded(package))
  package_hash=prep.digest(package)
  (stopped/'runtime.claim.json').write_bytes(prep.encoded({'packageHash':package_hash,'automaticReplayAllowed':False}))
  def raw_read(path,expected=None):
   raw=Path(path).read_bytes();legacy.require(expected is None or prep.sha(raw)==expected,'TEST_HASH_CHANGED');return raw
  def read(path,maximum=8388608,expected=None):return json.loads(raw_read(path,expected))
  return original,sources,case,package,package_hash,old_entry,read,raw_read
 def test_stopped_child_claims_and_sources_reconcile_without_writes(self):
  original,sources,case,package,package_hash,old_entry,read,raw_read=self.repair_fixture()
  before={str(p):p.read_bytes()for p in self.root.rglob('*')if p.is_file()}
  with patch.multiple(prep,STOPPED=self.context,STOPPED_PACKAGE=package_hash,
    STOPPED_CLOSURE=prep.digest(package['closure']),STOPPED_ENTRY=prep.sha(old_entry)):
   proof,bindings=prep.reconcile_stopped_child(read,raw_read,self.root,original,sources,{'sessionBinding':case['humanBinding']})
  self.assertEqual(proof['guardCode'],'EXACT_ROLLOUT_DOCUMENT_REQUIRED')
  self.assertIn(str(self.root/'consumed-continuation.claim.json'),bindings)
  self.assertEqual(before,{str(p):p.read_bytes()for p in self.root.rglob('*')if p.is_file()})
 def test_authority_or_effect_in_stopped_child_blocks_repair(self):
  original,sources,case,package,package_hash,old_entry,read,raw_read=self.repair_fixture()
  (self.context/'authority.json').write_text('must not open')
  with patch.multiple(prep,STOPPED=self.context,STOPPED_PACKAGE=package_hash,
    STOPPED_CLOSURE=prep.digest(package['closure']),STOPPED_ENTRY=prep.sha(old_entry)):
   with self.assertRaisesRegex(ValueError,'STOPPED_CHILD_EFFECT_RECONCILIATION_REQUIRED'):
    prep.reconcile_stopped_child(read,raw_read,self.root,original,sources,{'sessionBinding':case['humanBinding']})
if __name__=='__main__':unittest.main()
