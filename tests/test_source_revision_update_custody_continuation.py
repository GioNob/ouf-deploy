"""Real root shared metadata and one-use zero-effect scope succession in CI."""
import contextlib,copy,hashlib,json,os,tempfile,time,unittest
from pathlib import Path
from unittest.mock import patch
import test_source_revision_update_configuration
from tools.source_revision_update import native as n
from tools.source_revision_update.owner import digest
from tools.semantic_lease_recovery.recovery_journal import Journal
ROOT=Path(__file__).resolve().parents[1]
@unittest.skipUnless(os.environ.get('OUF_CUSTODY_CONTINUATION')=='1','explicit custody sealed-source fixture required')
class Custody(unittest.TestCase):
 def temporary(self):return tempfile.TemporaryDirectory(dir=os.environ['OUF_TEST_ROOT'])
 def put(self,path,value):
  raw=json.dumps(value,sort_keys=True).encode();path.write_bytes(raw);path.chmod(0o600);return {'path':str(path),'sha256':hashlib.sha256(raw).hexdigest()}
 def metadata(self,root):
  result=[];pins={}
  for name in ('permit.json','policy.json','profile.json'):
   path=root/name;binding=self.put(path,{'public':'root-produced metadata'});os.chown(path,0,10005);path.chmod(0o440)
   result.append(binding);pins[str(path)]={**binding,'metadata':n.custody_pin(path.stat())}
  return result,pins
 def predecessor(self,root,logical=None):
  context=root/'source-revision-execution-abcdefgh';context.mkdir(mode=0o700);logical=logical or '1'*64
  plan={'logicalUpdateRef':logical};plan_binding=self.put(context/'execution-plan.json',plan)
  review={'authorityDirectory':str(context),'sourceClosureHash':'c'*64,'scopes':{'sourceRevisionUpdate':{'planHash':digest(plan)}}}
  review_binding=self.put(context/'review.json',review)
  authority={'expiresAt':time.time()-120,'sourceClosureHash':'c'*64,'scopedExecution':{'reviewHash':review_binding['sha256']}}
  authority_binding=self.put(context/'authority.json',authority)
  row={'schema':'ouf.source-revision-update-journal.v1','version':0,'nextStage':0,'effects':[],'budgetReset':False,'readinessAttempts':0,'cumulativeReadinessAttempts':0,'authorityHash':authority_binding['sha256'],'scopeHash':digest(review['scopes']['sourceRevisionUpdate']),'bootId':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'expiresAt':time.time()-120,'expiresMonotonic':time.monotonic()-120}
  Journal(context).initialize(row);journal_binding={'path':str(context/'recovery.json'),'sha256':hashlib.sha256((context/'recovery.json').read_bytes()).hexdigest()}
  claim_binding=self.put(root/('source-revision-update-'+logical+'.claim.json'),{'planHash':digest(plan),'authorityHash':authority_binding['sha256'],'context':str(context),'automaticReplayAllowed':False})
  ref={'schema':'ouf.source-revision-zero-effect-expired-scope.v1','context':str(context),'logicalUpdateRef':logical,'journalBinding':journal_binding,'authorityBinding':authority_binding,'planBinding':plan_binding,'reviewBinding':review_binding,'claimBinding':claim_binding}
  return {'logicalUpdateRef':logical,'authorityDirectory':str(root/'source-revision-execution-successor'),'logicalScopeSuccessor':ref},row
 def rewrite_journal(self,plan,row):
  ref=plan['logicalScopeSuccessor'];ref['journalBinding']=self.put(Path(ref['context'])/'recovery.json',row)
 def test_exact_root_service_group0440_pin_passes_without_permission_changes(self):
  with self.temporary()as temp:
   bindings,pins=self.metadata(Path(temp))
   for binding in bindings:
    path=Path(binding['path']);before=n.custody_pin(path.stat());self.assertTrue(n.retained_metadata_file(binding,pins[str(path)])['custodyPreserved']);self.assertEqual(before,n.custody_pin(path.stat()))
    with self.assertRaises(Exception):n.private_file(str(path),binding['sha256'],65536)
 def test_changed_hash_inode_gid_mode_link_and_pin_all_stop(self):
  for change in ('bytes','inode','gid','mode','hardlink','symlink','pin'):
   with self.subTest(change=change),self.temporary()as temp:
    root=Path(temp);bindings,pins=self.metadata(root);binding=bindings[0];path=Path(binding['path']);pin=copy.deepcopy(pins[str(path)])
    if change=='bytes':path.write_bytes(b'changed')
    elif change=='inode':path.unlink();path.write_bytes(b'changed');os.chown(path,0,10005);path.chmod(0o440)
    elif change=='gid':os.chown(path,0,10006)
    elif change=='mode':path.chmod(0o640)
    elif change=='hardlink':os.link(path,root/'second')
    elif change=='symlink':path.unlink();path.symlink_to(root/'policy.json')
    else:pin['metadata'][7]+=1
    with self.assertRaises(Exception):n.retained_metadata_file(binding,pin)
 def test_atomic_successor_preserves_old_bytes_and_rejects_second_or_stale_worker(self):
  with self.temporary()as temp:
   plan,row=self.predecessor(Path(temp));ref=plan['logicalScopeSuccessor'];original={k:Path(v['path']).read_bytes()for k,v in ref.items()if k.endswith('Binding')}
   with Journal(ref['context']).invocation():
    with self.assertRaises(BlockingIOError):n.claim_zero_effect_successor(plan,'a'*64)
   n.claim_zero_effect_successor(plan,'a'*64);n.guard_zero_effect_successor(plan,'a'*64)
   for key,raw in original.items():self.assertEqual(Path(ref[key]['path']).read_bytes(),raw)
   with self.assertRaises(Exception):n.claim_zero_effect_successor(plan,'a'*64)
   with self.assertRaises(Exception):n.guard_zero_effect_successor(plan,'b'*64)
   bad=copy.deepcopy(plan);bad['authorityDirectory']+='-stale'
   with self.assertRaises(Exception):n.guard_zero_effect_successor(bad,'a'*64)
 def test_nonzero_history_unexpired_wall_monotonic_or_wrong_boot_block_succession(self):
  for change in ('effects','version','nextStage','readinessAttempts','cumulativeReadinessAttempts','budgetReset','bootId','expiresAt','expiresMonotonic'):
   with self.subTest(change=change),self.temporary()as temp:
    plan,row=self.predecessor(Path(temp))
    row[change]={'effects':[{'state':'CLAIMED'}],'version':1,'nextStage':1,'readinessAttempts':1,'cumulativeReadinessAttempts':1,'budgetReset':True,'bootId':'old-boot','expiresAt':time.time()+100,'expiresMonotonic':time.monotonic()+100}[change]
    self.rewrite_journal(plan,row)
    with self.assertRaises(Exception):n.claim_zero_effect_successor(plan,'a'*64)
    self.assertFalse((Path(plan['logicalScopeSuccessor']['context'])/'logical-successor.claim.json').exists())
 def test_private_plan_extension_binds_exact_three_metadata_and_predecessor(self):
  with self.temporary()as temp:
   root=Path(temp);plan,row=self.predecessor(root);bindings,pins=self.metadata(root);ref=plan.pop('logicalScopeSuccessor');plan['retainedMcpMetadata']=bindings
   reference={'schema':'ouf.source-revision-mcp-custody-continuation.v1','metadataPins':pins,'scopeSuccessor':ref};bound=n.bind_custody_continuation(plan,reference)
   self.assertEqual(bound['retainedMcpMetadataCustody'],pins);self.assertNotIn('logicalScopeSuccessor',plan);self.assertNotEqual(digest(bound),digest(plan));self.assertFalse((Path(ref['context'])/'logical-successor.claim.json').exists())
   n.claim_zero_effect_successor(bound,'a'*64)
   with self.assertRaises(Exception):n.bind_custody_continuation(plan,reference)
 def test_changed_historical_root_claim_or_authority_is_not_accepted_as_current(self):
  for key in ('claimBinding','authorityBinding','planBinding','reviewBinding'):
   with self.subTest(key=key),self.temporary()as temp:
    plan,row=self.predecessor(Path(temp));ref=plan['logicalScopeSuccessor'];path=Path(ref[key]['path']);path.write_bytes(b'{}')
    with self.assertRaises(Exception):n.zero_effect_predecessor(ref,plan['logicalUpdateRef'])
 def test_sealed_fixture_uses_only_explicit_successors(self):
  for name in ('native','entry','login'):self.assertEqual((ROOT/f'tools/source_revision_update/{name}.py').read_bytes(),(ROOT/f'tools/source_revision_update/custody_{name}.py').read_bytes())

@unittest.skipUnless(os.environ.get('OUF_CUSTODY_CONTINUATION')=='1','explicit custody sealed-source fixture required')
class CurrentHuman(unittest.TestCase):
 def test_native_refresh_188_to190_preserves_window_and_governed_owner_scope(self):
  import io
  import test_source_revision_update_governed_continuation as fixture
  import test_source_revision_authorization as owner_fixture
  from tools.source_revision_update import login as l
  from tools.chatbot_file_cohort import authorization as auth
  base=fixture.Governed()
  with base.temporary()as temp,base.environment():
   case,selection,directory,row,context=base.fixture(Path(temp));row['attempts']=188;case['postbootResumedHuman']['minimumOAuthAttempts']=188;(directory/'recovery.json').write_bytes(l.encoded(row));human=l.resumed_human(case,selection,base.read);calls=[]
   def http(url,values=None,bearer=None):
    calls.append(url)
    if values is not None:return 200,{'access_token':base.jwt(selection),'refresh_token':'NEW_PRIVATE_REFRESH','token_type':'bearer'},None
    return 200,{'sub':selection['subject']},None
   with patch.object(human,'_http',side_effect=http),patch.object(human,'login',side_effect=AssertionError('NO_NEW_LOGIN')),contextlib.redirect_stdout(io.StringIO())as out:l.refresh_resumed_human(human,case,context,base.read,print)
   after=human._read();self.assertEqual(after['attempts'],190);self.assertEqual(after['binding'],row['binding']);self.assertEqual(after['monotonicDeadline'],row['monotonicDeadline']);self.assertEqual(len(calls),2);self.assertNotIn('PRIVATE',out.getvalue())
   selected,observed=owner_fixture.existing.fixture();binding=human.current();binding['selectionHash']=auth.digest(selected)
   for key in ('issuer','subject','tenant'):binding[key]=selected[key]
   plan=auth.compile_plan(observed,owner_fixture.primitives(),selected,include_ingestion_status=False,now='2026-10-18T06:00:00Z',session_binding=binding);self.assertEqual(auth.authorization_scope(plan)['sessionBinding'],binding)
 def test_wrong_counter_expired_or_ambiguous_native_refresh_never_replays(self):
  import test_source_revision_update_governed_continuation as fixture
  from tools.source_revision_update import login as l
  from tools.csv_materialization_recovery import human_session as native
  base=fixture.Governed()
  for change in ('counter','expiry','uncertain'):
   with self.subTest(change=change),base.temporary()as temp,base.environment():
    case,selection,directory,row,context=base.fixture(Path(temp));row['attempts']=188;case['postbootResumedHuman']['minimumOAuthAttempts']=188
    if change=='counter':row['attempts']=189
    if change=='expiry':row['monotonicDeadline']=time.monotonic()-1
    (directory/'recovery.json').write_bytes(l.encoded(row))
    with patch.object(native.HumanSession,'login')as login,patch.object(native.HumanSession,'_http',side_effect=OSError('UNCERTAIN'))as http:
     if change!='uncertain':
      with self.assertRaises(Exception):l.resumed_human(case,selection,base.read)
      http.assert_not_called()
     else:
      human=l.resumed_human(case,selection,base.read)
      with self.assertRaises(native.HumanSessionPaused):l.refresh_resumed_human(human,case,context,base.read,print)
      self.assertEqual(human._read()['attempts'],189);self.assertEqual(human._read()['state'],'BLOCKED')
      with self.assertRaises(Exception):l.refresh_resumed_human(human,case,context,base.read,print)
      self.assertEqual(http.call_count,1)
     login.assert_not_called()

@unittest.skipUnless(os.environ.get('OUF_CUSTODY_CONTINUATION')=='1','explicit custody sealed-source fixture required')
class SignedSuccessor(unittest.TestCase):
 def test_new_dual_role_signature_binds_extended_plan_and_runs_one_scope_once(self):
  import test_source_revision_update_owner as fixture
  from tools.source_revision_update.owner import ReadinessUpdate,scope,STAGES
  from tools.semantic_policy_token_owner.owner_installation import AggregateAction
  original=fixture.Owner();original.setUp();self.addCleanup(original.doCleanups);c=original.crypto;helper=Custody()
  old,row=helper.predecessor(c.root,original.plan['logicalUpdateRef']);bindings,pins=helper.metadata(c.root)
  directory=c.root/'new-signed-successor';directory.mkdir(mode=0o700);plan=copy.deepcopy(original.plan);plan.update(authorityDirectory=str(directory),retainedMcpMetadata=bindings)
  plan=n.bind_custody_continuation(plan,{'schema':'ouf.source-revision-mcp-custody-continuation.v1','metadataPins':pins,'scopeSuccessor':old['logicalScopeSuccessor']})
  with self.assertRaises(Exception):original.action.guard('sourceRevisionUpdate',scope(plan))
  c.authority=fixture.crypto.encoded({'schema':'ouf.semantic-cutover-execution-authority.v1',**{k:v for k,v in c.expected.items()if k!='intakeHash'},'issuedAt':c.now,'expiresAt':c.now+480,'sourceRevisionUpdate':scope(plan)})
  c.approval['executionAuthorityHash']=fixture.crypto.sha(c.authority);c.write(c.mandate,fixture.crypto.encoded(c.approval));c.approved=fixture.crypto.sha(c.mandate.read_bytes())
  for role in c.grant['roles']:c.sign(role)
  action=AggregateAction(c.gate(),c.authority,c.expected['sourceClosureHash'])
  class Ports(fixture.FixturePorts):
   def claim_logical_scope(self):return n.NativePorts.claim_logical_scope(self)
   def guard_current(self,stage):
    self.action.guard('sourceRevisionUpdate',scope(self.plan));n.guard_zero_effect_successor(self.plan,self.action.authority_hash)
    for b in self.plan['retainedMcpMetadata']:n.retained_metadata_file(b,self.plan['retainedMcpMetadataCustody'][b['path']])
  ports=Ports(action,plan);journal=Journal(directory);owner=ReadinessUpdate(action,journal,plan,ports,lambda:(c.now,time.monotonic()));owner.initialize();owner.run();before=list(ports.calls);owner.run();self.assertEqual(ports.calls,before);self.assertEqual(len(before),len([s for s in STAGES if not s.endswith('.READINESS')and s!='VERIFY_FINAL']))
  self.assertEqual(journal.read()['cumulativeReadinessAttempts'],3);self.assertEqual(json.loads(Path(old['logicalScopeSuccessor']['journalBinding']['path']).read_bytes())['effects'],[])
  with self.assertRaises(Exception):n.claim_zero_effect_successor(plan,action.authority_hash)
