"""Read-only preparation, exact 316+128 compiler and safe token/route metadata."""
import ast,base64,copy,json,os,sys,tempfile,unittest
from pathlib import Path
from types import SimpleNamespace
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tests'),str(ROOT/'tools/semantic_policy_token_owner'),str(ROOT/'tools/semantic_application_cutover'),str(ROOT/'tools/semantic_cohort_admission/cohort-draft')]
from tools.teatri_recovery_review import entry as e
import test_teatri_policy_restore_remainder as remainder
original=remainder.original

class Review(unittest.TestCase):
 def test_real_compiler_preserves_exhausted316_and_proposes444_without_changing_records(self):
  base,records,first,worker=remainder.fixture();records['owner-session.json']=worker
  old=records['recovery.json'];old.update(attempts=8,publicationCount=8,controlledPredecessorGrantAttempts=308,
   controlledCumulativeGrantAttempts=316,workerSessionHash=original.fingerprint(worker),policyHash=original.fingerprint(worker['policy']),
   contextRef=worker['contextRef'],generationRef=worker['generationRef'])
  before=copy.deepcopy(records);journal=worker['fenceBinding']['value']['journalPath']
  review=e.worker_review(base,records,journal);policy={**worker['policy'],'max_attempts':128}
  scope=original.C['compile_governed_session'](review,records,first,policy,'7'*64,'8'*64,60)
  self.assertEqual(scope['predecessorGrantAttempts'],316);self.assertEqual(scope['maximumCumulativeGrantAttempts'],444)
  self.assertEqual(scope['predecessorCumulativeCeiling'],316);self.assertEqual(records,before)
  self.assertFalse(scope['consumedClaimReplayAllowed']);self.assertFalse(scope['automaticBudgetRenewalAllowed'])
  for changed in({'state':'ACTIVE'},{'controlledCumulativeGrantAttempts':315},{'publicationCount':7}):
   bad=copy.deepcopy(records);bad['recovery.json'].update(changed)
   with self.assertRaises(Exception):e.worker_review(base,bad,journal)
 def test_only_safe_route_fields_released_never_plugin_secrets(self):
  route={'id':'retry','uri':'/api/udp/v1/governance/materialization/jobs/*','methods':['POST'],
   'plugins':{'openid-connect':{'client_secret':'PRIVATE_SECRET','required_scopes':['udp.materialization.retry'],'bearer_only':True},
    'serverless-post-function':{'functions':['local allowed_actors={["HUMAN"]=true}']}}}
  result=e.route_metadata({'retry':route});self.assertEqual(result[0]['allowedActorsMetadata'],['HUMAN'])
  self.assertNotIn('PRIVATE',json.dumps(result));self.assertNotIn('client_secret',json.dumps(result))
 def test_readonly_entry_has_no_reachable_oauth_mutation_login_worker_or_approval(self):
  tree=ast.parse((ROOT/'tools/teatri_recovery_review/entry.py').read_text())
  names={n.func.attr for n in ast.walk(tree)if isinstance(n,ast.Call)and isinstance(n.func,ast.Attribute)}
  self.assertFalse(names.intersection({'terminal_consent','issue_action','start_refresh','refresh_if_due','install','login','retry','apply'}))
  verbs=[n.args[0].value for n in ast.walk(tree)if isinstance(n,ast.Call)and isinstance(n.func,ast.Attribute)and n.func.attr=='kc']
  self.assertEqual(verbs,['get']*4)
 def test_token_scope_metadata_is_not_an_authorization_or_signature_claim(self):
  with tempfile.TemporaryDirectory(dir=os.environ.get('OUF_TEST_ROOT',str(ROOT)))as place:
   root=Path(place);path=root/'human-access.jwt';selection={'subject':'human','issuer':'https://issuer.invalid','tenant':'tenant'}
   claims={'sub':'human','iss':selection['issuer'],'tenant_id':'tenant','ouf_actor_type':'HUMAN','azp':'ouf-human-admin',
    'scope':'openid udp.materialization.retry','exp':1}
   payload=base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b'=');path.write_bytes(b'unsigned.'+payload+b'.not-a-valid-signature');path.chmod(0o600)
   row={'binding':{'sessionDirectory':str(root)},'attempts':138}
   human=SimpleNamespace(directory=root,token_path=path,_read=lambda:row,_check_identity_and_budget=lambda r:None)
   value=e.token_metadata(human,selection);self.assertTrue(value['recoveryScopePresent']);self.assertTrue(value['expiredAtRead'])
   self.assertFalse(value['signatureVerifiedLocally']);self.assertTrue(value['claimsAreMetadataOnly']);self.assertEqual(value['oauthRequests'],0)
