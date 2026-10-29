"""Fresh authentication after a received refresh failure; no old-token replay."""
import ast,copy,json,os,time,unittest
from pathlib import Path
from unittest.mock import patch
import test_mcp_update_successor_session as fixtures
from tools.semantic_mcp_update import session as m

class BlockedLogin(fixtures.Successor):
 def blocked(self):
  row=self.human._read();row.update(state='BLOCKED',operation='REFRESH',attempts=81,
   reason='HUMAN_OAUTH_REVOKED_OR_PERMANENT_OR_UNKNOWN')
  self.human.journal.record.write_bytes(m.encoded(row));return row
 def test_fresh_login_preserves81_and_old_block_without_copying_credentials(self):
  self.blocked();before=self.human.journal.record.read_bytes()
  with patch.object(self.human,'_http',side_effect=AssertionError('old credential must never be sent')):
   review=m.blocked_refresh_login_review(self.human,self.operation)
   self.assertEqual(review['maximumRemainingOAuthAttempts'],47)
   self.assertFalse(review['failedRefreshReplayAllowed']);self.assertFalse(review['runtimeAuthorityIssued'])
   following=m.open_approved_login(self.human,review,self.decision(review))
  row=following._read();self.assertEqual(row['attempts'],81);self.assertEqual(row['state'],'NEW')
  self.assertNotIn('PRIVATE',json.dumps(row));self.assertFalse(following.token_path.exists())
  with self.assertRaises(Exception):following.current()
  self.assertEqual(self.human.journal.record.read_bytes(),before)
  with self.assertRaises(Exception):m.open_approved_login(self.human,review,self.decision(review))
 def test_unknown_transport_interrupted_exhausted_wrong_operation_cannot_open(self):
  initial=self.blocked()
  for change in ({'state':'REQUESTING'},{'reason':'HUMAN_OAUTH_OUTCOME_UNPROVEN'},
    {'reason':'HUMAN_REFRESH_INTERRUPTED_OUTCOME_UNPROVEN'},{'attempts':128},{'operation':'USERINFO'}):
   self.human.journal.record.write_bytes(m.encoded({**initial,**change}))
   with self.subTest(change=change),self.assertRaises(Exception):m.blocked_refresh_login_review(self.human,self.operation)
 def test_changed_predecessor_cannot_use_old_consent(self):
  row=self.blocked();review=m.blocked_refresh_login_review(self.human,self.operation)
  row['attempts']=82;self.human.journal.record.write_bytes(m.encoded(row))
  with self.assertRaises(Exception):m.open_approved_login(self.human,review,self.decision(review))
  self.assertFalse((self.directory/'successor-window.claim.json').exists())
 def test_exact_pre_authority_context_and81_are_required(self):
  self.blocked();context=self.root/'failed';context.mkdir(mode=0o700)
  case={'policyContext':str(self.root/'policy'),'blockedHumanPreparation':{'contextPath':str(context),'oauthAttempts':81}}
  rows={name:{}for name in('candidate-review.json','execution-plan.json','worker-review.json')}
  tree=ast.parse((fixtures.ROOT/'tools/onboarding_audit_update/entry.py').read_text())
  fn=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='blocked_preparation_binding')
  ns={'Path':Path,'os':os,'digest':m.digest,'require':m.require}
  exec(compile(ast.Module(body=[fn],type_ignores=[]),'<blocked-preparation>','exec'),ns)
  check=ns['blocked_preparation_binding'];read=lambda path,limit:copy.deepcopy(rows[path.name])
  self.assertEqual(len(check(case,read,self.human)),64)
  (context/'authority.json').write_text('{}')
  with self.assertRaises(Exception):check(case,read,self.human)
  (context/'authority.json').unlink();row=self.human._read();row['attempts']=82
  self.human.journal.record.write_bytes(m.encoded(row))
  with self.assertRaises(Exception):check(case,read,self.human)

if __name__=='__main__':unittest.main()
