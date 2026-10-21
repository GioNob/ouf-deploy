import ast,base64,importlib.util,json,struct,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];SCRIPT=ROOT/'scripts/read-mcp-human-issuer-correlation.py'
if not SCRIPT.exists():SCRIPT=Path(__file__).with_name(SCRIPT.name)
spec=importlib.util.spec_from_file_location('qualified_correlation_reader',SCRIPT);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class Correlation(unittest.TestCase):
 def setUp(self):
  self.selection={'realm':'fixture','subject':'subject','issuer':'https://issuer.invalid'};self.binding={'session':'fixture'}
  self.claims={'iss':self.selection['issuer'],'sub':'subject','azp':'ouf-human-admin','typ':'Refresh','jti':'PRIVATE-TOKEN-ID','sid':'PRIVATE-SESSION-ID'}
 def token(self,claims):return 'header.'+base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip('=')+'.signature'
 def journal(self,**changes):return {'schema':'ouf.chatbot-human-session.private.v1','binding':self.binding,'state':'BLOCKED',
  'operation':'REFRESH','attempts':217,'reason':'HUMAN_OAUTH_REVOKED_OR_PERMANENT_OR_UNKNOWN','budgetReset':False,
  'refreshToken':self.token(self.claims),'accessToken':'SECRET',**changes}
 def line(self,subject='null',token='PRIVATE-TOKEN-ID',session='PRIVATE-SESSION-ID',reason='Session not active'):
  return ('type="REFRESH_TOKEN_ERROR",realmName="fixture",clientId="ouf-human-admin",userId="'+subject+'",error="invalid_token",reason="'+reason+'",refresh_token_id="'+token+'",sessionId="'+session+'"\n').encode()
 def test_null_subject_correlates_exact_retained_token_id_without_disclosing_any_id(self):
  ids=m.correlation(self.journal(),self.binding,self.selection);result=m.projection(self.line(),self.selection,ids)
  self.assertTrue(result['matchingIssuerEventProven']);row=result['matchedErrorClasses'][0]
  self.assertTrue(row['refreshTokenIdMatched']);self.assertFalse(row['subjectMatched']);self.assertEqual(row['reasonCode'],'SESSION_NOT_ACTIVE')
  self.assertNotIn('PRIVATE',json.dumps(result));self.assertNotIn('SECRET',json.dumps(result))
 def test_different_concrete_subject_cannot_be_overridden_by_matching_identifiers(self):
  ids=m.correlation(self.journal(),self.binding,self.selection);r=m.projection(self.line(subject='other'),self.selection,ids)
  self.assertFalse(r['matchingIssuerEventProven']);self.assertFalse(r['unattributedEventsProveHumanCause'])
 def test_wrong_token_and_session_are_unattributed_but_safe_error_class_is_visible(self):
  ids=m.correlation(self.journal(),self.binding,self.selection);r=m.projection(self.line(token='other',session='other'),self.selection,ids)
  self.assertFalse(r['matchingIssuerEventProven']);self.assertEqual(r['unattributedClientErrorClasses'][0]['reasonCode'],'SESSION_NOT_ACTIVE')
 def test_bad_opaque_or_foreign_refresh_claims_do_not_provide_correlation(self):
  for token in ('opaque','a.!@#.z',self.token({**self.claims,'sub':'other'}),self.token({**self.claims,'azp':'other'}),self.token({**self.claims,'typ':'Offline'})):
   self.assertEqual(m.correlation(self.journal(refreshToken=token),self.binding,self.selection),{})
 def test_changed_blocked_history_cannot_be_correlated(self):
  for changes in ({'attempts':218},{'state':'READY'},{'operation':'USERINFO'},{'budgetReset':True},{'binding':{}},{'reason':'other'}):
   with self.subTest(changes=changes),self.assertRaises(Exception):m.correlation(self.journal(**changes),self.binding,self.selection)
 def test_unknown_issuer_details_redacted_even_for_correlated_event(self):
  ids=m.correlation(self.journal(),self.binding,self.selection);r=m.projection(self.line(reason='SECRET-DETAIL'),self.selection,ids)
  self.assertNotIn('SECRET',json.dumps(r));self.assertFalse(r['specificIssuerReasonProven'])
 def test_docker_framing_remains_bounded(self):
  raw=self.line();frame=b'\x01\x00\x00\x00'+struct.pack('>I',len(raw))+raw
  self.assertEqual(m.unframe(frame,False),raw)
  with self.assertRaises(Exception):m.unframe(frame[:-1],False)
 def test_only_three_engine_gets_and_no_oauth_login_write_or_transmission_of_identifiers(self):
  tree=ast.parse(SCRIPT.read_bytes());calls=[n for n in ast.walk(tree)if isinstance(n,ast.Call)]
  requests=[n for n in calls if ast.unparse(n.func)=='connection.request'];self.assertEqual(len(requests),1)
  self.assertEqual(ast.literal_eval(requests[0].args[0]),'GET');self.assertEqual(len(requests[0].args),2)
  self.assertFalse(any(ast.unparse(n.func).endswith(('.refresh_if_due','.login','.execv','.write','.start_refresh'))for n in calls))
if __name__=='__main__':unittest.main()
