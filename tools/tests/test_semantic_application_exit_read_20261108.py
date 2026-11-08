import importlib.util,json,unittest
from pathlib import Path
from unittest.mock import patch
s=importlib.util.spec_from_file_location('reader',Path(__file__).resolve().parents[2]/'scripts/read-semantic-application-exit-20261108.py')
r=importlib.util.module_from_spec(s);s.loader.exec_module(r)

class ReadExitTests(unittest.TestCase):
 def test_root_code_chain_and_redaction(self):
  raw=b'''Application run failed
org.springframework.beans.factory.BeanCreationException: Error creating bean with name 'semanticProposalReceiptVerifier': secret=do-not-print
Caused by: java.lang.IllegalStateException: SEM_PROPOSAL_KEY_CUSTODY_INVALID
 at it.comune.trieste.ouf.semantic.api.SemanticProposalReceiptVerifier.readKey(SemanticProposalReceiptVerifier.java:64)
Caused by: java.nio.file.AccessDeniedException: /secret/do-not-print
password=do-not-print Bearer eyJdo-not-print https://user:do-not-print@example.invalid
'''
  out=r.summarize(raw);serialized=json.dumps(out)
  self.assertIn('SEM_PROPOSAL_KEY_CUSTODY_INVALID',out['knownErrorCodes'])
  self.assertEqual(out['exceptionChain'][-1]['class'],'java.nio.file.AccessDeniedException')
  self.assertEqual(out['sourceFrames'][0]['sourceLine'],64)
  self.assertEqual(out['knownBeans'],['semanticProposalReceiptVerifier'])
  for secret in ('do-not-print','example.invalid','/secret/','eyJ'):self.assertNotIn(secret,serialized)
 def test_unknown_text_and_known_placeholder(self):
  out=r.summarize(b"Could not resolve placeholder 'OUF_SEM_DB_PASSWORD' in value secret-value\nCaused by: madeup.SecretException: secret-value\nError creating bean with name 'secret-value'")
  self.assertEqual(out['unresolvedKnownProperties'],['OUF_SEM_DB_PASSWORD'])
  self.assertEqual(out['unknownExceptionOccurrencesOmitted'],1)
  self.assertEqual(out['knownBeans'],[])
  self.assertNotIn('secret-value',json.dumps(out))
  self.assertNotIn('SecretException',json.dumps(out))
 def test_inspect_omits_configuration_and_engine_error(self):
  state=dict(Running=False,Paused=False,Restarting=False,OOMKilled=False,Dead=False,Pid=0,ExitCode=1,
   StartedAt='2026-11-08T18:09:30Z',FinishedAt='2026-11-08T18:09:49Z',Error='secret-value')
  raw=json.dumps([{'Id':r.CID,'Image':r.IMAGE,'State':state,'Config':{'Env':['PASSWORD=secret-value']}}]).encode()
  with patch.object(r,'command',return_value=({'exitCode':0,'truncated':False},raw,b'')) as call:
   out,_=r.inspect(Path('/unused'),'sample',r.CID)
  self.assertEqual(call.call_args.args[2],('container','inspect',r.CID))
  self.assertTrue(out['engineErrorPresent']);self.assertTrue(out['read'])
  self.assertNotIn('secret-value',json.dumps(out))

if __name__=='__main__':unittest.main()
