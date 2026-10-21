"""Existing-key signatures for exact fixture permit; no real owner/HUMAN claim."""
import copy,hashlib,json,time,uuid,unittest
from unittest.mock import patch
import test_mcp_scoped_authority as fixture
import test_mcp_update_plan as planfixture
from tools.semantic_mcp_update import permit as m

class Permit(fixture.Issuance):
 def setUp(self):
  super().setUp();self.private=planfixture.Compiler().fixture()[0]
  self.private['history'].update(humanSubject=self.hb['subject'],tenant=self.hb['tenant'])
  self.private['retainedClaim']['attemptId']=str(uuid.uuid4())
  self.binding={'path':str(self.c.root/'candidate.json'),'sha256':m.digest(self.private)}
  self.connection='link_'+'e'*32;now=int(time.time())
  self.proof={'schema':'ouf.semantic-owner-receipt-absence.v1','provenance':'LIVE_MCP_OWNER_RECEIPT_READ',
   'connectionRef':self.connection,'subject':self.hb['subject'],'tenant':self.hb['tenant'],
   'commandKey':self.private['history']['semanticCommandKey'],'httpStatus':404,'observedAt':now,
   'responseHash':'b'*64,'predecessorAttemptId':self.private['retainedClaim']['attemptId'],
   'predecessorRequestHash':self.private['retainedClaim']['requestHash']}
 def compile(self):return m.compile_review(self.private,self.binding,self.closure,self.hb,self.context,self.proof,int(time.time()),self.connection)
 def test_actual_existing_two_role_signatures_bind_the_same_payload(self):
  self.review=self.compile();self.c.write(self.context/'permit-review.json',m.encoded(self.review))
  files=m.issue(self.review,self.decision(),self.human,self.private)
  envelope=json.loads(files['permit.json']);raw=m.base64.b64decode(envelope['payload']);payload=json.loads(raw)
  self.assertEqual(payload['maximumCumulativeToolCalls'],2);self.assertEqual(payload['commandKey'],self.private['history']['semanticCommandKey'])
  verifier=m.DetachedAuthenticator(m.governance.POLICY,str(self.context),self.closure['executables']['openssl'])
  for field,role in(('intent','DEPLOYMENT_INTENT'),('approval','FINAL_DEPLOYMENT_APPROVAL')):
   self.assertTrue(verifier.verify_detached(raw,m.encoded(envelope[field]),role,self.c.context['intentIssuerRef'],self.c.context['installationRef'],self.c.context['entityRef']))
  self.assertFalse(self.review['installerDispatchAuthorized']);self.assertFalse(self.review['semanticApprovalAuthorized'])
  with self.assertRaises(Exception):m.issue(self.review,self.decision(),self.human,self.private)
 def test_403_stale_proof_wrong_account_and_changed_key_are_not_owner_absence(self):
  for key,value in(('httpStatus',403),('observedAt',int(time.time())-301),('connectionRef','link_other'),('commandKey','other')):
   proof=copy.deepcopy(self.proof);proof[key]=value
   with self.subTest(key=key),self.assertRaises(Exception):m.owner_absence_valid(proof,self.private,time.time(),self.connection)
 def test_expired_or_changed_receipt_is_rejected_before_private_signing(self):
  self.review=self.compile();self.c.write(self.context/'permit-review.json',m.encoded(self.review))
  self.review['ownerReceiptAbsence']['observedAt']=int(time.time())-301
  with patch.object(m.ExistingEd25519Signer,'sign')as signing:
   with self.assertRaises(Exception):m.issue(self.review,self.decision(),self.human,self.private)
  signing.assert_not_called();self.assertFalse((self.context/'permit-issuance.claim.json').exists())
if __name__=='__main__':unittest.main()
