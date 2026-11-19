"""Permission boundary, exact owner protocol and persistent ambiguous claims."""
import copy,json,os,sys,tempfile,time,unittest,uuid
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tests'),str(ROOT/'tools/semantic_policy_token_owner'),str(ROOT/'tools/semantic_application_cutover'),str(ROOT/'tools/semantic_cohort_admission/cohort-draft')]
from tools.teatri_materialization_apply import permissions as p
from tools.teatri_materialization_apply.owner import digest
CASE=json.loads((ROOT/'releases/teatri-materialization-apply-selection-20261017.json').read_text())

class Transport:
 def __init__(self,review,fail=None):self.r=review;self.fail=fail;self.calls=[];self.published=False
 def active(self):
  if not self.published:return copy.deepcopy(self.r['baseline'])
  return {'policyRef':self.r['candidatePolicy']['bundleId']+':41','contentHash':'server-native-content-hash','policy':copy.deepcopy(self.r['candidatePolicy'])}
 def request(self,path,method='GET',body=None,etag=None):
  self.calls.append((path,method,copy.deepcopy(body),etag))
  if self.fail=='draft'and path.endswith('/policies'):raise TimeoutError('simulated ambiguous create')
  draft={'id':'65cf849e-c06c-41ad-afd7-8cc0ace08d24','revision':0,'state':'DRAFT','policy':copy.deepcopy(self.r['candidatePolicy']),'baseActiveRef':self.r['baseline']['policyRef']}
  if path.endswith(':preview'):
   return 200,{'draftId':draft['id'],'revision':0,'baseActiveRef':draft['baseActiveRef'],'addedCapabilities':[],'removedCapabilities':[],
    'grantChanges':[{'grantId':g['grantId'],'before':None,'after':copy.deepcopy(g)}for g in self.r['addedGrants']]},{}
  if path.endswith(':publish'):
   self.published=True
   if self.fail=='publish':raise TimeoutError('simulated response lost after publication')
   return 200,{**draft,'state':'PUBLISHED','revision':1},{}
  return 200,draft,{}

class Permissions(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory(dir=os.environ.get('OUF_TEST_ROOT',str(ROOT)));self.addCleanup(self.tmp.cleanup);self.context=Path(self.tmp.name);self.context.chmod(0o700)
  self.selection={'issuer':'https://fixture.test/realms/ouf','tenant':'ouf-lab','subject':'b93d8cf6-cd14-4ee6-91d7-84cd76c4f500'}
  self.hb={**self.selection,'expiresAt':int(time.time())+7200};self.now=time.time()
  # Native DTO fields, including all constraints. Existing entries must survive
  # byte-semantically even if expired, unrelated or DENY.
  existing=[{'grantId':'expired-cinema','capabilityId':p.CAP,'tenantId':'ouf-lab','constraints':{'effect':'ALLOW','resourceId':'cinema'}},
   {'grantId':'unrelated-deny','capabilityId':'other.read','tenantId':'other','constraints':{'effect':'DENY'}}]
  active={'policyRef':'bundle:40','contentHash':'baseline-hash','policy':{'bundleId':'bundle','version':40,'publishedAt':'2026-10-17T10:00:00Z',
   'capabilities':[{'capabilityId':p.CAP,'operation':'COMMAND','requiredScope':p.CAP,'allowedActors':['HUMAN']}], 'grants':existing}}
  self.review=p.compile_review(active,CASE['confirmedJobs'],self.selection,self.hb,self.now,self.context,'c'*64)
  self.decision={'schema':'ouf.semantic-scoped-terminal-decision.v1','reviewHash':digest(self.review),'decision':'APPROVE_EXACT_FINITE_SCOPED_ACTION',
   'humanSessionHash':digest(self.hb),'sourceClosureHash':'c'*64,'approvedAt':int(time.time()),'expiresAt':int(time.time())+900}
  self.human=SimpleNamespace(current=lambda:copy.deepcopy(self.hb))
 def test_exact11_job_scopes_expiry_and_other_grants_preserved(self):
  self.assertEqual(self.review['candidatePolicy']['grants'][:2],self.review['baseline']['policy']['grants'])
  self.assertEqual(self.review['candidatePolicy']['capabilities'],self.review['baseline']['policy']['capabilities'])
  grants=self.review['addedGrants'];self.assertEqual(len(grants),11)
  self.assertEqual({g['constraints']['resourceId']for g in grants},{j['jobId']for j in CASE['confirmedJobs']})
  for g in grants:
   self.assertEqual(set(g),set(p.FIELDS));self.assertEqual(g['subjectId'],self.selection['subject'])
   self.assertEqual(g['constraints']['allowedDataLabels'],['RESTRICTED']);self.assertEqual(g['constraints']['resourceAttributes'],{'module':'UDP','sourceRef':'teatri-csv-6609b245','jobRef':'a3208f2f-ebfd-415d-bddc-79ab05dea78f','typeRef':'FILE'})
 def test_bad_source_existing_effect_unresolved_changed_job_version_never_qualify(self):
  for update in({'sourceId':'cinema'},{'canonicalEffectsPresent':True},{'issueState':'OPEN'},{'jobVersion':12},{'rawAccessLabel':'PUBLIC'}):
   rows=copy.deepcopy(CASE['confirmedJobs']);rows[0].update(update)
   with self.assertRaises(Exception):p.verify_jobs(rows,CASE['confirmedJobs'])
  with self.assertRaises(Exception):p.verify_jobs(CASE['confirmedJobs'][:-1],CASE['confirmedJobs'])
  duplicate=copy.deepcopy(CASE['confirmedJobs']);duplicate[-1]=copy.deepcopy(duplicate[0])
  with self.assertRaises(Exception):p.verify_jobs(duplicate,duplicate)
 def test_native_draft_preview_publish_and_readback_without_job_or_service_calls(self):
  t=Transport(self.review);result=p.publish(t,self.human,self.review,self.decision,self.context,lambda:None)
  self.assertTrue(result['complete']);self.assertEqual(result['addedGrants'],11);self.assertEqual(len(t.calls),3)
  self.assertTrue((self.context/'permission-publication.json').exists())
  self.assertEqual(sum(not path.endswith(':preview')for path,_,_,_ in t.calls),2)
 def test_uncertain_create_and_publish_claims_cannot_be_replayed(self):
  for failure in('draft','publish'):
   child=self.context/failure;child.mkdir(mode=0o700);t=Transport(self.review,failure)
   with self.assertRaises(TimeoutError):p.publish(t,self.human,self.review,self.decision,child,lambda:None)
   calls=len(t.calls);t.published=False
   with self.assertRaises(FileExistsError):p.publish(t,self.human,self.review,self.decision,child,lambda:None)
   self.assertEqual(len(t.calls),calls);self.assertTrue((child/'permission-draft-claim.json').exists())
 def test_preview_removal_replacement_and_extra_grants_denied(self):
  draft={'id':'65cf849e-c06c-41ad-afd7-8cc0ace08d24','revision':0}
  t=Transport(self.review);_,preview,_=t.request('x:preview','POST')
  for key,value in(('removedCapabilities',[{}]),('addedCapabilities',[{}]),('grantChanges',[])):
   with self.assertRaises(Exception):p.verify_preview({**preview,key:value},self.review,draft)
  preview['grantChanges'][0]['before']={'grantId':'existing'}
  with self.assertRaises(Exception):p.verify_preview(preview,self.review,draft)
 def test_revoked_identity_or_changed_baseline_blocks_before_mutation(self):
  t=Transport(self.review)
  with self.assertRaises(Exception):p.publish(t,SimpleNamespace(current=lambda:{}),self.review,self.decision,self.context,lambda:None)
  self.assertFalse(t.calls)
  t.active=lambda:{'policyRef':'bundle:41'}
  with self.assertRaises(Exception):p.publish(t,self.human,self.review,self.decision,self.context,lambda:None)
  self.assertFalse(t.calls);self.assertFalse((self.context/'permission-draft-claim.json').exists())
