"""Real local HTTP, durable claims and selected-job SQL; no external services."""
import copy,json,os,sys,tempfile,threading,time,unittest,urllib.request,uuid
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tests'),str(ROOT/'tools/semantic_policy_token_owner'),str(ROOT/'tools/semantic_application_cutover'),str(ROOT/'tools/semantic_cohort_admission/cohort-draft')]
from tools.csv_materialization_recovery import retry
from tools.teatri_materialization_apply.owner import digest

class API(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory(dir=os.environ.get('OUF_TEST_ROOT',str(ROOT)));self.addCleanup(self.tmp.cleanup);self.context=Path(self.tmp.name);self.context.chmod(0o700)
  self.jobs=[{'jobId':str(uuid.uuid4()),'issueId':str(uuid.uuid4()),'handoffId':str(uuid.uuid4()),'sourceId':'some-csv',
   'ingestionRunId':str(uuid.uuid4()),'jobVersion':11,'integrityAttempts':5,'safeFailureCode':'UDP_REFERENCE_INTEGRITY_MISSING','baselineHash':'sha256:'+'a'*64}for _ in range(2)]
  self.views={j['jobId']:{'jobId':j['jobId'],'handoffId':j['handoffId'],'sourceId':j['sourceId'],'ingestionRunId':j['ingestionRunId'],
   'state':'QUARANTINED','stateVersion':11,'intakeState':'DURABLE','integrityAttempts':5,'attempts':8,
   'safeFailureCode':j['safeFailureCode'],'retryEligible':True,'contractReady':True,'contractCheck':'READY',
   'verifiedBaselineHash':j['baselineHash'],'snapshotHash':'sha256:'+'b'*64}for j in self.jobs}
  self.posts=[];fixture=self
  class Handler(BaseHTTPRequestHandler):
   def log_message(self,*args):pass
   def do_GET(self):
    ident=self.path.rsplit('/',1)[1];data=json.dumps(fixture.views[ident]).encode();self.send_response(200);self.end_headers();self.wfile.write(data)
   def do_POST(self):
    ident=self.path.split('/')[-2];body=json.loads(self.rfile.read(int(self.headers['Content-Length'])));fixture.posts.append((ident,body))
    view=fixture.views[ident];reply={'operationId':body['operationId'],'jobId':ident,'handoffId':view['handoffId'],'acceptedVersion':12,'state':'READY','repeated':False}
    if getattr(fixture,'drop',False):self.connection.shutdown(2);self.connection.close();return
    data=json.dumps(reply).encode();self.send_response(200);self.end_headers();self.wfile.write(data)
  self.server=ThreadingHTTPServer(('127.0.0.1',0),Handler);threading.Thread(target=self.server.serve_forever,daemon=True).start()
  self.addCleanup(self.server.server_close);self.addCleanup(self.server.shutdown)
  transport=SimpleNamespace(selection={'origin':'http://127.0.0.1:'+str(self.server.server_port)},opener=urllib.request.build_opener(),token=lambda _: 'LOCAL_FIXTURE_TOKEN')
  self.client=retry.Client(transport)
 def decision(self,review):return {'reviewHash':digest(review),'decision':'APPROVE_EXACT_FINITE_SCOPED_ACTION','approvedAt':int(time.time()),'expiresAt':review['expiresAt']}
 def test_selected_jobs_native_reads_receipts_and_stable_operation_ids(self):
  review=retry.prepare(self.client,self.jobs,'c'*64,int(time.time())+60)
  same=retry.prepare(self.client,self.jobs,'c'*64,review['expiresAt']);self.assertEqual(review,same)
  result=retry.dispatch(self.client,review,self.decision(review),self.context,lambda:None,lambda _:None)
  self.assertEqual(len(result),2);self.assertEqual({j for j,_ in self.posts},{j['jobId']for j in self.jobs})
  self.assertEqual(len(list(self.context.glob('*-claim.json'))),2);self.assertEqual(len(list(self.context.glob('*-receipt.json'))),2)
  with self.assertRaises(FileExistsError):retry.dispatch(self.client,review,self.decision(review),self.context,lambda:None,lambda _:None)
  self.assertEqual(len(self.posts),2)
 def test_lost_ack_is_claimed_once_and_never_replayed(self):
  review=retry.prepare(self.client,self.jobs,'c'*64,int(time.time())+60);self.drop=True
  with self.assertRaises(Exception):retry.dispatch(self.client,review,self.decision(review),self.context,lambda:None,lambda _:None)
  self.assertEqual(len(self.posts),1)
  with self.assertRaises(FileExistsError):retry.dispatch(self.client,review,self.decision(review),self.context,lambda:None,lambda _:None)
  self.assertEqual(len(self.posts),1);self.assertEqual(len(list(self.context.glob('*-receipt.json'))),0)
 def test_references_missing_baseline_drift_and_ineligible_job_block_before_post(self):
  first=self.jobs[0]
  for change in({'retryEligible':False},{'contractReady':False},{'verifiedBaselineHash':'sha256:'+'f'*64},{'stateVersion':12}):
   bad=copy.deepcopy(self.views[first['jobId']]);bad.update(change)
   with self.assertRaises(Exception):retry.qualify(bad,first)
  review=retry.prepare(self.client,self.jobs,'c'*64,int(time.time())+60)
  self.views[first['jobId']]['snapshotHash']='sha256:'+'f'*64
  with self.assertRaisesRegex(Exception,'REVIEW_CHANGED'):retry.dispatch(self.client,review,self.decision(review),self.context,lambda:None,lambda _:None)
  self.assertFalse(self.posts)
 def test_sql_is_readonly_and_bound_to_selected_job_and_issue_ids(self):
  q=retry.proof_query(self.jobs,'test-tenant');self.assertTrue(q.startswith('BEGIN READ ONLY;'));self.assertTrue(q.endswith('ROLLBACK;'))
  self.assertNotIn('UPDATE ',q.upper());self.assertNotIn('INSERT ',q.upper());self.assertNotIn('DELETE ',q.upper())
  for j in self.jobs:self.assertIn(j['jobId'],q);self.assertIn(j['issueId'],q)
  with self.assertRaises(Exception):retry.proof_query(self.jobs,"tenant';DROP TABLE x")
