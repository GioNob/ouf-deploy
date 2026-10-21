"""Real PostgreSQL17 proof rejects missing revisions and excludes deferred jobs."""
import json,os,subprocess,sys,time,unittest,uuid
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tests'),str(ROOT/'tools/semantic_policy_token_owner'),str(ROOT/'tools/semantic_application_cutover'),str(ROOT/'tools/semantic_cohort_admission/cohort-draft')]
from tools.csv_materialization_recovery.retry import proof_query

@unittest.skipUnless(os.environ.get('OUF_NATIVE_SQL')=='1','requires disposable PostgreSQL17 container')
class SQL(unittest.TestCase):
 def test_native_schema_canonical_proof_requires_every_selected_job_revision_and_contribution(self):
  name='csv-proof-'+uuid.uuid4().hex[:12]
  def cli(*args):return subprocess.run(['docker',*args],input=None,check=True,capture_output=True,text=True).stdout.strip()
  cid=cli('run','-d','--rm','--name',name,'-e','POSTGRES_HOST_AUTH_METHOD=trust','postgres:17');self.addCleanup(lambda:cli('rm','-f',cid))
  deadline=time.monotonic()+40
  while subprocess.run(['docker','exec',cid,'pg_isready','-h','127.0.0.1','-U','postgres'],capture_output=True).returncode:
   self.assertLess(time.monotonic(),deadline);time.sleep(.2)
  def sql(q):return cli('exec',cid,'psql','-X','-q','-A','-t','-v','ON_ERROR_STOP=1','-U','postgres','-c',q)
  ids=[{'jobId':str(uuid.uuid4()),'issueId':str(uuid.uuid4())}for _ in range(3)]
  sql('''CREATE SCHEMA ouf_udp;
CREATE TABLE ouf_udp.materialization_job(job_id uuid,handoff_id text,state text,safe_failure_code text);
CREATE TABLE ouf_udp.handoff_intake(handoff_id text,state text,source_id text,type_code text,source_object_id text);
CREATE TABLE ouf_udp.resolution_issue(issue_id uuid,handoff_id text,state text,tenant_id text);
CREATE TABLE ouf_udp.source_binding(source_id text,type_code text,source_object_id text,urban_object_id uuid,state text);
CREATE TABLE ouf_udp.urban_object(urban_object_id uuid,tenant_id text,status text,current_revision_id uuid);
CREATE TABLE ouf_udp.materialization_observation(handoff_id text,urban_object_id uuid,revision_id uuid);
CREATE TABLE ouf_udp.object_revision(revision_id uuid,urban_object_id uuid);
CREATE TABLE ouf_udp.property_contribution(handoff_id text,urban_object_id uuid);''')
  objects=[str(uuid.uuid4())for _ in range(2)];revs=[str(uuid.uuid4())for _ in range(2)]
  for n,j in enumerate(ids):
   state='SUCCEEDED'if n<2 else'QUARANTINED';intake='PROCESSED'if n<2 else'DURABLE';issue='RESOLVED'if n<2 else'OPEN'
   sql(f"INSERT INTO ouf_udp.materialization_job VALUES('{j['jobId']}','row-{n}','{state}',NULL);INSERT INTO ouf_udp.handoff_intake VALUES('row-{n}','{intake}','arbitrary-csv','FILE','obj-{n}');INSERT INTO ouf_udp.resolution_issue VALUES('{j['issueId']}','row-{n}','{issue}','tenant');")
  for n in range(2):
   sql(f"INSERT INTO ouf_udp.source_binding VALUES('arbitrary-csv','FILE','obj-{n}','{objects[n]}','ACTIVE');INSERT INTO ouf_udp.urban_object VALUES('{objects[n]}','tenant','ACTIVE','{revs[n]}');INSERT INTO ouf_udp.materialization_observation VALUES('row-{n}','{objects[n]}','{revs[n]}');INSERT INTO ouf_udp.property_contribution VALUES('row-{n}','{objects[n]}');")
  sql(f"INSERT INTO ouf_udp.object_revision VALUES('{revs[0]}','{objects[0]}')")
  q=proof_query(ids[:2],'tenant');a=json.loads(sql(q));self.assertTrue(a['transactionReadOnly']);self.assertEqual(a['jobCount'],2);self.assertEqual(a['distinctObjects'],2);self.assertEqual(a['materializedRows'],1)
  sql(f"INSERT INTO ouf_udp.object_revision VALUES('{revs[1]}','{objects[1]}')")
  a=json.loads(sql(q));self.assertEqual(a['materializedRows'],2);self.assertEqual({r['job_id']for r in a['jobs']},{r['jobId']for r in ids[:2]})
  sql("DELETE FROM ouf_udp.property_contribution WHERE handoff_id='row-1'")
  self.assertEqual(json.loads(sql(q))['materializedRows'],1)
