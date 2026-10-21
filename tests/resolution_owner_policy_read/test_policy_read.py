import importlib.util,json,os,re,subprocess,time,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
s=importlib.util.spec_from_file_location('reader',ROOT/'scripts/read-resolution-owner-policy-metadata-20261017.py');m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
class Contract(unittest.TestCase):
 def test_query_is_single_readonly_transaction_and_identifiers_are_closed(self):
  sql=m.query('tenant-a','human-1');self.assertTrue(sql.startswith('BEGIN READ ONLY;'));self.assertTrue(sql.endswith('ROLLBACK;'));self.assertNotRegex(sql,r'(?i)\b(insert|update|delete|truncate|alter|create|grant|revoke)\b');self.assertIn("'resolution.issue.read'",sql);self.assertIn('resourceTypeMatchesDefaultCapability',sql)
  for value in("x';drop table x;--",'x\\y','x\n'):
   with self.assertRaises(Exception):m.query(value,'human')
 def test_current_rollout_binding_and_no_token_or_worker_activity(self):
  raw=(ROOT/'scripts/read-resolution-owner-policy-metadata-20261017.py').read_text();self.assertIn('resolution-config-execution-q91d2ut7',raw);self.assertIn("record['version']==37",raw);self.assertIn('==13 and all',raw);self.assertNotIn("'POST'",raw);self.assertNotIn('refresh_if_due',raw);self.assertNotIn('owner-session.json',raw)
@unittest.skipUnless(os.environ.get('OUF_NATIVE_SQL')=='1','explicit PostgreSQL17 read-only qualification')
class NativeSql(unittest.TestCase):
 def cli(self,*args,input=None):
  r=subprocess.run(['docker',*args],input=input,capture_output=True,timeout=120);self.assertEqual(r.returncode,0,r.stderr.decode()[-1500:]);return r.stdout.decode().strip()
 def test_real_postgres17_returns_bounded_resource_match_metadata_without_mutation(self):
  self.cli('pull','postgres:17-alpine');cid=self.cli('run','-d','--rm','-e','POSTGRES_HOST_AUTH_METHOD=trust','postgres:17-alpine');self.addCleanup(lambda:self.cli('rm','-f',cid))
  end=time.monotonic()+30
  while subprocess.run(['docker','exec',cid,'pg_isready','-h','127.0.0.1','-U','postgres'],capture_output=True).returncode:
   self.assertLess(time.monotonic(),end);time.sleep(.2)
  caps=[{'capabilityId':cap,'operation':'READ'if cap.endswith('read')else'COMMAND','requiredScope':cap,'allowedActors':['HUMAN']}for cap in('resolution.issue.read','resolution.match.approve')]
  grants=[{'capabilityId':cap,'tenantId':'tenant-a','subjectId':'human-1','validFrom':'2020-01-01T00:00:00Z','validUntil':'2099-01-01T00:00:00Z','constraints':{'effect':'ALLOW','resourceType':'resolution-issues','resourceAttributes':{}}}for cap in('resolution.issue.read','resolution.match.approve')]
  payload=json.dumps({'capabilities':caps,'grants':grants})
  setup="create schema ouf_authorization;create table ouf_authorization.policy_bundle(bundle_id text,version bigint,bundle_payload jsonb);create table ouf_authorization.active_policy_bundle(singleton_key boolean,bundle_id text,version bigint);insert into ouf_authorization.policy_bundle values('fixture',40,'"+payload+"');insert into ouf_authorization.active_policy_bundle values(true,'fixture',40);"
  self.cli('exec','-i',cid,'psql','-U','postgres','-v','ON_ERROR_STOP=1','-c',setup)
  raw=self.cli('exec','-i',cid,'psql','-U','postgres','-X','-q','-A','-t','-v','ON_ERROR_STOP=1','-c',m.query('tenant-a','human-1'));facts=json.loads(raw)
  self.assertTrue(facts['transactionReadOnly']);self.assertEqual(facts['bundleVersion'],40);self.assertEqual(len(facts['capabilities']),2);self.assertEqual(len(facts['grants']),2)
  self.assertTrue(all(g['resourceTypeMatchesResolutionIssues']and not g['resourceTypeMatchesDefaultCapability']and g['resourceAttributesMatchEmpty']and g['subjectMatchesReviewedHuman']for g in facts['grants']))
  count=self.cli('exec',cid,'psql','-U','postgres','-X','-q','-A','-t','-c','select count(*) from ouf_authorization.policy_bundle');self.assertEqual(count,'1')
if __name__=='__main__':unittest.main()
