import importlib.util,json,os,subprocess,sys,time,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[2]
sys.path[:0]=[str(ROOT),str(ROOT/'tools/semantic_application_cutover'),str(ROOT/'tools/semantic_policy_token_owner'),str(ROOT/'tools/semantic_cohort_admission/cohort-draft')]
from tools.teatri_materialization_update import preflight as m
class Readonly(unittest.TestCase):
 def test_both_queries_readonly_closed_and_no_payload_values_released(self):
  for sql in(m.jobs_query('ouf-lab'),m.policy_query('ouf-lab','human')):
   self.assertTrue(sql.startswith('BEGIN READ ONLY;'));self.assertTrue(sql.endswith('ROLLBACK;'));self.assertNotRegex(sql,r'(?i)\b(insert|update|delete|truncate|alter|create|grant|revoke)\b')
  with self.assertRaises(Exception):m.jobs_query("x';drop table x;--")
 def test_feature_metadata_never_reads_a_token_and_reports_observed_configuration_only(self):
  actual={'State':{'Pid':123},'Config':{'Env':['OUF_UDP_MATERIALIZATION_RECOVERY_ENABLED=true']}}
  real_open=os.open
  with patch.object(m.os,'open',side_effect=lambda *a,**kw:real_open(str(ROOT),os.O_RDONLY|os.O_DIRECTORY)),patch.object(m,'mounted_file',side_effect=AssertionError('no file required')):
   data=m.feature_metadata(actual)
  self.assertTrue(data['enabledInObservedConfiguration']);self.assertFalse(data['effectiveConfigProven']);self.assertFalse(data['configurationValuesPrinted'])
@unittest.skipUnless(os.environ.get('OUF_NATIVE_SQL')=='1','actual PostgreSQL17 fixture')
class Native(unittest.TestCase):
 def cli(self,*args):
  r=subprocess.run(['docker',*args],capture_output=True,timeout=120);self.assertEqual(r.returncode,0,r.stderr.decode()[-1800:]);return r.stdout.decode().strip()
 def test_exact11_decisions_excludes_deferred_and_returns_recovery_authorization_metadata(self):
  self.cli('pull','postgres:17-alpine');cid=self.cli('run','-d','--rm','-e','POSTGRES_HOST_AUTH_METHOD=trust','postgres:17-alpine');self.addCleanup(lambda:self.cli('rm','-f',cid))
  end=time.monotonic()+30
  while subprocess.run(['docker','exec',cid,'pg_isready','-h','127.0.0.1','-U','postgres'],capture_output=True).returncode:self.assertLess(time.monotonic(),end);time.sleep(.2)
  def sql(q):return self.cli('exec',cid,'psql','-U','postgres','-X','-q','-A','-t','-v','ON_ERROR_STOP=1','-c',q)
  sql((ROOT/'tests/teatri_materialization/fixture.sql').read_text());raw=sql(m.jobs_query('ouf-lab'));d=json.loads(raw)
  self.assertEqual(d['confirmedJobCount'],11);self.assertEqual(d['distinctContractSets'],1);self.assertNotIn('PRIVATE_',raw)
  self.assertTrue(all(j['humanReceiptMatchesResolvedIssue']and j['latestHumanDecisionMatches']and j['rawLakeBindingMatches']and not j['canonicalEffectsPresent']and j['governedDecisionMatches']for j in d['jobs']))
  policy=json.loads(sql(m.policy_query('ouf-lab','b93d8cf6-cd14-4ee6-91d7-84cd76c4f500')));self.assertTrue(policy['transactionReadOnly']);self.assertTrue(policy['grants'][0]['subjectMatchesReviewedHuman']);self.assertEqual(policy['capabilities'][0]['capabilityId'],'udp.materialization.retry')
  self.assertEqual(json.loads(sql(m.jobs_query('other')))['confirmedJobCount'],0)
if __name__=='__main__':unittest.main()
