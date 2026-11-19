import importlib.util,json,os,subprocess,time,unittest,contextlib,io
from pathlib import Path
from unittest.mock import patch,Mock
ROOT=Path(__file__).resolve().parents[2]
s=importlib.util.spec_from_file_location('preflight',ROOT/'scripts/read-teatri-reference-recovery-preflight-20261017.py');m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
class Contract(unittest.TestCase):
 def fixture(self):
  f={'schema':'ouf.semantic-functional-session-fence.v1','logicalOwnerScopeHash':'logic','reviewHash':'','journalPath':''}
  wr={'retained':'fixture'};f['reviewHash']=m.digest(wr);j=m.POLICY_CONTEXT.parent/('semantic-functional-worker-'+f['reviewHash']);f['journalPath']=str(j)
  p=j.parent/'semantic-functional-session-logic.fence.json';signed={'fenceBinding':{'path':str(p),'value':f},'reviewHash':f['reviewHash'],'predecessorGrantAttempts':248,'maximumCumulativeGrantAttempts':316,'policy':{'max_attempts':68}}
  worker={'state':'CANCELLED','reason':'CANCELLED_BY_OWNER','attempts':60,'publicationCount':60,'controlledPredecessorGrantAttempts':248,'controlledCumulativeGrantAttempts':308}
  hb={'sessionDirectory':'/etc/ouf/deploy-snapshots/semantic-token-execution-usx0tsem/human-successor-fixture','tokenPath':'/etc/ouf/deploy-snapshots/semantic-token-execution-usx0tsem/human-successor-fixture/human-access.jwt','issuer':'fixture','tenant':'ouf-lab','subject':'PRIVATE_SUBJECT','expiresAt':1}
  h={'binding':hb,'budgetReset':False,'attempts':99,'state':'READY','operation':'USERINFO','accessToken':'PRIVATE_TOKEN','refreshToken':'PRIVATE_REFRESH'}
  files={str(m.POLICY_CONTEXT/'review.json'):{'scopes':{'policyTokenFiniteWorkerSession':{'fenceBinding':{'path':str(p)},'logicalOwnerScopeHash':'logic'}}},str(p):f,str(j/'owner-session.json'):signed,str(j/'owner-session-review.json'):wr,str(j/'recovery.json'):worker,str(j/'owner-status.json'):{},str(j/'owner-admission.json'):{},str(Path(hb['sessionDirectory'])/'recovery.json'):h}
  read=Mock(side_effect=lambda path,*args:files[str(path)])
  return files,read,{'authenticatedHuman':hb},{k:hb[k]for k in('issuer','tenant','subject')},worker
 def test_current_fence_counts_and_human_projection_are_redacted_and_stable(self):
  files,read,review,selection,row=self.fixture()
  with patch.object(m,'unlocked',return_value=True),patch.object(m.os.path,'lexists',return_value=False),contextlib.redirect_stdout(io.StringIO())as out:m.recovery_metadata({'read':read},review,selection)
  rows=[json.loads(l)for l in out.getvalue().splitlines()];self.assertEqual(rows[0]['controlledCumulativeGrantAttempts'],308);self.assertEqual(rows[0]['remainingControlledGrantAttempts'],8);self.assertEqual(rows[1]['remainingOAuthAttempts'],29);self.assertNotIn('PRIVATE_',out.getvalue());self.assertEqual(read.call_args_list[0].args[2],m.POLICY_REVIEW)
  row['controlledCumulativeGrantAttempts']=1
  with self.assertRaisesRegex(ValueError,'EXACT_CURRENT_CUMULATIVE_BUDGET_REQUIRED'):m.recovery_metadata({'read':read},review,selection)
 def test_policy_query_readonly_and_rejects_identity_sql_injection(self):
  q=m.semantic_policy_query('ouf-lab',{'sub':'PRIVATE_SUBJECT','client_id':'ouf-udp'})
  self.assertTrue(q.startswith('BEGIN READ ONLY;'));self.assertTrue(q.endswith('ROLLBACK;'));self.assertNotRegex(q,r'(?i)\b(insert|update|delete|truncate|alter|create|grant|revoke)\b')
  with self.assertRaises(ValueError):m.semantic_policy_query('ouf-lab',{'sub':"';drop table x;--",'client_id':'ouf-udp'})
 def test_dependency_probe_never_calls_network(self):
  import base64
  token=b'e30.'+base64.urlsafe_b64encode(json.dumps({'exp':1,'sub':'PRIVATE_SUBJECT'}).encode()).rstrip(b'=')+b'.c2ln'
  actual={'State':{'Pid':123}};real_open=os.open
  with patch.object(m.Path,'read_text',return_value='123 (fixture) '+' '.join(['0']*20)),patch.object(m.os,'readlink',return_value='mnt:[fixture]'),patch.object(m.os,'open',side_effect=lambda *a,**kw:real_open(str(ROOT),os.O_RDONLY|os.O_DIRECTORY)),patch.object(m,'configured_properties',return_value=('https://approved.example','/run/secrets/token',None)),patch.object(m,'mounted_file',return_value=token),patch.object(m,'emit_route_access_metadata'),patch.object(m,'safe_get',side_effect=AssertionError('network forbidden')),contextlib.redirect_stdout(io.StringIO())as out:
   self.assertEqual(m.probe_dependencies(actual,{},'https://approved.example',{})['sub'],'PRIVATE_SUBJECT')
  self.assertNotIn('PRIVATE_',out.getvalue())
@unittest.skipUnless(os.environ.get('OUF_NATIVE_SQL')=='1','explicit PostgreSQL17 qualification')
class Native(unittest.TestCase):
 def cli(self,*args):
  r=subprocess.run(['docker',*args],capture_output=True,timeout=120);self.assertEqual(r.returncode,0,r.stderr.decode()[-1500:]);return r.stdout.decode().strip()
 def test_policy_grant_comparison_on_postgres17(self):
  self.cli('pull','postgres:17-alpine');cid=self.cli('run','-d','--rm','-e','POSTGRES_HOST_AUTH_METHOD=trust','postgres:17-alpine');self.addCleanup(lambda:self.cli('rm','-f',cid))
  end=time.monotonic()+30
  while subprocess.run(['docker','exec',cid,'pg_isready','-h','127.0.0.1','-U','postgres'],capture_output=True).returncode:self.assertLess(time.monotonic(),end);time.sleep(.2)
  def sql(q):return self.cli('exec',cid,'psql','-U','postgres','-X','-q','-A','-t','-v','ON_ERROR_STOP=1','-c',q)
  caps=[{'capabilityId':'ouf.semantic.read','allowedActors':['SERVICE'],'requiredScope':'ouf.semantic.read','operation':'READ'}]
  grants=[{'capabilityId':'ouf.semantic.read','tenantId':tenant,'servicePrincipalId':service,'subjectId':'PRIVATE_SUBJECT','validFrom':'2020-01-01T00:00:00Z','validUntil':'2099-01-01T00:00:00Z','constraints':{'effect':'ALLOW','resourceType':resource,'resourceAttributes':{'module':'SEMANTIC'}}}for tenant,service,resource in [('ouf-lab','ouf-udp','semantic.validation'),('ouf-lab','other','semantic.artifact'),('other','ouf-udp','semantic.validation')]]
  payload=json.dumps({'capabilities':caps,'grants':grants})
  sql("create schema ouf_authorization;create table ouf_authorization.policy_bundle(bundle_id text,version bigint,bundle_payload jsonb);create table ouf_authorization.active_policy_bundle(singleton_key boolean,bundle_id text,version bigint);insert into ouf_authorization.policy_bundle values('fixture',40,'"+payload+"');insert into ouf_authorization.active_policy_bundle values(true,'fixture',40);")
  raw=sql(m.semantic_policy_query('ouf-lab',{'sub':'PRIVATE_SUBJECT','client_id':'ouf-udp'}));d=json.loads(raw);self.assertTrue(d['transactionReadOnly']);self.assertEqual(d['bundleVersion'],40);self.assertEqual(len(d['grants']),2);self.assertNotIn('PRIVATE_',raw)
  yes=[g for g in d['grants']if g['servicePrincipalMatchesToken']];self.assertEqual(len(yes),1);self.assertTrue(yes[0]['resourceTypeMatchesValidation']);self.assertTrue(yes[0]['moduleConstraintMatches']);self.assertTrue(yes[0]['subjectMatchesToken'])
  sql((ROOT/'tests/reference_dependency_read/fixture.sql').read_text());self.assertEqual(json.loads(sql(m.acquisition_query('udp','ouf-lab')))['confirmedJobCount'],11)
if __name__=='__main__':unittest.main()
