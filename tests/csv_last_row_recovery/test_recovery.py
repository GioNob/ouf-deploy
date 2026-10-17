"""Closed source graph + native SQL + protocol tests; no target authority or credentials."""
import copy,hashlib,importlib.util,json,os,subprocess,sys,time,unittest,urllib.request
from pathlib import Path
from unittest.mock import Mock,patch
ROOT=Path(__file__).resolve().parents[2]
def module(name,path):
 spec=importlib.util.spec_from_file_location(name,ROOT/path);value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value
runtime=module('last_runtime','tools/csv_last_row_recovery/runtime.py')
bootstrap=module('last_bootstrap','scripts/execute-csv-last-row-recovery-20261018.py')
paths=json.loads((ROOT/'tools/chatbot_file_cohort/source_paths.json').read_bytes())
sources={name:b'pass\n'if path.startswith('ouf-onboarding:')else(ROOT/path).read_bytes()for name,path in paths.items()}
for name,(filename,path)in bootstrap.OVERLAYS.items():sources[name]=(ROOT/path).read_bytes()
loader=(ROOT/'tools/csv_last_row_recovery/runtime.py').read_bytes()
pins={'ouf-deploy':'a'*40,'ouf-onboarding':'b'*40};extra={'executorSha256':'c'*64,'caseSha256':'d'*64,'mode':'CSV_MATERIALIZATION_RECOVERY'}
declaration=runtime.declaration('a'*40,sources,loader,pins,extra)
def denied(*args,**kwargs):raise AssertionError('NO_EFFECTS_DURING_CLOSED_IMPORT')
with patch.object(os,'open',denied),patch.object(os,'mkdir',denied),patch.object(subprocess,'run',denied),patch.object(subprocess,'Popen',denied),patch.object(urllib.request.OpenerDirector,'open',denied):
 entry,_=runtime.load_entry('a'*40,sources,loader,runtime.digest(declaration),pins,extra)
p=sys.modules['tools.teatri_materialization_apply.permissions'];retry=sys.modules['tools.csv_materialization_recovery.retry']
authority=sys.modules['tools.csv_materialization_recovery.authority']
readback=__import__('importlib').import_module('tools.csv_materialization_recovery.readback')
class Protocol(unittest.TestCase):
 def setUp(self):
  self.now=time.time();self.hb={'tenant':'tenant','subject':'operator','issuer':'issuer','scopes':[p.CAP],'expiresAt':int(self.now)+7200}
  self.selection={k:self.hb[k]for k in('tenant','subject','issuer')}
  self.row={'job_id':'11111111-1111-1111-1111-111111111111','handoff_id':'22222222-2222-2222-2222-222222222222',
   'source_id':'roads-file','ingestion_run_id':'33333333-3333-3333-3333-333333333333','type_code':'ANY_FORMAT',
   'intake_state':'DURABLE','state':'QUARANTINED','state_version':11,'attempts':5,'integrity_attempts':5,
   'safe_failure_code':'UDP_REFERENCE_INTEGRITY_MISSING','missing_ref_hashes':['sha256:fixture'],
   'integrity_baseline_hash':'sha256:'+'a'*64,'lease_present':False,'lake_state':'VERIFIED','raw_access_label':'RESTRICTED',
   'issue_state':'RESOLVED','latest_action':'CREATE_NEW','binding_count':0,'observation_count':0,'contribution_count':0}
  self.one=p.job(self.row,'44444444-4444-4444-4444-444444444444')
  policy={'bundleId':'policy','version':41,'publishedAt':'2026-01-01T00:00:00Z',
   'capabilities':[{'capabilityId':p.CAP,'operation':'COMMAND','requiredScope':p.CAP,'allowedActors':['HUMAN']}],
   'grants':[{'grantId':'preserve-me','constraints':{'effect':'DENY','private':'preserve-value'}}],'roles':['preserve-role']}
  self.active={'policyRef':'policy:41','contentHash':'before','policy':policy}
  self.permission=p.compile_review(self.active,self.one,self.selection,self.hb,self.now,'/private/context','c'*64)
  self.approved={'sourceClosureHash':'c'*64,'authenticatedHuman':self.hb,'absoluteExpiresAt':self.now+300,
   'permissionReview':self.permission,'nativeRetryIntent':p.retry_intent(self.one,'binding')}
  self.decision={'decision':'APPROVE_EXACT_FINITE_SCOPED_ACTION','reviewHash':p.digest(self.approved),
   'sourceClosureHash':'c'*64,'humanSessionHash':p.digest(self.hb),'approvedAt':self.now-1,'expiresAt':self.now+250}
  self.native={'jobId':self.one['jobId'],'handoffId':self.one['handoffId'],'sourceId':self.one['sourceId'],
   'ingestionRunId':self.one['ingestionRunId'],'stateVersion':11,'integrityAttempts':5,'safeFailureCode':self.one['safeFailureCode'],
   'verifiedBaselineHash':self.one['baselineHash'],'snapshotHash':'sha256:'+'b'*64,'retryEligible':True,'contractReady':True,'contractCheck':'READY',
   'state':'QUARANTINED','intakeState':'DURABLE'}
  self.review={'jobs':[{'job':self.one,'review':self.native,'request':{'operationId':self.approved['nativeRetryIntent']['operationId'],
   'expectedVersion':11,'expectedSnapshotHash':self.native['snapshotHash'],'reason':'Reviewed technical recovery'}}],
   'authenticatedHuman':self.hb,'sourceClosureHash':'c'*64,'expiresAt':self.now+200}
 def test_closed_native_graph_and_readback_import_have_no_effects(self):
  self.assertTrue(callable(entry.main));self.assertEqual(set(sources),runtime.MODULES)
  self.assertEqual(declaration['entryModule'],'tools.csv_materialization_recovery.run')
  self.assertFalse(declaration['runtimeAuthorityIssued']);self.assertTrue(callable(readback.row_ledger))
 def test_candidate_adds_only_one_exact_grant_and_preserves_every_existing_entry(self):
  before=copy.deepcopy(self.active);candidate=self.permission['candidatePolicy']
  self.assertEqual(candidate['version'],42);self.assertEqual(candidate['grants'][:-1],before['policy']['grants'])
  for key in('capabilities','roles'):self.assertEqual(candidate[key],before['policy'][key])
  grant=candidate['grants'][-1];self.assertEqual(grant['subjectId'],'operator');self.assertIsNone(grant['servicePrincipalId'])
  self.assertEqual(grant['constraints']['resourceId'],self.one['jobId'])
  self.assertEqual(grant['constraints']['resourceAttributes'],{'module':'UDP','sourceRef':'roads-file','jobRef':self.one['ingestionRunId'],'typeRef':'ANY_FORMAT'})
  self.assertEqual(grant['constraints']['allowedDataLabels'],['RESTRICTED']);self.assertEqual(self.active,before)
 def test_policy_drift_missing_descriptor_and_wrong_operator_stop_preparation(self):
  for mutate in (lambda x:x['policy'].update(version=42),lambda x:x['policy'].update(capabilities=[])):
   active=copy.deepcopy(self.active);mutate(active)
   with self.assertRaises(Exception):p.compile_review(active,self.one,self.selection,self.hb,self.now,'context','c'*64)
  hb={**self.hb,'subject':'different'}
  with self.assertRaises(Exception):p.compile_review(self.active,self.one,self.selection,hb,self.now,'context','c'*64)
 def test_job_snapshot_detects_prior_effects_changed_version_or_other_job(self):
  p.verify_job([self.row],self.row)
  for key,value in(('state_version',12),('binding_count',1),('source_id','other'),('job_id','other')):
   changed={**self.row,key:value}
   with self.assertRaises(Exception):p.verify_job([changed],self.row)
  with self.assertRaises(Exception):p.verify_job([self.row,self.row],self.row)
 def test_one_composed_approval_admits_only_matching_fresh_owner_snapshot(self):
  p.authorize_fresh_retry(self.review,self.approved,self.decision,self.now)
  for key,value in(('stateVersion',12),('verifiedBaselineHash','sha256:'+'c'*64),('jobId','different'),('contractReady',False)):
   review=copy.deepcopy(self.review);review['jobs'][0]['review'][key]=value
   with self.assertRaises(Exception):p.authorize_fresh_retry(review,self.approved,self.decision,self.now)
 def test_unapproved_second_job_expired_review_or_changed_operation_is_denied(self):
  for mode in('second','expiry','operation','snapshot','operator'):
   review=copy.deepcopy(self.review)
   if mode=='second':review['jobs'].append(copy.deepcopy(review['jobs'][0]))
   if mode=='expiry':review['expiresAt']=self.now-1
   if mode=='operation':review['jobs'][0]['request']['operationId']='another'
   if mode=='snapshot':review['jobs'][0]['request']['expectedSnapshotHash']='sha256:'+'c'*64
   if mode=='operator':review['authenticatedHuman']['subject']='other'
   with self.assertRaises(Exception):p.authorize_fresh_retry(review,self.approved,self.decision,self.now)
 def test_old_or_modified_composed_decision_is_rejected(self):
  for decision in ({**self.decision,'expiresAt':self.now-1},{**self.decision,'reviewHash':'different'},{**self.decision,'humanSessionHash':'different'}):
   with self.assertRaises(Exception):p.authorize_fresh_retry(self.review,self.approved,decision,self.now)
 def test_operation_id_is_stable_for_same_prepared_plan_and_job(self):
  self.assertEqual(p.retry_intent(self.one,'binding'),p.retry_intent(self.one,'binding'))
  self.assertNotEqual(p.retry_intent(self.one,'other')['operationId'],p.retry_intent(self.one,'binding')['operationId'])
 def transport(self,preview_changed=False,uncertain=False):
  candidate=self.permission['candidatePolicy'];identifier='55555555-5555-5555-5555-555555555555'
  draft={'id':identifier,'state':'DRAFT','policy':candidate,'baseActiveRef':'policy:41','revision':1}
  preview={'draftId':identifier,'revision':1,'baseActiveRef':'policy:41','addedCapabilities':[],'removedCapabilities':[],
   'grantChanges':[{'grantId':self.permission['addedGrants'][0]['grantId'],'before':None,'after':self.permission['addedGrants'][0]}]}
  if preview_changed:preview['removedCapabilities']=['unexpected']
  published={'policyRef':'policy:42','contentHash':'after','policy':candidate}
  transport=Mock();transport.active.side_effect=[self.active,self.active,published]
  replies=[(201,draft,{}),(200,preview,{}),(200,{'id':identifier,'state':'PUBLISHED'},{})]
  transport.request.side_effect=RuntimeError('UNCERTAIN')if uncertain else replies
  return transport
 def test_native_policy_preview_and_readback_allow_only_single_addition(self):
  transport=self.transport();human=Mock();human.current.return_value=self.hb;documents=[]
  with patch.object(p,'publish_json',side_effect=lambda c,n,v:documents.append(n)):
   result=p.publish(transport,human,self.permission,self.approved,self.decision,'context',lambda:None)
  self.assertEqual(result['addedGrants'],1);self.assertEqual(transport.request.call_count,3)
  self.assertEqual(documents,['permission-draft-claim.json','permission-draft-receipt.json','permission-publish-claim.json','permission-publication.json'])
 def test_unexpected_policy_preview_stops_before_publish(self):
  transport=self.transport(preview_changed=True);human=Mock();human.current.return_value=self.hb
  with patch.object(p,'publish_json'):
   with self.assertRaises(Exception):p.publish(transport,human,self.permission,self.approved,self.decision,'context',lambda:None)
  self.assertEqual(transport.request.call_count,2)
 def test_ambiguous_policy_mutation_is_claimed_once_and_not_replayed(self):
  transport=self.transport(uncertain=True);human=Mock();human.current.return_value=self.hb;names=[]
  with patch.object(p,'publish_json',side_effect=lambda c,n,v:names.append(n)):
   with self.assertRaisesRegex(RuntimeError,'UNCERTAIN'):p.publish(transport,human,self.permission,self.approved,self.decision,'context',lambda:None)
  self.assertEqual(transport.request.call_count,1);self.assertEqual(names,['permission-draft-claim.json'])
 def test_native_retry_dispatch_claims_once_and_requires_second_fresh_read(self):
  client=Mock();request=self.review['jobs'][0]['request']
  client.request.side_effect=[self.native,{'jobId':self.one['jobId'],'handoffId':self.one['handoffId'],
   'operationId':request['operationId'],'acceptedVersion':12,'state':'READY','repeated':False}]
  docs=[]
  with patch.object(retry,'document',side_effect=lambda c,n,v:docs.append(n)):
   receipts=retry.dispatch(client,self.review,self.decision,'context',lambda:None,lambda s:None,approved_review=self.approved)
  self.assertEqual(len(receipts),1);self.assertEqual(client.request.call_count,2)
  self.assertTrue(docs[0].endswith('-claim.json'));self.assertTrue(docs[1].endswith('-receipt.json'))
 def test_uncertain_native_retry_is_not_automatically_replayed(self):
  client=Mock();client.request.side_effect=[self.native,RuntimeError('UNCERTAIN')]
  with patch.object(retry,'document'):
   with self.assertRaisesRegex(RuntimeError,'UNCERTAIN'):retry.dispatch(client,self.review,self.decision,'context',lambda:None,lambda s:None,approved_review=self.approved)
  self.assertEqual(client.request.call_count,2)
 def test_readonly_sql_uses_exact_ids_and_rejects_injection(self):
  raw=p.job_query(self.one,'tenant');self.assertTrue(raw.startswith('BEGIN READ ONLY;'));self.assertTrue(raw.endswith('ROLLBACK;'))
  with self.assertRaises(Exception):p.job_query(self.one,"';drop table x;--")
 @unittest.skipUnless(os.environ.get('OUF_NATIVE_SQL')=='1','actual PostgreSQL17 qualification')
 def test_exact_job_query_on_actual_postgresql17(self):
  def cli(*args):
   result=subprocess.run(['docker',*args],capture_output=True,timeout=120);self.assertEqual(result.returncode,0,result.stderr.decode()[-1500:]);return result.stdout.decode().strip()
  cli('pull','postgres:17-alpine');cid=cli('run','-d','--rm','-e','POSTGRES_HOST_AUTH_METHOD=trust','postgres:17-alpine');self.addCleanup(lambda:cli('rm','-f',cid))
  end=time.monotonic()+30
  while subprocess.run(['docker','exec',cid,'pg_isready','-h','127.0.0.1','-U','postgres'],capture_output=True).returncode:
   self.assertLess(time.monotonic(),end);time.sleep(.2)
  def sql(raw):return cli('exec',cid,'psql','-U','postgres','-X','-q','-A','-t','-v','ON_ERROR_STOP=1','-c',raw)
  sql("""
  create schema ouf_udp;
  create table ouf_udp.materialization_job(job_id uuid,handoff_id text,state text,state_version bigint,attempts int,integrity_attempts int,safe_failure_code text,missing_ref_hashes jsonb,integrity_baseline_hash text,claimed_by text,lease_until timestamptz);
  create table ouf_udp.handoff_intake(handoff_id text,ingestion_run_id text,source_id text,type_code text,state text,source_object_id text,raw_lake_object_id uuid);
  create table ouf_udp.resolution_issue(issue_id uuid,handoff_id text,tenant_id text,state text);
  create table ouf_udp.lake_object(lake_object_id uuid,tenant_id text,state text,access_label text);
  create table ouf_udp.human_resolution_decision(issue_id uuid,action text,decided_at timestamptz);
  create table ouf_udp.source_binding(first_handoff_id text,source_id text,type_code text,source_object_id text);
  create table ouf_udp.materialization_observation(handoff_id text);
  create table ouf_udp.property_contribution(handoff_id text);
  insert into ouf_udp.materialization_job values('11111111-1111-1111-1111-111111111111','22222222-2222-2222-2222-222222222222','QUARANTINED',11,5,5,'UDP_REFERENCE_INTEGRITY_MISSING','["sha256:fixture"]','sha256:"""+'a'*64+"""',null,null);
  insert into ouf_udp.handoff_intake values('22222222-2222-2222-2222-222222222222','33333333-3333-3333-3333-333333333333','roads-file','ANY_FORMAT','DURABLE','PRIVATE_RECORD','66666666-6666-6666-6666-666666666666');
  insert into ouf_udp.resolution_issue values('44444444-4444-4444-4444-444444444444','22222222-2222-2222-2222-222222222222','tenant','RESOLVED');
  insert into ouf_udp.lake_object values('66666666-6666-6666-6666-666666666666','tenant','VERIFIED','RESTRICTED');
  insert into ouf_udp.human_resolution_decision values('44444444-4444-4444-4444-444444444444','CREATE_NEW',now());
  """)
  raw=sql(p.job_query(self.one,'tenant'));self.assertNotIn('PRIVATE_',raw);facts=json.loads(raw)
  self.assertTrue(facts['transactionReadOnly']);p.verify_job(facts['jobs'],self.row)
  self.assertEqual(json.loads(sql(p.job_query(self.one,'another-tenant')))['jobs'],[])
  sql("update ouf_udp.materialization_job set state_version=12")
  with self.assertRaises(Exception):p.verify_job(json.loads(sql(p.job_query(self.one,'tenant')))['jobs'],self.row)

 def test_explicit_native_denial_is_one_read_without_automatic_retry(self):
  for status in(401,403):
   client=Mock();client.request.side_effect=ValueError('NATIVE_RECOVERY_HTTP_'+str(status))
   with self.assertRaises(ValueError):retry.prepare(client,[self.one],'binding',self.now+200)
   self.assertEqual(client.request.call_count,1)
 def test_only_one_runtime_consent_is_present_in_composed_entry(self):
  import ast
  tree=ast.parse((ROOT/'tools/csv_last_row_recovery/run.py').read_bytes())
  calls=[n for n in ast.walk(tree)if isinstance(n,ast.Call)and isinstance(n.func,ast.Attribute)and n.func.attr=='terminal_consent']
  self.assertEqual(len(calls),1)
 def test_worker_authority_accepts_only_preserved318_and126_scope(self):
  worker={'schema':'ouf.policy-token-governed-worker-session.v1','predecessorGrantAttempts':318,'maximumCumulativeGrantAttempts':444,
   'policy':{'delays':[5,15,60,300,900],'max_attempts':126,'max_elapsed':3600,'attempt_timeout':30,'jitter':.2},
   'automaticBudgetRenewalAllowed':False,'consumedClaimReplayAllowed':False,'predecessorFenceBinding':{},'reviewHash':'review'}
  owner={'sourceClosureHash':'c'*64,'workerSessionScopeHash':p.digest(worker),
   'operation':'INSTALL_TOKEN_ONLY_GOVERNED_CONTINUATION_NO_FIRST_GRANT','initializeJournalOnlyIfAbsent':True,
   'automaticReplayAllowed':False,'applicationAcceptanceGranted':False,'ownerBindingHash':'owner'}
  scopes={'policyTokenFiniteWorkerSession':worker,'policyTokenOwnerInstallation':owner,
   'tokenOwnerRuntime':{'operation':'RENEW_EXISTING_POLICY_READ_CREDENTIAL','ownerBindingHash':'owner',
    'automaticBudgetResetAllowed':False,'legacyWriterMustBeMasked':True,'credentialReestablishmentRequired':True},
   'semanticFunctionalRuntime':{'reviewHash':'review'}}
  authority.scopes_valid('POLICY_TEST_SESSION',scopes,'c'*64)
  for key,value in(('predecessorGrantAttempts',317),('maximumCumulativeGrantAttempts',445)):
   changed=copy.deepcopy(scopes);changed['policyTokenFiniteWorkerSession'][key]=value
   changed['policyTokenOwnerInstallation']['workerSessionScopeHash']=p.digest(changed['policyTokenFiniteWorkerSession'])
   with self.assertRaises(Exception):authority.scopes_valid('POLICY_TEST_SESSION',changed,'c'*64)


 def test_delivered_package_matches_every_real_overlay_and_bootstrap(self):
  package_path=ROOT/'releases/csv-last-row-recovery-code-package-20261018.json'
  package=json.loads(package_path.read_bytes())
  self.assertEqual(set(package['sourceHashes']),set(bootstrap.OVERLAYS))
  self.assertFalse(package['runtimeAuthorityIssued'])
  for name,(filename,path)in bootstrap.OVERLAYS.items():
   self.assertEqual(hashlib.sha256((ROOT/path).read_bytes()).hexdigest(),package['sourceHashes'][name],name)
  for path,key in(('scripts/execute-csv-last-row-recovery-20261018.py','executorSha256'),('tools/csv_last_row_recovery/runtime.py','loaderSha256'),('releases/csv-last-row-recovery-selection-20261018.json','caseSha256')):
   self.assertEqual(hashlib.sha256((ROOT/path).read_bytes()).hexdigest(),package[key],key)
  launcher=(ROOT/'scripts/launch-csv-last-row-recovery-20261018.sh').read_text()
  self.assertIn(hashlib.sha256(package_path.read_bytes()).hexdigest(),launcher)
  for value in package['sourceHashes'].values():self.assertIn(value,launcher)
  self.assertIn(package['sourceCommit'],launcher)

if __name__=='__main__':unittest.main(verbosity=2)
