import contextlib,copy,hashlib,importlib.util,io,json,os,signal,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
import test_prepared_source_revision_delivery as delivery
ROOT=Path(__file__).resolve().parents[1]
def load(name,path):
 spec=importlib.util.spec_from_file_location(name,ROOT/path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
m=load('custody_capsule','scripts/prepare-source-revision-custody-continuation.py');stage=load('custody_stage','scripts/stage-source-revision-custody.py')
class Capsule(unittest.TestCase):
 def temp(self):return tempfile.TemporaryDirectory(dir=os.environ['OUF_TEST_ROOT'])
 def tearDown(self):signal.alarm(0)
 def test_stage_exact_five_pinned_source_only_files_no_overwrite(self):
  with self.temp()as temp,contextlib.redirect_stdout(io.StringIO()):
   target=Path(temp)/'code';stage.stage(ROOT,target,'a'*40);manifest=json.loads((target/'manifest.json').read_bytes());self.assertEqual(set(p.name for p in target.iterdir()),{'manifest.json','prepare.py','native.py','entry.py','login.py'})
   for name,digest in manifest['files'].items():self.assertEqual(m.sha(m.stage_read(target/name,digest)),digest)
   with self.assertRaises(ValueError):stage.stage(ROOT,target,'a'*40)
 def test_full_81_file_reload_reads_retained_original_from_its_actual_context(self):
  with self.temp()as temp:
   root=Path(temp);prepared=root/'capsule';prepared.mkdir(mode=0o700);retained=root/'retained';retained.mkdir(mode=0o700)
   profile,result=delivery.PreparedDelivery().fixture(prepared)
   for key,name in (('currentOriginalPreparationBinding','current-original-preparation.json'),('preparedInputsBinding','postboot-private-inputs.json')):
    (prepared/name).rename(retained/name);result[key]['path']=str(retained/name)
   code=prepared/'executor-code';case=json.loads((code/'case.json').read_bytes());case['preparedPlanBinding']=result['preparedInputsBinding'];case['postbootOriginalPreparationBinding']=result['currentOriginalPreparationBinding'];(code/'case.json').write_bytes(m.encoded(case));profile['caseSha256']=m.sha((code/'case.json').read_bytes());result['caseBinding']['sha256']=profile['caseSha256'];package=json.loads((code/'package.json').read_bytes());package['caseSha256']=profile['caseSha256'];(code/'package.json').write_bytes(m.encoded(package));profile['packageSha256']=m.sha((code/'package.json').read_bytes());result['executorCodeBinding']['packageSha256']=profile['packageSha256'];(prepared/'postboot-preparation-result.json').write_bytes(m.encoded(result));profile['preparationResultSha256']=m.sha((prepared/'postboot-preparation-result.json').read_bytes());profile['retainedInputContext']=str(retained)
   namespace={'__name__':'fixture'};exec(compile(m.VERIFIER_SOURCE,'<exact-successor-verifier>','exec'),namespace)
   with contextlib.redirect_stdout(io.StringIO()):code,executor,original=namespace['verify_prepared'](profile)
   self.assertEqual(original,{'secret':'CANARY'});self.assertFalse((prepared/'current-original-preparation.json').exists())
   (retained/'current-original-preparation.json').write_bytes(b'drift')
   with self.assertRaises(Exception),contextlib.redirect_stdout(io.StringIO()):namespace['verify_prepared'](profile)
 def report(self):return {'contextFiles':22,'authorityArtifactsObserved':True,'signatureFilesPresent':2,'decisionReviewBound':True,'issuanceDecisionBound':True,'logicalScopeClaimBound':True,'updateJournal':{'version':0,'nextStage':0,'effectCount':0,'effects':[],'expiredByWallClock':True},'containerReadback':{k:{'identityMatchesExpected':True,'running':True,'paused':False,'restarting':False}for k in ('onboarding','mcp','udp','ingestion')},'humanSession':{'state':'READY','attempts':188,'remainingAttempts':68,'expiredByWallClock':False,'windowRemainingSeconds':4400}}
 def test_reconciliation_requires_consumed_expired_zero_effect_scope_and_exact_human188(self):
  changes=[None,('humanSession','attempts',189),('humanSession','windowRemainingSeconds',1199),('updateJournal','effectCount',1),('updateJournal','expiredByWallClock',False),(None,'logicalScopeClaimBound',False),(None,'contextFiles',23)]
  for change in changes:
   with self.subTest(change=change):
    report=self.report()
    if change:
     group,key,value=change;(report[group]if group else report)[key]=value
    with patch.object(m,'DIAGNOSTIC_SOURCE','def main():return '+repr(report)):
     if change:
      with self.assertRaises(Exception):m.reconcile()
     else:self.assertEqual(m.reconcile()[0],report)
 def test_embedded_read_is_exact_and_canonical_private_reader_not_modified(self):
  self.assertEqual(m.DIAGNOSTIC_SOURCE,(ROOT/'scripts/read-source-revision-after-approval-custody-20261019.py').read_text());self.assertEqual(set(m.MODULES),{'tools.source_revision_update.native','tools.source_revision_update.entry','tools.source_revision_update.login'})
  self.assertIn("read(binding['path'],binding['sha256'])",m.VERIFIER_SOURCE)
  self.assertIn("read(result['currentOriginalPreparationBinding']['path']",m.VERIFIER_SOURCE)
  self.assertEqual(m.BASE_PROFILE['retainedInputContext'],'/etc/ouf/deploy-snapshots/source-revision-postboot-prepared-kfy691gh')
