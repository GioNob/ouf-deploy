import copy,hashlib,importlib.util,json,os,signal,tempfile,types,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
def load(name,path):
 spec=importlib.util.spec_from_file_location(name,ROOT/path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
m=load('governed_capsule','scripts/prepare-source-revision-governed-continuation.py');stage=load('governed_stage','scripts/stage-source-revision-governed.py')
class Capsule(unittest.TestCase):
 def temp(self):return tempfile.TemporaryDirectory(dir=os.environ.get('OUF_TEST_ROOT',str(ROOT.parent)))
 def tearDown(self):signal.alarm(0)
 def test_stage_is_five_exact_files_and_pinned_no_overwrite(self):
  with self.temp()as temp:
   from contextlib import redirect_stdout
   import io
   target=Path(temp)/'code'
   with redirect_stdout(io.StringIO()):stage.stage(ROOT,target,'a'*40)
   manifest=json.loads((target/'manifest.json').read_bytes());self.assertEqual(set(p.name for p in target.iterdir()),{'manifest.json','prepare.py','entry.py','login.py','authorization.py'})
   for name,digest in manifest['files'].items():self.assertEqual(m.sha(m.stage_read(target/name,digest)),digest)
   with self.assertRaises(ValueError):stage.stage(ROOT,target,'a'*40)
 def test_source_tamper_symlink_and_unsafe_name_stop(self):
  with self.temp()as temp:
   root=Path(temp);p=root/'file';p.write_bytes(b'qualified');p.chmod(0o600);digest=m.sha(p.read_bytes())
   p.write_bytes(b'changed')
   with self.assertRaises(ValueError):m.stage_read(p,digest)
   other=root/'other';other.write_bytes(b'qualified');p.unlink();p.symlink_to(other)
   with self.assertRaises(ValueError):m.stage_read(p,digest)
   with self.assertRaises(ValueError):m.write_new(root,'../escape',b'denied')
 def test_private_capsule_member_persisted_and_duplicate_denied(self):
  with self.temp()as temp:
   root=Path(temp);binding=m.write_new(root,'completion.json',b'{"complete":true}')
   self.assertEqual(binding['sha256'],m.sha((root/'completion.json').read_bytes()));self.assertEqual((root/'completion.json').stat().st_mode&0o777,0o600)
   with self.assertRaises(FileExistsError):m.write_new(root,'completion.json',b'drift')
   self.assertEqual((root/'completion.json').read_bytes(),b'{"complete":true}')
 def test_readonly_reconciliation_requires_exact_ready_186_unclaimed_current_window(self):
  base={'executionReconciliation':{'contextClosureSha256':m.STOP_CLOSURE,'contextFiles':11},'humanSession':{'state':'READY','attempts':186,'remainingAttempts':70,'currentBootMatches':True,'expiredByWallClock':False,'monotonicDeadlinePassed':False,'windowRemainingSeconds':6700,'successorClaimPresent':False,'frozenGovernedHumanIdentityResult':'ACCEPTED'}}
  for field,value in ((None,None),('attempts',187),('state','BLOCKED'),('currentBootMatches',False),('expiredByWallClock',True),('monotonicDeadlinePassed',True),('windowRemainingSeconds',1199),('successorClaimPresent',True)):
   with self.subTest(field=field):
    report=copy.deepcopy(base)
    if field:report['humanSession'][field]=value
    source='def main():return '+repr(report)
    with patch.object(m,'DIAGNOSTIC_SOURCE',source):
     if field:
      with self.assertRaises(ValueError):m.reconcile()
     else:self.assertEqual(m.reconcile()[0],base)
 def test_frozen_predicate_diagnostic_and_verifier_are_exact_retained_bytes(self):
  self.assertEqual(m.DIAGNOSTIC_SOURCE,(ROOT/'scripts/read-source-revision-human-binding-stop-20261019.py').read_text())
  source=(ROOT/'scripts/resume-source-revision-iam-20261019.py').read_text();self.assertEqual(m.VERIFIER_SOURCE,source[:source.index('\nPROFILE=')]);self.assertEqual(m.BASE_PROFILE['contextPath'],'/etc/ouf/deploy-snapshots/source-revision-postboot-prepared-kfy691gh')
  self.assertEqual(set(m.MODULES),{'tools.chatbot_file_cohort.authorization','tools.source_revision_update.entry','tools.source_revision_update.login'})
if __name__=='__main__':unittest.main()
